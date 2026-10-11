#!/usr/bin/env python3
"""Generate the cudabom Hugo documentation site.

This is the single source of truth for the content tree the Hugo site builds
from. It does three things, deterministically:

  1. Copies the long-form prose (README.md + docs/*.md) into Hugo's content/
     tree, adding Relearn front-matter and a stable menu weight per page.
  2. Generates data-driven reference pages that would be tedious and
     error-prone to maintain by hand, straight from the committed data:
       - CUDA fingerprint coverage, from fingerprints/cuda/*.json
       - NVIDIA advisory coverage, from advisories/index.json
       - the CLI command surface, from `cudabom --help`
  3. Writes a landing page (_index.md) that frames the project.

Nothing here invents facts: every generated number is read from the repo's own
data or the built binary. Re-run after editing docs/*.md or refreshing data:

    python .hugo/scripts/build_docs.py
    hugo server -s .hugo

The content/ tree is overwritten on every run; do not hand-edit it.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import urllib.parse
from pathlib import Path

# Resolve repo-root-relative paths so the script works from any CWD.
HUGO_DIR = Path(__file__).resolve().parent.parent
REPO = HUGO_DIR.parent
CONTENT = HUGO_DIR / "content"
DOCS = REPO / "docs"
FINGERPRINTS = REPO / "fingerprints"
ADVISORIES = REPO / "advisories" / "index.json"

# Ordered prose pages: (source file, slug, nav title, menu weight).
# README becomes the overview; each docs/*.md becomes a section page.
PROSE_PAGES = [
    (REPO / "README.md", "overview", "Overview", 10),
    (DOCS / "architecture.md", "architecture", "Architecture", 30),
    (DOCS / "evidence-model.md", "evidence-model", "Evidence model", 40),
    (DOCS / "policy.md", "policy", "Gate policy", 45),
    (DOCS / "advisories.md", "advisories", "Advisories", 50),
    (DOCS / "sources.md", "sources", "Data sources", 60),
    (DOCS / "comparison.md", "comparison", "Comparison", 70),
    # docs/benchmarks.md is intentionally NOT published as its own page: speed
    # and peak RSS now live in the comparison page's performance section (one
    # source of truth, measured head-to-head by `cargo xtask eval`). The repo
    # file is a short pointer to that section.
    (DOCS / "threat-model.md", "threat-model", "Threat model", 90),
]

# Documentation link per fingerprinted component family. Most families follow
# the convention https://docs.nvidia.com/cuda/<name>/, which component_doc_url
# derives automatically, so a new family that follows it is linked with no code
# change. Only families whose documentation lives elsewhere need an entry here;
# the binary-utility tools share the CUDA Binary Utilities guide, and the nvpl-*
# families live under the NVPL docs. The docs link-check (build_docs.py
# --check-links, run in CI) verifies every resolved URL still returns 200, so
# rot surfaces as a failing build rather than a dead link on the site.
COMPONENT_DOC_OVERRIDES = {
    "cudart": "https://docs.nvidia.com/cuda/cuda-runtime-api/",
    "cudla": "https://docs.nvidia.com/cuda/cudla-api/",
    "cudnn": "https://docs.nvidia.com/deeplearning/cudnn/",
    "cufile": "https://docs.nvidia.com/gpudirect-storage/api-reference-guide/",
    "cuobjclient": "https://docs.nvidia.com/cuda/cuda-binary-utilities/",
    "cuobjdump": "https://docs.nvidia.com/cuda/cuda-binary-utilities/",
    "cupti": "https://docs.nvidia.com/cupti/",
    "cuxxfilt": "https://docs.nvidia.com/cuda/cuda-binary-utilities/",
    "nccl": "https://docs.nvidia.com/deeplearning/nccl/",
    "nvpl-blas": "https://docs.nvidia.com/nvpl/_static/blas/index.html",
    "nvpl-fft": "https://docs.nvidia.com/nvpl/_static/fft/index.html",
    "nvpl-lapack": "https://docs.nvidia.com/nvpl/_static/lapack/index.html",
    "nvpl-rand": "https://docs.nvidia.com/nvpl/_static/rand/index.html",
    "nvpl-scalapack": "https://docs.nvidia.com/nvpl/_static/scalapack/index.html",
    "nvpl-sparse": "https://docs.nvidia.com/nvpl/_static/sparse/index.html",
    "nvpl-tensor": "https://docs.nvidia.com/nvpl/_static/tensor/index.html",
    "nvshmem": "https://docs.nvidia.com/nvshmem/api/",
    "nvvm": "https://docs.nvidia.com/cuda/nvvm-ir-spec/",
}


def component_doc_url(name: str) -> str:
    """NVIDIA documentation URL for a component family.

    Families whose docs follow the common convention resolve to
    https://docs.nvidia.com/cuda/<name>/ automatically; the rest come from
    COMPONENT_DOC_OVERRIDES. Every URL is validated by `--check-links`.
    """
    return COMPONENT_DOC_OVERRIDES.get(name, f"https://docs.nvidia.com/cuda/{name}/")


PACKAGE_KEY = re.compile(r"^(lib)?[a-z0-9]+(_[a-z0-9]+)*$")


def best_description(variants: set[str]) -> str:
    """Pick the most human-readable description among a family's variants.

    NVIDIA labels the same component differently across releases: prose like
    "CUDA cuBLAS" in some shards, the bare package key "libcublas" in others.
    Prefer a variant that reads as a phrase (has a space and is not just a
    package key), then the longest, so the table shows real descriptions.
    """
    if not variants:
        return ""

    def score(d: str) -> tuple[int, int]:
        # Rank anything that is not a bare package key above those that are, so
        # "cuDLA" beats "libcudla" even without a space; prefer longer within a
        # rank so fuller phrases win.
        return (0 if PACKAGE_KEY.match(d) else 1, len(d))

    return max(variants, key=score)


def component_families() -> set[str]:
    """Every component family name present in the fingerprint shards."""
    names: set[str] = set()
    for shard in FINGERPRINTS.glob("*/redistrib_*.json"):
        data = json.loads(shard.read_text(encoding="utf-8"))
        for c in data.get("components", []):
            name = c.get("name")
            if name:
                names.add(name)
    return names


def check_links() -> int:
    """Verify every component's documentation URL still resolves (HTTP 200).

    Run in CI so a convention change, a renamed NVIDIA page, or a newly
    fingerprinted family with a broken derived URL fails the build instead of
    shipping a dead link. Returns a process exit code.
    """
    import urllib.error
    import urllib.request

    families = sorted(component_families())
    log(f"checking {len(families)} component documentation link(s)")
    failures: list[tuple[str, str, str]] = []
    for name in families:
        url = component_doc_url(name)
        status: object = None
        for method in ("HEAD", "GET"):
            req = urllib.request.Request(
                url, method=method, headers={"User-Agent": "cudabom-docs-linkcheck"}
            )
            try:
                with urllib.request.urlopen(req, timeout=20) as resp:
                    status = resp.status
                break
            except urllib.error.HTTPError as e:
                status = e.code
                if method == "HEAD":
                    continue  # some servers reject HEAD; retry with GET
            except Exception as e:  # noqa: BLE001 - report any transport error
                status = str(e)
                if method == "HEAD":
                    continue
        if status != 200:
            failures.append((name, url, str(status)))
            log(f"  FAIL {name}: {status}  {url}")
        else:
            log(f"  ok   {name}  {url}")
    if failures:
        log(f"{len(failures)} documentation link(s) did not return 200")
        return 1
    log("all component documentation links resolved")
    return 0


def log(msg: str) -> None:
    print(f"build_docs: {msg}", file=sys.stderr)


def front_matter(title: str, weight: int, extra: str = "") -> str:
    """A minimal Relearn front-matter block."""
    block = f'+++\ntitle = "{title}"\nweight = {weight}\n'
    if extra:
        block += extra
    block += "+++\n\n"
    return block


BADGES_BLOCK = re.compile(r"<!--\s*BADGES_START.*?BADGES_END\s*-->\s*", re.DOTALL)


def strip_badges(body: str) -> str:
    """Drop the README badge block (shields.io images that only resolve against
    the GitHub repo) from pages rendered into the Hugo site, which has its own
    chrome. The `<!-- BADGES_START/END -->` markers delimit the block.
    """
    return BADGES_BLOCK.sub("", body)


def strip_leading_h1(body: str) -> str:
    """Drop a leading `# Title` so it does not duplicate the front-matter title."""
    lines = body.splitlines()
    for i, line in enumerate(lines):
        if line.strip() == "":
            continue
        if line.startswith("# "):
            return "\n".join(lines[i + 1 :]).lstrip("\n")
        break
    return body


def assets_base() -> str:
    """The site-root-relative base for copied brand assets.

    README art is referenced by its `raw.githubusercontent.com` URL; on the
    site it is served from `static/assets` (see `copy_docs_assets`). Raw `<img>`
    `src` attributes in the prose are not run through Hugo's `relURL`, so unlike
    Markdown links they do not pick up the Pages subpath automatically. Build the
    subpath here from the same `HUGO_BASEURL` the deploy uses, so the images
    resolve both locally (`/`) and under the project path (`/cudabom/`).
    """
    base = os.environ.get("HUGO_BASEURL", "/")
    path = urllib.parse.urlsplit(base).path or "/"
    return "/" + path.strip("/") + "/assets/" if path.strip("/") else "/assets/"


def rewrite_repo_links(body: str) -> str:
    """Point intra-repo doc links at their generated site pages.

    Prose cross-links use repo-relative paths (e.g. `docs/threat-model.md` or
    `../CONTRIBUTING.md`). On the site, map the docs we publish to their slugs
    and leave the rest pointing at GitHub so nothing dead-ends. Brand art that
    the README references by its raw.githubusercontent.com URL is repointed to
    the site-local copy under `static/assets` (see `copy_docs_assets`), through
    the baseURL-aware `assets_base` so the images render on the project subpath.
    """
    gh = "https://github.com/cpeoples/cudabom/blob/main"
    raw = "https://raw.githubusercontent.com/cpeoples/cudabom/main/docs/assets/"
    body = body.replace(raw, assets_base())
    replacements = {
        "docs/architecture.md": "/architecture/",
        "docs/evidence-model.md": "/evidence-model/",
        "docs/policy.md": "/policy/",
        "docs/advisories.md": "/advisories/",
        "docs/sources.md": "/sources/",
        "docs/comparison.md": "/comparison/",
        "docs/benchmarks.md": "/comparison/",
        "docs/threat-model.md": "/threat-model/",
        "../CONTRIBUTING.md": f"{gh}/CONTRIBUTING.md",
        "CONTRIBUTING.md": f"{gh}/CONTRIBUTING.md",
        "SECURITY.md": f"{gh}/SECURITY.md",
        "NOTICE": f"{gh}/NOTICE",
        "LICENSE": f"{gh}/LICENSE",
        "Cargo.toml": f"{gh}/Cargo.toml",
        "rust-toolchain.toml": f"{gh}/rust-toolchain.toml",
        "rustfmt.toml": f"{gh}/rustfmt.toml",
        "clippy.toml": f"{gh}/clippy.toml",
        "deny.toml": f"{gh}/deny.toml",
    }
    for src, dst in replacements.items():
        body = body.replace(f"]({src})", f"]({dst})")
    return body


def write_page(slug: str, text: str) -> None:
    out = CONTENT / f"{slug}.md"
    out.write_text(text, encoding="utf-8")


def copy_prose() -> int:
    count = 0
    for src, slug, title, weight in PROSE_PAGES:
        if not src.exists():
            log(f"skip missing {src.relative_to(REPO)}")
            continue
        body = src.read_text(encoding="utf-8")
        body = strip_badges(body)
        body = strip_leading_h1(body)
        if slug == "overview":
            # The README hero uses the dark GIF for dark mode; on the site's
            # overview, use the transparent (panel + light text) GIF in dark
            # mode so it sits on the page background, keeping the light GIF for
            # light mode. The light <source> is unchanged.
            body = body.replace(
                "docs/assets/brand-mark-animated.gif",
                "docs/assets/brand-mark-animated-transparent.gif",
            )
        body = rewrite_repo_links(body)
        write_page(slug, front_matter(title, weight) + body)
        count += 1
    log(f"copied {count} prose page(s)")
    return count


def gen_coverage() -> None:
    """CUDA fingerprint coverage, from every tree under fingerprints/.

    Each product tree is a subdirectory of fingerprints/ holding
    redistrib_<version>.json shards (cuda, cudnn, nccl, jetson, ...). The trees
    are discovered from the filesystem rather than listed here, so a tree added
    by a future refresh appears on this page with no code change.
    """

    def ver_key(label: str):
        parts = []
        for p in label.replace("-", ".").split("."):
            parts.append(int(p) if p.isdigit() else 0)
        return parts

    trees = sorted(d for d in FINGERPRINTS.iterdir() if d.is_dir())
    # Per tree: its releases; plus repo-wide rollups for the summary line.
    per_tree: list[tuple[str, list[tuple[str, str, int, int]]]] = []
    components: dict[str, int] = {}
    descriptions: dict[str, set[str]] = {}
    total_hashes = 0
    total_releases = 0
    # Releases NVIDIA lists but that ship no fingerprintable library (the CUDA
    # redist program predates the toolkit libraries: 11.0.3-11.4.1 carry only
    # fabricmanager/nscq, no cublas/cudart/etc.). Counted and explained, but not
    # shown as empty rows that would read as missing coverage.
    empty_releases = 0
    for tree in trees:
        releases = []
        for shard in sorted(tree.glob("redistrib_*.json")):
            data = json.loads(shard.read_text(encoding="utf-8"))
            rel = data.get("release", {})
            label = rel.get("label", shard.stem)
            comps = data.get("components", [])
            shard_hashes = 0
            for c in comps:
                name = c.get("name", "?")
                n = len(c.get("file_hashes", {}) or {})
                components[name] = components.get(name, 0) + n
                desc = (c.get("description") or "").strip()
                if desc:
                    # NVIDIA's descriptions vary across releases: some shards
                    # carry prose ("CUDA cuBLAS"), others only the raw package
                    # key ("libcublas"). Collect every variant and pick the most
                    # readable one at render time rather than letting shard order
                    # decide.
                    descriptions.setdefault(name, set()).add(desc)
                shard_hashes += n
            if shard_hashes == 0:
                empty_releases += 1
                continue
            total_hashes += shard_hashes
            releases.append((label, rel.get("date", ""), len(comps), shard_hashes))
        if not releases:
            continue
        releases.sort(key=lambda r: ver_key(r[0]))
        total_releases += len(releases)
        per_tree.append((tree.name, releases))

    summary = (
        f"**{total_releases} releases** fingerprinted across "
        f"**{len(per_tree)} product trees**, **{total_hashes:,} file hashes** "
        f"across **{len(components)} component families**.\n"
    )
    if empty_releases:
        summary += (
            f"\n{empty_releases} earlier release(s) NVIDIA lists carry no "
            "redistributable libraries (the CUDA redist program began at "
            "11.4.2), so they hold no fingerprints and are omitted below.\n"
        )
    lines = [
        front_matter("CUDA coverage", 20),
        "cudabom identifies CUDA components by matching an artifact's content "
        "against fingerprints **derived from NVIDIA's own redistributable "
        "archives**. This page is generated from the committed fingerprint "
        "database, so it always reflects exactly what the current build can "
        "recognize.\n",
        summary,
        "## Component families\n",
        "| Component | Description | File hashes |",
        "|---|---|---|",
    ]
    for name, n in sorted(components.items(), key=lambda kv: kv[0]):
        url = component_doc_url(name)
        desc = best_description(descriptions.get(name, set()))
        lines.append(f"| [`{name}`]({url}) | {desc} | {n:,} |")
    lines += ["", "## Fingerprinted releases\n"]
    for tree_name, releases in per_tree:
        tree_hashes = sum(r[3] for r in releases)
        lines += [
            f"### {tree_name}\n",
            f"{len(releases)} release(s), {tree_hashes:,} file hashes.\n",
            "| Release | Date | Components | File hashes |",
            "|---|---|---|---|",
        ]
        for label, date, ncomp, nhash in releases:
            lines.append(f"| {label} | {date or '-'} | {ncomp} | {nhash:,} |")
        lines.append("")
    write_page("coverage", "\n".join(lines))
    log(
        f"generated coverage page ({total_releases} releases across "
        f"{len(per_tree)} trees, {total_hashes} hashes)"
    )


def gen_advisories_stats() -> None:
    """Advisory coverage, from advisories/index.json: a severity rollup plus a
    compact per-advisory table (CVE, severity, CVSS, affected components, the
    version each is fixed in, and the canonical link). Data-driven, so it tracks
    the committed index on every refresh."""
    if not ADVISORIES.exists():
        log("skip advisory stats (advisories/index.json missing)")
        return
    data = json.loads(ADVISORIES.read_text(encoding="utf-8"))
    advs = data.get("advisories", [])
    sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
    sev_rank = {s: i for i, s in enumerate(sev_order)}
    by_sev: dict[str, int] = {}
    with_refs = 0
    total_refs = 0
    for a in advs:
        sev = (a.get("severity") or "UNKNOWN").upper()
        by_sev[sev] = by_sev.get(sev, 0) + 1
        refs = a.get("references", []) or []
        if refs:
            with_refs += 1
        total_refs += len(refs)
    lines = [
        front_matter("Advisory coverage", 55),
        "cudabom correlates identified CUDA versions against a normalized "
        "index built from **NVIDIA's machine-readable (CSAF) security "
        "bulletins**. This page is generated from the committed advisory "
        "index.\n",
        f"**{len(advs)} advisories** indexed from NVIDIA CSAF "
        f"(source commit `{data.get('source_commit', 'n/a')[:12]}`), "
        f"with **{total_refs} reference links** across **{with_refs}** of them.\n",
        "## By severity\n",
        "| Severity | Advisories |",
        "|---|---|",
    ]
    for sev in sev_order:
        if sev in by_sev:
            lines.append(f"| {sev} | {by_sev[sev]} |")

    def affected_cell(a: dict) -> tuple[str, str]:
        """(components, fixed-versions) cells for one advisory, joining the
        per-component fixed version from its ranges."""
        comps, fixes = [], []
        for item in a.get("affected", []) or []:
            comps.append(item.get("component", "?"))
            fixes += [
                r.get("fixed") for r in item.get("fixed_ranges", []) or [] if r.get("fixed")
            ]
        uniq = lambda xs: ", ".join(dict.fromkeys(xs)) or "-"  # noqa: E731
        return uniq(comps), uniq(fixes)

    advs_sorted = sorted(
        advs,
        key=lambda a: (
            sev_rank.get((a.get("severity") or "UNKNOWN").upper(), 99),
            -(a.get("cvss_score") or 0.0),  # highest CVSS first within a severity
            a.get("id", ""),  # stable, deterministic tiebreaker
        ),
    )
    lines += [
        "",
        "## Indexed advisories\n",
        "| CVE | Severity | CVSS | Affected | Fixed in |",
        "|---|---|---|---|---|",
    ]
    for a in advs_sorted:
        sev = (a.get("severity") or "UNKNOWN").upper()
        cvss = a.get("cvss_score")
        comps, fixes = affected_cell(a)
        cve = a.get("id", "?")
        refs = a.get("references", []) or []
        cve_cell = f"[`{cve}`]({refs[0]})" if refs else f"`{cve}`"
        lines.append(
            f"| {cve_cell} | {sev} | {cvss if cvss is not None else '-'} "
            f"| {comps} | {fixes} |"
        )
    lines.append("")
    write_page("advisory-coverage", "\n".join(lines))
    log(f"generated advisory-coverage page ({len(advs)} advisories)")


def gen_cli_reference() -> None:
    """CLI surface, from `cudabom --help` of each subcommand."""
    binary = None
    for cand in ("target/release/cudabom", "target/debug/cudabom"):
        p = REPO / cand
        if p.exists():
            binary = p
            break
    if binary is None:
        log("skip CLI reference (cudabom binary not built)")
        return

    def help_of(args: list[str]) -> str:
        try:
            out = subprocess.run(
                [str(binary), *args, "--help"],
                capture_output=True,
                text=True,
                timeout=20,
            )
            return (out.stdout or out.stderr).strip()
        except Exception as exc:  # noqa: BLE001 - best-effort doc generation
            return f"(could not capture help: {exc})"

    subcommands = [
        "scan",
        "gate",
        "enrich",
        "vex",
        "reconcile",
        "explain",
        "db",
        "update",
        "schema",
        "version",
    ]
    lines = [
        front_matter("CLI reference", 25),
        "Generated from `cudabom --help`, so it always matches the built "
        "binary. Exit codes: `0` success, `1` policy/threshold violation, "
        "`2` usage error, `3` input error, `4` internal error.\n",
        "## `cudabom`\n",
        "```text",
        help_of([]),
        "```",
    ]
    for sub in subcommands:
        lines += [f"\n## `cudabom {sub}`\n", "```text", help_of([sub]), "```"]
    write_page("cli", "\n".join(lines))
    log(f"generated CLI reference ({len(subcommands)} subcommands)")


def copy_docs_assets() -> None:
    """Mirror docs/assets into static/assets and seed the favicon/logo.

    The landing hero and the Relearn sidebar logo both reference brand art
    under docs/assets; Hugo serves static/ at the site root, so the files are
    copied there and the square icon is seeded as the favicon and sidebar logo.
    """
    docs_assets = DOCS / "assets"
    if not docs_assets.exists():
        log("skip asset copy (docs/assets missing)")
        return
    static_assets = HUGO_DIR / "static" / "assets"
    if static_assets.exists():
        shutil.rmtree(static_assets)
    static_assets.mkdir(parents=True, exist_ok=True)
    copied = 0
    for src in docs_assets.iterdir():
        if src.is_file():
            shutil.copy2(src, static_assets / src.name)
            copied += 1
    log(f"copied {copied} asset(s) -> static/assets/")

    icon = docs_assets / "cudabom-icon.svg"
    if icon.exists():
        static_images = HUGO_DIR / "static" / "images"
        static_images.mkdir(parents=True, exist_ok=True)
        for name in ("favicon.svg", "logo.svg"):
            shutil.copy2(icon, static_images / name)
        log("seeded favicon/logo from cudabom-icon.svg -> static/images/")


def write_landing() -> None:
    # Front matter: a rich `description` for SEO and the sidebar, no `home`
    # archetype. The
    # body opens with a centered brand hero (light/dark marks) and is pure
    # product prose, no "generated by build_docs.py" furniture, matching the
    # reference sites.
    front = front_matter(
        "CudaBOM",
        1,
        'description = "Find the CUDA your SBOM missed: evidence-backed CUDA '
        'identity for artifacts."\n'
        "alwaysopen = true\n",
    )
    hero = "{{< brandhero >}}\n\n"
    body = (
        "**Find the CUDA your SBOM missed.**\n\n"
        "cudabom is an open-source Rust CLI that proves which NVIDIA CUDA "
        "software is actually inside an artifact (Python wheels, shared "
        "libraries, executables, and container images) and turns that "
        "evidence into security-grade SBOM, advisory, and VEX data.\n\n"
        "Start with the [Overview](/overview/), jump to the "
        "[CLI reference](/cli/), see what it recognizes under "
        "[CUDA coverage](/coverage/) and [Advisory coverage]"
        "(/advisory-coverage/), and read the measured [Comparison]"
        "(/comparison/) against blint, Syft, and Trivy.\n"
    )
    write_page("_index", front + hero + body)


def main() -> int:
    if "--check-links" in sys.argv[1:]:
        return check_links()
    if CONTENT.exists():
        shutil.rmtree(CONTENT)
    CONTENT.mkdir(parents=True)
    copy_docs_assets()
    write_landing()
    copy_prose()
    gen_cli_reference()
    gen_coverage()
    gen_advisories_stats()
    log(f"content written to {CONTENT.relative_to(REPO)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
