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
import re
import shutil
import subprocess
import sys
from pathlib import Path

# Resolve repo-root-relative paths so the script works from any CWD.
HUGO_DIR = Path(__file__).resolve().parent.parent
REPO = HUGO_DIR.parent
CONTENT = HUGO_DIR / "content"
DOCS = REPO / "docs"
FINGERPRINTS = REPO / "fingerprints" / "cuda"
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


def rewrite_repo_links(body: str) -> str:
    """Point intra-repo doc links at their generated site pages.

    Prose cross-links use repo-relative paths (e.g. `docs/threat-model.md` or
    `../CONTRIBUTING.md`). On the site, map the docs we publish to their slugs
    and leave the rest pointing at GitHub so nothing dead-ends. Brand art that
    the README references by its raw.githubusercontent.com URL is repointed to
    the site-local copy under /assets/ (see `copy_docs_assets`), so the images
    render on the site instead of depending on the public GitHub raw host.
    """
    gh = "https://github.com/cpeoples/cudabom/blob/main"
    raw = "https://raw.githubusercontent.com/cpeoples/cudabom/main/docs/assets/"
    body = body.replace(raw, "/assets/")
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
        body = rewrite_repo_links(body)
        write_page(slug, front_matter(title, weight) + body)
        count += 1
    log(f"copied {count} prose page(s)")
    return count


def gen_coverage() -> None:
    """CUDA fingerprint coverage, from fingerprints/cuda/*.json."""
    shards = sorted(FINGERPRINTS.glob("*.json"))
    releases = []
    components: dict[str, int] = {}
    total_hashes = 0
    for shard in shards:
        data = json.loads(shard.read_text(encoding="utf-8"))
        rel = data.get("release", {})
        label = rel.get("label", shard.stem)
        comps = data.get("components", [])
        shard_hashes = 0
        for c in comps:
            name = c.get("name", "?")
            n = len(c.get("file_hashes", {}) or {})
            components[name] = components.get(name, 0) + n
            shard_hashes += n
        total_hashes += shard_hashes
        releases.append((label, rel.get("date", ""), len(comps), shard_hashes))

    def ver_key(label: str):
        parts = []
        for p in label.replace("-", ".").split("."):
            parts.append(int(p) if p.isdigit() else 0)
        return parts

    releases.sort(key=lambda r: ver_key(r[0]))

    lines = [
        front_matter("CUDA coverage", 20),
        "cudabom identifies CUDA components by matching an artifact's content "
        "against fingerprints **derived from NVIDIA's own redistributable "
        "archives**. This page is generated from the committed fingerprint "
        "database, so it always reflects exactly what the current build can "
        "recognize.\n",
        f"**{len(releases)} CUDA releases** fingerprinted, "
        f"**{total_hashes:,} file hashes** across "
        f"**{len(components)} component families**.\n",
        "## Component families\n",
        "| Component | File hashes |",
        "|---|---|",
    ]
    for name, n in sorted(components.items(), key=lambda kv: (-kv[1], kv[0])):
        lines.append(f"| `{name}` | {n:,} |")
    lines += [
        "",
        "## Fingerprinted releases\n",
        "| CUDA release | Date | Components | File hashes |",
        "|---|---|---|---|",
    ]
    for label, date, ncomp, nhash in releases:
        lines.append(f"| {label} | {date or '-'} | {ncomp} | {nhash:,} |")
    lines.append("")
    write_page("coverage", "\n".join(lines))
    log(f"generated coverage page ({len(releases)} releases, {total_hashes} hashes)")


def gen_advisories_stats() -> None:
    """Advisory coverage, from advisories/index.json."""
    if not ADVISORIES.exists():
        log("skip advisory stats (advisories/index.json missing)")
        return
    data = json.loads(ADVISORIES.read_text(encoding="utf-8"))
    advs = data.get("advisories", [])
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
    sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
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
