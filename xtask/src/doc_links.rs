//! `cargo xtask doc-links`: resolve the canonical NVIDIA documentation URL for
//! every fingerprinted component family and write them to
//! `advisories/component-docs.json`.
//!
//! Historically the doc link per family was guessed by `build_docs.py` from the
//! `docs.nvidia.com/cuda/<name>/` convention, with a hand-maintained override
//! table (`COMPONENT_DOC_OVERRIDES`) for every family that lived elsewhere. That
//! table grew with each auto-derived (Model B) library and was only validated at
//! site-build time by `--check-links`, so a wrong guess shipped as a dead link
//! until someone noticed. This task replaces the guessing with an active,
//! staged discovery that proves each URL against the live docs during the
//! nightly refresh, and records the result in a committed, reviewable sidecar.
//!
//! Discovery is deliberately conservative. For each family it resolves a URL in
//! stages and takes the first that is proven to name the component:
//!
//!   1. **Declared exception**: a tiny, reviewed table ([`EXCEPTIONS`]) of
//!      families whose documentation genuinely cannot be derived (a renamed
//!      slug, a guide section no rule can single out). Each carries the reason,
//!      so the table stays honest and small.
//!   2. **Ranked templates**: the handful of real NVIDIA/RAPIDS URL layouts a
//!      family can follow (`docs.nvidia.com/cuda/<name>/`, `.../<name>-api/`,
//!      `docs.nvidia.com/deeplearning/<name>/`, the NVPL static tree, the
//!      developer-site landing). Each candidate is fetched and classified
//!      (below); the first VALID one wins.
//!   3. **Parent crawl**: when no template is VALID but a plausible parent
//!      landing page exists (e.g. a library documented as a sub-page of its
//!      toolkit), the parent is fetched and scanned for a link whose slug is
//!      exactly `<name>.html` or `/<name>/` (so `cal.html` wins over
//!      `cal_to_nccl.html`).
//!   4. **Guide-section anchor**: for a family documented as a section inside a
//!      shared guide, the guides' machine-readable Sphinx inventories
//!      (`objects.inv`) are read for a label that exactly names the family, and
//!      the result deep-links `guide#anchor`. Guides are enumerated from the
//!      published `docs.nvidia.com/cuda/llms.txt` index, so a new
//!      section-documented library is found with no code change.
//!
//! Classification of a fetched candidate is three-state, so a JavaScript shell
//! page (200 with an empty rendered body, e.g. cuQuantum/cuTensor) is never
//! mistaken for a wrong page:
//!   - **Valid**: the component name or a declared alias appears in the page
//!     `<title>` or an `<h1>`..`<h4>`.
//!   - **Blank**: the page returned 200 but carries no usable heading text (a
//!     client-rendered shell). A Blank on a name-matching slug is *accepted*
//!     (the URL is right even though we cannot read the heading), never vetoed.
//!   - **Mismatch**: the page affirmatively names a *different* component. Only
//!     a Mismatch downgrades a candidate; a 404 (`FetchError::Status(404)`)
//!     simply moves to the next candidate.
//!
//! Modes mirror `product-map` so CI stays offline and deterministic:
//!   - `--check` (default): re-render the committed sidecar in canonical form
//!     and compare byte-for-byte. No network. Catches hand-edits and drift.
//!   - `--write`: run the online discovery and write the sidecar. Run in the
//!     nightly refresh so a newly fingerprinted family's link is discovered and
//!     reviewed in the same PR that introduces it.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use cudabom_fetch::{get, FetchError, GetOptions};

use crate::verbosity::{detail, status};
use crate::{flag, has_flag};

/// Default output path for the generated sidecar.
const DEFAULT_OUT: &str = "advisories/component-docs.json";

/// Root directory holding the committed fingerprint shards. Component families
/// are enumerated from this tree (the same source `build_docs.py` reads), so a
/// family added by a refresh is discovered with no code change.
const DEFAULT_SHARD_ROOT: &str = "fingerprints";

/// The sidecar schema version this generator emits.
const SCHEMA_VERSION: u32 = 1;

/// A reviewed documentation exception: a family whose canonical URL cannot be
/// derived from any template or parent crawl, with the reason recorded so the
/// table stays small and auditable.
struct Exception {
    /// The component family name as it appears in the shards.
    component: &'static str,
    /// The canonical documentation URL.
    url: &'static str,
    /// Why this family needs a hand-declared URL (shown in review, not emitted).
    reason: &'static str,
}

/// The irreducible set of families whose documentation does not follow any
/// derivable NVIDIA/RAPIDS layout and cannot be found by the guide-section
/// anchor lookup either. Everything else is discovered live.
///
/// Kept as small as the real world allows. `cuobjdump` and `cu++filt` are NOT
/// here: they are sections of the shared CUDA Binary Utilities guide that
/// [`resolve_guide_anchor`] finds by exact inventory match. The entries that
/// remain are the genuinely underivable ones: a renamed slug (`cudart`,
/// `nvvm`), a guide section whose title no rule can single out (`cufile`, among
/// the guide's many "cuFile ..." headings), and a client library the guide
/// never names in a heading (`cuobjclient`).
const EXCEPTIONS: &[Exception] = &[
    Exception {
        component: "cudart",
        url: "https://docs.nvidia.com/cuda/cuda-runtime-api/",
        reason: "the CUDA runtime is documented as 'cuda-runtime-api', not a /cuda/cudart/ slug",
    },
    Exception {
        component: "cufile",
        url: "https://docs.nvidia.com/gpudirect-storage/api-reference-guide/#cufile-api-specification",
        reason: "the overview section 'cuFile API Specification' is not derivable among the \
                 guide's many 'cuFile ...' API headings, so it is pinned rather than crawled",
    },
    Exception {
        component: "nvvm",
        url: "https://docs.nvidia.com/cuda/nvvm-ir-spec/",
        reason: "NVVM is documented as the 'nvvm-ir-spec', not a /cuda/nvvm/ slug",
    },
    Exception {
        component: "cuobjclient",
        url: "https://docs.nvidia.com/cuda/cuda-binary-utilities/",
        reason: "the client library is not named in any heading of the Binary Utilities guide, \
                 so the crawl finds no anchor; it falls back to the guide landing",
    },
    Exception {
        component: "compat_orin",
        url: "https://docs.nvidia.com/cuda/cuda-for-tegra-appnote/",
        reason: "the Orin/L4T forward-compatibility package is documented in the CUDA for Tegra \
                 app note, not a /cuda/compat_orin/ slug the templates or crawl can derive",
    },
    Exception {
        component: "nvprof",
        url: "https://docs.nvidia.com/cuda/profiler-users-guide/",
        reason: "the legacy command-line profiler is documented in the Profiler User's Guide, \
                 whose slug shares no token with 'nvprof' so no template or crawl reaches it",
    },
];

/// Known heading aliases: strings (besides the family name itself) that count as
/// a VALID name match when found in a page title or heading. NVIDIA brands many
/// libraries with mixed case or a marketing name the slug drops; matching is
/// case-insensitive on the normalized form, so this only needs genuinely
/// different spellings, not case variants.
fn heading_aliases(component: &str) -> &'static [&'static str] {
    match component {
        "cudart" => &["cuda runtime", "cuda-runtime-api"],
        "nvjpeg2000" => &["nvjpeg 2000"],
        "cal" => &["communication abstraction layer"],
        "cuxxfilt" => &["cu++filt"],
        _ => &[],
    }
}

/// `doc-links [--check | --write] [--out <file>] [--shards <dir>]`
pub(crate) fn run(args: &[String]) -> Result<()> {
    let out = PathBuf::from(flag(args, "--out").unwrap_or_else(|| DEFAULT_OUT.to_string()));
    let shard_root =
        PathBuf::from(flag(args, "--shards").unwrap_or_else(|| DEFAULT_SHARD_ROOT.to_string()));
    if has_flag(args, "--write") && has_flag(args, "--check") {
        bail!("--write and --check are mutually exclusive");
    }

    // --check is the safe default so a bare invocation never touches the network
    // or mutates the tree.
    if has_flag(args, "--write") {
        let families = component_families(&shard_root)?;
        status!(
            "xtask: resolving documentation links for {} component families",
            families.len()
        );
        let (resolved, unresolved) = resolve_all(&families);
        if !unresolved.is_empty() {
            bail!(
                "no documentation URL resolved for {} family/families: {}.\n\
                 Each is a family whose docs live at a slug no template, parent \
                 crawl, or guide-section anchor can derive. Add a reviewed entry \
                 to EXCEPTIONS in xtask/src/doc_links.rs (with the proven URL and \
                 the reason), then re-run.",
                unresolved.len(),
                unresolved.join(", ")
            );
        }
        let generated = render(&resolved);
        if let Some(parent) = out.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        std::fs::write(&out, &generated).with_context(|| format!("writing {}", out.display()))?;
        status!(
            "xtask: wrote {} ({} link(s))",
            out.display(),
            resolved.len()
        );
        return Ok(());
    }

    // Offline: parse the committed sidecar and re-render it canonically. A
    // mismatch means the file was hand-edited or formatted differently, not
    // that a link rotted (that is `build_docs.py --check-links`, online).
    let existing = std::fs::read_to_string(&out).with_context(|| {
        format!(
            "reading {} (run `cargo xtask doc-links --write`)",
            out.display()
        )
    })?;
    let parsed = parse(&existing)
        .with_context(|| format!("parsing {} (is it valid sidecar JSON?)", out.display()))?;
    let regenerated = render(&parsed);
    if existing == regenerated {
        status!("xtask: {} is canonically formatted", out.display());
        return Ok(());
    }
    bail!(
        "{} is not in canonical form.\n\
         Re-run `cargo xtask doc-links --write` (online) to regenerate it, or \
         hand-fix the formatting to match (sorted keys, 2-space indent, trailing newline).",
        out.display()
    )
}

/// Every component family name present in the committed shard tree, sorted and
/// de-duplicated. Mirrors `build_docs.py`'s `component_families()` so the
/// sidecar covers exactly the families the site links.
fn component_families(shard_root: &std::path::Path) -> Result<Vec<String>> {
    let (db, _report) = cudabom_identify::FingerprintDb::from_dir(shard_root)
        .with_context(|| format!("loading shards from {}", shard_root.display()))?;
    let mut names: Vec<String> = db.components.into_iter().map(|c| c.name).collect();
    names.sort();
    names.dedup();
    Ok(names)
}

/// Resolve a documentation URL for every family. Returns the proven links plus
/// the families that resolved to nothing, so the caller can refuse to write a
/// sidecar that would leave a family to `build_docs.py`'s 404-prone fallback.
fn resolve_all(families: &[String]) -> (BTreeMap<String, String>, Vec<String>) {
    let mut out = BTreeMap::new();
    let mut unresolved = Vec::new();
    for name in families {
        if let Some(url) = resolve_one(name) {
            detail!("xtask:   {name} -> {url}");
            out.insert(name.clone(), url);
        } else {
            status!("xtask:   {name}: no documentation URL resolved");
            unresolved.push(name.clone());
        }
    }
    (out, unresolved)
}

/// Resolve a single family through the staged pipeline: declared exception,
/// ranked templates, parent crawl, then guide-section anchor, with a BLANK
/// template accepted only as a last resort.
fn resolve_one(name: &str) -> Option<String> {
    if let Some(ex) = EXCEPTIONS.iter().find(|e| e.component == name) {
        detail!("xtask:   {name}: declared exception ({})", ex.reason);
        return Some(ex.url.to_string());
    }

    // Stage 2: ranked templates. Keep the first VALID candidate; remember the
    // first BLANK (200 but unreadable) as a fallback if nothing validates.
    let mut blank_fallback: Option<String> = None;
    for url in template_candidates(name) {
        match classify(name, &url) {
            Classification::Valid => {
                detail!("xtask:   {name}: template VALID {url}");
                return Some(url);
            }
            Classification::Blank => {
                detail!("xtask:   {name}: template BLANK (shell) {url}");
                if blank_fallback.is_none() {
                    blank_fallback = Some(url);
                }
            }
            Classification::Mismatch => {
                detail!("xtask:   {name}: template MISMATCH {url}");
            }
            Classification::Absent => {}
        }
    }

    // Stage 3: parent crawl. For families documented as a sub-page of a toolkit
    // landing page, scan plausible parents for an exact-slug link.
    for parent in parent_candidates(name) {
        if let Some(url) = crawl_for_slug(name, &parent) {
            detail!("xtask:   {name}: crawl found {url} under {parent}");
            return Some(url);
        }
    }

    // Stage 3b: in-page section anchor. For families documented as a section of
    // a shared CUDA guide, look up the guides' machine-readable Sphinx
    // inventories for a label that exactly names the family and deep-link to
    // `guide#anchor`. Fully generic: guides come from the published llms.txt
    // index, so a new section-documented tool is found with no code change.
    if let Some(url) = resolve_guide_anchor(name) {
        detail!("xtask:   {name}: inventory anchor {url}");
        return Some(url);
    }

    // A BLANK template (right slug, client-rendered body) beats nothing: the URL
    // named the component and returned 200, we just could not read a heading.
    if let Some(url) = blank_fallback {
        detail!("xtask:   {name}: accepting BLANK template {url}");
        return Some(url);
    }

    None
}

/// Ordered documentation URL templates to probe for a family, most-conventional
/// first. These are the real NVIDIA/RAPIDS layouts libraries follow; the first
/// that classifies VALID (or, failing all, BLANK) wins.
fn template_candidates(name: &str) -> Vec<String> {
    let mut v = vec![
        format!("https://docs.nvidia.com/cuda/{name}/"),
        format!("https://docs.nvidia.com/cuda/{name}-api/"),
        format!("https://docs.nvidia.com/deeplearning/{name}/"),
        format!("https://docs.nvidia.com/{name}/"),
    ];
    // NVPL families (nvpl-blas, ...) live under a static per-library tree keyed
    // by the suffix after the `nvpl-` prefix.
    if let Some(suffix) = name.strip_prefix("nvpl-") {
        v.push(format!(
            "https://docs.nvidia.com/nvpl/_static/{suffix}/index.html"
        ));
    }
    // Developer-site landing is last: it is the least specific and some of these
    // pages are marketing shells, so it only wins when nothing better validates.
    v.push(format!("https://developer.nvidia.com/{name}"));
    v
}

/// Plausible parent landing pages to crawl for a family's sub-page. Only used
/// when no template validated. Each parent is a page likely to link the
/// family's own page by an exact `<name>.html` slug.
fn parent_candidates(name: &str) -> Vec<String> {
    match name {
        // CAL (communication abstraction layer) is documented as a sub-page of
        // the cuBLASMp guide rather than its own tree.
        "cal" => vec!["https://docs.nvidia.com/cuda/cublasmp/".to_string()],
        _ => Vec::new(),
    }
}

/// Resolve a family to an in-page section anchor inside a shared CUDA guide,
/// using the guides' machine-readable Sphinx inventories (`objects.inv`).
///
/// This is the fully generic replacement for a hardcoded guide/component map.
/// It enumerates the CUDA documentation guides from the published
/// `docs.nvidia.com/cuda/llms.txt` index (falling back to the HTML index), then
/// for each guide reads its `objects.inv` and looks for a label whose anchor id
/// OR human display text normalizes *exactly* to the family name or a declared
/// alias. The first exact match becomes `guide#anchor`.
///
/// Exact match (not substring) is what makes this safe: the binary-utilities
/// inventory carries both `cuobjdump` (the section) and `cuobjdump-usage`,
/// `differences-...`, etc.; only the first equals the family name. A family the
/// inventories never name exactly (e.g. `cufile`, whose canonical section is the
/// human-titled "cuFile API Specification" among dozens of `cuFile*` API labels)
/// yields nothing and falls through to its declared exception. Returns the first
/// `guide#anchor` found, or `None`.
fn resolve_guide_anchor(name: &str) -> Option<String> {
    let needles = name_needles(name);
    for guide in cuda_guide_bases() {
        let Some(labels) = guide_inventory(guide) else {
            continue;
        };
        // Prefer a label whose anchor id equals the name, then one whose display
        // text equals it; both are exact so order only breaks genuine ties.
        let mut by_display: Option<String> = None;
        for (label, (uri, display)) in &labels {
            let norm_label = normalize(label);
            if needles.contains(&norm_label) {
                return Some(join_guide_uri(guide, uri));
            }
            if by_display.is_none() && display != "-" {
                let norm_display = normalize(display);
                if needles.contains(&norm_display) {
                    by_display = Some(join_guide_uri(guide, uri));
                }
            }
        }
        if let Some(url) = by_display {
            return Some(url);
        }
    }
    None
}

/// The CUDA documentation guide base URLs, discovered once per run from the
/// published `llms.txt` index (with the server-rendered HTML index as a
/// fallback). Each entry ends in `/` so a relative `objects.inv`/`index.html`
/// resolves against it. Cached for the life of the process.
fn cuda_guide_bases() -> &'static [String] {
    static CACHE: std::sync::OnceLock<Vec<String>> = std::sync::OnceLock::new();
    CACHE.get_or_init(|| {
        let mut bases = guide_bases_from_llms();
        if bases.is_empty() {
            bases = guide_bases_from_html_index();
        }
        detail!("xtask:   enumerated {} CUDA doc guide(s)", bases.len());
        bases
    })
}

/// Parse guide base URLs out of `docs.nvidia.com/cuda/llms.txt`. The file lists
/// each guide as a Markdown link `[desc](https://.../<guide>/index.html[.md])`;
/// we strip the trailing `index.html`/`index.html.md` to get the base dir and
/// keep only `docs.nvidia.com` guides (the inventory lives there).
fn guide_bases_from_llms() -> Vec<String> {
    let Ok(body) = fetch("https://docs.nvidia.com/cuda/llms.txt") else {
        return Vec::new();
    };
    let text = String::from_utf8_lossy(&body);
    let mut bases = std::collections::BTreeSet::new();
    for url in markdown_link_targets(&text) {
        if !url.starts_with("https://docs.nvidia.com/") {
            continue;
        }
        let base = url
            .trim_end_matches(".md")
            .trim_end_matches("index.html")
            .to_string();
        let base = if base.ends_with('/') {
            base
        } else {
            format!("{base}/")
        };
        bases.insert(base);
    }
    bases.into_iter().collect()
}

/// Fallback guide enumeration from the server-rendered CUDA HTML index. Collects
/// `<slug>/index.html` relative links under `docs.nvidia.com/cuda/`.
fn guide_bases_from_html_index() -> Vec<String> {
    let Ok(body) = fetch("https://docs.nvidia.com/cuda/") else {
        return Vec::new();
    };
    let text = String::from_utf8_lossy(&body);
    let mut bases = std::collections::BTreeSet::new();
    for href in extract_hrefs(&text) {
        // Relative "slug/index.html" or absolute ".../cuda/slug/index.html".
        if let Some(slug) = href.strip_suffix("/index.html") {
            let slug = slug.rsplit('/').next().unwrap_or(slug);
            if !slug.is_empty() && slug.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
                bases.insert(format!("https://docs.nvidia.com/cuda/{slug}/"));
            }
        }
    }
    bases.into_iter().collect()
}

/// Extract the URL targets from Markdown links `[text](url)` in `text`.
fn markdown_link_targets(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(rel) = text[i..].find("](") {
        let start = i + rel + 2;
        if let Some(erel) = text[start..].find(')') {
            out.push(text[start..start + erel].trim().to_string());
            i = start + erel + 1;
        } else {
            break;
        }
    }
    out
}

/// Fetch and decode a guide's Sphinx inventory (`objects.inv`), returning a map
/// of `label -> (uri, display)`. The inventory is a 4-line text header followed
/// by a zlib-compressed body of `name domain:role priority uri display` rows,
/// where a `uri` ending in `#$` abbreviates `#<name>`. Returns `None` when the
/// guide has no inventory (not a Sphinx site). Cached per guide for the run so a
/// repeated lookup never re-fetches.
fn guide_inventory(base: &str) -> Option<InventoryMap> {
    static CACHE: std::sync::OnceLock<std::sync::Mutex<BTreeMap<String, Option<InventoryMap>>>> =
        std::sync::OnceLock::new();
    let cache = CACHE.get_or_init(|| std::sync::Mutex::new(BTreeMap::new()));
    if let Some(hit) = cache
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(base)
    {
        return hit.clone();
    }
    let parsed = fetch_and_parse_inventory(base);
    cache
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(base.to_string(), parsed.clone());
    parsed
}

/// `label -> (uri, display)` for one guide's inventory.
type InventoryMap = BTreeMap<String, (String, String)>;

/// Fetch `base/objects.inv`, decompress, and parse it into an [`InventoryMap`].
fn fetch_and_parse_inventory(base: &str) -> Option<InventoryMap> {
    let url = format!("{base}objects.inv");
    let raw = fetch(&url).ok()?;
    // Header: four '\n'-terminated comment lines, then the zlib stream.
    let mut newlines = 0;
    let mut body_start = 0;
    for (i, b) in raw.iter().enumerate() {
        if *b == b'\n' {
            newlines += 1;
            if newlines == 4 {
                body_start = i + 1;
                break;
            }
        }
    }
    if body_start == 0 || body_start >= raw.len() {
        return None;
    }
    let mut decoder = flate2::read::ZlibDecoder::new(&raw[body_start..]);
    let mut inventory_text = String::new();
    std::io::Read::read_to_string(&mut decoder, &mut inventory_text).ok()?;

    let map = parse_inventory_body(&inventory_text);
    if map.is_empty() {
        None
    } else {
        Some(map)
    }
}

/// Parse the decompressed body of a Sphinx `objects.inv` into `label -> (uri,
/// display)`. Each row is `name domain:role priority uri display`; the display
/// may be `-` or contain spaces, and a `uri` ending in `#$` abbreviates
/// `#<name>`. Split out from the fetch/decompress step so it is unit-testable
/// without network or a hand-rolled copy of the loop.
fn parse_inventory_body(body: &str) -> InventoryMap {
    let mut map = InventoryMap::new();
    for line in body.lines() {
        let mut fields = line.splitn(5, ' ');
        let (Some(name), Some(_domain), Some(_priority), Some(uri)) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        let display = fields.next().unwrap_or("-").trim().to_string();
        let uri = uri.replace("#$", &format!("#{name}"));
        map.insert(name.to_string(), (uri, display));
    }
    map
}

/// Join a guide base URL with an inventory `uri` (relative like
/// `index.html#anchor`, or absolute).
fn join_guide_uri(base: &str, uri: &str) -> String {
    if uri.starts_with("http://") || uri.starts_with("https://") {
        uri.to_string()
    } else {
        format!("{base}{uri}")
    }
}

/// Three-state (plus Absent) outcome of inspecting a fetched candidate page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Classification {
    /// The page title/heading names the family (or a declared alias).
    Valid,
    /// 200, but no readable heading text (a client-rendered JS shell). The slug
    /// is presumed correct; accepted only as a fallback.
    Blank,
    /// The page affirmatively names a different component. Downgraded.
    Mismatch,
    /// 404 or unreachable. Skipped.
    Absent,
}

/// Fetch `url` and classify whether it documents `name`.
fn classify(name: &str, url: &str) -> Classification {
    // A 404 means the slug does not exist; any other error (transport, a
    // non-404 status) is treated the same way so one flaky URL never promotes a
    // wrong page. Discovery runs in the refresh where a transient miss is
    // recovered on the next run.
    let Ok(body) = fetch(url) else {
        return Classification::Absent;
    };
    let text = String::from_utf8_lossy(&body);
    let headings = extract_headings(&text);
    if headings.is_empty() {
        // 200 with no heading text: a JS shell (cuquantum/cutensor render client
        // side). We cannot read a name, but the slug matched and returned 200.
        return Classification::Blank;
    }
    let needles = name_needles(name);
    let haystack: String = headings.join(" \u{1}");
    let norm_hay = normalize(&haystack);
    if needles.iter().any(|n| norm_hay.contains(n.as_str())) {
        Classification::Valid
    } else {
        // Headings exist and none names the family: this page is about something
        // else. Downgrade so a loose template never records a wrong page.
        Classification::Mismatch
    }
}

/// The normalized strings that count as naming `name`: the family name itself
/// plus any declared heading aliases.
fn name_needles(name: &str) -> Vec<String> {
    let mut v = vec![normalize(name)];
    for alias in heading_aliases(name) {
        v.push(normalize(alias));
    }
    v
}

/// Crawl a parent landing page for a link whose slug is exactly `<name>.html` or
/// `/<name>/`, preferring an exact slug over a loose substring (`cal.html` over
/// `cal_to_nccl.html`). Returns the absolute URL of the matched link.
fn crawl_for_slug(name: &str, parent: &str) -> Option<String> {
    let body = fetch(parent).ok()?;
    let text = String::from_utf8_lossy(&body);
    let hrefs = extract_hrefs(&text);
    // Exact-slug match first.
    let exact_file = format!("{name}.html");
    let exact_dir = format!("{name}/");
    let hit = hrefs.iter().find(|h| {
        let tail = h.rsplit('/').next().unwrap_or(h);
        tail == exact_file || h.ends_with(&exact_dir)
    })?;
    Some(absolutize(parent, hit))
}

/// Fetch a URL with the shared verified/retrying primitive and the project user
/// agent. Returns the body bytes or the underlying [`FetchError`].
fn fetch(url: &str) -> Result<Vec<u8>, FetchError> {
    detail!("xtask:     GET {url}");
    get(
        url,
        &GetOptions {
            user_agent: cudabom_fetch::DEFAULT_USER_AGENT.to_string(),
            ..GetOptions::default()
        },
    )
}

/// Extract the text of the `<title>` and `<h1>`..`<h4>` elements from an HTML
/// document, tags stripped. Deliberately small and dependency-free: NVIDIA doc
/// pages carry a server-rendered title/heading for the real pages, and the JS
/// shells carry none (which is exactly the Blank signal we want).
fn extract_headings(html: &str) -> Vec<String> {
    let mut out = Vec::new();
    for tag in ["title", "h1", "h2", "h3", "h4"] {
        collect_tag_text(html, tag, &mut out);
    }
    out.into_iter()
        .map(|s| strip_tags(&s))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Append the inner text of every `<tag>...</tag>` occurrence to `out`.
/// Case-insensitive on the tag name; non-greedy on the content.
fn collect_tag_text(html: &str, tag: &str, out: &mut Vec<String>) {
    let lower = html.to_ascii_lowercase();
    let open = format!("<{tag}");
    let close = format!("</{tag}>");
    let mut from = 0;
    while let Some(rel) = lower[from..].find(&open) {
        let start = from + rel;
        // Find the end of the opening tag.
        let Some(gt) = lower[start..].find('>') else {
            break;
        };
        let content_start = start + gt + 1;
        let Some(crel) = lower[content_start..].find(&close) else {
            break;
        };
        let content_end = content_start + crel;
        out.push(html[content_start..content_end].to_string());
        from = content_end + close.len();
    }
}

/// Strip HTML tags from a fragment, leaving the text content.
fn strip_tags(fragment: &str) -> String {
    let mut out = String::with_capacity(fragment.len());
    let mut in_tag = false;
    for c in fragment.chars() {
        match c {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => out.push(c),
            _ => {}
        }
    }
    out
}

/// Extract the `href` attribute values from every `<a>` tag in a document.
fn extract_hrefs(html: &str) -> Vec<String> {
    let lower = html.to_ascii_lowercase();
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(rel) = lower[from..].find("href=") {
        let start = from + rel + "href=".len();
        let bytes = html.as_bytes();
        if start >= bytes.len() {
            break;
        }
        let quote = bytes[start];
        let (value_start, delim): (usize, &[char]) = if quote == b'"' || quote == b'\'' {
            (start + 1, if quote == b'"' { &['"'] } else { &['\''] })
        } else {
            (start, &[' ', '>'])
        };
        let end = html[value_start..]
            .find(|c| delim.contains(&c))
            .map_or(html.len(), |e| value_start + e);
        out.push(html[value_start..end].to_string());
        from = end;
    }
    out
}

/// Resolve a possibly-relative `href` against the `base` page URL. Handles
/// absolute URLs, root-relative paths, and plain relative paths; good enough for
/// the doc trees we crawl (no `..` traversal appears in practice).
fn absolutize(base: &str, href: &str) -> String {
    if href.starts_with("http://") || href.starts_with("https://") {
        return href.to_string();
    }
    // Split scheme://host from the rest of the base.
    let scheme_end = base.find("://").map_or(0, |i| i + 3);
    let host_end = base[scheme_end..]
        .find('/')
        .map_or(base.len(), |i| scheme_end + i);
    let origin = &base[..host_end];
    if let Some(rooted) = href.strip_prefix('/') {
        return format!("{origin}/{rooted}");
    }
    // Relative to the base directory (strip the trailing filename if any).
    let dir_end = base.rfind('/').map_or(base.len(), |i| i + 1);
    format!("{}{href}", &base[..dir_end])
}

/// Normalize a string for name matching: lowercase, and collapse any run of
/// non-alphanumeric characters to a single space, trimmed. So `cuBLASMp`,
/// `cublasmp`, and `cu BLAS Mp` all compare on their alphanumeric content, and
/// `nvjpeg2000` stays distinct from `nvjpeg`.
fn normalize(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut last_space = true; // trim leading
    for c in s.chars() {
        if c.is_ascii_alphanumeric() {
            out.extend(c.to_lowercase());
            last_space = false;
        } else if !last_space {
            out.push(' ');
            last_space = true;
        }
    }
    out.trim_end().to_string()
}

/// Render the sidecar as stable, pretty JSON matching the committed file.
///
/// Hand-rolled rather than via `serde_json::to_string_pretty` so the exact
/// formatting (2-space indent, one entry per line, sorted keys, trailing
/// newline) is pinned and reviewable, mirroring `product-map`'s `render`. The
/// input is a `BTreeMap`, so key order is already deterministic.
fn render(links: &BTreeMap<String, String>) -> String {
    let mut s = String::new();
    s.push_str("{\n");
    let _ = writeln!(s, "  \"schema_version\": {SCHEMA_VERSION},");
    if links.is_empty() {
        s.push_str("  \"links\": {}\n");
        s.push_str("}\n");
        return s;
    }
    s.push_str("  \"links\": {\n");
    let n = links.len();
    for (i, (component, url)) in links.iter().enumerate() {
        let comma = if i + 1 < n { "," } else { "" };
        let _ = writeln!(
            s,
            "    {}: {}{comma}",
            json_string(component),
            json_string(url)
        );
    }
    s.push_str("  }\n");
    s.push_str("}\n");
    s
}

/// Parse a committed sidecar back into its `component -> url` map. Used only by
/// `--check` to re-render in canonical form; tolerant of serde's own output as
/// well as the hand-rolled form, since the comparison is against the canonical
/// re-render, not the raw bytes.
fn parse(text: &str) -> Result<BTreeMap<String, String>> {
    let value: serde_json::Value =
        serde_json::from_str(text).context("sidecar is not valid JSON")?;
    let links = value
        .get("links")
        .and_then(serde_json::Value::as_object)
        .context("sidecar has no 'links' object")?;
    let mut out = BTreeMap::new();
    for (k, v) in links {
        let url = v
            .as_str()
            .with_context(|| format!("link for '{k}' is not a string"))?;
        out.insert(k.clone(), url.to_string());
    }
    Ok(out)
}

/// Encode a string as a JSON string literal. Component names and NVIDIA URLs are
/// ASCII with no control characters, so escaping quotes and backslashes is
/// sufficient and keeps output identical to the committed file.
fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            _ => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_collapses_non_alnum_and_lowercases() {
        assert_eq!(normalize("cuBLASMp"), "cublasmp");
        assert_eq!(normalize("CUDA Runtime API"), "cuda runtime api");
        assert_eq!(normalize("nvpl-blas"), "nvpl blas");
        assert_eq!(normalize("  nvJPEG 2000 "), "nvjpeg 2000");
        // Distinct families stay distinct after normalization.
        assert_ne!(normalize("nvjpeg2000"), normalize("nvjpeg"));
    }

    #[test]
    fn headings_extracted_and_tag_stripped() {
        let html = "<html><head><title>cuBLAS :: NVIDIA Docs</title></head>\
                    <body><h1>cuBLAS <span>library</span></h1>\
                    <h2>Introduction</h2></body></html>";
        let headings = extract_headings(html);
        assert!(headings.iter().any(|h| h.contains("cuBLAS")));
        assert!(headings.iter().any(|h| h == "cuBLAS library"));
        assert!(headings.iter().any(|h| h == "Introduction"));
    }

    #[test]
    fn blank_shell_has_no_headings() {
        let shell = "<html><head><title></title></head><body><div id=\"app\"></div></body></html>";
        assert_eq!(extract_headings(shell), Vec::<String>::new());
    }

    #[test]
    fn name_needles_include_aliases() {
        let needles = name_needles("cudart");
        assert!(needles.contains(&"cudart".to_string()));
        assert!(needles.contains(&"cuda runtime".to_string()));
    }

    #[test]
    fn href_extraction_handles_quotes_and_relative() {
        let html =
            r#"<a href="cal.html">CAL</a> <a href='/cuda/x/'>x</a> <a href=https://e.com/y>y</a>"#;
        let hrefs = extract_hrefs(html);
        assert!(hrefs.contains(&"cal.html".to_string()));
        assert!(hrefs.contains(&"/cuda/x/".to_string()));
        assert!(hrefs.contains(&"https://e.com/y".to_string()));
    }

    #[test]
    fn absolutize_resolves_each_href_shape() {
        let base = "https://docs.nvidia.com/cuda/cublasmp/index.html";
        assert_eq!(absolutize(base, "https://x.com/a"), "https://x.com/a");
        assert_eq!(
            absolutize(base, "/cuda/foo/"),
            "https://docs.nvidia.com/cuda/foo/"
        );
        assert_eq!(
            absolutize(base, "usage/cal.html"),
            "https://docs.nvidia.com/cuda/cublasmp/usage/cal.html"
        );
    }

    #[test]
    fn render_is_canonical_and_sorted() {
        let mut links = BTreeMap::new();
        links.insert(
            "cufft".to_string(),
            "https://docs.nvidia.com/cuda/cufft/".to_string(),
        );
        links.insert(
            "cublas".to_string(),
            "https://docs.nvidia.com/cuda/cublas/".to_string(),
        );
        let rendered = render(&links);
        let expected = "{\n  \"schema_version\": 1,\n  \"links\": {\n    \
            \"cublas\": \"https://docs.nvidia.com/cuda/cublas/\",\n    \
            \"cufft\": \"https://docs.nvidia.com/cuda/cufft/\"\n  }\n}\n";
        assert_eq!(rendered, expected);
    }

    #[test]
    fn render_empty_links() {
        let rendered = render(&BTreeMap::new());
        assert_eq!(
            rendered,
            "{\n  \"schema_version\": 1,\n  \"links\": {}\n}\n"
        );
    }

    #[test]
    fn parse_then_render_roundtrips() {
        let mut links = BTreeMap::new();
        links.insert(
            "cal".to_string(),
            "https://docs.nvidia.com/cuda/cublasmp/usage/initialization/cal.html".to_string(),
        );
        links.insert(
            "opencl".to_string(),
            "https://developer.nvidia.com/opencl".to_string(),
        );
        let rendered = render(&links);
        let parsed = parse(&rendered).expect("parse canonical output");
        assert_eq!(parsed, links);
        assert_eq!(render(&parsed), rendered);
    }

    #[test]
    fn exceptions_are_unique_and_nonempty() {
        let mut seen = std::collections::BTreeSet::new();
        for ex in EXCEPTIONS {
            assert!(
                seen.insert(ex.component),
                "duplicate exception {}",
                ex.component
            );
            assert!(ex.url.starts_with("https://"), "{} url", ex.component);
            assert!(!ex.reason.is_empty(), "{} reason", ex.component);
        }
    }

    #[test]
    fn markdown_link_targets_extracts_urls() {
        let md = "- [desc one](https://docs.nvidia.com/cuda/cublas/index.html.md)\n\
                  - [desc two](https://docs.nvidia.com/cuda/npp/index.html)";
        let urls = markdown_link_targets(md);
        assert_eq!(
            urls,
            vec![
                "https://docs.nvidia.com/cuda/cublas/index.html.md".to_string(),
                "https://docs.nvidia.com/cuda/npp/index.html".to_string(),
            ]
        );
    }

    #[test]
    fn llms_bases_strip_index_and_keep_docs_host() {
        // guide_bases_from_llms is online; test the pure transform it relies on
        // by replicating the normalization on sample link targets.
        let targets = [
            "https://docs.nvidia.com/cuda/cuda-binary-utilities/index.html.md",
            "https://docs.nvidia.com/cuda/npp/index.html",
            "https://nvidia.github.io/cccl/thrust/", // non-docs host, dropped
        ];
        let mut bases: Vec<String> = targets
            .iter()
            .filter(|u| u.starts_with("https://docs.nvidia.com/"))
            .map(|u| {
                let b = u.trim_end_matches(".md").trim_end_matches("index.html");
                if b.ends_with('/') {
                    b.to_string()
                } else {
                    format!("{b}/")
                }
            })
            .collect();
        bases.sort();
        assert_eq!(
            bases,
            vec![
                "https://docs.nvidia.com/cuda/cuda-binary-utilities/".to_string(),
                "https://docs.nvidia.com/cuda/npp/".to_string(),
            ]
        );
    }

    #[test]
    fn join_guide_uri_handles_relative_and_absolute() {
        let base = "https://docs.nvidia.com/cuda/cuda-binary-utilities/";
        assert_eq!(
            join_guide_uri(base, "index.html#cuobjdump"),
            "https://docs.nvidia.com/cuda/cuda-binary-utilities/index.html#cuobjdump"
        );
        assert_eq!(
            join_guide_uri(base, "https://x.com/a#b"),
            "https://x.com/a#b"
        );
    }

    #[test]
    fn inventory_parse_expands_dollar_and_keeps_display() {
        // The parser expands "#$" to "#<name>" and preserves the display text
        // (which carries the cu++filt alias used for matching).
        let body = "cuobjdump std:label -1 index.html#$ -\n\
                    cuplusplusfilt std:label -1 index.html#$ cu++filt\n";
        let map = parse_inventory_body(body);
        assert_eq!(
            map["cuobjdump"],
            ("index.html#cuobjdump".to_string(), "-".to_string())
        );
        assert_eq!(
            map["cuplusplusfilt"],
            (
                "index.html#cuplusplusfilt".to_string(),
                "cu++filt".to_string()
            )
        );
    }
}
