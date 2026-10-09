//! Shared competitor-probe helpers for the evaluation harnesses
//! (`eval_groundtruth` and `eval_distribution`).
//!
//! Both harnesses measure the same external tools (Syft, Trivy, blint) against
//! the same question, "does this tool name a CUDA component / report a CVE?",
//! so the probes live here once rather than drifting between the two callers.
//! Every probe is a generous, pro-competitor read: naming counts any CUDA-ish
//! token, and a tool that cannot run simply reports `false`.

use std::path::Path;
use std::process::Command;
use std::time::Instant;

use anyhow::{Context, Result};

/// User-agent sent by every evaluation-harness download. Single-sourced from
/// the shared network layer so no fetch site can drift.
pub(crate) const USER_AGENT: &str = cudabom_fetch::DEFAULT_USER_AGENT;

/// Path to the system `time` utility used to read kernel peak RSS.
const TIME_BIN: &str = "/usr/bin/time";

/// Syft CycloneDX-JSON output flags, shared by every Syft invocation.
const SYFT_ARGS: [&str; 3] = ["-o", "cyclonedx-json", "-q"];

/// Trivy JSON output flags, shared by every Trivy invocation.
const TRIVY_ARGS: [&str; 3] = ["--quiet", "--format", "json"];

/// blint flags that suppress its banner and interactive review prompts.
const BLINT_ARGS: [&str; 2] = ["--no-banner", "--no-reviews"];

/// Suffix of the per-object metadata files blint writes into its output dir.
const BLINT_META_SUFFIX: &str = "-metadata.json";

/// blint JSON keys that carry the scanned object's path, most specific first.
const BLINT_PATH_KEYS: [&str; 3] = ["file_path", "exe_name", "name"];

/// Resolve a runnable blint: the one on `PATH`, else a project-local venv.
fn resolve_blint_bin() -> Option<String> {
    if probe(&["blint", "--help"]) {
        Some("blint".to_string())
    } else {
        blint_in_venv()
    }
}

/// Run blint over `input` into a fresh `out_dir`, returning the timed run and
/// the metadata files it emitted. Shared by the per-file probe and the
/// whole-tree scan so blint's invocation and output layout live in one place.
fn run_blint(input: &Path, out_dir: &Path) -> Option<(TimedRun, Vec<std::path::PathBuf>)> {
    let _ = std::fs::remove_dir_all(out_dir);
    let bin = resolve_blint_bin()?;
    let run = run_timed(&[
        bin.as_str(),
        "-i",
        &input.to_string_lossy(),
        "-o",
        &out_dir.to_string_lossy(),
        BLINT_ARGS[0],
        BLINT_ARGS[1],
    ])
    .ok()?;
    let metas = std::fs::read_dir(out_dir)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.ends_with(BLINT_META_SUFFIX))
        })
        .collect();
    Some((run, metas))
}

/// The outcome of running a tool under the platform `time` utility: its stdout,
/// exit code, and the two performance figures the head-to-head records.
pub(crate) struct TimedRun {
    /// The tool's stdout bytes (its report; parsed by the caller for accuracy).
    pub stdout: Vec<u8>,
    /// The tool's process exit code, or `None` if it was killed by a signal.
    pub code: Option<i32>,
    /// Wall-clock time, measured by a monotonic clock in the harness.
    pub wall_ms: u128,
    /// Peak resident set size of the tool process, in bytes.
    pub peak_rss_bytes: u64,
}

/// Run `argv` under `/usr/bin/time`, capturing its stdout and both performance
/// figures. Wall time is measured here with a monotonic clock (precise and
/// independent of the utility's text format); peak RSS is read from the
/// utility's report.
///
/// `/usr/bin/time` gives a kernel peak-RSS figure with no `unsafe`/libc: macOS
/// prints "maximum resident set size" in bytes with `-l`; GNU time prints
/// "Maximum resident set size (kbytes)" with `-v`. Unix-only, which is every
/// evaluation host (CI and local dev run on Linux/macOS). The timed tool's
/// stderr is discarded (only `time`'s own report is read).
pub(crate) fn run_timed(argv: &[&str]) -> Result<TimedRun> {
    use std::process::Stdio;

    let time_bin = TIME_BIN;
    if !Path::new(time_bin).exists() {
        anyhow::bail!("{time_bin} not found; the comparison harness needs it to read peak RSS");
    }
    let rss_flag = if cfg!(target_os = "macos") {
        "-l"
    } else {
        "-v"
    };
    let (prog, rest) = argv
        .split_first()
        .ok_or_else(|| anyhow::anyhow!("run_timed: empty argv"))?;

    let start = Instant::now();
    let output = Command::new(time_bin)
        .arg(rss_flag)
        .arg(prog)
        .args(rest)
        .stdout(Stdio::piped())
        // `time` writes its report to stderr; the tool's own stderr is merged
        // there too, so the RSS parser tolerates extra lines (it scans for the
        // one "maximum resident set size" line).
        .stderr(Stdio::piped())
        .output()
        .with_context(|| format!("running {prog} under {time_bin}"))?;
    let wall_ms = start.elapsed().as_millis();

    let stderr = String::from_utf8_lossy(&output.stderr);
    let peak_rss_bytes = parse_peak_rss(&stderr).unwrap_or(0);
    Ok(TimedRun {
        stdout: output.stdout,
        code: output.status.code(),
        wall_ms,
        peak_rss_bytes,
    })
}

/// Extract peak RSS (normalized to bytes) from a `/usr/bin/time` report.
///
/// macOS BSD `time -l` prints `<N>  maximum resident set size` where `<N>` is
/// in bytes. GNU `time -v` prints `Maximum resident set size (kbytes): <N>`.
/// The units are detected from the line itself so one parser handles both.
fn parse_peak_rss(report: &str) -> Option<u64> {
    for line in report.lines() {
        let lower = line.to_ascii_lowercase();
        if !lower.contains("maximum resident set size") {
            continue;
        }
        let in_kbytes = lower.contains("kbytes");
        let digits: String = line.chars().filter(char::is_ascii_digit).collect();
        let value: u64 = digits.parse().ok()?;
        return Some(if in_kbytes {
            value.saturating_mul(1024)
        } else {
            value
        });
    }
    None
}

/// Format a millisecond figure as seconds (two decimals) at or above 1s, else
/// `<N> ms`. Integer math only, so there is no lossy `as f64` cast.
pub(crate) fn human_ms(ms: u128) -> String {
    if ms >= 1000 {
        let hundredths = ms / 10;
        format!("{}.{:02} s", hundredths / 100, hundredths % 100)
    } else {
        format!("{ms} ms")
    }
}

/// Format a byte count as a compact human figure (MiB/KiB). Integer math only.
pub(crate) fn human_bytes(bytes: u64) -> String {
    const MIB: u64 = 1024 * 1024;
    const KIB: u64 = 1024;
    if bytes >= MIB {
        let tenths = bytes * 10 / MIB;
        format!("{}.{} MiB", tenths / 10, tenths % 10)
    } else if bytes >= KIB {
        let tenths = bytes * 10 / KIB;
        format!("{}.{} KiB", tenths / 10, tenths % 10)
    } else {
        format!("{bytes} B")
    }
}

/// Probe the competitor tools the comparison harnesses measure, returning
/// `(have_blint, have_syft, have_trivy)`. The argument lists are the canonical
/// presence checks for each tool, defined here once.
pub(crate) fn probe_competitors() -> (bool, bool, bool) {
    let have_blint = probe(&["blint", "--help"]) || blint_in_venv().is_some();
    let have_syft = probe(&["syft", "version"]);
    let have_trivy = probe(&["trivy", "--version"]);
    (have_blint, have_syft, have_trivy)
}

/// Whether a Docker daemon is reachable (used by the distribution harness for
/// image artifacts).
pub(crate) fn probe_docker() -> bool {
    probe(&["docker", "version"])
}

/// A container image exported to a local filesystem for scanning: the directory
/// all tools scan (scoped to the CUDA subtree when one exists) and the resolved
/// image digest for reproducibility.
pub(crate) struct ExportedImage {
    /// The directory all tools scan: the CUDA subtree if present, else the
    /// whole exported rootfs.
    pub scan_dir: std::path::PathBuf,
    /// Human label describing the scanned scope (for the comparison note).
    pub scope: String,
    /// The resolved `repo@sha256:...` digest of the pulled image.
    pub digest: String,
}

/// Pull `image` (by tag or digest), export its flattened rootfs under `work`,
/// and return the path all tools should scan plus the resolved digest.
///
/// The rootfs is produced with `docker create` + `docker export` (one flattened
/// tar), which is simpler and more reliable than reassembling `docker save`
/// layers. When the image carries a `/usr/local/cuda*` tree the scan is scoped
/// to it so every tool sees the identical CUDA bytes (and the run stays within a
/// sane time budget on multi-GB images); otherwise the whole rootfs is scanned.
pub(crate) fn export_image_rootfs(image: &str, work: &Path) -> Result<ExportedImage> {
    use std::process::Command;

    let pull = Command::new("docker")
        .args(["pull", "--quiet", image])
        .status()
        .with_context(|| format!("docker pull {image}"))?;
    if !pull.success() {
        anyhow::bail!("docker pull {image} failed");
    }
    let digest_out = Command::new("docker")
        .args(["inspect", "--format", "{{index .RepoDigests 0}}", image])
        .output()
        .with_context(|| format!("docker inspect {image}"))?;
    let digest = String::from_utf8_lossy(&digest_out.stdout)
        .trim()
        .to_string();

    let rootfs = work.join("rootfs");
    std::fs::create_dir_all(&rootfs).with_context(|| format!("creating {}", rootfs.display()))?;
    let cid_out = Command::new("docker")
        .args(["create", image])
        .output()
        .with_context(|| format!("docker create {image}"))?;
    let cid = String::from_utf8_lossy(&cid_out.stdout).trim().to_string();
    if cid.is_empty() {
        anyhow::bail!("docker create {image} produced no container id");
    }
    let tar_path = work.join("rootfs.tar");
    let exported = Command::new("docker")
        .args(["export", "-o"])
        .arg(&tar_path)
        .arg(&cid)
        .status()
        .with_context(|| format!("docker export {cid}"))?;
    let _ = Command::new("docker").args(["rm", "-f", &cid]).status();
    if !exported.success() {
        anyhow::bail!("docker export {cid} failed");
    }
    let untar = Command::new("tar")
        .arg("-xf")
        .arg(&tar_path)
        .arg("-C")
        .arg(&rootfs)
        .status()
        .with_context(|| "untar exported rootfs")?;
    let _ = std::fs::remove_file(&tar_path);
    if !untar.success() {
        anyhow::bail!("unpacking exported rootfs failed");
    }

    // Scope to the CUDA tree when the image has one, so every tool scans the
    // same CUDA bytes rather than the whole OS (fair and bounded). The scope
    // label is the in-image path (temp staging dir stripped) so the committed
    // comparison stays reproducible and free of host-specific noise.
    let (scan_dir, scope) = find_cuda_subtree(&rootfs).map_or_else(
        || (rootfs.clone(), "whole rootfs".to_string()),
        |p| {
            let in_image = p
                .strip_prefix(&rootfs)
                .map_or_else(|_| p.clone(), |rel| Path::new("/").join(rel));
            let s = format!("CUDA subtree ({})", in_image.display());
            (p, s)
        },
    );

    Ok(ExportedImage {
        scan_dir,
        scope,
        digest,
    })
}

/// Find a `/usr/local/cuda*` directory under an exported rootfs, if present.
fn find_cuda_subtree(rootfs: &Path) -> Option<std::path::PathBuf> {
    let local = rootfs.join("usr/local");
    let rd = std::fs::read_dir(&local).ok()?;
    let mut candidates: Vec<std::path::PathBuf> = rd
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.is_dir()
                && p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with("cuda"))
        })
        .collect();
    // Prefer a versioned `cuda-12.4` over the `cuda` symlink for a real tree.
    candidates.sort();
    candidates
        .into_iter()
        .max_by_key(|p| p.file_name().and_then(|n| n.to_str()).map_or(0, str::len))
}

/// Download `url` into `dest`, verifying it against `sha256`. If `dest` already
/// holds bytes matching the checksum, no network request is made. The parent
/// directory is created as needed. Shared by every evaluation download site so
/// the retry policy, user-agent, and verification live in one place.
pub(crate) fn fetch_verified(url: &str, sha256: &str, dest: &Path) -> Result<()> {
    use cudabom_fetch::{get, verify_sha256, GetOptions, RetryPolicy};

    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let present = std::fs::read(dest).is_ok_and(|b| verify_sha256(&b, sha256).is_ok());
    if present {
        return Ok(());
    }
    let body = get(
        url,
        &GetOptions {
            retry: RetryPolicy::default(),
            expected_sha256: Some(sha256.to_string()),
            user_agent: USER_AGENT.to_string(),
            headers: Vec::new(),
        },
    )
    .with_context(|| format!("fetching {url}"))?;
    std::fs::write(dest, &body).with_context(|| format!("writing {}", dest.display()))?;
    Ok(())
}

/// Run `cudabom scan <path> --format json`, returning the parsed
/// report plus the run's performance. Exit codes `0` (clean) and `1` (gate
/// failed) both carry a valid report; any other code (or a spawn failure)
/// yields `None` for the report. Shared by both evaluation harnesses so the
/// invocation, exit-code contract, and timing live once.
pub(crate) fn run_cudabom_scan_timed(
    bin: &Path,
    path: &Path,
    db: &str,
    advisories: &str,
) -> (Option<serde_json::Value>, Option<TimedRun>) {
    let bin_s = bin.to_string_lossy();
    let path_s = path.to_string_lossy();
    let argv = [
        bin_s.as_ref(),
        "scan",
        path_s.as_ref(),
        "--db",
        db,
        "--advisories",
        advisories,
        "--format",
        "json",
    ];
    let Ok(run) = run_timed(&argv) else {
        return (None, None);
    };
    let report = match run.code {
        Some(0 | 1) => serde_json::from_slice(&run.stdout).ok(),
        _ => None,
    };
    (report, Some(run))
}

/// Convenience wrapper that returns only the parsed report (no timing), for
/// callers that do not record performance.
pub(crate) fn run_cudabom_scan(
    bin: &Path,
    path: &Path,
    db: &str,
    advisories: &str,
) -> Option<serde_json::Value> {
    run_cudabom_scan_timed(bin, path, db, advisories).0
}

/// Extract each finding's `(name, version, confidence)` triple from a parsed
/// cudabom report. Shared so both harnesses read the same JSON pointers.
pub(crate) fn parse_findings(report: &serde_json::Value) -> Vec<(String, String, String)> {
    report
        .get("findings")
        .and_then(|v| v.as_array())
        .map(|findings| {
            findings
                .iter()
                .map(|f| {
                    let name = f
                        .pointer("/component/name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let version = f
                        .pointer("/component/version")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let confidence = f
                        .get("confidence")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    (name, version, confidence)
                })
                .collect()
        })
        .unwrap_or_default()
}

/// A `blint` executable inside a conventional local venv, if present.
pub(crate) fn blint_in_venv() -> Option<String> {
    [
        std::env::var("BLINT_BIN").ok(),
        Some("/tmp/blint-venv/bin/blint".to_string()),
    ]
    .into_iter()
    .flatten()
    .find(|candidate| Path::new(candidate).exists())
}

/// Is a command runnable? Used to probe for installed competitors.
pub(crate) fn probe(cmd: &[&str]) -> bool {
    let [prog, args @ ..] = cmd else {
        return false;
    };
    Command::new(prog)
        .args(args)
        .output()
        .is_ok_and(|o| o.status.success() || !o.stdout.is_empty())
}

/// Render a tool-presence bit for the comparison tables: `yes` when installed,
/// `not installed` otherwise.
pub(crate) fn yesno(b: bool) -> &'static str {
    if b {
        "yes"
    } else {
        "not installed"
    }
}

/// Lowercase tokens that, if they appear in a component name or binary
/// metadata, count as "named a CUDA component". Shared so every harness applies
/// the identical, generous rule.
pub(crate) fn names_cuda_token(lower: &str) -> bool {
    lower.contains("cud") || lower.contains("nccl") || lower.contains("nvidia")
}

/// The result of running one tool once over a whole directory of binaries: the
/// headline outcome count (what the tool actually produced), plus timing.
///
/// This is the honest, fair performance measurement: one process launch per
/// tool over an identical input tree, so process-startup overhead is amortized
/// once and no tool is credited for a fast run that found nothing. The outcome
/// field is reported *beside* the speed/RSS so a cheap empty scan cannot
/// masquerade as a performance win.
pub(crate) struct DirScan {
    /// Short label for what the tool named, in its own units (e.g.
    /// "91 identities", "1353 objects", "16 packages"), shown as a sub-note so
    /// the raw figure is visible without dominating the comparison.
    pub named_label: String,
    /// Distinct top-level input files the tool associated with a CUDA verdict,
    /// the comparable cross-tool unit. `None` when the tool exposes no per-path
    /// attribution (e.g. Trivy, which reports CVEs rather than named files).
    pub named_files: Option<usize>,
    /// Whether the tool pins an exact CUDA release version. `None` when the
    /// capability does not apply to the tool at all.
    pub pins_version: Option<bool>,
    /// Count of CVE / advisory matches the tool correlated, or `None` when the
    /// tool does not attempt CVE correlation.
    pub cve_matches: Option<usize>,
    /// Every filesystem path the tool associated with a CUDA verdict. Used to
    /// compute `named_files` against the known staged inputs. Empty when the
    /// tool exposes no per-path attribution.
    pub cuda_paths: Vec<String>,
    /// Wall time and peak RSS for the single whole-tree invocation.
    pub run: TimedRun,
}

/// Run `cudabom scan <dir>` once over a whole directory, returning its outcome
/// (named / versioned / CVE-correlated counts) and timing.
pub(crate) fn cudabom_scan_dir(
    bin: &Path,
    dir: &Path,
    db: &str,
    advisories: &str,
) -> Option<DirScan> {
    let (report, run) = run_cudabom_scan_timed(bin, dir, db, advisories);
    let run = run?;
    let json = report.unwrap_or(serde_json::Value::Null);
    let findings = json
        .get("findings")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let named = findings.len();
    let versioned = findings
        .iter()
        .filter(|f| {
            f.pointer("/component/version")
                .and_then(|v| v.as_str())
                .is_some_and(|s| !s.is_empty())
        })
        .count();
    let cves = json
        .pointer("/advisories/matches")
        .and_then(|v| v.as_array())
        .map_or(0, Vec::len);
    // Collect the evidence file path for each finding so counts can be
    // normalized to distinct top-level input files.
    let mut cuda_paths = Vec::new();
    for f in &findings {
        if let Some(ev) = f.get("evidence").and_then(|v| v.as_array()) {
            for e in ev {
                if let Some(p) = e.pointer("/location/path").and_then(|v| v.as_str()) {
                    cuda_paths.push(p.to_string());
                }
            }
        }
    }
    Some(DirScan {
        named_label: format!("{named} identities"),
        named_files: None,
        pins_version: Some(versioned > 0),
        cve_matches: Some(cves),
        cuda_paths,
        run,
    })
}

/// Run `syft dir:<dir>` (or `syft <ref>` for an image) once over a whole tree,
/// returning the count of CUDA-named components and timing.
pub(crate) fn syft_scan_dir(target: &str, is_image: bool) -> Option<DirScan> {
    let arg = if is_image {
        target.to_string()
    } else {
        format!("dir:{target}")
    };
    let run = run_timed(&["syft", &arg, SYFT_ARGS[0], SYFT_ARGS[1], SYFT_ARGS[2]]).ok()?;
    let json: serde_json::Value =
        serde_json::from_slice(&run.stdout).unwrap_or(serde_json::Value::Null);
    let components = json
        .get("components")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let mut cuda_paths = Vec::new();
    let mut named = 0usize;
    for c in &components {
        let is_cuda = c
            .get("name")
            .and_then(|n| n.as_str())
            .is_some_and(|s| names_cuda_token(&s.to_ascii_lowercase()));
        if !is_cuda {
            continue;
        }
        named += 1;
        // CycloneDX from Syft records file locations under evidence.occurrences
        // and/or properties named `syft:location:*:path`.
        if let Some(occ) = c
            .pointer("/evidence/occurrences")
            .and_then(|v| v.as_array())
        {
            for o in occ {
                if let Some(p) = o.get("location").and_then(|v| v.as_str()) {
                    cuda_paths.push(p.to_string());
                }
            }
        }
        if let Some(props) = c.get("properties").and_then(|v| v.as_array()) {
            for p in props {
                let is_path = p
                    .get("name")
                    .and_then(|v| v.as_str())
                    .is_some_and(|n| n.contains("location") && n.ends_with("path"));
                if is_path {
                    if let Some(v) = p.get("value").and_then(|v| v.as_str()) {
                        cuda_paths.push(v.to_string());
                    }
                }
            }
        }
    }
    Some(DirScan {
        named_label: format!("{named} packages"),
        named_files: None,
        pins_version: Some(false),
        cve_matches: Some(0),
        cuda_paths,
        run,
    })
}

/// Run `trivy rootfs <dir>` (or `trivy image <ref>`) once over a whole tree,
/// returning the count of correlated vulnerabilities and timing.
pub(crate) fn trivy_scan_dir(target: &str, is_image: bool) -> Option<DirScan> {
    let subcmd = if is_image { "image" } else { "rootfs" };
    let run = run_timed(&[
        "trivy",
        subcmd,
        target,
        TRIVY_ARGS[0],
        TRIVY_ARGS[1],
        TRIVY_ARGS[2],
    ])
    .ok()?;
    let json: serde_json::Value =
        serde_json::from_slice(&run.stdout).unwrap_or(serde_json::Value::Null);
    let vulns = json
        .get("Results")
        .and_then(|v| v.as_array())
        .map_or(0, |rs| {
            rs.iter()
                .map(|r| {
                    r.get("Vulnerabilities")
                        .and_then(|v| v.as_array())
                        .map_or(0, Vec::len)
                })
                .sum()
        });
    Some(DirScan {
        named_label: String::new(),
        named_files: None,
        pins_version: None,
        cve_matches: Some(vulns),
        cuda_paths: Vec::new(),
        run,
    })
}

/// Run blint once with the whole directory as input (`blint -i <dir>`),
/// returning whether its metadata names any CUDA library and timing.
///
/// blint is per-binary forensics rather than a tree cataloguer, but it accepts a
/// directory, so a single whole-tree invocation is the fair amortized measure.
pub(crate) fn blint_scan_dir(dir: &Path) -> Option<DirScan> {
    let out_dir = std::env::temp_dir().join("cudabom-eval-blint-dir");
    let (run, metas) = run_blint(dir, &out_dir)?;
    let mut named = 0usize;
    let mut cuda_paths = Vec::new();
    for meta in metas {
        let Ok(text) = std::fs::read_to_string(&meta) else {
            continue;
        };
        if !names_cuda_token(&text.to_ascii_lowercase()) {
            continue;
        }
        named += 1;
        // Attribute to the scanned object's path so the count can be normalized
        // to distinct input files (blint emits one record per archive member).
        if let Some(path) = blint_scanned_path(&text) {
            cuda_paths.push(path);
        }
    }
    // The raw count is per object (static archives explode into their members),
    // so the label keeps the raw figure while `cuda_paths` lets the caller
    // normalize to the comparable per-input-file unit. blint pins no version
    // and correlates no CVE for a bare native binary.
    Some(DirScan {
        named_label: format!("{named} objects"),
        named_files: None,
        pins_version: Some(false),
        cve_matches: Some(0),
        cuda_paths,
        run,
    })
}

/// Extract the scanned object's path from one blint metadata JSON document.
fn blint_scanned_path(text: &str) -> Option<String> {
    let json: serde_json::Value = serde_json::from_str(text).ok()?;
    BLINT_PATH_KEYS
        .iter()
        .find_map(|k| json.get(*k).and_then(|v| v.as_str()))
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
}

/// Whether Syft names any CUDA component for `target`, with timing. `is_image`
/// selects an image reference (`syft <ref>`) over a loose file
/// (`syft file:<path>`).
pub(crate) fn syft_names_cuda_timed(target: &str, is_image: bool) -> (bool, Option<TimedRun>) {
    let arg = if is_image {
        target.to_string()
    } else {
        format!("file:{target}")
    };
    let Ok(run) = run_timed(&["syft", &arg, SYFT_ARGS[0], SYFT_ARGS[1], SYFT_ARGS[2]]) else {
        return (false, None);
    };
    let json: serde_json::Value =
        serde_json::from_slice(&run.stdout).unwrap_or(serde_json::Value::Null);
    let named = json
        .get("components")
        .and_then(|v| v.as_array())
        .is_some_and(|cs| {
            cs.iter().any(|c| {
                c.get("name")
                    .and_then(|n| n.as_str())
                    .is_some_and(|s| names_cuda_token(&s.to_ascii_lowercase()))
            })
        });
    (named, Some(run))
}

/// Whether Syft names any CUDA component for `target` (no timing).
pub(crate) fn syft_names_cuda(target: &str, is_image: bool) -> bool {
    syft_names_cuda_timed(target, is_image).0
}

/// Whether Trivy reports any vulnerability for `target`, with timing.
/// `is_image` selects `trivy image <ref>` (its real strength) over
/// `trivy rootfs <path>`.
pub(crate) fn trivy_has_cve_timed(target: &str, is_image: bool) -> (bool, Option<TimedRun>) {
    let subcmd = if is_image { "image" } else { "rootfs" };
    let Ok(run) = run_timed(&[
        "trivy",
        subcmd,
        target,
        TRIVY_ARGS[0],
        TRIVY_ARGS[1],
        TRIVY_ARGS[2],
    ]) else {
        return (false, None);
    };
    let json: serde_json::Value =
        serde_json::from_slice(&run.stdout).unwrap_or(serde_json::Value::Null);
    let has_cve = json
        .get("Results")
        .and_then(|v| v.as_array())
        .is_some_and(|rs| {
            rs.iter().any(|r| {
                r.get("Vulnerabilities")
                    .and_then(|v| v.as_array())
                    .is_some_and(|v| !v.is_empty())
            })
        });
    (has_cve, Some(run))
}

/// Whether Trivy reports any vulnerability for `target` (no timing).
pub(crate) fn trivy_has_cve(target: &str, is_image: bool) -> bool {
    trivy_has_cve_timed(target, is_image).0
}

/// Run blint on `path` and report `(ran, named_cuda)` with timing.
///
/// blint is a binary-forensics tool, so it surfaces SONAME/symbol strings
/// (hence it *names* CUDA) but never pins a CUDA release version or correlates
/// a CVE for a bare native library. The naming read deliberately includes the
/// path-echoing `name`/`file_path` fields, making this a generous read.
pub(crate) fn blint_probe_timed(path: &Path) -> (bool, bool, Option<TimedRun>) {
    let out_dir = std::env::temp_dir().join("cudabom-eval-blint");
    let Some((run, metas)) = run_blint(path, &out_dir) else {
        return (false, false, None);
    };
    let ran = !metas.is_empty();
    let named_cuda = metas.iter().any(|meta| {
        std::fs::read_to_string(meta).is_ok_and(|text| names_cuda_token(&text.to_ascii_lowercase()))
    });
    (ran, named_cuda, Some(run))
}

/// Run blint on `path` and report `(ran, named_cuda)` (no timing).
pub(crate) fn blint_probe(path: &Path) -> (bool, bool) {
    let (ran, named, _) = blint_probe_timed(path);
    (ran, named)
}
