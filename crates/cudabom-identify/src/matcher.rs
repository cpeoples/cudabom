//! The identification engine: facts + fingerprint DB -> findings.
//!
//! This implements the confidence rules from `docs/evidence-model.md`. The
//! guiding principle: never assert more than the evidence supports. Structural
//! signals (a SONAME's stem and ABI major version) yield at most `Likely`, and
//! only when corroborated; a bare dependency name is `Unknown`. Strong signals
//! (a known file hash or build-id from the fingerprint DB) yield `Exact`.

use cudabom_core::{Component, Confidence, Evidence, EvidenceKind, Finding, Relationship};

use crate::db::{ComponentFingerprint, FingerprintDb};
use crate::soname::{major_version, parse_soname};
use crate::FileFacts;

/// Run identification for one file's facts against the database.
///
/// Returns zero or more findings. A file with no CUDA-related signal produces
/// no findings; a file with signals produces one finding per identified
/// component (or one `Unknown` finding when a CUDA signal exists but identity
/// cannot be established).
#[must_use]
pub fn identify_file(facts: &FileFacts, db: &FingerprintDb) -> Vec<Finding> {
    let mut findings = Vec::new();
    let arch_evidence = facts.architecture_evidence();

    // 1. Strongest signal first: a known file hash pins an exact version.
    if let Some(sha) = &facts.sha256 {
        if let Some((comp, versions)) = lookup_hash(db, sha) {
            findings.push(exact_finding(
                facts,
                comp,
                versions,
                Relationship::EmbeddedCopy,
                Evidence {
                    kind: EvidenceKind::KnownFileHash,
                    location: facts.location(),
                    detail: sha.clone(),
                },
            ));
            // A hash match is definitive for this file; no need to guess more.
            append_architecture(&mut findings, arch_evidence.as_ref());
            return findings;
        }
    }

    // 2. Build-id match (also strong) from the ELF facts.
    if let Some(elf) = &facts.elf {
        if let Some(build_id) = &elf.build_id {
            if let Some((comp, versions)) = lookup_build_id(db, build_id) {
                findings.push(exact_finding(
                    facts,
                    comp,
                    versions,
                    Relationship::EmbeddedCopy,
                    Evidence {
                        kind: EvidenceKind::BuildId,
                        location: facts.location(),
                        detail: build_id.clone(),
                    },
                ));
                append_architecture(&mut findings, arch_evidence.as_ref());
                return findings;
            }
        }
    }

    // 3. Structural SONAME attribution. The library's own SONAME plus the
    //    file name are combined. If the DB knows this stem, we can name the
    //    component (Likely, since the ABI major version is not a full version);
    //    otherwise we still surface the ABI major as Unknown for investigation.
    if let Some(elf) = &facts.elf {
        if let Some(soname) = &elf.soname {
            if let Some(finding) = identify_from_soname(facts, db, soname) {
                findings.push(finding);
            }
        }
    }

    // 3b. PE structural attribution (Windows). A PE carries no SONAME; its
    //     equivalents are the VS_VERSIONINFO strings (NVIDIA stamps a product
    //     name and version there) and its imported DLL names. Neither is as
    //     strong as a hash match, so both yield at most Likely.
    if findings.is_empty() {
        if let Some(pe) = &facts.pe {
            if let Some(finding) = identify_from_pe(facts, db, pe) {
                findings.push(finding);
            }
        }
    }

    // 3c. Symbol-set attribution. A static archive's member objects carry no
    //     SONAME and are not hash-fingerprinted (their hashes do not survive
    //     linking), but they export the component's namespaced public API
    //     symbols (e.g. `ncclAllReduce`). When those match a component's
    //     derived symbol markers, name the component at Likely: a symbol set
    //     identifies the component, never an exact version.
    if findings.is_empty() {
        if let Some(elf) = &facts.elf {
            if let Some(finding) = identify_from_symbols(facts, db, &elf.exported_symbols) {
                findings.push(finding);
            }
        }
    }

    // 4. NEEDED entries: a dependency on a known CUDA library stem is a weak
    //    dynamic-dependency signal (the library itself lives elsewhere).
    if let Some(elf) = &facts.elf {
        for needed in &elf.needed {
            if let Some(finding) = identify_needed(facts, db, needed) {
                findings.push(finding);
            }
        }
    }

    // Attach the observed architecture to every finding. It is not an identity
    // signal, but it records which ABI the match came from, the one thing
    // that distinguishes an otherwise identical `linux-x86_64` vs `linux-sbsa`
    // SONAME match, and travels through every output format.
    append_architecture(&mut findings, arch_evidence.as_ref());

    findings
}

/// Append an [`Architecture`](EvidenceKind::Architecture) evidence item to each
/// finding, when the file's architecture is known. Idempotent per call; callers
/// invoke it exactly once per finding on the path that produced it.
fn append_architecture(findings: &mut [Finding], arch_evidence: Option<&Evidence>) {
    let Some(arch_evidence) = arch_evidence else {
        return;
    };
    for finding in findings {
        finding.evidence.push(arch_evidence.clone());
    }
}

/// Attribute a library to a component from its own SONAME.
fn identify_from_soname(facts: &FileFacts, db: &FingerprintDb, soname: &str) -> Option<Finding> {
    let parts = parse_soname(soname)?;
    let evidence = Evidence {
        kind: EvidenceKind::Soname,
        location: facts.location(),
        detail: soname.to_string(),
    };

    if let Some(comp) = db
        .components
        .iter()
        .find(|c| c.soname_stems.iter().any(|s| s == &parts.stem))
    {
        // Known stem: name the component. Version is the ABI major only, so the
        // best honest claim is a major-version range at Likely confidence.
        let version = major_version(&parts).map(|m| format!("{m}.x"));
        Some(Finding {
            id: finding_id(&facts.path, &comp.name),
            component: Component {
                name: comp.name.clone(),
                version,
                candidate_versions: Vec::new(),
                relationship: Relationship::EmbeddedCopy,
            },
            confidence: Confidence::Likely,
            evidence: vec![evidence],
            conflicts: Vec::new(),
        })
    } else {
        // Unknown stem: we cannot name a component, but a versioned .so is a
        // CUDA-adjacent signal worth surfacing at Unknown confidence.
        None
    }
}

/// Attribute a component from a scanned object's exported symbol set.
///
/// Fires when the object exports at least `MIN_SYMBOL_MATCHES` symbols that the
/// database records as a component's identifying markers. This is the signal
/// for static-archive member objects (`.o` inside a `.a`), which carry no
/// SONAME and are not hash-fingerprinted. A symbol set names the component but
/// not a version, so the confidence is `Likely`, never `Exact`. Requiring more
/// than one matching symbol guards against a lone generic symbol coincidentally
/// matching; the markers are already namespaced to the component, so a genuine
/// member matches many.
fn identify_from_symbols(
    facts: &FileFacts,
    db: &FingerprintDb,
    exported: &[String],
) -> Option<Finding> {
    /// Minimum number of matching marker symbols before a component is named.
    const MIN_SYMBOL_MATCHES: usize = 2;

    if exported.is_empty() {
        return None;
    }
    let exported_set: std::collections::BTreeSet<&str> =
        exported.iter().map(String::as_str).collect();

    // Pick the component with the most marker matches, so a member that happens
    // to reference two components attributes to the one it most belongs to.
    let best = db
        .components
        .iter()
        .filter(|c| !c.symbol_markers.is_empty())
        .map(|c| {
            let hits = c
                .symbol_markers
                .iter()
                .filter(|m| exported_set.contains(m.as_str()))
                .count();
            (c, hits)
        })
        .filter(|(_, hits)| *hits >= MIN_SYMBOL_MATCHES)
        .max_by_key(|(_, hits)| *hits)?;

    let (comp, hits) = best;
    Some(Finding {
        id: finding_id(&facts.path, &comp.name),
        component: Component {
            name: comp.name.clone(),
            // A symbol set names the component, not a version.
            version: None,
            candidate_versions: Vec::new(),
            relationship: Relationship::StaticallyLinked,
        },
        confidence: Confidence::Likely,
        evidence: vec![Evidence {
            kind: EvidenceKind::ExportedSymbolSet,
            location: facts.location(),
            detail: format!("{hits} {} API symbol(s) matched", comp.name),
        }],
        conflicts: Vec::new(),
    })
}

/// Attribute a component from a Windows PE image, matching its version
/// resource and its own file name against known DLL stems. Returns at most a
/// `Likely` finding; a version resource and a file name are both spoofable, so
/// only a hash match (handled earlier) is ever `Exact`.
///
/// The version string, when present, carries the full micro version (e.g.
/// `12.4.99`), which is far more precise than the ABI-major range the ELF
/// SONAME path can offer; it is reported verbatim as the component version.
fn identify_from_pe(
    facts: &FileFacts,
    db: &FingerprintDb,
    pe: &cudabom_pe::PeFacts,
) -> Option<Finding> {
    // Prefer the version resource: NVIDIA stamps "NVIDIA CUDA <ver> Runtime"
    // (and similar) plus a ProductVersion/FileVersion. From the product name we
    // recover the component; from the product string we recover the version.
    let product = pe
        .version_string("ProductName")
        .or_else(|| pe.version_string("FileDescription"));
    if let Some(product) = product {
        if let Some(component) = component_for_pe_product(db, product) {
            // The exact micro version may live in ProductName or in
            // FileDescription (NVIDIA puts "..., Version X.Y.Z" there for some
            // libraries). Try both, preferring the first that yields a dotted
            // version; nothing is inferred beyond literal dotted-digit runs.
            let version = pe
                .version_string("ProductName")
                .and_then(cuda_version_in)
                .or_else(|| {
                    pe.version_string("FileDescription")
                        .and_then(cuda_version_in)
                });
            return Some(Finding {
                id: finding_id(&facts.path, &component),
                component: Component {
                    name: component,
                    version,
                    candidate_versions: Vec::new(),
                    relationship: Relationship::EmbeddedCopy,
                },
                confidence: Confidence::Likely,
                evidence: vec![Evidence {
                    kind: EvidenceKind::Soname,
                    location: facts.location(),
                    detail: format!("PE version resource: {product}"),
                }],
                conflicts: Vec::new(),
            });
        }
    }

    // Fall back to the DLL file name (e.g. `cudart64_12.dll`): map it to a
    // component stem the DB knows. Version is the embedded ABI major only.
    let base = facts.path.rsplit('/').next().unwrap_or(&facts.path);
    if let Some(component) = component_for_pe_dll_name(db, base) {
        let version = pe_dll_major(base).map(|m| format!("{m}.x"));
        return Some(Finding {
            id: finding_id(&facts.path, &component),
            component: Component {
                name: component,
                version,
                candidate_versions: Vec::new(),
                relationship: Relationship::EmbeddedCopy,
            },
            confidence: Confidence::Likely,
            evidence: vec![Evidence {
                kind: EvidenceKind::Soname,
                location: facts.location(),
                detail: format!("PE image name: {base}"),
            }],
            conflicts: Vec::new(),
        });
    }

    None
}

/// Map a PE product/description string to a known component name.
///
/// Matches on the component token appearing in the product string (e.g.
/// "NVIDIA CUDA 12.4.99 Runtime" -> `cudart`; a cuBLAS product -> `cublas`),
/// gated on the DB actually knowing that component so we never name something
/// the database cannot back.
fn component_for_pe_product(db: &FingerprintDb, product: &str) -> Option<String> {
    let lower = product.to_ascii_lowercase();
    let known = |name: &str| db.components.iter().any(|c| c.name == name);
    // Order matters: check the more specific library names before the generic
    // "cuda ... runtime" phrasing that NVIDIA uses for cudart (the product
    // string is e.g. "NVIDIA CUDA 12.4.99 Runtime", with the version between
    // the words, so match the words independently rather than as a phrase).
    let candidates: &[(&[&str], &str)] = &[
        (&["cublaslt"], "cublas"),
        (&["cublas"], "cublas"),
        (&["cuda", "blas"], "cublas"),
        (&["cufft"], "cufft"),
        (&["cuda", "fft"], "cufft"),
        (&["curand"], "curand"),
        (&["cuda", "random"], "curand"),
        (&["cusolver"], "cusolver"),
        (&["cuda", "solver"], "cusolver"),
        (&["cusparse"], "cusparse"),
        (&["cuda", "sparse"], "cusparse"),
        (&["nvjpeg"], "nvjpeg"),
        (&["nvrtc"], "nvrtc"),
        (&["npp"], "npp"),
        (&["cudart"], "cudart"),
        // Generic CUDA runtime phrasing (words may be separated by a version).
        (&["cuda", "runtime"], "cudart"),
    ];
    for (needles, canonical) in candidates {
        if needles.iter().all(|n| lower.contains(n)) && known(canonical) {
            return Some((*canonical).to_string());
        }
    }
    None
}

/// Map a Windows CUDA DLL file name (e.g. `cudart64_12.dll`, `cublas64_11.dll`)
/// to a known component name, gated on the DB knowing it.
fn component_for_pe_dll_name(db: &FingerprintDb, name: &str) -> Option<String> {
    let lower = name.to_ascii_lowercase();
    // Require a `.dll` extension (lower is already lowercased, so this is a
    // case-insensitive check on the original name).
    let Some((stem, "dll")) = lower.rsplit_once('.') else {
        return None;
    };
    // Strip the trailing `64_<major>` / `32_<major>` decoration NVIDIA uses.
    let base = stem
        .split("64_")
        .next()
        .unwrap_or(stem)
        .split("32_")
        .next()
        .unwrap_or(stem);
    let candidates: &[(&str, &str)] = &[
        ("cudart", "cudart"),
        ("cublaslt", "cublas"),
        ("cublas", "cublas"),
        ("cufft", "cufft"),
        ("curand", "curand"),
        ("cusolver", "cusolver"),
        ("cusparse", "cusparse"),
        ("nvjpeg", "nvjpeg"),
        ("nvrtc", "nvrtc"),
    ];
    for (needle, canonical) in candidates {
        if base.starts_with(needle) && db.components.iter().any(|c| c.name == *canonical) {
            return Some((*canonical).to_string());
        }
    }
    None
}

/// The ABI major version embedded in a Windows CUDA DLL name
/// (`cudart64_12.dll` -> 12, `cudart32_110.dll` -> 110).
fn pe_dll_major(name: &str) -> Option<u32> {
    let lower = name.to_ascii_lowercase();
    let stem = lower.trim_end_matches(".dll");
    for sep in ["64_", "32_"] {
        if let Some(idx) = stem.find(sep) {
            let digits: String = stem[idx + sep.len()..]
                .chars()
                .take_while(char::is_ascii_digit)
                .collect();
            if let Ok(n) = digits.parse::<u32>() {
                return Some(n);
            }
        }
    }
    None
}

/// Extract a dotted CUDA version (e.g. `12.4.99`) from a product string, if one
/// is present. Reads only literal dotted-digit runs; nothing is inferred.
fn cuda_version_in(product: &str) -> Option<String> {
    let bytes = product.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_digit() {
            let start = i;
            let mut dots = 0;
            while i < bytes.len() && (bytes[i].is_ascii_digit() || (bytes[i] == b'.' && dots < 3)) {
                if bytes[i] == b'.' {
                    dots += 1;
                }
                i += 1;
            }
            let token = product[start..i].trim_end_matches('.');
            // Require at least one dot so a bare major (e.g. "64") is not taken.
            if token.contains('.') {
                return Some(token.to_string());
            }
        } else {
            i += 1;
        }
    }
    None
}

/// Attribute a NEEDED dependency to a known component as a dynamic dependency.
fn identify_needed(facts: &FileFacts, db: &FingerprintDb, needed: &str) -> Option<Finding> {
    let parts = parse_soname(needed)?;
    let comp = db
        .components
        .iter()
        .find(|c| c.soname_stems.iter().any(|s| s == &parts.stem))?;

    let version = major_version(&parts).map(|m| format!("{m}.x"));
    Some(Finding {
        id: finding_id(&facts.path, &format!("{}-dep", comp.name)),
        component: Component {
            name: comp.name.clone(),
            version,
            candidate_versions: Vec::new(),
            // The dependency is supplied elsewhere, not embedded here.
            relationship: Relationship::DynamicDependency,
        },
        // A NEEDED entry is a weak signal: the dependency is declared, not
        // proven to be any particular build.
        confidence: Confidence::Unknown,
        evidence: vec![Evidence {
            kind: EvidenceKind::NeededEntry,
            location: facts.location(),
            detail: needed.to_string(),
        }],
        conflicts: Vec::new(),
    })
}

/// Find the component whose `select`ed map contains `key`, with its sorted
/// version set. Shared by the hash and build-id lookups, which differ only in
/// the map they consult.
fn lookup_in<'a>(
    db: &'a FingerprintDb,
    key: &str,
    select: impl Fn(&'a ComponentFingerprint) -> &'a std::collections::BTreeMap<String, Vec<String>>,
) -> Option<(&'a ComponentFingerprint, Vec<String>)> {
    db.components.iter().find_map(|comp| {
        select(comp)
            .get(key)
            .filter(|versions| !versions.is_empty())
            .map(|versions| (comp, sorted_unique(versions)))
    })
}

fn lookup_hash<'a>(
    db: &'a FingerprintDb,
    sha: &str,
) -> Option<(&'a ComponentFingerprint, Vec<String>)> {
    lookup_in(db, sha, |comp| &comp.file_hashes)
}

fn lookup_build_id<'a>(
    db: &'a FingerprintDb,
    build_id: &str,
) -> Option<(&'a ComponentFingerprint, Vec<String>)> {
    lookup_in(db, build_id, |comp| &comp.build_ids)
}

/// Sort and de-duplicate a version set so the representative (first element) is
/// deterministic and the candidate set carries no repeats.
///
/// Sorting is segment-aware numeric (so `11.9.0` precedes `11.10.0`), falling
/// back to lexical comparison for non-numeric segments. A plain string sort
/// would order `11.10.0` before `11.9.0`, picking the wrong representative.
fn sorted_unique(versions: &[String]) -> Vec<String> {
    let mut out = versions.to_vec();
    out.sort_by(|a, b| version_cmp(a, b));
    out.dedup();
    out
}

/// Compare two version strings segment by segment. Dot-separated segments that
/// both parse as integers compare numerically; otherwise they compare lexically.
/// Shorter versions sort before longer ones when all shared segments are equal
/// (e.g. `11.4` before `11.4.1`).
pub(crate) fn version_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    let mut sa = a.split('.');
    let mut sb = b.split('.');
    loop {
        match (sa.next(), sb.next()) {
            (Some(x), Some(y)) => {
                let ord = match (x.parse::<u64>(), y.parse::<u64>()) {
                    (Ok(nx), Ok(ny)) => nx.cmp(&ny),
                    _ => x.cmp(y),
                };
                if ord != Ordering::Equal {
                    return ord;
                }
            }
            (Some(_), None) => return Ordering::Greater,
            (None, Some(_)) => return Ordering::Less,
            (None, None) => return Ordering::Equal,
        }
    }
}

/// Insert `version` into a sorted, de-duplicated version set, keeping it in
/// `version_cmp` order. The single home for the "add a version to a set" idiom
/// shared by the binary and DB-merge paths.
pub(crate) fn insert_version(set: &mut Vec<String>, version: &str) {
    if !set.iter().any(|v| v == version) {
        set.push(version.to_string());
        set.sort_by(|a, b| version_cmp(a, b));
    }
}

/// Build an `Exact` finding from a strong (hash/build-id) evidence item.
///
/// `versions` is the full, sorted set the signal maps to. `version` is set to
/// the lowest (a deterministic representative) for the single `Component.version`
/// field; when the set holds more than one, `candidate_versions` carries the
/// whole set so the match stays honest about which micro version(s) the
/// byte-identical binary could be, and `release_versions` spans every candidate
/// for advisory correlation.
fn exact_finding(
    facts: &FileFacts,
    comp: &ComponentFingerprint,
    versions: Vec<String>,
    relationship: Relationship,
    evidence: Evidence,
) -> Finding {
    let version = versions.first().cloned();
    // Only record the candidate set when it is genuinely ambiguous (>1); a
    // single-version signal leaves `candidate_versions` empty.
    let candidate_versions = if versions.len() > 1 {
        versions
    } else {
        Vec::new()
    };
    Finding {
        id: finding_id(&facts.path, &comp.name),
        component: Component {
            name: comp.name.clone(),
            version,
            candidate_versions,
            relationship,
        },
        confidence: Confidence::Exact,
        evidence: vec![evidence],
        conflicts: Vec::new(),
    }
}

/// A stable, deterministic finding id derived from the file path and component.
fn finding_id(path: &str, component: &str) -> String {
    // Deterministic and readable; uniqueness is per (path, component).
    format!("{path}::{component}")
}

#[cfg(test)]
mod pe_tests {
    use super::*;
    use cudabom_pe::{PeClass, PeFacts, PeKind, VersionString};

    fn db_with(components: &[&str]) -> FingerprintDb {
        let comps: Vec<String> = components
            .iter()
            .map(|n| format!(r#"{{ "name": "{n}", "soname_stems": [] }}"#))
            .collect();
        let json = format!(
            r#"{{ "schema_version": 1, "components": [{}] }}"#,
            comps.join(",")
        );
        FingerprintDb::from_json(json.as_bytes()).unwrap()
    }

    fn pe_with(version_strings: &[(&str, &str)]) -> PeFacts {
        PeFacts {
            class: PeClass::Pe32Plus,
            kind: PeKind::Dll,
            machine: "X86_64".into(),
            imported_dlls: Vec::new(),
            exported_symbols: Vec::new(),
            section_names: Vec::new(),
            version_strings: version_strings
                .iter()
                .map(|(k, v)| VersionString {
                    key: (*k).to_string(),
                    value: (*v).to_string(),
                })
                .collect(),
        }
    }

    fn facts_pe(path: &str, pe: PeFacts) -> FileFacts {
        FileFacts {
            path: path.into(),
            sha256: None,
            layer_digest: None,
            elf: None,
            pe: Some(pe),
            gpu_code: None,
        }
    }

    #[test]
    fn cuda_version_in_extracts_dotted_version() {
        assert_eq!(
            cuda_version_in("NVIDIA CUDA 12.4.99 Runtime").as_deref(),
            Some("12.4.99")
        );
        assert_eq!(
            cuda_version_in("NVIDIA CUDA BLAS Library, Version 11.11.3").as_deref(),
            Some("11.11.3")
        );
        // A bare integer is not a version.
        assert_eq!(cuda_version_in("cudart64 only"), None);
    }

    #[test]
    fn pe_dll_major_reads_decoration() {
        assert_eq!(pe_dll_major("cudart64_12.dll"), Some(12));
        assert_eq!(pe_dll_major("cudart32_110.dll"), Some(110));
        assert_eq!(pe_dll_major("cublas64_11.dll"), Some(11));
        assert_eq!(pe_dll_major("notadll"), None);
    }

    #[test]
    fn runtime_product_names_cudart_with_exact_version() {
        let db = db_with(&["cudart"]);
        let pe = pe_with(&[
            ("ProductName", "NVIDIA CUDA 12.4.99 Runtime"),
            ("FileVersion", "6,14,11,12040"),
        ]);
        let facts = facts_pe("cudart64_12.dll", pe);
        let findings = identify_file(&facts, &db);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].component.name, "cudart");
        assert_eq!(findings[0].component.version.as_deref(), Some("12.4.99"));
        assert_eq!(findings[0].confidence, Confidence::Likely);
    }

    #[test]
    fn blas_description_names_cublas_with_version_from_description() {
        let db = db_with(&["cublas"]);
        let pe = pe_with(&[
            ("ProductName", "NVIDIA CUDA BLAS Library"),
            (
                "FileDescription",
                "NVIDIA CUDA BLAS Library, Version 11.11.3",
            ),
        ]);
        let facts = facts_pe("cublas64_11.dll", pe);
        let findings = identify_file(&facts, &db);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].component.name, "cublas");
        assert_eq!(findings[0].component.version.as_deref(), Some("11.11.3"));
    }

    #[test]
    fn falls_back_to_dll_name_when_no_version_resource() {
        let db = db_with(&["cudart"]);
        let pe = pe_with(&[]); // no version strings
        let facts = facts_pe("some/path/cudart64_12.dll", pe);
        let findings = identify_file(&facts, &db);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].component.name, "cudart");
        // Only the ABI major is known from the file name.
        assert_eq!(findings[0].component.version.as_deref(), Some("12.x"));
    }

    #[test]
    fn unknown_component_in_product_names_nothing() {
        // DB does not know this component, so we refuse to name it.
        let db = db_with(&["cudart"]);
        let pe = pe_with(&[("ProductName", "NVIDIA CUDA FFT Library")]);
        let facts = facts_pe("cufft64_11.dll", pe);
        let findings = identify_file(&facts, &db);
        assert!(
            findings.is_empty(),
            "an unknown component in the product string must not be named"
        );
    }

    #[test]
    fn version_cmp_orders_segments_numerically() {
        use std::cmp::Ordering;
        // The regression: a lexical sort would put 11.10.0 before 11.9.0.
        assert_eq!(version_cmp("11.9.0", "11.10.0"), Ordering::Less);
        assert_eq!(version_cmp("12.4.1", "12.4.108"), Ordering::Less);
        assert_eq!(version_cmp("11.4", "11.4.1"), Ordering::Less);
        assert_eq!(version_cmp("12.0.0", "12.0.0"), Ordering::Equal);
        // Non-numeric segments fall back to lexical compare.
        assert_eq!(
            version_cmp("2.32.3-cuda12.9", "2.32.3-cuda13.0"),
            Ordering::Less
        );
    }

    #[test]
    fn representative_is_lowest_numeric_version() {
        let set = sorted_unique(&[
            "11.10.0".to_string(),
            "11.9.0".to_string(),
            "11.9.0".to_string(),
        ]);
        assert_eq!(set, vec!["11.9.0".to_string(), "11.10.0".to_string()]);
        // `exact_finding` reports the first (lowest) element as the representative.
        assert_eq!(set.first().map(String::as_str), Some("11.9.0"));
    }

    /// A fingerprint DB whose single component carries the given symbol markers.
    fn db_with_symbol_markers(name: &str, markers: &[&str]) -> FingerprintDb {
        let list: Vec<String> = markers.iter().map(|m| format!(r#""{m}""#)).collect();
        let json = format!(
            r#"{{ "schema_version": 3, "components": [
                {{ "name": "{name}", "soname_stems": [], "symbol_markers": [{}] }}
            ] }}"#,
            list.join(",")
        );
        FingerprintDb::from_json(json.as_bytes()).unwrap()
    }

    /// ELF facts for a static-archive member: no SONAME, no build-id, just the
    /// exported (static) symbols.
    fn facts_elf_symbols(path: &str, exported: &[&str]) -> FileFacts {
        use cudabom_elf::{ElfClass, ElfFacts, ElfType, Endianness};
        FileFacts {
            path: path.into(),
            sha256: None,
            layer_digest: None,
            elf: Some(ElfFacts {
                class: ElfClass::Elf64,
                endianness: Endianness::Little,
                elf_type: ElfType::Relocatable,
                architecture: "X86_64".to_string(),
                soname: None,
                needed: Vec::new(),
                runpaths: Vec::new(),
                build_id: None,
                section_names: Vec::new(),
                exported_symbols: exported.iter().map(ToString::to_string).collect(),
                dynamically_linked: false,
            }),
            pe: None,
            gpu_code: None,
        }
    }

    #[test]
    fn symbol_markers_name_component_at_likely() {
        let db = db_with_symbol_markers("nccl", &["ncclAllReduce", "ncclCommInitRank"]);
        let facts = facts_elf_symbols(
            "libnccl_static.a/init.o",
            &["ncclAllReduce", "ncclCommInitRank", "memcpy"],
        );
        let findings = identify_file(&facts, &db);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].component.name, "nccl");
        // A symbol set names the component, not a version.
        assert_eq!(findings[0].component.version, None);
        assert_eq!(findings[0].confidence, Confidence::Likely);
        assert_eq!(
            findings[0].component.relationship,
            Relationship::StaticallyLinked
        );
        assert_eq!(
            findings[0].evidence[0].kind,
            EvidenceKind::ExportedSymbolSet
        );
    }

    #[test]
    fn single_symbol_match_is_not_enough() {
        // One matching symbol is below the MIN_SYMBOL_MATCHES guard, so no
        // component is named: a lone symbol must not trigger attribution.
        let db = db_with_symbol_markers("nccl", &["ncclAllReduce", "ncclCommInitRank"]);
        let facts = facts_elf_symbols("x.o", &["ncclAllReduce", "unrelated"]);
        assert!(
            identify_file(&facts, &db).is_empty(),
            "a single marker match is below MIN_SYMBOL_MATCHES"
        );
    }

    #[test]
    fn no_symbol_markers_in_db_yields_no_symbol_finding() {
        // A DB component without derived symbol markers never matches on symbols.
        let db = db_with(&["nccl"]);
        let facts = facts_elf_symbols("x.o", &["ncclAllReduce", "ncclCommInitRank"]);
        assert!(
            identify_file(&facts, &db).is_empty(),
            "a component without symbol markers never matches on symbols"
        );
    }

    #[test]
    fn hash_match_wins_over_symbol_markers() {
        // When a strong hash signal is present, it is used and the symbol-set
        // step does not also fire (the earlier return short-circuits).
        let json = r#"{
            "schema_version": 3,
            "components": [
                { "name": "nccl", "soname_stems": [],
                  "file_hashes": { "abc123": ["2.20.5"] },
                  "symbol_markers": ["ncclAllReduce", "ncclCommInitRank"] }
            ]
        }"#;
        let db = FingerprintDb::from_json(json.as_bytes()).unwrap();
        let mut facts = facts_elf_symbols("x.o", &["ncclAllReduce", "ncclCommInitRank"]);
        facts.sha256 = Some("abc123".to_string());
        let findings = identify_file(&facts, &db);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].confidence, Confidence::Exact);
        assert_eq!(findings[0].evidence[0].kind, EvidenceKind::KnownFileHash);
    }
}
