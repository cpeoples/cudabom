//! Derive fingerprint-database entries from NVIDIA redistributable manifests.
//!
//! A manifest (see [`crate::redist`]) is authoritative for *version <-> archive
//! sha256*. Turning that into a [`FingerprintDb`] requires one more piece of
//! knowledge the manifest does not carry: which canonical cudabom component a
//! manifest key represents, and which SONAME stems that component publishes.
//!
//! That knowledge is a small, reviewed table ([`component_profiles`]), never
//! guessed. A manifest key such as `cuda_cudart` maps to the component `cudart`
//! with stem `libcudart.so`; a key like `cuda_nvcc` (a compiler, not a shared
//! library) is intentionally absent, so its archives are reported as
//! *underived* rather than being given a fabricated `libnvcc.so` stem. This
//! upholds the project rule: cudabom does not invent fingerprints.
//!
//! Scope of a derived hash: the manifest sha256 is of the published *archive*,
//! so a derived `file_hashes` entry proves "these bytes are the published
//! `cudart` 11.4.108 archive", i.e. it fires when cudabom scans the archive
//! itself. Identifying a `.so` unpacked from the archive requires the separate,
//! binary-derived build-id/hash layer and is not claimed here.

use std::collections::BTreeMap;

use crate::db::{ComponentFingerprint, FingerprintDb};
use crate::redist::RedistManifest;

/// A reviewed profile linking a manifest key to a cudabom component identity.
#[derive(Debug, Clone, Copy)]
struct ComponentProfile {
    /// The manifest key (e.g. `cuda_cudart`).
    manifest_key: &'static str,
    /// The canonical cudabom component name (e.g. `cudart`).
    component: &'static str,
    /// The SONAME stems this component publishes (e.g. `libcudart.so`). Empty
    /// for components that ship no shared library (e.g. compilers, headers).
    soname_stems: &'static [&'static str],
    /// Normalized substrings that, when found in a CSAF advisory product name,
    /// map that advisory to this component. These are the authoritative source
    /// from which `advisories/product-map.json` is *generated* (see
    /// [`advisory_terms`]), so adding a component in one place keeps fingerprint
    /// attribution and advisory matching in lockstep. Empty when the component
    /// has no distinct advisory vocabulary (its archives still yield
    /// version<->hash records). Order within an entry is most-specific-first.
    advisory_terms: &'static [&'static str],
}

/// The reviewed set of component profiles.
///
/// Each entry is a documented fact about a CUDA redistributable, not a guess.
/// SONAME stems are the versioned-library base names NVIDIA ships (without the
/// `.<major>` ABI suffix). Components that ship no shared object have an empty
/// stem list: their archives still yield a version<->hash record, but they
/// contribute no SONAME attribution.
///
/// This table is deliberately conservative and easy to extend: adding a
/// component is a one-line, reviewable change.
// The table grows by one entry per CUDA component; it is a flat data literal,
// not control flow, so the line count is expected to exceed the default.
#[allow(clippy::too_many_lines)]
const fn component_profiles() -> &'static [ComponentProfile] {
    &[
        ComponentProfile {
            manifest_key: "cuda_cudart",
            component: "cudart",
            soname_stems: &["libcudart.so"],
            advisory_terms: &["cuda runtime", "cudart"],
        },
        ComponentProfile {
            manifest_key: "libcublas",
            component: "cublas",
            soname_stems: &["libcublas.so", "libcublasLt.so"],
            advisory_terms: &["cublas"],
        },
        ComponentProfile {
            manifest_key: "libcufft",
            component: "cufft",
            soname_stems: &["libcufft.so", "libcufftw.so"],
            advisory_terms: &["cufft"],
        },
        ComponentProfile {
            manifest_key: "libcurand",
            component: "curand",
            soname_stems: &["libcurand.so"],
            advisory_terms: &["curand"],
        },
        ComponentProfile {
            manifest_key: "libcusolver",
            component: "cusolver",
            soname_stems: &["libcusolver.so", "libcusolverMg.so"],
            advisory_terms: &["cusolver"],
        },
        ComponentProfile {
            manifest_key: "libcusparse",
            component: "cusparse",
            soname_stems: &["libcusparse.so"],
            advisory_terms: &["cusparse"],
        },
        ComponentProfile {
            manifest_key: "libnpp",
            component: "npp",
            soname_stems: &[
                "libnppc.so",
                "libnppial.so",
                "libnppicc.so",
                "libnppidei.so",
                "libnppif.so",
                "libnppig.so",
                "libnppim.so",
                "libnppist.so",
                "libnppisu.so",
                "libnppitc.so",
                "libnpps.so",
            ],
            advisory_terms: &["npp"],
        },
        ComponentProfile {
            manifest_key: "libnvjpeg",
            component: "nvjpeg",
            soname_stems: &["libnvjpeg.so"],
            advisory_terms: &["nvjpeg"],
        },
        ComponentProfile {
            manifest_key: "nvcomp",
            component: "nvcomp",
            soname_stems: &["libnvcomp.so", "libnvcomp_cpu.so"],
            advisory_terms: &["nvcomp"],
        },
        ComponentProfile {
            manifest_key: "cuda_nvrtc",
            component: "nvrtc",
            soname_stems: &["libnvrtc.so", "libnvrtc-builtins.so"],
            advisory_terms: &["nvrtc"],
        },
        ComponentProfile {
            manifest_key: "libnvjitlink",
            component: "nvjitlink",
            soname_stems: &["libnvJitLink.so"],
            advisory_terms: &["nvjitlink", "nvjit link"],
        },
        ComponentProfile {
            manifest_key: "libcufile",
            component: "cufile",
            soname_stems: &["libcufile.so", "libcufile_rdma.so"],
            advisory_terms: &["cufile", "gpudirect storage"],
        },
        ComponentProfile {
            manifest_key: "libnvfatbin",
            component: "nvfatbin",
            soname_stems: &["libnvfatbin.so"],
            advisory_terms: &["nvfatbin"],
        },
        ComponentProfile {
            // CUPTI: the CUDA Profiling Tools Interface. Ships several shared
            // libraries and has carried CVEs of its own, so attributing a
            // scanned `libcupti.so` matters. Stems verified from the
            // `cuda_cupti` redist archive.
            manifest_key: "cuda_cupti",
            component: "cupti",
            soname_stems: &[
                "libcupti.so",
                "libnvperf_host.so",
                "libnvperf_target.so",
                "libcheckpoint.so",
                "libpcsamplingutil.so",
            ],
            advisory_terms: &["profiling tools interface", "cupti"],
        },
        ComponentProfile {
            // NVVM: the compiler library (LLVM-based) that ships `libnvvm.so`.
            manifest_key: "libnvvm",
            component: "nvvm",
            soname_stems: &["libnvvm.so"],
            advisory_terms: &["nvvm"],
        },
        ComponentProfile {
            // cuDLA: the CUDA Deep Learning Accelerator runtime (Tegra/Orin).
            manifest_key: "libcudla",
            component: "cudla",
            soname_stems: &["libcudla.so"],
            advisory_terms: &["cudla"],
        },
        ComponentProfile {
            // cuobjclient: the CUDA object client shared library.
            manifest_key: "libcuobjclient",
            component: "cuobjclient",
            soname_stems: &["libcuobjclient.so"],
            advisory_terms: &["cuobjclient"],
        },
        ComponentProfile {
            manifest_key: "cuda_cuobjdump",
            component: "cuobjdump",
            soname_stems: &[],
            advisory_terms: &["cuobjdump"],
        },
        ComponentProfile {
            manifest_key: "cuda_cuxxfilt",
            component: "cuxxfilt",
            soname_stems: &[],
            advisory_terms: &["cuxxfilt", "cu++filt"],
        },
        // --- Sibling CUDA-X redistributable trees -------------------------
        // These ship from parallel `compute/<product>/redist/` channels that
        // share the manifest schema. SONAME stems are verified from the real
        // linux-x86_64 archives (see `cargo xtask corpus` / the build-time
        // archive guard), never guessed.
        ComponentProfile {
            // cuDNN: the deep neural network library. Modern cuDNN (9.x) is
            // split into many sub-libraries; all are attributed to `cudnn`.
            manifest_key: "cudnn",
            component: "cudnn",
            soname_stems: &[
                "libcudnn.so",
                "libcudnn_adv.so",
                "libcudnn_cnn.so",
                "libcudnn_ops.so",
                "libcudnn_graph.so",
                "libcudnn_engines_precompiled.so",
                "libcudnn_engines_runtime_compiled.so",
                "libcudnn_engines_tensor_ir.so",
                "libcudnn_heuristic.so",
                "libcudnn_ext.so",
            ],
            advisory_terms: &["cudnn", "cuda deep neural network"],
        },
        ComponentProfile {
            // NCCL: the collective communications library. Standalone redist
            // tree (`compute/nccl/redist/`) with CUDA-qualified manifest names.
            manifest_key: "nccl",
            component: "nccl",
            soname_stems: &["libnccl.so"],
            advisory_terms: &["nccl", "collective communications"],
        },
        ComponentProfile {
            // cuTENSOR: the tensor linear-algebra library.
            manifest_key: "libcutensor",
            component: "cutensor",
            soname_stems: &["libcutensor.so", "libcutensorMg.so", "libcutensorMp.so"],
            advisory_terms: &["cutensor"],
        },
        ComponentProfile {
            // cuDSS: the direct sparse solver library.
            manifest_key: "libcudss",
            component: "cudss",
            soname_stems: &[
                "libcudss.so",
                "libcudss_commlayer_nccl.so",
                "libcudss_commlayer_openmpi.so",
                "libcudss_mtlayer_gomp.so",
            ],
            advisory_terms: &["cudss"],
        },
        ComponentProfile {
            // cuSPARSELt: the structured-sparsity matmul library. Note the
            // archive SONAME is `libcusparseLt.so` (camelCase) and the manifest
            // key is `libcusparse_lt`.
            manifest_key: "libcusparse_lt",
            component: "cusparselt",
            soname_stems: &["libcusparseLt.so"],
            advisory_terms: &["cusparselt"],
        },
        ComponentProfile {
            // cuQuantum: quantum-computing SDK libraries (state-vector, tensor
            // network, density-matrix, Pauli propagation, stabilizer).
            manifest_key: "cuquantum",
            component: "cuquantum",
            soname_stems: &[
                "libcustatevec.so",
                "libcutensornet.so",
                "libcudensitymat.so",
                "libcupauliprop.so",
                "libcustabilizer.so",
            ],
            advisory_terms: &["cuquantum"],
        },
        ComponentProfile {
            // nvJPEG2000: JPEG 2000 codec library.
            manifest_key: "libnvjpeg_2k",
            component: "nvjpeg2000",
            soname_stems: &["libnvjpeg2k.so"],
            advisory_terms: &["nvjpeg2000", "nvjpeg 2000", "nvjpeg2k"],
        },
        ComponentProfile {
            // nvTIFF: TIFF codec library.
            manifest_key: "libnvtiff",
            component: "nvtiff",
            soname_stems: &["libnvtiff.so"],
            advisory_terms: &["nvtiff"],
        },
        ComponentProfile {
            // cuBLASMp: multi-process/multi-GPU dense linear algebra.
            manifest_key: "libcublasmp",
            component: "cublasmp",
            soname_stems: &["libcublasmp.so"],
            advisory_terms: &["cublasmp"],
        },
        ComponentProfile {
            // NVSHMEM: GPU-initiated communication library. Only the host-side
            // shared object ships (`libnvshmem_host.so`); the device library is
            // static.
            manifest_key: "libnvshmem",
            component: "nvshmem",
            soname_stems: &["libnvshmem_host.so"],
            advisory_terms: &["nvshmem"],
        },
        // NVPL: the NVIDIA Performance Libraries (aarch64/sbsa CPU math). Each
        // package is a distinct component so a scanned `.so` is attributed to
        // the right library. SONAME stems verified from the sbsa archives.
        ComponentProfile {
            manifest_key: "nvpl_blas",
            component: "nvpl-blas",
            soname_stems: &[
                "libnvpl_blas_core.so",
                "libnvpl_blas_ilp64_gomp.so",
                "libnvpl_blas_ilp64_seq.so",
                "libnvpl_blas_lp64_gomp.so",
                "libnvpl_blas_lp64_seq.so",
            ],
            advisory_terms: &["nvpl blas"],
        },
        ComponentProfile {
            manifest_key: "nvpl_fft",
            component: "nvpl-fft",
            soname_stems: &["libnvpl_fftw.so"],
            advisory_terms: &["nvpl fft"],
        },
        ComponentProfile {
            manifest_key: "nvpl_lapack",
            component: "nvpl-lapack",
            soname_stems: &[
                "libnvpl_lapack_core.so",
                "libnvpl_lapack_ilp64_gomp.so",
                "libnvpl_lapack_ilp64_seq.so",
                "libnvpl_lapack_lp64_gomp.so",
                "libnvpl_lapack_lp64_seq.so",
            ],
            advisory_terms: &["nvpl lapack"],
        },
        ComponentProfile {
            manifest_key: "nvpl_rand",
            component: "nvpl-rand",
            soname_stems: &["libnvpl_rand.so", "libnvpl_rand_mt.so"],
            advisory_terms: &["nvpl rand"],
        },
        ComponentProfile {
            manifest_key: "nvpl_scalapack",
            component: "nvpl-scalapack",
            soname_stems: &[
                "libnvpl_scalapack_ilp64.so",
                "libnvpl_scalapack_lp64.so",
                "libnvpl_blacs_ilp64_mpich.so",
                "libnvpl_blacs_ilp64_openmpi3.so",
                "libnvpl_blacs_ilp64_openmpi4.so",
                "libnvpl_blacs_ilp64_openmpi5.so",
                "libnvpl_blacs_lp64_mpich.so",
                "libnvpl_blacs_lp64_openmpi3.so",
                "libnvpl_blacs_lp64_openmpi4.so",
                "libnvpl_blacs_lp64_openmpi5.so",
            ],
            advisory_terms: &["nvpl scalapack"],
        },
        ComponentProfile {
            manifest_key: "nvpl_sparse",
            component: "nvpl-sparse",
            soname_stems: &["libnvpl_sparse.so"],
            advisory_terms: &["nvpl sparse"],
        },
        ComponentProfile {
            manifest_key: "nvpl_tensor",
            component: "nvpl-tensor",
            soname_stems: &["libnvpl_tensor.so"],
            advisory_terms: &["nvpl tensor"],
        },
    ]
}

/// The reviewed `(advisory_term, component)` pairs that generate the CSAF
/// product → component map (`advisories/product-map.json`).
///
/// Each pair is a documented fact already carried by a `ComponentProfile`, so
/// `product-map.json` is *derived* from the same reviewed table that drives
/// fingerprint attribution; adding a component in one place keeps advisory
/// matching and identification in lockstep rather than maintaining two lists.
///
/// Pairs are returned in a stable order: profile order (most components in
/// dependency/popularity order), and within a component the profile's own
/// term order (most-specific-first). `product-map.json`'s substring rules are
/// order-sensitive, so this ordering is part of the contract.
#[must_use]
pub fn advisory_terms() -> Vec<(&'static str, &'static str)> {
    component_profiles()
        .iter()
        .flat_map(|p| p.advisory_terms.iter().map(move |t| (*t, p.component)))
        .collect()
}

/// Resolve a manifest key (e.g. `cuda_cudart`) to its canonical cudabom
/// component name (e.g. `cudart`) using the reviewed profile table. Returns
/// `None` for keys with no profile, so callers never guess an identity.
///
/// This shares one source of truth with [`derive()`], so the corpus lockfile
/// and the fingerprint derivation agree on which components are attributable.
#[must_use]
pub fn resolve_component(manifest_key: &str) -> Option<String> {
    component_profiles()
        .iter()
        .find(|p| p.manifest_key == manifest_key)
        .map(|p| p.component.to_string())
}

/// The reviewed SONAME stems that belong to a canonical component (e.g.
/// `cudart` -> `["libcudart.so"]`). Returns an empty slice for components that
/// ship no shared library, or names with no profile.
///
/// This is the allowlist used to decide whether a `.so` unpacked from an
/// archive truly belongs to the component: NVIDIA archives often bundle extra
/// libraries (a `libcuda.so` driver stub, `libOpenCL.so`) that must not be
/// attributed to the component whose archive happened to carry them. Grounding
/// attribution in the reviewed table keeps identity a documented fact.
#[must_use]
pub fn soname_stems_for(component: &str) -> &'static [&'static str] {
    component_profiles()
        .iter()
        .find(|p| p.component == component)
        .map_or(&[], |p| p.soname_stems)
}

/// Reverse lookup: the profiled component that already owns a given SONAME
/// stem, if any. Matching is on stem equality after normalizing both sides to
/// their `.so` stem (dropping any ABI version suffix), so a scanned
/// `libcudnn_graph.so.9` or the bare `libcudnn_graph.so` both resolve to the
/// `cudnn` component that lists `libcudnn_graph.so` in its reviewed profile.
///
/// This is what lets Model B *fold* an auto-derived library into an existing
/// reviewed component rather than minting a fragment: cuDNN publishes several
/// of its sub-libraries (e.g. `libcudnn_graph.so`,
/// `libcudnn_engines_runtime_compiled.so`) under the separate `cudnn_jit`
/// manifest key, but those stems are already owned by `cudnn`, so their
/// fingerprints must accrue to `cudnn`. Returns `None` for a stem no profile
/// owns (a genuinely new library), so the caller then auto-derives it.
#[must_use]
pub fn component_owning_soname(soname_stem: &str) -> Option<&'static str> {
    // Normalize the query to its `.so` stem (`libcudnn_graph.so.9` ->
    // `libcudnn_graph.so`) so a versioned SONAME matches the profile's stem.
    let normalized = soname_stem
        .find(".so")
        .map_or(soname_stem, |idx| &soname_stem[..idx + ".so".len()]);
    component_profiles()
        .iter()
        .find_map(|p| p.soname_stems.contains(&normalized).then_some(p.component))
}

/// Normalize a manifest key to a component display name: lowercase, drop a
/// leading `lib` or `cuda_` decoration, and fold separators to `_`.
///
/// This is the first-party NVIDIA unit name (`libcal` -> `cal`, `cuda_nvtx` ->
/// `nvtx`, `cuda_opencl` -> `opencl`), used both as the identity for a
/// genuinely new auto-derived component and (lowercased) as its advisory term,
/// so a scanned library and a CSAF product name reconcile by the same name
/// NVIDIA ships the package under.
#[must_use]
pub fn normalize_manifest_key_name(manifest_key: &str) -> String {
    let key = manifest_key.to_ascii_lowercase();
    let core = key
        .strip_prefix("lib")
        .or_else(|| key.strip_prefix("cuda_"))
        .unwrap_or(&key);
    core.replace(['-', ' '], "_")
}

/// Map a *declared* component name or purl (as a third party like NGC writes
/// it) to a canonical cudabom component name, when it names a CUDA component
/// cudabom knows.
///
/// Third-party SBOMs name CUDA components inconsistently: `cuda-cudart`,
/// `cuda_cudart`, `libcublas`, `libcublas-12-4`, a versioned SONAME like
/// `libcudart.so.12`, or a purl like `pkg:generic/cuda-cudart@12.4.127`. This
/// normalizes all of those to the same canonical vocabulary the identify engine
/// and fingerprint DB use (`cudart`, `cublas`, ...), so declared and discovered
/// components can be reconciled by identity rather than by spelling.
///
/// Returns `None` for names that do not resolve to a known CUDA component; the
/// caller decides how to treat unrecognized declared entries (they are not CUDA
/// components cudabom reasons about).
#[must_use]
pub fn canonicalize_declared_name(declared: &str) -> Option<String> {
    // Strip a purl prefix (`pkg:type/namespace/name`) down to the last name
    // segment, and drop any `@version`, `?qualifiers`, or `#subpath`.
    let mut s = declared.trim();
    if let Some(rest) = s.strip_prefix("pkg:") {
        s = rest.rsplit('/').next().unwrap_or(rest);
    }
    for sep in ['@', '?', '#'] {
        if let Some(idx) = s.find(sep) {
            s = &s[..idx];
        }
    }
    // Drop a versioned SONAME suffix (`libcudart.so.12.4` -> `libcudart.so`),
    // then normalize separators and case.
    let lowered = s.to_ascii_lowercase();
    let base = lowered.split(".so").next().unwrap_or(&lowered);
    let normalized: String = base
        .chars()
        .map(|c| if c == '-' || c == ' ' { '_' } else { c })
        .collect();
    // Normalize a PyPI wheel spelling (`nvidia-nccl-cu12`, `cutensor-cu12`,
    // `cupy-cuda12x`) down to its CUDA component. This folds the project ->
    // component knowledge that distribution discovery needs into the single
    // canonical resolver, so the scanner and the eval agree by construction.
    let normalized = normalize_pypi_wheel(&normalized);
    // Trim a trailing package version-track suffix like `_12_4` or `_13`.
    let normalized = trim_version_track(&normalized);

    let profiles = component_profiles();
    // 1. Exact canonical name (`cudart`).
    if let Some(p) = profiles.iter().find(|p| p.component == normalized) {
        return Some(p.component.to_string());
    }
    // 2. Manifest key form (`cuda_cudart`, `libcublas`).
    if let Some(p) = profiles.iter().find(|p| p.manifest_key == normalized) {
        return Some(p.component.to_string());
    }
    // 3. `lib<canonical>` / `cuda_<canonical>` spellings.
    for p in profiles {
        let lib = format!("lib{}", p.component);
        let cuda = format!("cuda_{}", p.component);
        if normalized == lib || normalized == cuda {
            return Some(p.component.to_string());
        }
    }
    // 4. A SONAME stem (`libcudart`, from `libcudart.so.12`).
    for p in profiles {
        for stem in p.soname_stems {
            let stem_base = stem.strip_suffix(".so").unwrap_or(stem);
            if normalized == stem_base.to_ascii_lowercase() {
                return Some(p.component.to_string());
            }
        }
    }
    None
}

/// Trim a trailing package version-track suffix (`_12_4`, `_13`, `_12_4_1`) that
/// Linux package naming appends (e.g. `libcublas_12_4`). Only trims when the
/// suffix is purely numeric segments, so it never clips a real name.
fn trim_version_track(name: &str) -> String {
    let mut parts: Vec<&str> = name.split('_').collect();
    while parts.len() > 1
        && parts
            .last()
            .is_some_and(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
    {
        parts.pop();
    }
    parts.join("_")
}

/// Normalize a PyPI wheel project name to the canonical CUDA component spelling,
/// if the name is a recognized CUDA wheel. Input is already lowercased with
/// separators folded to `_` (e.g. `nvidia_cuda_runtime_cu12`, `cutensor_cu12`,
/// `cupy_cuda12x`).
///
/// NVIDIA publishes each CUDA library as a `nvidia-<name>-cu1X` wheel whose
/// version *is* the component version; third-party frameworks bundle CUDA under
/// their own names. This folds the `nvidia_`/`cu1X`/`cuda1Xx` build-track
/// decoration and resolves the few names that differ from their component
/// (`cuda_runtime` -> `cudart`, `cuda_nvrtc` -> `nvrtc`). Names it does not
/// recognize are returned unchanged, so the caller's profile matching still
/// runs (and third-party bundles like `cupy`/`torch` simply resolve to `None`).
fn normalize_pypi_wheel(name: &str) -> String {
    // Strip NVIDIA's wheel namespace prefix.
    let stem = name.strip_prefix("nvidia_").unwrap_or(name);
    // Strip a trailing CUDA build-track token: `_cu12`, `_cu13`, or an embedded
    // `_cuda12x`-style token (CuPy). The token is `cu` or `cuda` followed by
    // digits and an optional trailing `x`.
    let stem = stem
        .rsplit_once('_')
        .filter(|(_, tail)| is_cuda_track_token(tail))
        .map_or(stem, |(head, _)| head);
    // The handful of official wheel names whose stem differs from the canonical
    // component. Everything else (`cudnn`, `nccl`, `cublas`, `cutensor`, ...)
    // already equals its component and resolves via the profile table.
    for (wheel, component) in WHEEL_ALIASES {
        if stem == *wheel {
            return (*component).to_string();
        }
    }
    stem.to_string()
}

/// Official NVIDIA wheel names whose stem differs from the canonical component
/// (`cuda_runtime` -> `cudart`). Every other CUDA wheel already equals its
/// component name and resolves via the profile table.
const WHEEL_ALIASES: &[(&str, &str)] = &[("cuda_runtime", "cudart"), ("cuda_nvrtc", "nvrtc")];

/// True if a token is a CUDA build-track decoration like `cu12`, `cu13`, or
/// `cuda12x` (`cu`/`cuda` + digits + optional trailing `x`).
fn is_cuda_track_token(tok: &str) -> bool {
    let rest = tok.strip_prefix("cuda").or_else(|| tok.strip_prefix("cu"));
    let Some(rest) = rest else { return false };
    let digits = rest.strip_suffix('x').unwrap_or(rest);
    !digits.is_empty() && digits.chars().all(|c| c.is_ascii_digit())
}

/// Reduce a SONAME stem to its *stem-core*: strip a leading `lib`, a trailing
/// `.so` (and any ABI version suffix after it), leaving the library's bare name.
///
/// Examples: `libcal.so` -> `cal`; `libcal.so.12` -> `cal`;
/// `libnvToolsExt.so.1` -> `nvToolsExt`; `libOpenCL.so` -> `OpenCL`. A name
/// with no `.so` is treated as not a shared-library stem and yields `None`, so
/// callers never fabricate an identity from a non-library file name.
#[must_use]
pub fn soname_stem_core(soname_stem: &str) -> Option<String> {
    // The core is everything between a leading `lib` and the first `.so`.
    let so_idx = soname_stem.find(".so")?;
    let before = &soname_stem[..so_idx];
    let core = before.strip_prefix("lib").unwrap_or(before);
    if core.is_empty() {
        return None;
    }
    Some(core.to_string())
}

/// Derive the canonical component name for a genuinely new shared library
/// NVIDIA ships under `manifest_key`, whose real archive SONAME stem is
/// `soname_stem`.
///
/// The name comes from the *manifest key* (the first-party NVIDIA unit name),
/// normalized by stripping a leading `lib` or `cuda_` and folding separators
/// (`libcal` -> `cal`, `cuda_nvtx` -> `nvtx`, `cuda_opencl` -> `opencl`). This
/// matches how advisories refer to a package better than the raw SONAME
/// stem-core (`nvToolsExt`, `OpenCL`) would. The `soname_stem` is still read and
/// attached elsewhere as the real matching signal; it is used here only as a
/// fallback label when the key normalizes to nothing usable.
///
/// Callers must first consult [`component_owning_soname`]: a stem already owned
/// by a reviewed profile folds into that component and never reaches here.
#[must_use]
pub fn auto_identity(soname_stem: &str, manifest_key: &str) -> String {
    let component = normalize_manifest_key_name(manifest_key);
    if component.is_empty() {
        return soname_stem_core(soname_stem).unwrap_or_else(|| manifest_key.to_string());
    }
    component
}

/// First-party license classification: is an unprofiled key's manifest
/// `license` one of NVIDIA's driver/datacenter/IDE tags that must NOT
/// auto-derive as a CUDA runtime component?
///
/// Model B mints a component for any unprofiled key whose archive ships a
/// `.so`. By itself that would wrongly mint non-CUDA units whose primary
/// library name-matches the key: datacenter telemetry/management
/// (`collectx_bringup`, `libnvsdm`, `libnvidia_nscq`, `fabricmanager`, `nvlsm`,
/// `mft`), the driver (`nvidia_driver`), and IDE tooling (`nsight_compute`,
/// `nsight_systems`). NVIDIA already classifies these in the redist manifest
/// via the `license` field, so this uses NVIDIA's own tag rather than our own
/// key-name denylist (future-proof: a new driver/datacenter archive carrying
/// one of these licenses is excluded automatically).
///
/// EXCLUDED is EXACTLY these four tags (trimmed, case-insensitive):
/// `NVIDIA Driver`, `NVIDIA Proprietary`, `NVIDIA SLA`, and bare `NVIDIA`. This
/// is a full-string match, never a substring: a CUDA license such as
/// `CUDA Toolkit` (which contains neither tag) and product licenses like
/// `cuTensor`, `NVPL`, or `libcal library` all fall through as eligible. A key
/// with no `license` field is NOT excluded here (it falls through to the other
/// gates: ships-a-`.so` and the `soname_belongs_to_key` attribution guard).
#[must_use]
pub fn license_is_excluded(license: Option<&str>) -> bool {
    let Some(license) = license else {
        return false; // absent license is not an exclusion signal
    };
    let normalized = license.trim().to_ascii_lowercase();
    matches!(
        normalized.as_str(),
        "nvidia driver" | "nvidia proprietary" | "nvidia sla" | "nvidia"
    )
}

/// Attribution-safety predicate for an auto-derived component: does a `.so`
/// whose SONAME stem is `soname_stem` belong to the archive published under
/// `manifest_key`?
///
/// NVIDIA archives bundle unrelated libraries (a `libcuda.so` driver stub, a
/// `libOpenCL.so`). A reviewed `ComponentProfile` gates these with
/// [`soname_stems_for`]; an auto-derived key has no allowlist, so this applies
/// a principled rule mirroring `dll_name_belongs_to`: credit the `.so` only
/// when its stem-core relates to the key's core name. "Relates" means either
/// name is a prefix of the other after normalization (so `cal` matches the
/// `libcal` key, and `cudnn_graph` matches the `cudnn_jit` family's `cudnn`
/// root), while an unrelated bundled stub (`cuda`, `OpenCL`) is dropped.
#[must_use]
pub fn soname_belongs_to_key(soname_stem: &str, manifest_key: &str) -> bool {
    let Some(core) = soname_stem_core(soname_stem) else {
        return false;
    };
    let core = core.to_ascii_lowercase();
    // Normalize the manifest key to a comparable core: drop a leading `lib`
    // or `cuda_` decoration and fold separators, matching how NVIDIA names the
    // archive after its primary library (`libcal` -> `cal`, `cuda_nvtx` ->
    // `nvtx`).
    let key_core = normalize_manifest_key_name(manifest_key);
    if key_core.is_empty() {
        return false;
    }
    // Relate on a shared prefix in either direction, token-aware so a stub like
    // `cuda` does not match a `cudnn_*` key by raw character prefix.
    related_core(&core, &key_core) || related_core(&key_core, &core)
}

/// True if `a` relates to `b`: equal, one extends the other at a token (`_`)
/// boundary, or they share the same leading token. This credits `cudnn_graph`
/// and `cudnn_engines_runtime_compiled` to the `cudnn_jit` key (shared `cudnn`
/// family token) and `cal` to `cal`, while rejecting `cuda` vs `cudnn` (their
/// leading tokens differ: `cuda` != `cudnn`).
fn related_core(a: &str, b: &str) -> bool {
    if a == b {
        return true;
    }
    // `a` extends `b` when it begins with `b` followed by a token separator,
    // so `cudnn_graph` extends `cudnn` but `cudnnx` does not extend `cudnn`.
    if a.strip_prefix(b).is_some_and(|rest| rest.starts_with('_')) {
        return true;
    }
    // Family relation: same leading token (`cudnn_graph` ~ `cudnn_jit` via
    // `cudnn`). A single-token core only relates to another single-token core
    // when equal (handled above), so this never over-matches `cal` ~ `cublas`.
    let a_head = a.split('_').next().unwrap_or(a);
    let b_head = b.split('_').next().unwrap_or(b);
    a_head == b_head && a.contains('_') && b.contains('_')
}

/// The outcome of deriving a [`FingerprintDb`] from a manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Derived {
    /// The derived database (only mapped components appear).
    pub db: FingerprintDb,
    /// Manifest keys with no reviewed profile, in sorted order. These are
    /// surfaced so the profile table can be extended rather than silently
    /// dropping data or guessing an identity.
    pub underived: Vec<String>,
}

/// Derive fingerprint entries from one redistributable manifest.
///
/// For every manifest component that has a reviewed profile, this records the
/// component's SONAME stems and one `file_hashes` entry per published archive
/// (archive sha256 -> the manifest's exact version). Components without a
/// profile are collected into [`Derived::underived`].
#[must_use]
pub fn derive(manifest: &RedistManifest) -> Derived {
    let profiles = component_profiles();

    // Accumulate per canonical component so multiple manifest keys or repeated
    // derivations merge cleanly.
    let mut by_component: BTreeMap<&'static str, ComponentFingerprint> = BTreeMap::new();
    let mut underived: Vec<String> = Vec::new();

    for (key, component) in &manifest.components {
        let Some(profile) = profiles.iter().find(|p| p.manifest_key == key.as_str()) else {
            underived.push(key.clone());
            continue;
        };

        let entry = by_component
            .entry(profile.component)
            .or_insert_with(|| ComponentFingerprint {
                name: profile.component.to_string(),
                // First-party descriptive metadata straight from the manifest.
                description: Some(component.name.clone()),
                license: component.license.clone(),
                soname_stems: profile
                    .soname_stems
                    .iter()
                    .map(|s| (*s).to_string())
                    .collect(),
                file_hashes: BTreeMap::new(),
                build_ids: BTreeMap::new(),
                version_markers: Vec::new(),
                symbol_markers: Vec::new(),
                release_versions: BTreeMap::new(),
            });

        // One archive hash -> the exact component version. Stored as a set so
        // that if the same archive bytes recur under another version, both are
        // recorded rather than one overwriting the other.
        for archive in component.archives.values() {
            crate::matcher::insert_version(
                entry.file_hashes.entry(archive.sha256.clone()).or_default(),
                &component.version,
            );
        }

        // Record the first-party link from this component's exact version to
        // the CUDA toolkit release that shipped it (the manifest's
        // `release_label`). This is what lets toolkit-level advisories reach an
        // individually-scanned library later.
        if let Some(release) = &manifest.release_label {
            crate::matcher::insert_version(
                entry
                    .release_versions
                    .entry(component.version.clone())
                    .or_default(),
                release,
            );
        }
    }

    underived.sort();
    underived.dedup();

    let mut components: Vec<ComponentFingerprint> = by_component.into_values().collect();
    components.sort_by(|a, b| a.name.cmp(&b.name));

    Derived {
        db: FingerprintDb {
            schema_version: FingerprintDb::CURRENT_SCHEMA,
            release: Some(crate::db::ReleaseInfo {
                label: manifest.release_label.clone(),
                date: manifest.release_date.clone(),
            }),
            release_dates: BTreeMap::new(),
            provenance: None,
            components,
        },
        underived,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"{
        "release_label": "11.4.2",
        "cuda_cudart": {
            "name": "CUDA Runtime (cudart)",
            "version": "11.4.108",
            "linux-x86_64": {
                "relative_path": "cuda_cudart/linux-x86_64/cuda_cudart-linux-x86_64-11.4.108-archive.tar.xz",
                "sha256": "d08a1b731e5175aa3ae06a6d1c6b3059dd9ea13836d947018ea5e3ec2ca3d62b"
            },
            "linux-sbsa": {
                "relative_path": "cuda_cudart/linux-sbsa/cuda_cudart-linux-sbsa-11.4.108-archive.tar.xz",
                "sha256": "2ab9599bbaebdcf59add73d1f1a352ae619f8cb5ccec254093c98efd4c14553c"
            }
        },
        "cuda_nvcc": {
            "name": "CUDA NVCC",
            "version": "11.4.152",
            "linux-x86_64": {
                "relative_path": "cuda_nvcc/linux-x86_64/cuda_nvcc-linux-x86_64-11.4.152-archive.tar.xz",
                "sha256": "1111111111111111111111111111111111111111111111111111111111111111"
            }
        }
    }"#;

    #[test]
    fn derives_mapped_component_with_version_and_hashes() {
        let m = RedistManifest::from_json(SAMPLE.as_bytes()).unwrap();
        let d = derive(&m);

        // cudart is mapped; nvcc is not (no shared library -> reported underived).
        assert_eq!(d.db.components.len(), 1);
        let cudart = &d.db.components[0];
        assert_eq!(cudart.name, "cudart");
        assert_eq!(cudart.soname_stems, vec!["libcudart.so"]);

        // Both platform archives contribute a hash -> the exact version.
        assert_eq!(cudart.file_hashes.len(), 2);
        assert_eq!(
            cudart.file_hashes["d08a1b731e5175aa3ae06a6d1c6b3059dd9ea13836d947018ea5e3ec2ca3d62b"],
            vec!["11.4.108".to_string()]
        );
    }

    #[test]
    fn unmapped_component_is_reported_not_guessed() {
        let m = RedistManifest::from_json(SAMPLE.as_bytes()).unwrap();
        let d = derive(&m);
        assert_eq!(d.underived, vec!["cuda_nvcc"]);
        // No fabricated libnvcc.so stem anywhere.
        assert!(d
            .db
            .components
            .iter()
            .all(|c| !c.soname_stems.iter().any(|s| s.contains("nvcc"))));
    }

    #[test]
    fn derived_db_round_trips_through_json() {
        let m = RedistManifest::from_json(SAMPLE.as_bytes()).unwrap();
        let d = derive(&m);
        let json = serde_json::to_vec(&d.db).unwrap();
        let reloaded = FingerprintDb::from_json(&json).unwrap();
        assert_eq!(reloaded, d.db);
    }

    #[test]
    fn reviewed_profiles_resolve_to_expected_components() {
        // A representative sample of the reviewed table; guards against typos
        // in manifest keys or canonical names.
        let cases = [
            ("cuda_cudart", "cudart"),
            ("libcublas", "cublas"),
            ("libnvjitlink", "nvjitlink"),
            ("libcufile", "cufile"),
            ("libnvfatbin", "nvfatbin"),
            ("cuda_nvrtc", "nvrtc"),
            // Newly added real shared-library components (were being missed).
            ("cuda_cupti", "cupti"),
            ("libnvvm", "nvvm"),
            ("libcudla", "cudla"),
            ("libcuobjclient", "cuobjclient"),
        ];
        for (key, want) in cases {
            assert_eq!(resolve_component(key).as_deref(), Some(want), "key {key}");
        }
        // A key with no profile resolves to nothing (never guessed).
        assert_eq!(resolve_component("cuda_does_not_exist"), None);
    }

    #[test]
    fn soname_allowlist_is_grounded_in_the_profile_table() {
        // cudart owns exactly libcudart.so, not the libcuda.so stub or
        // libOpenCL.so that its archive happens to bundle.
        assert_eq!(soname_stems_for("cudart"), &["libcudart.so"]);
        assert!(soname_stems_for("cudart")
            .iter()
            .all(|s| *s != "libcuda.so" && *s != "libOpenCL.so"));
        // cupti owns its full set of profiling shared libraries.
        assert_eq!(
            soname_stems_for("cupti"),
            &[
                "libcupti.so",
                "libnvperf_host.so",
                "libnvperf_target.so",
                "libcheckpoint.so",
                "libpcsamplingutil.so",
            ]
        );
        // A no-shared-library tool has an empty allowlist.
        assert!(
            soname_stems_for("cuobjdump").is_empty(),
            "a tool with no shared libraries has an empty allowlist"
        );
        // An unknown component has an empty allowlist (never guessed).
        assert!(
            soname_stems_for("nope").is_empty(),
            "an unknown component has an empty allowlist (never guessed)"
        );
    }

    #[test]
    fn canonicalize_declared_name_handles_third_party_spellings() {
        // Canonical, manifest-key, dash, and cuda_/lib prefixes all resolve.
        assert_eq!(
            canonicalize_declared_name("cudart").as_deref(),
            Some("cudart")
        );
        assert_eq!(
            canonicalize_declared_name("cuda_cudart").as_deref(),
            Some("cudart")
        );
        assert_eq!(
            canonicalize_declared_name("cuda-cudart").as_deref(),
            Some("cudart")
        );
        assert_eq!(
            canonicalize_declared_name("libcublas").as_deref(),
            Some("cublas")
        );
        // Versioned package track suffix (Linux packaging) is trimmed.
        assert_eq!(
            canonicalize_declared_name("libcublas-12-4").as_deref(),
            Some("cublas")
        );
        // A versioned SONAME resolves via the soname stem.
        assert_eq!(
            canonicalize_declared_name("libcudart.so.12.4").as_deref(),
            Some("cudart")
        );
        // A purl resolves down to the name segment, version stripped.
        assert_eq!(
            canonicalize_declared_name("pkg:generic/cuda-cudart@12.4.127").as_deref(),
            Some("cudart")
        );
        // Non-CUDA declared components do not resolve.
        assert_eq!(canonicalize_declared_name("openssl"), None);
        assert_eq!(canonicalize_declared_name("pkg:pypi/numpy@1.26.0"), None);
    }

    #[test]
    fn canonicalize_resolves_pypi_wheel_names() {
        // Official NVIDIA wheels resolve to their CUDA component, including the
        // two whose stem differs from the component name.
        assert_eq!(
            canonicalize_declared_name("nvidia-cuda-runtime-cu12").as_deref(),
            Some("cudart")
        );
        assert_eq!(
            canonicalize_declared_name("nvidia-cuda-runtime-cu13").as_deref(),
            Some("cudart")
        );
        assert_eq!(
            canonicalize_declared_name("nvidia-cuda-nvrtc-cu12").as_deref(),
            Some("nvrtc")
        );
        assert_eq!(
            canonicalize_declared_name("nvidia-nccl-cu12").as_deref(),
            Some("nccl")
        );
        assert_eq!(
            canonicalize_declared_name("nvidia-cublas-cu13").as_deref(),
            Some("cublas")
        );
        assert_eq!(
            canonicalize_declared_name("cutensor-cu12").as_deref(),
            Some("cutensor")
        );
        // A purl spelling of a wheel also resolves.
        assert_eq!(
            canonicalize_declared_name("pkg:pypi/nvidia-cudnn-cu12@9.1.0").as_deref(),
            Some("cudnn")
        );
        // Third-party frameworks that merely bundle CUDA do not resolve to a
        // single component (detection-only).
        assert_eq!(canonicalize_declared_name("cupy-cuda12x"), None);
        assert_eq!(canonicalize_declared_name("torch"), None);
        assert_eq!(canonicalize_declared_name("jax-cuda12-plugin"), None);
    }

    #[test]
    fn cuda_track_token_detection() {
        assert!(is_cuda_track_token("cu12"));
        assert!(is_cuda_track_token("cu13"));
        assert!(is_cuda_track_token("cuda12x"));
        assert!(is_cuda_track_token("cuda11"));
        // Not tracks: bare words, missing digits, a real name segment.
        assert!(!is_cuda_track_token("runtime"));
        assert!(!is_cuda_track_token("cu"));
        assert!(!is_cuda_track_token("cuda"));
        assert!(!is_cuda_track_token("cublas"));
    }

    #[test]
    fn soname_stem_core_strips_lib_so_and_abi_version() {
        // Leading `lib` and trailing `.so`(+ABI) are stripped to the bare core.
        assert_eq!(soname_stem_core("libcal.so").as_deref(), Some("cal"));
        assert_eq!(soname_stem_core("libcal.so.12").as_deref(), Some("cal"));
        assert_eq!(
            soname_stem_core("libnvToolsExt.so.1").as_deref(),
            Some("nvToolsExt")
        );
        // Case is preserved for the core (identity is read, not normalized).
        assert_eq!(soname_stem_core("libOpenCL.so").as_deref(), Some("OpenCL"));
        // A versioned real SONAME still reduces to the stem-core.
        assert_eq!(
            soname_stem_core("libcudnn_graph.so.9").as_deref(),
            Some("cudnn_graph")
        );
        // Non-library names (no `.so`) are rejected: never fabricate identity.
        assert_eq!(soname_stem_core("cuobjdump"), None);
        assert_eq!(soname_stem_core("libnvptxcompiler_static.a"), None);
        // A degenerate `lib.so` has no core.
        assert_eq!(soname_stem_core("lib.so"), None);
    }

    #[test]
    fn auto_identity_reads_name_from_manifest_key() {
        // The component name comes from the normalized manifest key, not the
        // raw SONAME stem-core.
        assert_eq!(auto_identity("libcal.so", "libcal"), "cal");
        // libnvToolsExt.so under key `cuda_nvtx` -> `nvtx`, NOT `nvToolsExt`.
        assert_eq!(auto_identity("libnvToolsExt.so", "cuda_nvtx"), "nvtx");
        // libOpenCL.so under key `cuda_opencl` -> `opencl`, NOT `OpenCL`.
        assert_eq!(auto_identity("libOpenCL.so", "cuda_opencl"), "opencl");
        // Separators in the key fold to `_` after prefix stripping.
        assert_eq!(
            auto_identity("libfoo.so", "cuda_foo-bar baz"),
            "foo_bar_baz"
        );
    }

    #[test]
    fn component_owning_soname_folds_cudnn_sublibraries() {
        // cuDNN sub-libraries shipped under the cudnn_jit key are already owned
        // by the reviewed `cudnn` profile, so they fold into `cudnn`.
        assert_eq!(component_owning_soname("libcudnn_graph.so"), Some("cudnn"));
        assert_eq!(
            component_owning_soname("libcudnn_engines_runtime_compiled.so"),
            Some("cudnn")
        );
        // A versioned SONAME normalizes to the `.so` stem before matching.
        assert_eq!(
            component_owning_soname("libcudnn_graph.so.9"),
            Some("cudnn")
        );
        // A genuinely new library no profile owns returns None, so the caller
        // auto-derives it.
        assert_eq!(component_owning_soname("libcal.so"), None);
        assert_eq!(component_owning_soname("libnvToolsExt.so"), None);
    }

    #[test]
    fn license_is_excluded_matches_only_the_four_nvidia_tags() {
        // The four EXCLUDED driver/datacenter/IDE tags, case-insensitive +
        // trimmed.
        assert!(license_is_excluded(Some("NVIDIA Driver")));
        assert!(license_is_excluded(Some("NVIDIA Proprietary")));
        assert!(license_is_excluded(Some("NVIDIA SLA")));
        assert!(license_is_excluded(Some("NVIDIA")));
        assert!(license_is_excluded(Some("  nvidia sla  ")));
        assert!(license_is_excluded(Some("nvidia driver")));
        // CUDA-family / product licenses are allowed.
        assert!(!license_is_excluded(Some("CUDA Toolkit")));
        assert!(!license_is_excluded(Some("cuDNN")));
        assert!(!license_is_excluded(Some("libcal library")));
        assert!(!license_is_excluded(Some("cuTensor")));
        assert!(!license_is_excluded(Some("NVPL")));
        // Must be a full-string match, never a substring of "NVIDIA".
        assert!(!license_is_excluded(Some("NVIDIA cuTENSOR")));
        assert!(!license_is_excluded(Some("NVIDIA Math Library")));
        // Absent license falls through (not excluded).
        assert!(!license_is_excluded(None));
    }

    #[test]
    fn soname_belongs_to_key_credits_primary_and_drops_bundled_stubs() {
        // The archive's primary library (named like the key) is kept.
        assert!(soname_belongs_to_key("libcal.so", "libcal"));
        assert!(soname_belongs_to_key("libOpenCL.so", "cuda_opencl"));
        // cudnn_jit ships cudnn_* family libraries: credited to the cudnn root.
        assert!(soname_belongs_to_key("libcudnn_graph.so", "cudnn_jit"));
        assert!(soname_belongs_to_key(
            "libcudnn_engines_runtime_compiled.so",
            "cudnn_jit"
        ));
        // A bundled unrelated driver stub is NOT credited to an auto key.
        assert!(!soname_belongs_to_key("libcuda.so", "libcal"));
        assert!(!soname_belongs_to_key("libcuda.so", "cuda_opencl"));
        assert!(!soname_belongs_to_key("libOpenCL.so", "libcal"));
        // A near-miss first token (`cuda` vs `cudnn`) is rejected: a `libcuda.so`
        // stub bundled in a cudnn_jit archive must not be credited.
        assert!(!soname_belongs_to_key("libcuda.so", "cudnn_jit"));
        // Non-library stems never belong.
        assert!(!soname_belongs_to_key("cuobjdump", "cuda_cuobjdump"));
    }
}
