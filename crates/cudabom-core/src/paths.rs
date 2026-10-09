//! The committed data-tree layout, defined once.
//!
//! The repository, the published data bundle (`cudabom update`), and the
//! per-user data directory a scan reads all share the **same** relative layout:
//!
//! ```text
//! <root>/
//!   fingerprints/                 # the fingerprint database (loaded recursively)
//!   fingerprints/cuda/            # the CUDA redistrib shard
//!   advisories/index.json         # the advisory index
//! ```
//!
//! These relative path fragments were previously re-spelled as string literals
//! across the CLI, the `xtask` tooling, and the data-bundle fetcher. Centralizing
//! them here makes the layout a single documented fact: the binary runtime, the
//! dev tooling, and the bundle producer agree by construction, not convention.
//!
//! Every value is a path *relative to a chosen root* (a repository checkout or a
//! resolved data directory). Callers join them onto their own root.

/// The fingerprint-database directory. `FingerprintDb::from_dir` loads this
/// recursively, picking up every per-product subdirectory (`cuda`, `cudnn`, ...).
pub const FINGERPRINTS_DIR: &str = "fingerprints";

/// The CUDA redistrib shard within [`FINGERPRINTS_DIR`]. Also the historical
/// single-product layout a scan falls back to for older data bundles.
pub const CUDA_SHARD_DIR: &str = "fingerprints/cuda";

/// The advisory index file, relative to the data root.
pub const ADVISORY_INDEX: &str = "advisories/index.json";
