//! Tunable safety limits for extraction and parsing.
//!
//! cudabom consumes attacker-controlled archives and binaries (see
//! `docs/threat-model.md`). Every bound that protects the scanner from a
//! decompression bomb, a deeply nested archive, or a runaway parser lives here
//! as a single, serde-deserializable struct so operators can tune the whole
//! safety envelope from one config file rather than hunting for constants.
//!
//! The [`Default`] impl encodes conservative, CI-friendly values. Load an
//! override from TOML/JSON via serde and merge it over the defaults.

use serde::{Deserialize, Serialize};

/// Bounds applied while walking, extracting, and parsing artifacts.
///
/// All fields are `pub` and individually documented so a config file can set
/// exactly the knobs it cares about. Unset fields fall back to [`Default`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Limits {
    /// Maximum archive nesting depth (a wheel inside a tarball inside an image
    /// layer is depth 3). Guards against nesting-based resource exhaustion.
    pub max_depth: u32,

    /// Maximum total bytes cudabom will decompress across a single scan.
    pub max_total_bytes: u64,

    /// Maximum bytes for any single extracted member. Caps individual
    /// zip-bomb entries before the aggregate limit trips.
    pub max_file_bytes: u64,

    /// Maximum allowed decompression ratio (uncompressed / compressed) for a
    /// single entry before it is treated as a bomb and rejected.
    pub max_decompression_ratio: u32,

    /// Maximum number of entries cudabom will process per archive.
    pub max_entries_per_archive: u64,

    /// Per-file parsing timeout, in milliseconds. A parser that exceeds this
    /// is abandoned with an error rather than allowed to hang the scan.
    pub per_file_timeout_ms: u64,
}

/// Default safety envelope: conservative enough for untrusted CI input, roomy
/// enough for real CUDA wheels and NGC layers. Tune via a config override.
pub const DEFAULT_MAX_DEPTH: u32 = 32;
pub const DEFAULT_MAX_TOTAL_BYTES: u64 = 8 * 1024 * 1024 * 1024; // 8 GiB
pub const DEFAULT_MAX_FILE_BYTES: u64 = 4 * 1024 * 1024 * 1024; // 4 GiB
pub const DEFAULT_MAX_DECOMPRESSION_RATIO: u32 = 200;
pub const DEFAULT_MAX_ENTRIES_PER_ARCHIVE: u64 = 100_000;
pub const DEFAULT_PER_FILE_TIMEOUT_MS: u64 = 30_000;

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_depth: DEFAULT_MAX_DEPTH,
            max_total_bytes: DEFAULT_MAX_TOTAL_BYTES,
            max_file_bytes: DEFAULT_MAX_FILE_BYTES,
            max_decompression_ratio: DEFAULT_MAX_DECOMPRESSION_RATIO,
            max_entries_per_archive: DEFAULT_MAX_ENTRIES_PER_ARCHIVE,
            per_file_timeout_ms: DEFAULT_PER_FILE_TIMEOUT_MS,
        }
    }
}

impl Limits {
    /// Start a fresh [`Budget`] that tracks consumption against these limits.
    #[must_use]
    pub fn budget(&self) -> Budget {
        Budget {
            limits: self.clone(),
            total_consumed: 0,
        }
    }

    /// Check that a single extracted member's uncompressed size is within the
    /// per-file cap and does not exceed the allowed decompression ratio versus
    /// its compressed size. `compressed` of 0 disables the ratio check (the
    /// input was not compressed).
    pub fn check_member(&self, uncompressed: u64, compressed: u64) -> crate::Result<()> {
        if uncompressed > self.max_file_bytes {
            return Err(crate::Error::LimitExceeded(format!(
                "member size {uncompressed} exceeds per-file cap {}",
                self.max_file_bytes
            )));
        }
        if compressed > 0 {
            let ratio = uncompressed / compressed.max(1);
            if ratio > u64::from(self.max_decompression_ratio) {
                return Err(crate::Error::LimitExceeded(format!(
                    "decompression ratio {ratio} exceeds cap {}",
                    self.max_decompression_ratio
                )));
            }
        }
        Ok(())
    }
}

/// A mutable accounting of resources consumed while extracting one target.
///
/// Held for the duration of a scan and threaded through nested extraction so
/// the *aggregate* byte budget and entry counts are enforced across the whole
/// tree, not just per archive. Cloning the [`Limits`] into the budget keeps the
/// thresholds immutable while the counters advance.
#[derive(Debug, Clone)]
pub struct Budget {
    limits: Limits,
    total_consumed: u64,
}

impl Budget {
    /// The limits this budget enforces.
    #[must_use]
    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    /// Total uncompressed bytes consumed so far.
    #[must_use]
    pub fn total_consumed(&self) -> u64 {
        self.total_consumed
    }

    /// Record `bytes` of newly produced (uncompressed) output, failing if it
    /// would push the running total past the aggregate cap.
    pub fn consume(&mut self, bytes: u64) -> crate::Result<()> {
        let next = self.total_consumed.saturating_add(bytes);
        if next > self.limits.max_total_bytes {
            return Err(crate::Error::LimitExceeded(format!(
                "total extracted bytes {next} exceeds cap {}",
                self.limits.max_total_bytes
            )));
        }
        self.total_consumed = next;
        Ok(())
    }

    /// Check that descending to `depth` is within the nesting cap.
    pub fn check_depth(&self, depth: u32) -> crate::Result<()> {
        if depth > self.limits.max_depth {
            return Err(crate::Error::LimitExceeded(format!(
                "nesting depth {depth} exceeds cap {}",
                self.limits.max_depth
            )));
        }
        Ok(())
    }

    /// Check that an archive's entry count is within the per-archive cap.
    pub fn check_entry_count(&self, entries: u64) -> crate::Result<()> {
        if entries > self.limits.max_entries_per_archive {
            return Err(crate::Error::LimitExceeded(format!(
                "archive entry count {entries} exceeds cap {}",
                self.limits.max_entries_per_archive
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_stable() {
        let limits = Limits::default();
        assert_eq!(limits.max_depth, DEFAULT_MAX_DEPTH);
        assert_eq!(limits.max_total_bytes, DEFAULT_MAX_TOTAL_BYTES);
    }

    #[test]
    fn partial_config_falls_back_to_defaults() {
        // Only one field set; the rest must come from Default.
        let limits: Limits = serde_json::from_str(r#"{ "max_depth": 4 }"#).unwrap();
        assert_eq!(limits.max_depth, 4);
        assert_eq!(limits.max_total_bytes, DEFAULT_MAX_TOTAL_BYTES);
    }

    #[test]
    fn unknown_fields_are_rejected() {
        // A typo'd knob should fail loudly rather than be silently ignored.
        let err = serde_json::from_str::<Limits>(r#"{ "max_dept": 4 }"#);
        assert!(err.is_err());
    }

    #[test]
    fn budget_enforces_aggregate_total() {
        let limits = Limits {
            max_total_bytes: 100,
            ..Limits::default()
        };
        let mut budget = limits.budget();
        assert!(budget.consume(60).is_ok());
        assert!(budget.consume(40).is_ok()); // exactly at the cap
        assert_eq!(budget.total_consumed(), 100);
        assert!(budget.consume(1).is_err()); // one over
    }

    #[test]
    fn budget_consume_saturates_without_overflow() {
        let limits = Limits {
            max_total_bytes: u64::MAX,
            ..Limits::default()
        };
        let mut budget = limits.budget();
        assert!(budget.consume(u64::MAX).is_ok());
        // A second huge add saturates rather than wrapping; still within MAX.
        assert!(budget.consume(u64::MAX).is_ok());
        assert_eq!(budget.total_consumed(), u64::MAX);
    }

    #[test]
    fn depth_and_entry_caps() {
        let limits = Limits {
            max_depth: 3,
            max_entries_per_archive: 10,
            ..Limits::default()
        };
        let budget = limits.budget();
        assert!(budget.check_depth(3).is_ok());
        assert!(budget.check_depth(4).is_err());
        assert!(budget.check_entry_count(10).is_ok());
        assert!(budget.check_entry_count(11).is_err());
    }

    #[test]
    fn member_size_and_ratio_checks() {
        let limits = Limits {
            max_file_bytes: 1000,
            max_decompression_ratio: 10,
            ..Limits::default()
        };
        // Within size and ratio.
        assert!(limits.check_member(500, 100).is_ok());
        // Over the per-file size cap.
        assert!(limits.check_member(2000, 2000).is_err());
        // Within size but a 100:1 ratio (bomb) exceeds the 10:1 cap.
        assert!(limits.check_member(1000, 10).is_err());
        // compressed == 0 means "not compressed"; ratio check is skipped.
        assert!(limits.check_member(1000, 0).is_ok());
    }
}
