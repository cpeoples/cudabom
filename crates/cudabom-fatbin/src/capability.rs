//! GPU capability manifest: what SM (streaming multiprocessor) architectures an
//! artifact's GPU code targets.
//!
//! This aggregates the `sm_arch` observations already recovered from fatbin
//! entries, cubins, and PTX `.target` directives into one artifact-level view:
//! "this artifact contains device code for sm_70, sm_80, sm_90; PTX present for
//! forward-compatible JIT." It is a pure summary of facts; it introduces no
//! new parsing and makes no identity claims.

use serde::Serialize;

use crate::facts::{EntryKind, GpuCode};

/// The GPU capabilities an artifact targets, aggregated across all its GPU code.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct CapabilityManifest {
    /// All SM architectures targeted by compiled cubins, ascending and
    /// de-duplicated (e.g. `[70, 80, 90]` for sm_70/sm_80/sm_90).
    pub cubin_sm_targets: Vec<u32>,
    /// All SM architectures targeted by PTX `.target` directives, ascending and
    /// de-duplicated. PTX is forward-compatible via JIT, so these indicate the
    /// minimum architecture the code can be JIT-compiled for.
    pub ptx_sm_targets: Vec<u32>,
    /// True if any PTX is present (relevant for forward compatibility).
    pub has_ptx: bool,
    /// True if any compiled cubin is present.
    pub has_cubin: bool,
    /// Number of GPU code units (fatbin containers + standalone modules) that
    /// contributed to this manifest.
    pub gpu_code_units: usize,
}

impl CapabilityManifest {
    /// True if no GPU code contributed (the artifact has no device code).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.gpu_code_units == 0
    }

    /// The full set of SM architectures targeted by any code form.
    #[must_use]
    pub fn all_sm_targets(&self) -> Vec<u32> {
        let mut all: Vec<u32> = self
            .cubin_sm_targets
            .iter()
            .chain(&self.ptx_sm_targets)
            .copied()
            .collect();
        all.sort_unstable();
        all.dedup();
        all
    }
}

/// Accumulates GPU code facts into a [`CapabilityManifest`]. Feed every
/// [`GpuCode`] found in an artifact (standalone modules and the facts of every
/// embedded fatbin), then call [`Builder::build`].
#[derive(Debug, Default)]
pub struct Builder {
    cubin: std::collections::BTreeSet<u32>,
    ptx: std::collections::BTreeSet<u32>,
    has_ptx: bool,
    has_cubin: bool,
    units: usize,
}

impl Builder {
    /// Start an empty builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Fold one [`GpuCode`] unit (a standalone fatbin or PTX module) in.
    pub fn add_gpu_code(&mut self, code: &GpuCode) {
        self.units += 1;
        match code {
            GpuCode::Fatbin(facts) => self.add_fatbin(facts),
            GpuCode::Ptx(ptx) => {
                self.has_ptx = true;
                for t in &ptx.targets {
                    self.ptx.insert(*t);
                }
            }
        }
    }

    /// Fold one fatbin container's facts in (used for embedded fatbins, which
    /// are surfaced by facts rather than as a [`GpuCode`]).
    pub fn add_fatbin(&mut self, facts: &crate::facts::FatbinFacts) {
        for entry in &facts.entries {
            match entry.kind {
                EntryKind::Cubin => {
                    self.has_cubin = true;
                    if let Some(sm) = entry.sm_arch {
                        self.cubin.insert(sm);
                    }
                }
                EntryKind::Ptx => {
                    self.has_ptx = true;
                    if let Some(sm) = entry.sm_arch {
                        self.ptx.insert(sm);
                    }
                }
                EntryKind::Unknown(_) => {}
            }
        }
    }

    /// Fold one embedded fatbin container in, counting it as a unit.
    pub fn add_embedded_fatbin(&mut self, facts: &crate::facts::FatbinFacts) {
        self.units += 1;
        self.add_fatbin(facts);
    }

    /// Finish, producing the sorted, de-duplicated manifest.
    #[must_use]
    pub fn build(self) -> CapabilityManifest {
        CapabilityManifest {
            cubin_sm_targets: self.cubin.into_iter().collect(),
            ptx_sm_targets: self.ptx.into_iter().collect(),
            has_ptx: self.has_ptx,
            has_cubin: self.has_cubin,
            gpu_code_units: self.units,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::facts::{FatbinEntry, FatbinFacts, PtxFacts};

    fn cubin_entry(sm: u32) -> FatbinEntry {
        FatbinEntry {
            kind: EntryKind::Cubin,
            sm_arch: Some(sm),
            payload_offset: 0,
            payload_len: 0,
            compressed: false,
        }
    }

    fn ptx_entry(sm: u32) -> FatbinEntry {
        FatbinEntry {
            kind: EntryKind::Ptx,
            sm_arch: Some(sm),
            payload_offset: 0,
            payload_len: 0,
            compressed: false,
        }
    }

    #[test]
    fn empty_builder_is_empty() {
        let m = Builder::new().build();
        assert!(m.is_empty());
        assert!(
            m.all_sm_targets().is_empty(),
            "an empty module reports no SM targets"
        );
    }

    #[test]
    fn aggregates_and_dedups_sm_targets_across_units() {
        let mut b = Builder::new();
        b.add_gpu_code(&GpuCode::Fatbin(FatbinFacts {
            version: 1,
            payload_size: 0,
            entries: vec![cubin_entry(90), cubin_entry(80), ptx_entry(70)],
            truncated: false,
        }));
        b.add_gpu_code(&GpuCode::Ptx(PtxFacts {
            isa_version: Some("8.3".into()),
            targets: vec![80, 70], // overlaps cubin/ptx above
            address_size: Some(64),
        }));
        let m = b.build();

        assert_eq!(m.cubin_sm_targets, vec![80, 90]);
        assert_eq!(m.ptx_sm_targets, vec![70, 80]);
        assert!(m.has_ptx && m.has_cubin);
        assert_eq!(m.gpu_code_units, 2);
        assert_eq!(m.all_sm_targets(), vec![70, 80, 90]);
    }

    #[test]
    fn embedded_fatbins_count_as_units() {
        let mut b = Builder::new();
        b.add_embedded_fatbin(&FatbinFacts {
            version: 1,
            payload_size: 0,
            entries: vec![cubin_entry(75)],
            truncated: false,
        });
        let m = b.build();
        assert_eq!(m.gpu_code_units, 1);
        assert_eq!(m.cubin_sm_targets, vec![75]);
        assert!(m.has_cubin && !m.has_ptx);
    }
}
