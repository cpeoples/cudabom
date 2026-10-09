//! The policy file schema.
//!
//! A policy is a small, reviewable JSON document that turns a scan result into a
//! pass/fail decision for `cudabom gate`. The design goal is that the *default*
//! is a sensible security posture and every relaxation is explicit and
//! justified.
//!
//! Example:
//!
//! ```json
//! {
//!   "schema_version": 1,
//!   "fail_on": {
//!     "advisory_verdicts": ["affected"],
//!     "min_confidence": null,
//!     "under_investigation": false
//!   },
//!   "allow": [
//!     { "advisory": "CVE-2025-0001", "reason": "not reachable in our build; tracked in TICKET-42" }
//!   ]
//! }
//! ```

use serde::{Deserialize, Serialize};

use crate::input::Verdict;

/// A parsed policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// Schema version of this policy file.
    pub schema_version: u32,
    /// The conditions that cause the gate to fail.
    #[serde(default)]
    pub fail_on: FailOn,
    /// Explicit, justified exemptions.
    #[serde(default)]
    pub allow: Vec<Allow>,
}

/// The conditions under which the gate fails.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FailOn {
    /// Advisory verdicts that fail the gate. Defaults to `["affected"]`.
    pub advisory_verdicts: Vec<PolicyVerdict>,
    /// Fail when any finding is identified at or above this confidence. `None`
    /// (the default) means identification alone never fails the gate; only
    /// advisory verdicts do.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_confidence: Option<PolicyConfidence>,
    /// Fail when an advisory verdict is `under_investigation`. Defaults to
    /// `false`: an unresolved verdict warns but does not block, so a partial
    /// advisory index does not wedge a pipeline.
    pub under_investigation: bool,
}

impl Default for FailOn {
    fn default() -> Self {
        // Secure-by-default: an `affected` advisory verdict fails the gate;
        // identification alone and unresolved verdicts do not.
        Self {
            advisory_verdicts: vec![PolicyVerdict::Affected],
            min_confidence: None,
            under_investigation: false,
        }
    }
}

/// An explicit exemption. A reason is required so allowlists stay auditable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Allow {
    /// Exempt a specific advisory id (matches advisory-verdict failures).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub advisory: Option<String>,
    /// Exempt a specific component name (matches confidence failures and
    /// advisory failures for that component).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub component: Option<String>,
    /// Why this exemption exists. Required and non-empty.
    pub reason: String,
}

/// Verdict tokens usable in a policy file. Kept separate from
/// [`crate::input::Verdict`] so the policy schema owns its own (de)serialization
/// without coupling the neutral input type to serde.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyVerdict {
    Affected,
    NotAffected,
    UnderInvestigation,
}

impl PolicyVerdict {
    /// True if this policy token matches a runtime verdict.
    #[must_use]
    pub fn matches(self, v: Verdict) -> bool {
        matches!(
            (self, v),
            (Self::Affected, Verdict::Affected)
                | (Self::NotAffected, Verdict::NotAffected)
                | (Self::UnderInvestigation, Verdict::UnderInvestigation)
        )
    }
}

/// Confidence tokens usable in a policy file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicyConfidence {
    Unknown,
    Likely,
    Exact,
}

impl PolicyConfidence {
    /// The corresponding core confidence, for threshold comparison.
    #[must_use]
    pub fn to_core(self) -> cudabom_core::Confidence {
        use cudabom_core::Confidence;
        match self {
            Self::Unknown => Confidence::Unknown,
            Self::Likely => Confidence::Likely,
            Self::Exact => Confidence::Exact,
        }
    }
}

impl Policy {
    /// The current policy schema version this build understands.
    pub const CURRENT_SCHEMA: u32 = 1;

    /// The built-in default policy, used when `cudabom gate` is run without a
    /// `--policy` file: fail on any `affected` advisory verdict.
    #[must_use]
    pub fn secure_default() -> Self {
        Self {
            schema_version: Self::CURRENT_SCHEMA,
            fail_on: FailOn::default(),
            allow: Vec::new(),
        }
    }

    /// Load a policy from JSON bytes, validating the schema version and the
    /// allowlist entries.
    ///
    /// # Errors
    /// Returns an error if the JSON is malformed, the schema is newer than this
    /// build understands, or an allow entry is empty or lacks a reason.
    pub fn from_json(bytes: &[u8]) -> Result<Self, PolicyError> {
        let policy: Policy =
            serde_json::from_slice(bytes).map_err(|e| PolicyError::Parse(e.to_string()))?;
        if policy.schema_version > Self::CURRENT_SCHEMA {
            return Err(PolicyError::UnsupportedSchema {
                found: policy.schema_version,
                supported: Self::CURRENT_SCHEMA,
            });
        }
        for (i, allow) in policy.allow.iter().enumerate() {
            if allow.reason.trim().is_empty() {
                return Err(PolicyError::AllowWithoutReason(i));
            }
            if allow.advisory.is_none() && allow.component.is_none() {
                return Err(PolicyError::AllowMatchesNothing(i));
            }
        }
        Ok(policy)
    }
}

/// Errors from loading a policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyError {
    Parse(String),
    UnsupportedSchema {
        found: u32,
        supported: u32,
    },
    /// An allow entry (by index) has an empty reason.
    AllowWithoutReason(usize),
    /// An allow entry (by index) specifies neither advisory nor component.
    AllowMatchesNothing(usize),
}

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Parse(msg) => write!(f, "policy parse error: {msg}"),
            Self::UnsupportedSchema { found, supported } => write!(
                f,
                "policy schema {found} is newer than supported {supported}"
            ),
            Self::AllowWithoutReason(i) => {
                write!(f, "allow entry {i} must have a non-empty reason")
            }
            Self::AllowMatchesNothing(i) => write!(
                f,
                "allow entry {i} must specify an advisory and/or a component"
            ),
        }
    }
}

impl std::error::Error for PolicyError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secure_default_fails_on_affected_only() {
        let p = Policy::secure_default();
        assert_eq!(p.fail_on.advisory_verdicts, vec![PolicyVerdict::Affected]);
        assert!(p.fail_on.min_confidence.is_none());
        assert!(!p.fail_on.under_investigation);
    }

    #[test]
    fn parses_a_full_policy() {
        let json = r#"{
            "schema_version": 1,
            "fail_on": {
                "advisory_verdicts": ["affected", "under_investigation"],
                "min_confidence": "exact",
                "under_investigation": true
            },
            "allow": [
                { "advisory": "CVE-2025-0001", "reason": "mitigated in prod" }
            ]
        }"#;
        let p = Policy::from_json(json.as_bytes()).unwrap();
        assert_eq!(p.fail_on.min_confidence, Some(PolicyConfidence::Exact));
        assert_eq!(p.allow.len(), 1);
        assert_eq!(p.allow[0].advisory.as_deref(), Some("CVE-2025-0001"));
    }

    #[test]
    fn empty_object_uses_defaults_via_missing_fields() {
        // Only schema_version is required; fail_on defaults apply.
        let json = r#"{ "schema_version": 1 }"#;
        let p = Policy::from_json(json.as_bytes()).unwrap();
        assert_eq!(p.fail_on, FailOn::default());
        assert!(p.allow.is_empty(), "a policy without an allowlist has none");
    }

    #[test]
    fn rejects_future_schema() {
        let json = r#"{ "schema_version": 99 }"#;
        assert!(matches!(
            Policy::from_json(json.as_bytes()),
            Err(PolicyError::UnsupportedSchema { .. })
        ));
    }

    #[test]
    fn rejects_allow_without_reason() {
        let json =
            r#"{ "schema_version": 1, "allow": [ { "advisory": "CVE-1", "reason": "  " } ] }"#;
        assert!(matches!(
            Policy::from_json(json.as_bytes()),
            Err(PolicyError::AllowWithoutReason(0))
        ));
    }

    #[test]
    fn rejects_allow_matching_nothing() {
        let json = r#"{ "schema_version": 1, "allow": [ { "reason": "no target" } ] }"#;
        assert!(matches!(
            Policy::from_json(json.as_bytes()),
            Err(PolicyError::AllowMatchesNothing(0))
        ));
    }

    #[test]
    fn rejects_unknown_fields() {
        let json = r#"{ "schema_version": 1, "surprise": true }"#;
        assert!(matches!(
            Policy::from_json(json.as_bytes()),
            Err(PolicyError::Parse(_))
        ));
    }
}
