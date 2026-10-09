//! Dotted numeric version parsing and comparison for advisory matching.
//!
//! CUDA component versions are dotted numeric strings (`12`, `12.4`, `12.4.1`).
//! They are not full semver, so this is a small, purpose-built comparator:
//! components are compared left to right as integers, and a missing trailing
//! component is treated as zero (so `12.4` == `12.4.0` for ordering). This is
//! enough for the boundary logic advisory matching needs and is exhaustively
//! tested.

use std::cmp::Ordering;

/// A dotted numeric version, e.g. `12.4.1`.
///
/// Equality and ordering are consistent: trailing zero components are
/// insignificant, so `12.4` equals `12.4.0`.
#[derive(Debug, Clone)]
pub struct Version {
    parts: Vec<u64>,
}

impl Version {
    /// Parse a dotted numeric version. Returns `None` if any component is not a
    /// non-negative integer, or the string is empty.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        if s.is_empty() {
            return None;
        }
        let mut parts = Vec::new();
        for component in s.split('.') {
            let n: u64 = component.parse().ok()?;
            parts.push(n);
        }
        Some(Self { parts })
    }

    /// The major (first) component, or 0 if somehow empty.
    #[must_use]
    pub fn major(&self) -> u64 {
        self.parts.first().copied().unwrap_or(0)
    }
}

impl PartialEq for Version {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for Version {}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        // Compare component-wise; a missing component counts as zero, so
        // `12.4` and `12.4.0` are equal.
        let len = self.parts.len().max(other.parts.len());
        for i in 0..len {
            let a = self.parts.get(i).copied().unwrap_or(0);
            let b = other.parts.get(i).copied().unwrap_or(0);
            match a.cmp(&b) {
                Ordering::Equal => {}
                non_eq => return non_eq,
            }
        }
        Ordering::Equal
    }
}

/// An inclusive/exclusive version bound.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Bound {
    /// No bound on this side (unbounded).
    Unbounded,
    /// Inclusive bound (`>=` or `<=`).
    Inclusive(Version),
    /// Exclusive bound (`>` or `<`).
    Exclusive(Version),
}

/// A version range `[lower, upper]` with independent bound kinds. Used to model
/// an advisory's affected/fixed version constraints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionRange {
    pub lower: Bound,
    pub upper: Bound,
}

impl VersionRange {
    /// A range that matches any version.
    #[must_use]
    pub fn any() -> Self {
        Self {
            lower: Bound::Unbounded,
            upper: Bound::Unbounded,
        }
    }

    /// True if `v` falls within this range.
    #[must_use]
    pub fn contains(&self, v: &Version) -> bool {
        let lower_ok = match &self.lower {
            Bound::Unbounded => true,
            Bound::Inclusive(b) => v >= b,
            Bound::Exclusive(b) => v > b,
        };
        let upper_ok = match &self.upper {
            Bound::Unbounded => true,
            Bound::Inclusive(b) => v <= b,
            Bound::Exclusive(b) => v < b,
        };
        lower_ok && upper_ok
    }

    /// True if *every* version sharing the given major number is inside the
    /// range. Used for `LIKELY` findings whose version is only a major range
    /// like `12.x`: we can make a definitive claim only when the entire major
    /// series is on one side of the boundary.
    #[must_use]
    pub fn contains_entire_major(&self, major: u64) -> bool {
        // The major series spans [major.0.0, major.MAX...]. It is fully inside
        // the range iff the lower bound is at or below major.0 and the upper
        // bound is unbounded (any finite upper bound would exclude some patch
        // in the series).
        let lower_ok = match &self.lower {
            Bound::Unbounded => true,
            Bound::Inclusive(b) | Bound::Exclusive(b) => {
                b.major() < major || (b.major() == major && is_zero_after_major(b))
            }
        };
        let upper_unbounded = matches!(self.upper, Bound::Unbounded);
        lower_ok && upper_unbounded
    }

    /// True if *no* version sharing the given major number is inside the range
    /// (the whole series is outside). Used to make a definitive "not affected"
    /// claim for a `LIKELY` major-only version.
    #[must_use]
    pub fn excludes_entire_major(&self, major: u64) -> bool {
        // The entire major series is excluded iff the range's upper bound is
        // below major.0.0, or its lower bound is above the top of the series.
        let below = match &self.upper {
            Bound::Unbounded => false,
            Bound::Inclusive(b) => b.major() < major,
            Bound::Exclusive(b) => {
                b.major() < major || (b.major() == major && is_zero_after_major(b))
            }
        };
        let above = match &self.lower {
            Bound::Unbounded => false,
            Bound::Inclusive(b) | Bound::Exclusive(b) => b.major() > major,
        };
        below || above
    }
}

/// True if the version is exactly `major` with all later components zero
/// (i.e. it equals `major.0.0...`).
fn is_zero_after_major(v: &Version) -> bool {
    v.parts.iter().skip(1).all(|&p| p == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &str) -> Version {
        Version::parse(s).unwrap()
    }

    #[test]
    fn parses_and_rejects() {
        assert_eq!(v("12.4.1").parts, vec![12, 4, 1]);
        assert_eq!(v("12").parts, vec![12]);
        assert!(Version::parse("").is_none());
        assert!(Version::parse("12.x").is_none());
        assert!(Version::parse("1.2.beta").is_none());
    }

    #[test]
    fn orders_component_wise_with_zero_fill() {
        assert!(v("12.4") < v("12.4.1"));
        assert_eq!(v("12.4"), v("12.4.0"));
        assert!(v("12.10") > v("12.9"));
        assert!(v("13") > v("12.99.99"));
        assert!(v("12.4.1") > v("12.4"));
    }

    #[test]
    fn range_contains() {
        // [12.0, 12.4)
        let r = VersionRange {
            lower: Bound::Inclusive(v("12.0")),
            upper: Bound::Exclusive(v("12.4")),
        };
        assert!(r.contains(&v("12.0")));
        assert!(r.contains(&v("12.3.99")));
        assert!(!r.contains(&v("12.4")));
        assert!(!r.contains(&v("11.9")));
    }

    #[test]
    fn any_range_contains_everything() {
        let r = VersionRange::any();
        assert!(r.contains(&v("0")));
        assert!(r.contains(&v("999.999")));
    }

    #[test]
    fn entire_major_inside() {
        // >= 12.0 with no upper bound: the whole 12.x series is affected.
        let r = VersionRange {
            lower: Bound::Inclusive(v("12.0")),
            upper: Bound::Unbounded,
        };
        assert!(r.contains_entire_major(12));
        assert!(r.contains_entire_major(13));
        assert!(!r.contains_entire_major(11));
    }

    #[test]
    fn entire_major_excluded() {
        // < 12.0: the entire 12.x series is NOT affected; 11.x is affected.
        let r = VersionRange {
            lower: Bound::Unbounded,
            upper: Bound::Exclusive(v("12.0")),
        };
        assert!(r.excludes_entire_major(12));
        assert!(r.excludes_entire_major(13));
        assert!(!r.excludes_entire_major(11));
    }

    #[test]
    fn bounded_range_neither_fully_includes_nor_excludes_a_straddling_major() {
        // [12.2, 12.5): the 12.x series straddles the range: no definitive
        // whole-series claim either way.
        let r = VersionRange {
            lower: Bound::Inclusive(v("12.2")),
            upper: Bound::Exclusive(v("12.5")),
        };
        assert!(!r.contains_entire_major(12));
        assert!(!r.excludes_entire_major(12));
    }
}
