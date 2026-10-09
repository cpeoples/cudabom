//! Retry policy: attempt budget, exponential backoff with jitter, and the
//! decision of whether a given outcome is worth retrying.
//!
//! The math here is pure and deterministic given a jitter source, so it is unit
//! tested without any network or real sleeping. The policy is deliberately
//! conservative: a security tool must be persistent enough to ride out a flaky
//! mirror or a rate limit, but must never hammer a host or mask a real,
//! non-transient failure (a `404` is a bug or a bad URL, not something to retry).

use std::time::Duration;

/// How the client retries transient failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    /// Total attempts, including the first. `1` disables retrying.
    pub max_attempts: u32,
    /// Base delay for the first backoff step.
    pub base: Duration,
    /// Multiplier applied each step (exponential growth). Typically 2.
    pub factor: u32,
    /// Upper bound on any single backoff wait, before jitter.
    pub max_backoff: Duration,
    /// Apply full jitter (`random(0, computed)`), spreading retries so many
    /// clients do not wake simultaneously.
    pub jitter: bool,
}

impl Default for RetryPolicy {
    /// The conservative default: 5 attempts, 500ms base, doubling, capped at
    /// 30s per wait, full jitter.
    fn default() -> Self {
        Self {
            max_attempts: 5,
            base: Duration::from_millis(500),
            factor: 2,
            max_backoff: Duration::from_secs(30),
            jitter: true,
        }
    }
}

impl RetryPolicy {
    /// A policy that never retries (single attempt). Useful for `--no-retry`.
    #[must_use]
    pub fn none() -> Self {
        Self {
            max_attempts: 1,
            ..Self::default()
        }
    }

    /// True if another attempt is allowed after `attempts_made` have completed.
    #[must_use]
    pub fn may_retry(&self, attempts_made: u32) -> bool {
        attempts_made < self.max_attempts
    }

    /// The base (pre-jitter) backoff before the retry that follows
    /// `attempts_made` completed attempts. `attempts_made == 1` yields `base`,
    /// then `base*factor`, and so on, saturating at `max_backoff`.
    ///
    /// Returns [`Duration::ZERO`] if `attempts_made == 0` (no attempt has failed
    /// yet, so there is nothing to back off from).
    #[must_use]
    pub fn backoff(&self, attempts_made: u32) -> Duration {
        if attempts_made == 0 {
            return Duration::ZERO;
        }
        let exp = attempts_made - 1;
        // Compute base * factor^exp in millis with saturation, avoiding overflow.
        let base_ms = u64::try_from(self.base.as_millis()).unwrap_or(u64::MAX);
        let cap_ms = u64::try_from(self.max_backoff.as_millis()).unwrap_or(u64::MAX);
        let mut ms = base_ms;
        for _ in 0..exp {
            ms = ms.saturating_mul(u64::from(self.factor));
            if ms >= cap_ms {
                ms = cap_ms;
                break;
            }
        }
        Duration::from_millis(ms.min(cap_ms))
    }

    /// The actual wait for the retry after `attempts_made`, given a `jitter`
    /// fraction in `[0.0, 1.0)` (ignored when `self.jitter` is false) and an
    /// optional server-supplied `retry_after`.
    ///
    /// A `Retry-After` from the server always wins over the computed backoff
    /// (the server is telling us exactly how long to wait), but is still bounded
    /// by `max_backoff` so a hostile or mistaken header cannot stall the tool
    /// indefinitely.
    #[must_use]
    pub fn wait_for(
        &self,
        attempts_made: u32,
        jitter_fraction: f64,
        retry_after: Option<Duration>,
    ) -> Duration {
        if let Some(server) = retry_after {
            return server.min(self.max_backoff);
        }
        let computed = self.backoff(attempts_made);
        if !self.jitter {
            return computed;
        }
        // Full jitter: random point in [0, computed].
        let frac = jitter_fraction.clamp(0.0, 1.0);
        let computed_ms = u64::try_from(computed.as_millis()).unwrap_or(u64::MAX);
        #[allow(
            clippy::cast_precision_loss,
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss
        )]
        let jittered = (computed_ms as f64 * frac) as u64;
        Duration::from_millis(jittered)
    }
}

/// Classification of a single attempt's outcome for retry purposes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Attempt {
    /// The request succeeded; carries nothing (the caller holds the body).
    Success,
    /// A rate limit (HTTP 429). Optional server-directed wait.
    RateLimited { retry_after: Option<Duration> },
    /// A transient server error (HTTP 5xx). Optional server-directed wait.
    ServerError {
        status: u16,
        retry_after: Option<Duration>,
    },
    /// A transport/network error (connection reset, timeout, DNS, ...).
    Transport,
    /// A non-transient failure (e.g. 4xx other than 429). Never retried.
    Fatal { status: u16 },
}

impl Attempt {
    /// Whether this outcome is eligible for a retry (independent of the attempt
    /// budget, which [`RetryPolicy::may_retry`] enforces).
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Attempt::RateLimited { .. } | Attempt::ServerError { .. } | Attempt::Transport
        )
    }

    /// The server-directed wait carried by this outcome, if any.
    #[must_use]
    pub fn retry_after(&self) -> Option<Duration> {
        match self {
            Attempt::RateLimited { retry_after } | Attempt::ServerError { retry_after, .. } => {
                *retry_after
            }
            _ => None,
        }
    }
}

/// Classify an HTTP status code into an [`Attempt`] (without a body). `429` is a
/// rate limit, `5xx` is transient, other non-2xx are fatal.
#[must_use]
pub fn classify_status(status: u16, retry_after: Option<Duration>) -> Attempt {
    match status {
        200..=299 => Attempt::Success,
        429 => Attempt::RateLimited { retry_after },
        500..=599 => Attempt::ServerError {
            status,
            retry_after,
        },
        other => Attempt::Fatal { status: other },
    }
}

/// Parse an HTTP `Retry-After` header value: either delta-seconds
/// (e.g. `120`) or an HTTP-date. `now_epoch_secs` anchors the date form.
///
/// Returns `None` if the value is neither a valid integer nor a parseable date,
/// or if the date is in the past.
#[must_use]
pub fn parse_retry_after(value: &str, now_epoch_secs: u64) -> Option<Duration> {
    let trimmed = value.trim();
    if let Ok(secs) = trimmed.parse::<u64>() {
        return Some(Duration::from_secs(secs));
    }
    let when = parse_http_date_epoch(trimmed)?;
    when.checked_sub(now_epoch_secs).map(Duration::from_secs)
}

/// Parse an IMF-fixdate HTTP date (`Sun, 06 Nov 1994 08:49:37 GMT`) to epoch
/// seconds. Only this canonical form is supported (the one servers must send per
/// RFC 7231); the obsolete RFC 850 / asctime forms are rare and intentionally
/// not accepted rather than parsed loosely.
#[must_use]
fn parse_http_date_epoch(s: &str) -> Option<u64> {
    // Format: "Wdy, DD Mon YYYY HH:MM:SS GMT"
    let s = s.strip_suffix(" GMT")?;
    let (_weekday, rest) = s.split_once(", ")?;
    let mut it = rest.split(' ');
    let day: i64 = it.next()?.parse().ok()?;
    let month = month_number(it.next()?)?;
    let year: i64 = it.next()?.parse().ok()?;
    let time = it.next()?;
    if it.next().is_some() {
        return None;
    }
    let mut t = time.split(':');
    let hour: i64 = t.next()?.parse().ok()?;
    let min: i64 = t.next()?.parse().ok()?;
    let sec: i64 = t.next()?.parse().ok()?;
    if t.next().is_some() {
        return None;
    }

    let days = days_from_civil(year, month, day);
    let total = days * 86_400 + hour * 3_600 + min * 60 + sec;
    u64::try_from(total).ok()
}

fn month_number(m: &str) -> Option<i64> {
    Some(match m {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => return None,
    })
}

/// Days since the Unix epoch for a civil date (Howard Hinnant's algorithm).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_policy_is_conservative() {
        let p = RetryPolicy::default();
        assert_eq!(p.max_attempts, 5);
        assert_eq!(p.base, Duration::from_millis(500));
        assert_eq!(p.factor, 2);
        assert_eq!(p.max_backoff, Duration::from_secs(30));
        assert!(p.jitter);
    }

    #[test]
    fn none_policy_disables_retry() {
        let p = RetryPolicy::none();
        assert_eq!(p.max_attempts, 1);
        assert!(!p.may_retry(1));
        assert!(p.may_retry(0));
    }

    #[test]
    fn backoff_grows_exponentially_and_saturates() {
        let p = RetryPolicy {
            max_attempts: 10,
            base: Duration::from_millis(500),
            factor: 2,
            max_backoff: Duration::from_secs(30),
            jitter: false,
        };
        assert_eq!(p.backoff(0), Duration::ZERO);
        assert_eq!(p.backoff(1), Duration::from_millis(500));
        assert_eq!(p.backoff(2), Duration::from_secs(1));
        assert_eq!(p.backoff(3), Duration::from_secs(2));
        assert_eq!(p.backoff(4), Duration::from_secs(4));
        // Eventually caps at max_backoff.
        assert_eq!(p.backoff(20), Duration::from_secs(30));
    }

    #[test]
    fn wait_applies_full_jitter() {
        let p = RetryPolicy {
            jitter: true,
            ..RetryPolicy::default()
        };
        // attempts_made=2 -> computed 1000ms; jitter 0.5 -> 500ms.
        assert_eq!(p.wait_for(2, 0.5, None), Duration::from_millis(500));
        // jitter 0.0 -> 0; jitter ~1.0 -> ~computed.
        assert_eq!(p.wait_for(2, 0.0, None), Duration::ZERO);
    }

    #[test]
    fn server_retry_after_overrides_but_is_capped() {
        let p = RetryPolicy::default();
        // A modest server wait is honored verbatim.
        assert_eq!(
            p.wait_for(1, 0.5, Some(Duration::from_secs(5))),
            Duration::from_secs(5)
        );
        // An absurd server wait is capped at max_backoff.
        assert_eq!(
            p.wait_for(1, 0.5, Some(Duration::from_secs(9999))),
            Duration::from_secs(30)
        );
    }

    #[test]
    fn classify_maps_status_families() {
        assert_eq!(classify_status(200, None), Attempt::Success);
        assert!(matches!(
            classify_status(429, None),
            Attempt::RateLimited { .. }
        ));
        assert!(matches!(
            classify_status(503, None),
            Attempt::ServerError { status: 503, .. }
        ));
        assert!(matches!(
            classify_status(404, None),
            Attempt::Fatal { status: 404 }
        ));
    }

    #[test]
    fn retryable_classification() {
        assert!(Attempt::Transport.is_retryable());
        assert!(Attempt::RateLimited { retry_after: None }.is_retryable());
        assert!(Attempt::ServerError {
            status: 500,
            retry_after: None
        }
        .is_retryable());
        assert!(!Attempt::Fatal { status: 404 }.is_retryable());
        assert!(!Attempt::Success.is_retryable());
    }

    #[test]
    fn parse_retry_after_delta_seconds() {
        assert_eq!(parse_retry_after("120", 0), Some(Duration::from_secs(120)));
        assert_eq!(parse_retry_after("  30 ", 0), Some(Duration::from_secs(30)));
    }

    #[test]
    fn parse_retry_after_http_date() {
        // 1994-11-06 08:49:37 GMT == epoch 784111777.
        let epoch = 784_111_777;
        assert_eq!(
            parse_retry_after("Sun, 06 Nov 1994 08:49:37 GMT", epoch - 60),
            Some(Duration::from_secs(60))
        );
        // A past date yields None (nothing to wait).
        assert_eq!(
            parse_retry_after("Sun, 06 Nov 1994 08:49:37 GMT", epoch + 60),
            None
        );
    }

    #[test]
    fn parse_retry_after_rejects_garbage() {
        assert_eq!(parse_retry_after("soon", 0), None);
        assert_eq!(parse_retry_after("Sun, 06 Foo 1994 08:49:37 GMT", 0), None);
    }
}
