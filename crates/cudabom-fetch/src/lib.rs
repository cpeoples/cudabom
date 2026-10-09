//! Verified HTTP download with retry, backoff, jitter, and rate-limit awareness.
//!
//! This is the single network layer in cudabom, shared by `db update` (advisory
//! ingestion) and the fingerprint corpus fetcher. Everything network-touching
//! that cudabom does flows through [`get`].
//!
//! Design for testability: the retry *loop* is written against three injected
//! seams: a [`Transport`] (does one HTTP GET), a [`Clock`] (sleeps and reads
//! time), and a jitter source, so the full retry/backoff behavior is unit
//! tested deterministically with fakes, never real sockets or real sleeps. The
//! production entry point [`get`] wires in the real ureq transport and a real
//! clock.

#![forbid(unsafe_code)]

mod retry;

pub use retry::{classify_status, parse_retry_after, Attempt, RetryPolicy};

use std::io::Read as _;
use std::time::Duration;

use sha2::{Digest, Sha256};

/// The default HTTP `User-Agent` cudabom sends. This is the single source of
/// truth for the client identifier; higher-level crates that build their own
/// [`GetOptions`] reference this constant rather than re-spelling the string.
pub const DEFAULT_USER_AGENT: &str = "cudabom";

/// Errors from a verified download.
#[derive(Debug)]
pub enum FetchError {
    /// All attempts were exhausted; carries the last outcome description.
    Exhausted { attempts: u32, last: String },
    /// A non-transient HTTP status (e.g. 404) that is never retried.
    Status(u16),
    /// The downloaded bytes did not match the expected sha256.
    Integrity { expected: String, actual: String },
    /// Reading the response body failed.
    Body(String),
}

impl std::fmt::Display for FetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Exhausted { attempts, last } => {
                write!(f, "download failed after {attempts} attempt(s): {last}")
            }
            Self::Status(s) => write!(f, "download failed with HTTP status {s}"),
            Self::Integrity { expected, actual } => write!(
                f,
                "integrity check failed: expected sha256 {expected}, got {actual}"
            ),
            Self::Body(m) => write!(f, "reading response body: {m}"),
        }
    }
}

impl std::error::Error for FetchError {}

/// The result of a single transport GET: either a successful body, or a
/// classified non-success outcome.
#[derive(Debug)]
pub enum TransportOutcome {
    /// 2xx with the response body bytes.
    Ok(Vec<u8>),
    /// A non-2xx status, pre-classified (the transport parses `Retry-After`).
    Status(Attempt),
    /// A transport/network error (connection, timeout, DNS).
    Transport(String),
}

/// One HTTP GET. Implementors do exactly one request with no retrying; the
/// retry loop lives in [`get_with`].
pub trait Transport {
    /// Perform a single GET of `url`, returning a classified outcome.
    fn get_once(&self, url: &str) -> TransportOutcome;
}

/// Time + sleep, injected so tests neither wait nor read the wall clock.
pub trait Clock {
    /// Sleep for `dur` (a no-op recorder in tests).
    fn sleep(&self, dur: Duration);
    /// Current Unix time in seconds (anchors `Retry-After` HTTP-date parsing).
    fn now_epoch_secs(&self) -> u64;
    /// A jitter fraction in `[0.0, 1.0)`. Real clock uses a PRNG; tests fix it.
    fn jitter_fraction(&self) -> f64;
}

/// Options for a verified download.
#[derive(Debug, Clone)]
pub struct GetOptions {
    /// Retry/backoff policy.
    pub retry: RetryPolicy,
    /// Expected sha256 (hex) of the body; verified when set.
    pub expected_sha256: Option<String>,
    /// `User-Agent` header value.
    pub user_agent: String,
    /// Extra request headers (name, value), e.g. `Authorization: Bearer <key>`
    /// for authenticated endpoints. Empty by default so unauthenticated,
    /// public fetches (the common case) send no credentials.
    pub headers: Vec<(String, String)>,
}

impl Default for GetOptions {
    fn default() -> Self {
        Self {
            retry: RetryPolicy::default(),
            expected_sha256: None,
            user_agent: DEFAULT_USER_AGENT.to_string(),
            headers: Vec::new(),
        }
    }
}

/// Download `url` with the real ureq transport and a real clock, applying
/// `options` (retry policy, integrity check).
///
/// # Errors
/// Returns [`FetchError`] on a non-transient status, exhausted retries, a body
/// read failure, or an integrity mismatch.
pub fn get(url: &str, options: &GetOptions) -> Result<Vec<u8>, FetchError> {
    let transport = UreqTransport {
        user_agent: options.user_agent.clone(),
        headers: options.headers.clone(),
    };
    let clock = SystemClock;
    get_with(url, options, &transport, &clock)
}

/// The transport- and clock-injected retry loop. This is the tested core of the
/// crate; [`get`] is the thin production wiring around it.
///
/// # Errors
/// See [`get`].
pub fn get_with(
    url: &str,
    options: &GetOptions,
    transport: &dyn Transport,
    clock: &dyn Clock,
) -> Result<Vec<u8>, FetchError> {
    let policy = options.retry;
    let mut attempts: u32 = 0;

    loop {
        attempts += 1;
        match transport.get_once(url) {
            TransportOutcome::Ok(body) => {
                if let Some(expected) = &options.expected_sha256 {
                    verify_sha256(&body, expected)?;
                }
                return Ok(body);
            }
            TransportOutcome::Status(attempt) => {
                if let Attempt::Fatal { status } = attempt {
                    return Err(FetchError::Status(status));
                }
                if !attempt.is_retryable() || !policy.may_retry(attempts) {
                    return Err(FetchError::Exhausted {
                        attempts,
                        last: describe(&attempt),
                    });
                }
                sleep_before_retry(&policy, attempts, attempt.retry_after(), clock);
            }
            TransportOutcome::Transport(msg) => {
                if !policy.may_retry(attempts) {
                    return Err(FetchError::Exhausted {
                        attempts,
                        last: format!("transport error: {msg}"),
                    });
                }
                sleep_before_retry(&policy, attempts, None, clock);
            }
        }
    }
}

fn sleep_before_retry(
    policy: &RetryPolicy,
    attempts_made: u32,
    retry_after: Option<Duration>,
    clock: &dyn Clock,
) {
    let wait = policy.wait_for(attempts_made, clock.jitter_fraction(), retry_after);
    if wait > Duration::ZERO {
        clock.sleep(wait);
    }
}

fn describe(attempt: &Attempt) -> String {
    match attempt {
        Attempt::RateLimited { .. } => "rate limited (HTTP 429)".to_string(),
        Attempt::ServerError { status, .. } => format!("server error (HTTP {status})"),
        Attempt::Transport => "transport error".to_string(),
        Attempt::Fatal { status } => format!("fatal status {status}"),
        Attempt::Success => "success".to_string(),
    }
}

/// Verify the sha256 (hex) of `bytes` against `expected` (case-insensitive).
///
/// # Errors
/// Returns [`FetchError::Integrity`] if the digests differ.
pub fn verify_sha256(bytes: &[u8], expected: &str) -> Result<(), FetchError> {
    let actual = hex_sha256(bytes);
    if actual.eq_ignore_ascii_case(expected.trim()) {
        Ok(())
    } else {
        Err(FetchError::Integrity {
            expected: expected.trim().to_lowercase(),
            actual,
        })
    }
}

/// Lowercase hex sha256 of `bytes`.
///
/// Deliberately standalone (not `cudabom_core::hex_lower`) to keep this base
/// network crate dependency-light.
#[must_use]
pub fn hex_sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(digest.len() * 2);
    for b in digest {
        use std::fmt::Write as _;
        let _ = write!(out, "{b:02x}");
    }
    out
}

// --- Production transport + clock --------------------------------------------

struct UreqTransport {
    user_agent: String,
    headers: Vec<(String, String)>,
}

impl Transport for UreqTransport {
    fn get_once(&self, url: &str) -> TransportOutcome {
        // ureq 3.x returns non-2xx as `Err(Error::StatusCode)` by default;
        // disable that so we receive the response and can read `Retry-After`
        // before classifying the status ourselves.
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .build()
            .into();

        let mut request = agent.get(url).header("User-Agent", &self.user_agent);
        for (name, value) in &self.headers {
            request = request.header(name, value);
        }

        match request.call() {
            Ok(mut response) => {
                let status = response.status().as_u16();
                if (200..300).contains(&status) {
                    let mut body = Vec::new();
                    match response
                        .body_mut()
                        .as_reader()
                        .take(u64::from(u32::MAX))
                        .read_to_end(&mut body)
                    {
                        Ok(_) => TransportOutcome::Ok(body),
                        Err(e) => TransportOutcome::Transport(e.to_string()),
                    }
                } else {
                    let now = SystemClock.now_epoch_secs();
                    let retry_after = response
                        .headers()
                        .get("Retry-After")
                        .and_then(|v| v.to_str().ok())
                        .and_then(|v| parse_retry_after(v, now));
                    TransportOutcome::Status(classify_status(status, retry_after))
                }
            }
            Err(e) => TransportOutcome::Transport(e.to_string()),
        }
    }
}

struct SystemClock;

impl Clock for SystemClock {
    fn sleep(&self, dur: Duration) {
        std::thread::sleep(dur);
    }

    fn now_epoch_secs(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
    }

    fn jitter_fraction(&self) -> f64 {
        // A small, dependency-free PRNG seeded from the clock. Jitter quality
        // only needs to spread retries, not be cryptographic.
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.subsec_nanos());
        f64::from(nanos % 1_000_000) / 1_000_000.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    /// A transport that returns a scripted sequence of outcomes.
    struct ScriptedTransport {
        script: RefCell<Vec<TransportOutcome>>,
        calls: RefCell<u32>,
    }

    impl ScriptedTransport {
        fn new(outcomes: Vec<TransportOutcome>) -> Self {
            Self {
                script: RefCell::new(outcomes),
                calls: RefCell::new(0),
            }
        }
    }

    impl Transport for ScriptedTransport {
        fn get_once(&self, _url: &str) -> TransportOutcome {
            *self.calls.borrow_mut() += 1;
            let mut s = self.script.borrow_mut();
            if s.is_empty() {
                TransportOutcome::Transport("script exhausted".into())
            } else {
                s.remove(0)
            }
        }
    }

    /// A clock that records sleeps and never actually waits.
    struct FakeClock {
        slept: RefCell<Vec<Duration>>,
        jitter: f64,
    }

    impl FakeClock {
        fn new(jitter: f64) -> Self {
            Self {
                slept: RefCell::new(Vec::new()),
                jitter,
            }
        }
        fn total_sleep(&self) -> Duration {
            self.slept.borrow().iter().sum()
        }
        fn sleeps(&self) -> usize {
            self.slept.borrow().len()
        }
    }

    impl Clock for FakeClock {
        fn sleep(&self, dur: Duration) {
            self.slept.borrow_mut().push(dur);
        }
        fn now_epoch_secs(&self) -> u64 {
            0
        }
        fn jitter_fraction(&self) -> f64 {
            self.jitter
        }
    }

    fn opts(retry: RetryPolicy, expected: Option<&str>) -> GetOptions {
        GetOptions {
            retry,
            expected_sha256: expected.map(ToString::to_string),
            user_agent: "cudabom-test".into(),
            headers: Vec::new(),
        }
    }

    #[test]
    fn succeeds_on_first_attempt_without_sleeping() {
        let t = ScriptedTransport::new(vec![TransportOutcome::Ok(b"hello".to_vec())]);
        let clock = FakeClock::new(0.5);
        let out = get_with("http://x", &opts(RetryPolicy::default(), None), &t, &clock).unwrap();
        assert_eq!(out, b"hello");
        assert_eq!(clock.sleeps(), 0);
        assert_eq!(*t.calls.borrow(), 1);
    }

    #[test]
    fn retries_on_server_error_then_succeeds() {
        let t = ScriptedTransport::new(vec![
            TransportOutcome::Status(Attempt::ServerError {
                status: 503,
                retry_after: None,
            }),
            TransportOutcome::Status(Attempt::Transport),
            TransportOutcome::Ok(b"ok".to_vec()),
        ]);
        let clock = FakeClock::new(1.0); // full computed backoff
        let out = get_with("http://x", &opts(RetryPolicy::default(), None), &t, &clock).unwrap();
        assert_eq!(out, b"ok");
        assert_eq!(*t.calls.borrow(), 3);
        assert_eq!(clock.sleeps(), 2); // one wait before each retry
    }

    #[test]
    fn never_retries_a_fatal_status() {
        let t = ScriptedTransport::new(vec![TransportOutcome::Status(Attempt::Fatal {
            status: 404,
        })]);
        let clock = FakeClock::new(0.5);
        let err =
            get_with("http://x", &opts(RetryPolicy::default(), None), &t, &clock).unwrap_err();
        assert!(matches!(err, FetchError::Status(404)));
        assert_eq!(*t.calls.borrow(), 1);
        assert_eq!(clock.sleeps(), 0);
    }

    #[test]
    fn exhausts_attempts_and_reports_last_outcome() {
        let policy = RetryPolicy {
            max_attempts: 3,
            ..RetryPolicy::default()
        };
        let t = ScriptedTransport::new(vec![
            TransportOutcome::Transport("reset".into()),
            TransportOutcome::Transport("reset".into()),
            TransportOutcome::Transport("reset".into()),
        ]);
        let clock = FakeClock::new(0.5);
        let err = get_with("http://x", &opts(policy, None), &t, &clock).unwrap_err();
        match err {
            FetchError::Exhausted { attempts, .. } => assert_eq!(attempts, 3),
            other => panic!("expected Exhausted, got {other}"),
        }
        assert_eq!(*t.calls.borrow(), 3);
        assert_eq!(clock.sleeps(), 2); // sleeps between the 3 attempts
    }

    #[test]
    fn honors_server_retry_after_over_backoff() {
        let t = ScriptedTransport::new(vec![
            TransportOutcome::Status(Attempt::RateLimited {
                retry_after: Some(Duration::from_secs(3)),
            }),
            TransportOutcome::Ok(b"ok".to_vec()),
        ]);
        let clock = FakeClock::new(0.0); // would otherwise sleep 0 with jitter 0
        get_with("http://x", &opts(RetryPolicy::default(), None), &t, &clock).unwrap();
        // The single sleep equals the server-directed 3s, not the jittered 0.
        assert_eq!(clock.total_sleep(), Duration::from_secs(3));
    }

    #[test]
    fn no_retry_policy_makes_a_single_attempt() {
        let t = ScriptedTransport::new(vec![TransportOutcome::Status(Attempt::ServerError {
            status: 500,
            retry_after: None,
        })]);
        let clock = FakeClock::new(0.5);
        let err = get_with("http://x", &opts(RetryPolicy::none(), None), &t, &clock).unwrap_err();
        assert!(matches!(err, FetchError::Exhausted { attempts: 1, .. }));
        assert_eq!(clock.sleeps(), 0);
    }

    #[test]
    fn verifies_sha256_of_body() {
        let body = b"hello".to_vec();
        let good = hex_sha256(&body);
        let t = ScriptedTransport::new(vec![TransportOutcome::Ok(body.clone())]);
        let clock = FakeClock::new(0.5);
        assert!(get_with(
            "http://x",
            &opts(RetryPolicy::default(), Some(&good)),
            &t,
            &clock
        )
        .is_ok());

        let t2 = ScriptedTransport::new(vec![TransportOutcome::Ok(body)]);
        let err = get_with(
            "http://x",
            &opts(RetryPolicy::default(), Some("00")),
            &t2,
            &clock,
        )
        .unwrap_err();
        assert!(matches!(err, FetchError::Integrity { .. }));
    }
}
