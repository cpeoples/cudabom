//! Shared text primitives for CSAF-derived advisory rendering.
//!
//! Both the Markdown renderer here and the CLI's terminal table clean the same
//! CSAF note text and rank the same severity labels, so the logic lives once.

/// Remove simple HTML tags (e.g. `<br/>`, `<p>`) that occasionally appear in
/// CSAF note text, replacing each tag with a space so words do not run
/// together.
#[must_use]
pub fn strip_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_tag = false;
    for c in s.chars() {
        match c {
            '<' => in_tag = true,
            '>' => {
                in_tag = false;
                out.push(' ');
            }
            _ if !in_tag => out.push(c),
            _ => {}
        }
    }
    out
}

/// Collapse a CSAF note to a single clean line: HTML tags stripped and all
/// runs of whitespace (including newlines) reduced to single spaces, so it fits
/// one table cell or terminal row without wrapping into a paragraph.
#[must_use]
pub fn clean_note(s: &str) -> String {
    strip_html(s)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// Map a free-text severity to a sort rank (higher = worse). Unknown or
/// unrated severities rank lowest so they never masquerade as the headline.
#[must_use]
pub fn severity_rank(severity: Option<&str>) -> u8 {
    match severity.map(str::to_ascii_lowercase).as_deref() {
        Some("critical") => 4,
        Some("high") => 3,
        Some("medium") => 2,
        Some("low") => 1,
        _ => 0,
    }
}
