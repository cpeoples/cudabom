#![no_main]
//! Fuzz the fatbin / cubin / PTX inspection path. Must not panic on a
//! malformed container or header.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = cudabom_fatbin::inspect(data);
    let _ = cudabom_fatbin::parse_ptx(data);
    let _ = cudabom_fatbin::looks_like_ptx(data);
    let _ = cudabom_fatbin::has_fatbin_magic(data);
    let _ = cudabom_fatbin::find_embedded_fatbins(data, 8);
});
