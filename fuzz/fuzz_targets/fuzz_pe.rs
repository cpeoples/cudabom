#![no_main]
//! Fuzz the PE fact extractor. `parse` must not panic on malformed input.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = cudabom_pe::parse(data);
});
