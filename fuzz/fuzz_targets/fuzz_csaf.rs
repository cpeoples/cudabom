#![no_main]
//! Fuzz CSAF advisory ingestion. `ingest` deserializes untrusted JSON (NVIDIA
//! CSAF documents) and must not panic on malformed input.
use cudabom_advisory::{ingest, ProductMap};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // An empty map still exercises the parse/ingest path.
    let map = ProductMap::default();
    let _ = ingest(&[data.to_vec()], &map, None);
});
