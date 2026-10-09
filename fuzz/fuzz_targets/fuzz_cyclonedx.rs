#![no_main]
//! Fuzz CycloneDX SBOM/VEX ingestion. `DeclaredBom::from_json` deserializes an
//! untrusted SBOM and must not panic on malformed input.
use cudabom_sbom::DeclaredBom;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = DeclaredBom::from_json(data);
});
