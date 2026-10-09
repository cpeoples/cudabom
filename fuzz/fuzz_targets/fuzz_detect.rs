#![no_main]
//! Fuzz the archive/binary content classifier. `detect_kind` reads leading
//! bytes (and the tar ustar signature at offset 257) to classify a blob as
//! ELF/PE/zip/gzip/tar/ar and must not panic on arbitrary input.
use cudabom_extract::detect_kind;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = detect_kind(data);
});
