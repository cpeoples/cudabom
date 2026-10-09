#![no_main]
//! Fuzz the ELF fact extractor. `parse` must not panic on malformed input.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = cudabom_elf::parse(data);
    let _ = cudabom_elf::find_embedded_elf(data, 8);
});
