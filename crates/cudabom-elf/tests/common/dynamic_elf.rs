//! Shared test fixture: a hand-built, valid ELF64 little-endian `ET_DYN` shared
//! object carrying a `.dynamic` section with `DT_SONAME` and `DT_NEEDED`.
//!
//! The `object` crate's *writer* cannot synthesize a `.dynamic` section, so to
//! exercise SONAME/NEEDED parsing without a real linker (and thus on every host,
//! not just Linux) we assemble the bytes directly. Every offset is computed, so
//! the result is a real ELF that `object`'s *reader* parses normally.
//!
//! This is intentionally minimal: enough structure for the reader to locate the
//! section headers, the `.dynamic` array, and the `.dynstr` table it links to.
//! It is not a loadable library (no program headers/segments), which the
//! reader does not require to report dynamic-section facts.
//!
//! Included via `#[path]` in the tests that need it.

/// Build an ELF64 LE `ET_DYN` with the given SONAME and NEEDED entries.
///
/// Section layout in the file:
/// 1. ELF header (64 bytes)
/// 2. `.dynstr` string table (SONAME + NEEDED names, NUL-separated)
/// 3. `.dynamic` array of `Elf64_Dyn` (16 bytes each)
/// 4. `.shstrtab` section-name string table
/// 5. section header table (4 entries: NULL, .dynstr, .dynamic, .shstrtab)
#[allow(dead_code, clippy::too_many_lines)]
pub(crate) fn build_dynamic_elf(soname: &str, needed: &[&str]) -> Vec<u8> {
    // ELF constants.
    const ET_DYN: u16 = 3;
    const EM_X86_64: u16 = 62;
    const SHT_STRTAB: u32 = 3;
    const SHT_DYNAMIC: u32 = 6;
    const DT_NEEDED: i64 = 1;
    const DT_SONAME: i64 = 14;
    const DT_STRTAB: i64 = 5;
    const DT_STRSZ: i64 = 10;
    const DT_NULL: i64 = 0;

    // --- .dynstr: index 0 is an empty string; then each name NUL-terminated.
    let mut dynstr = vec![0u8];
    let str_offset = |s: &str, table: &mut Vec<u8>| -> u32 {
        let off = u32::try_from(table.len()).expect("string table offset fits u32");
        table.extend_from_slice(s.as_bytes());
        table.push(0);
        off
    };
    let soname_off = str_offset(soname, &mut dynstr);
    let needed_offs: Vec<u32> = needed.iter().map(|n| str_offset(n, &mut dynstr)).collect();

    // --- .dynamic: SONAME, each NEEDED, STRTAB, STRSZ, NULL terminator.
    // The STRTAB value is the *virtual address* of .dynstr; with no segments we
    // use its file offset, which the reader resolves against the section that
    // covers that address. To keep the reader's resolution simple, the elf
    // parser links .dynamic to .dynstr via sh_link, so DT_STRTAB's exact value
    // is not what the reader uses, but we set it consistently anyway.
    let mut dyn_entries: Vec<(i64, u64)> = Vec::new();
    dyn_entries.push((DT_SONAME, u64::from(soname_off)));
    for off in &needed_offs {
        dyn_entries.push((DT_NEEDED, u64::from(*off)));
    }
    // STRTAB/STRSZ are filled after we know the .dynstr file offset.
    let strtab_placeholder_idx = dyn_entries.len();
    dyn_entries.push((DT_STRTAB, 0)); // patched below
    dyn_entries.push((DT_STRSZ, dynstr.len() as u64));
    dyn_entries.push((DT_NULL, 0));

    // --- .shstrtab: names of the sections.
    let mut shstrtab = vec![0u8];
    let name_dynstr = str_offset(".dynstr", &mut shstrtab);
    let name_dynamic = str_offset(".dynamic", &mut shstrtab);
    let name_shstrtab = str_offset(".shstrtab", &mut shstrtab);

    // --- Compute file offsets.
    let eh_size: u64 = 64;
    let dynstr_off = eh_size;
    let dynstr_size = dynstr.len() as u64;

    let dynamic_off = dynstr_off + dynstr_size;
    let dynamic_size = (dyn_entries.len() * 16) as u64;

    let shstrtab_off = dynamic_off + dynamic_size;
    let shstrtab_size = shstrtab.len() as u64;

    let shoff = shstrtab_off + shstrtab_size; // section header table offset

    // Patch DT_STRTAB to the .dynstr file offset (used as its address here).
    dyn_entries[strtab_placeholder_idx].1 = dynstr_off;

    // --- Assemble.
    let mut out = Vec::new();

    // ELF header (Elf64_Ehdr), little-endian.
    out.extend_from_slice(&[0x7f, b'E', b'L', b'F']); // EI_MAG
    out.push(2); // EI_CLASS = ELFCLASS64
    out.push(1); // EI_DATA = ELFDATA2LSB
    out.push(1); // EI_VERSION
    out.push(0); // EI_OSABI
    out.extend_from_slice(&[0u8; 8]); // EI_ABIVERSION + padding
    out.extend_from_slice(&ET_DYN.to_le_bytes()); // e_type
    out.extend_from_slice(&EM_X86_64.to_le_bytes()); // e_machine
    out.extend_from_slice(&1u32.to_le_bytes()); // e_version
    out.extend_from_slice(&0u64.to_le_bytes()); // e_entry
    out.extend_from_slice(&0u64.to_le_bytes()); // e_phoff (no program headers)
    out.extend_from_slice(&shoff.to_le_bytes()); // e_shoff
    out.extend_from_slice(&0u32.to_le_bytes()); // e_flags
    out.extend_from_slice(&u16::try_from(eh_size).unwrap().to_le_bytes()); // e_ehsize
    out.extend_from_slice(&0u16.to_le_bytes()); // e_phentsize
    out.extend_from_slice(&0u16.to_le_bytes()); // e_phnum
    out.extend_from_slice(&64u16.to_le_bytes()); // e_shentsize (Elf64_Shdr)
    out.extend_from_slice(&4u16.to_le_bytes()); // e_shnum (NULL,.dynstr,.dynamic,.shstrtab)
    out.extend_from_slice(&3u16.to_le_bytes()); // e_shstrndx (.shstrtab is index 3)

    debug_assert_eq!(out.len() as u64, eh_size);

    // .dynstr
    out.extend_from_slice(&dynstr);
    // .dynamic
    for (tag, val) in &dyn_entries {
        out.extend_from_slice(&tag.to_le_bytes());
        out.extend_from_slice(&val.to_le_bytes());
    }
    // .shstrtab
    out.extend_from_slice(&shstrtab);

    // Section header table: 4 * Elf64_Shdr (64 bytes each).
    // Index 0: SHN_UNDEF (all zero).
    write_shdr(&mut out, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    // Index 1: .dynstr
    write_shdr(
        &mut out,
        name_dynstr,
        SHT_STRTAB,
        0,
        0,
        dynstr_off,
        dynstr_size,
        0,
        0,
        1,
        0,
    );
    // Index 2: .dynamic, sh_link -> .dynstr (section index 1), entsize 16.
    write_shdr(
        &mut out,
        name_dynamic,
        SHT_DYNAMIC,
        0,
        0,
        dynamic_off,
        dynamic_size,
        1, // sh_link = .dynstr
        0,
        8,
        16,
    );
    // Index 3: .shstrtab
    write_shdr(
        &mut out,
        name_shstrtab,
        SHT_STRTAB,
        0,
        0,
        shstrtab_off,
        shstrtab_size,
        0,
        0,
        1,
        0,
    );

    out
}

/// Append one `Elf64_Shdr` (64 bytes, little-endian).
#[allow(clippy::too_many_arguments, dead_code)]
fn write_shdr(
    out: &mut Vec<u8>,
    sh_name: u32,
    sh_type: u32,
    sh_flags: u64,
    sh_addr: u64,
    sh_offset: u64,
    sh_size: u64,
    sh_link: u32,
    sh_info: u32,
    sh_addralign: u64,
    sh_entsize: u64,
) {
    out.extend_from_slice(&sh_name.to_le_bytes());
    out.extend_from_slice(&sh_type.to_le_bytes());
    out.extend_from_slice(&sh_flags.to_le_bytes());
    out.extend_from_slice(&sh_addr.to_le_bytes());
    out.extend_from_slice(&sh_offset.to_le_bytes());
    out.extend_from_slice(&sh_size.to_le_bytes());
    out.extend_from_slice(&sh_link.to_le_bytes());
    out.extend_from_slice(&sh_info.to_le_bytes());
    out.extend_from_slice(&sh_addralign.to_le_bytes());
    out.extend_from_slice(&sh_entsize.to_le_bytes());
}
