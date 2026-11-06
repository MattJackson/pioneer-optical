//! Exact resident COMP inflater graph, before execution certification.
//!
//! This is a binding/retargeting stage, NOT authorization to reclaim compressed
//! bytes. Its caller must prove all native stream executions, status, input
//! bounds, register ABI and scratch effects after placing OEM arithmetic.
//! No semantics of unavailable mask-ROM arithmetic are assumed.
//! Captured native graph: decoded Normal SHA256
//! fc13ef323a6d9b92cb79db617d4ba3e8def15b9ed4c6a8f2196141d2925d38be.
//! Whole-image identity is not used by recognition.
/// Bounded execution certificate for the actual emitted COMP streams.
pub mod execution;
use alloc::vec::Vec;
use core::ops::Range;
use h8_asm::{
    isa::{decode_insn, encode_insn, Ea, Operand},
    Mode, Target,
};

const BASE: usize = 0x410000;
const PROGRAMS: &[(usize, &[u8])] = &[
    (
        0x57ae64,
        include_bytes!("native_comp/wrapper_and_inflate.bin"),
    ),
    (0x57ccd0, include_bytes!("native_comp/fast_and_tables.bin")),
    (0x57deae, include_bytes!("native_comp/shifts.bin")),
];
const COMBINE: &[u8] = include_bytes!("native_comp/adler_combine.bin");
const DATA: &[u8] = include_bytes!("native_comp/constants.bin");
const LOADER: &[u8] = include_bytes!("native_comp/loader.bin");

/// Role indexes are multiply, signed division, unsigned division.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Call {
    /// Normal file offset of the complete four-byte JSR.
    pub offset: usize,
    /// Index into the arithmetic entry array.
    pub role: usize,
}
/// Native locations, all CPU addresses unless explicitly documented otherwise.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Binding {
    /// uncompress ABI: ER0 output, ER1 produced-length pointer, ER2 input;
    /// caller stack contains input length then output capacity, both u32.
    pub entry: u32,
    /// Complete Normal file ranges, excluding unused adler32_combine.
    pub programs: Vec<Range<usize>>,
    /// Unchanged adjacent complete routine used only for instruction boundaries.
    pub boundary_program: Range<usize>,
    /// Read-only version, switch, fixed Huffman and base/extra tables.
    pub data: Range<usize>,
    /// Full COMP loader (unchanged by arithmetic retargeting).
    pub loader: Range<usize>,
    /// Native fixed inflater state. This is existing RAM, not an allocation.
    pub state: Range<u32>,
    /// Native existing sliding window.
    pub window: Range<u32>,
    /// Fixed free callback: a single RTS; no heap/persistent effects.
    pub free: u32,
    /// Native forward byte copy helper.
    pub copy: u32,
    /// Every external arithmetic call in the closed inflater regions.
    pub calls: Vec<Call>,
}
fn role(address: usize) -> Option<usize> {
    match address {
        0x1058a6 => Some(0),
        0x105588 => Some(1),
        0x1055ae => Some(2),
        _ => None,
    }
}
/// Bind complete reviewed native instruction bytes and their immutable tables.
/// Exact instruction templates deliberately reject other implementations. The
/// byte images are evidence for this graph, not a firmware identity allowlist.
pub fn observe(image: &[u8]) -> Option<Binding> {
    let regions = crate::image::regions(image)?;
    let stored = |range: &Range<usize>| {
        regions.stored.iter().any(|s| {
            let at = s.as_ptr() as usize - image.as_ptr() as usize;
            at <= range.start && range.end <= at + s.len()
        })
    };
    let mut starts = Vec::new();
    let mut edges = Vec::new();
    let mut calls = Vec::new();
    let mut programs = Vec::new();
    for &(address, bytes) in PROGRAMS {
        let span = address - BASE..address - BASE + bytes.len();
        if !stored(&span) || image.get(span.clone())? != bytes {
            return None;
        }
        let mut at = span.start;
        while at < span.end {
            let d = decode_insn(image.get(at..span.end)?, Target::H8S2000, Mode::Advanced).ok()?;
            starts.push(BASE + at);
            for operand in d.insn.operands {
                match operand {
                    Operand::Address(Ea::PcRelative { value, .. }) => {
                        edges.push((BASE + at + d.len).checked_add_signed(value as isize)?);
                    }
                    Operand::Address(Ea::Absolute { value, bits: 24 })
                        if matches!(d.insn.mnemonic, "JSR" | "JMP") =>
                    {
                        if let Some(role) = role(value as usize) {
                            if d.insn.mnemonic != "JSR" || d.len != 4 {
                                return None;
                            }
                            calls.push(Call { offset: at, role });
                        } else {
                            edges.push(value as usize);
                        }
                    }
                    _ => {}
                }
            }
            at += d.len;
        }
        programs.push(span);
    }
    if edges.iter().any(|a| !starts.contains(a)) || calls.len() != 10 {
        return None;
    }
    let boundary_program = 0x57cc18 - BASE..0x57ccd0 - BASE;
    if !stored(&boundary_program) || image.get(boundary_program.clone())? != COMBINE {
        return None;
    }
    let data = 0x5abd02 - BASE..0x5abd02 - BASE + DATA.len();
    let loader = 0x54b724 - BASE..0x54b724 - BASE + LOADER.len();
    if !stored(&data)
        || !stored(&loader)
        || image.get(data.clone())? != DATA
        || image.get(loader.clone())? != LOADER
    {
        return None;
    }
    // State is range checked to 0..=30 before the sole indirect branch.
    // Each table word is an unsigned byte displacement from 57b362.
    for word in image.get(0x5abd08 - BASE..0x5abd46 - BASE)?.chunks_exact(2) {
        let target = 0x57b362 + usize::from(u16::from_be_bytes([word[0], word[1]]));
        if !starts.contains(&target) {
            return None;
        }
    }
    Some(Binding {
        entry: 0x57ae64,
        programs,
        boundary_program,
        data,
        loader,
        state: 0xa0be86..0xa0da50,
        window: 0xa0da50..0xa15a50,
        free: 0x57db1e,
        copy: 0x57db04,
        calls,
    })
}

/// Require complete Normal/paired-Kernel reference closure for the three
/// routines whose arithmetic changes. Internal calls and the bounded loader
/// are accounted for; new outside clients refuse. The caller establishes
/// that `kernel` is the exact component paired with this Normal image.
pub fn observe_with_kernel(image: &[u8], kernel: &[u8]) -> Option<Binding> {
    let binding = observe(image)?;
    let modified = [
        0x57b28e - BASE..0x57c9aa - BASE,
        0x57c9fc - BASE..0x57cc18 - BASE,
        0x57d3dc - BASE..0x57db04 - BASE,
    ];
    let mut accounted = binding.programs.clone();
    accounted.push(binding.data.clone());
    accounted.push(binding.loader.clone());
    let mut boundaries = binding.programs.clone();
    boundaries.push(binding.boundary_program.clone());
    super::retirement::references_clear(image, kernel, &modified, &accounted, &boundaries)?;
    Some(binding)
}

/// Retarget only decoded inflater arithmetic calls to complete, already placed
/// OEM arithmetic bodies. Placement ownership and execution certification are
/// separate requirements; this function neither allocates nor admits a route.
/// Entries are [multiply, signed divide, unsigned divide].
pub fn retarget_arithmetic(image: &[u8], entries: [u32; 3]) -> Option<Vec<u8>> {
    let binding = observe(image)?;
    let arithmetic = crate::filters::phase::native::arithmetic::observe(
        image,
        BASE as u32,
        entries[0],
        entries[1],
    )?;
    if BASE + arithmetic.unsigned_divide.start != entries[2] as usize {
        return None;
    }
    let mut changed = image.to_vec();
    for call in binding.calls {
        let d = decode_insn(&image[call.offset..], Target::H8S2000, Mode::Advanced).ok()?;
        let mut insn = d.insn;
        insn.operands[0] = Operand::Address(Ea::Absolute {
            value: entries[call.role],
            bits: 24,
        });
        let code = encode_insn(insn, Target::H8S2000, Mode::Advanced).ok()?;
        if code.len() != 4 {
            return None;
        }
        changed[call.offset..call.offset + 4].copy_from_slice(&code);
    }
    Some(changed)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> Vec<u8> {
        let mut image = alloc::vec![0xff; 0x1c0000];
        for &(address, bytes) in PROGRAMS
            .iter()
            .chain([(0x5abd02, DATA), (0x54b724, LOADER), (0x57cc18, COMBINE)].iter())
        {
            image[address - BASE..address - BASE + bytes.len()].copy_from_slice(bytes);
        }
        image
    }
    #[test]
    fn complete_native_graph_and_switch_bind() {
        let image = fixture();
        let b = observe(&image).expect("complete captured native graph");
        assert_eq!(b.calls.iter().filter(|c| c.role == 0).count(), 3);
        assert_eq!(b.calls.iter().filter(|c| c.role == 1).count(), 1);
        assert_eq!(b.calls.iter().filter(|c| c.role == 2).count(), 6);
        assert_eq!(b.free, 0x57db1e);
    }
    #[test]
    fn altered_effects_switch_and_constants_refuse() {
        let image = fixture();
        for address in [0x57db1e, 0x57b0b8, 0x57b3e8, 0x5abd08, 0x5ac630, 0x54b85a] {
            let mut changed = image.clone();
            changed[address - BASE] ^= 1;
            assert!(observe(&changed).is_none(), "{address:x}");
        }
        assert!(retarget_arithmetic(&image, [0x410100, 0x410120, 0x410160]).is_none());
    }

    #[test]
    fn retargets_only_ten_bound_jsrs_to_complete_oem_bodies() {
        const MULTIPLY: &[u8] = &[
            0x01, 0x10, 0x6d, 0xf2, 0x0d, 0x82, 0x52, 0x12, 0x0d, 0x93, 0x52, 0x03, 0x52, 0x10,
            0x09, 0x28, 0x09, 0x38, 0x01, 0x10, 0x6d, 0x73, 0x54, 0x70,
        ];
        const SIGNED: &[u8] = &[
            0x6d, 0xf2, 0x0d, 0x82, 0x0c, 0x2a, 0x4a, 0x02, 0x17, 0xb0, 0x0d, 0x99, 0x4a, 0x04,
            0xd2, 0x80, 0x17, 0xb1, 0x5e, 0x10, 0x55, 0xae, 0x0c, 0x22, 0x4a, 0x02, 0x17, 0xb0,
            0x0c, 0xaa, 0x4a, 0x02, 0x17, 0xb1, 0x6d, 0x72, 0x54, 0x70,
        ];
        const UNSIGNED: &[u8] = &[
            0x01, 0x00, 0x6d, 0xf2, 0x0d, 0x99, 0x46, 0x10, 0x0d, 0x82, 0x17, 0x72, 0x53, 0x12,
            0x0d, 0xa8, 0x53, 0x10, 0x0d, 0x81, 0x0d, 0x28, 0x40, 0x1e, 0x0f, 0x92, 0x0d, 0x81,
            0x17, 0x71, 0x79, 0x08, 0x00, 0x10, 0x12, 0x10, 0x12, 0x31, 0x1a, 0xa1, 0x44, 0x02,
            0x0a, 0xa1, 0x1b, 0x58, 0x46, 0xf2, 0x12, 0x10, 0x17, 0x10, 0x17, 0x70, 0x01, 0x00,
            0x6d, 0x72, 0x54, 0x70,
        ];
        let mut image = fixture();
        let entries = [0x410200, 0x410220, 0x410250];
        image[0x200..0x200 + MULTIPLY.len()].copy_from_slice(MULTIPLY);
        image[0x220..0x220 + SIGNED.len()].copy_from_slice(SIGNED);
        image[0x220 + 19..0x220 + 22].copy_from_slice(&[0x41, 0x02, 0x50]);
        image[0x250..0x250 + UNSIGNED.len()].copy_from_slice(UNSIGNED);
        let before = observe(&image).unwrap();
        let changed = retarget_arithmetic(&image, entries).unwrap();
        for (at, (a, b)) in image.iter().zip(&changed).enumerate() {
            if a != b {
                assert!(before
                    .calls
                    .iter()
                    .any(|c| (c.offset + 1..c.offset + 4).contains(&at)));
            }
        }
        for call in before.calls {
            let d = decode_insn(&changed[call.offset..], Target::H8S2000, Mode::Advanced).unwrap();
            assert_eq!(
                d.insn.operands[0],
                Operand::Address(Ea::Absolute {
                    value: entries[call.role],
                    bits: 24
                })
            );
        }
    }

    #[test]
    fn outside_decoder_clients_refuse() {
        let image = fixture();
        let kernel = alloc::vec![0xff; crate::image::KERNEL_LEN];
        assert!(observe_with_kernel(&image, &kernel).is_some());
        let mut changed = image.clone();
        changed[0x800..0x804].copy_from_slice(&[0x5e, 0x57, 0xc9, 0xfc]);
        assert!(observe_with_kernel(&changed, &kernel).is_none());
        let mut resident = kernel;
        resident[0x800..0x804].copy_from_slice(&[0x5e, 0x57, 0xd3, 0xdc]);
        assert!(observe_with_kernel(&image, &resident).is_none());
    }

    #[test]
    #[ignore = "requires exact local paired Normal/Kernel corpus"]
    fn actual_paired_decoder_reference_closure() {
        let path = std::env::var("PIONEER_NATIVE_COMP_NORMAL").unwrap();
        let image = std::fs::read(&path).unwrap();
        let kernel = std::fs::read(path.replace(".bin", ".kernel.bin")).unwrap();
        assert!(observe_with_kernel(&image, &kernel).is_some());
    }
}
