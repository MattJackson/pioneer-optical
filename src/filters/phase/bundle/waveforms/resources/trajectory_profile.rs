//! Complete PR1 OEM trajectory profiles with a target-native speed coordinate.
//! No storage is allocated here: executable/data slots and three private volatile
//! bytes require the composition owner's independent ownership proof. No settings
//! or persistent storage are written. Outer controller proves nonnull22-byte
//! profile lifetime and mode-one configuration; generic heap/media paths are not
//! part of this specialized graph.
use alloc::vec::Vec;
use core::ops::Range;
use h8_asm::{
    isa::{decode_insn, encode_insn, Ea, Operand},
    Mode, Target,
};
use sha2::{Digest, Sha256};
const BASE: u32 = 0x410000;
// Complete-body provenance: PR1 decoded8037cdb3ae67e04a82aa3e9b7a0f52202e17f1e39d1f50b894158d9be0cec898;
// UD04 decoded87e8152f1de1d3be53eb4ad9144c1bb0c45a9be6f78713a0b7487a637f989bf1.
// Hashes bind every instruction/data byte, not merely an image identity.
const SOURCE: &[(u32, u32, [u8; 32])] = &[
    (
        0x5d5aa6,
        0x5d5d60,
        [
            0xa7, 0x60, 0xc7, 0xb8, 0xe5, 0x99, 0xf1, 0xdb, 0x8d, 0x30, 0x32, 0x22, 0x11, 0x78,
            0xeb, 0xc2, 0x06, 0x73, 0xed, 0x23, 0x9b, 0xa1, 0xbc, 0xaf, 0x91, 0x63, 0xc1, 0x01,
            0xf4, 0x34, 0x68, 0xce,
        ],
    ),
    (
        0x5d5d60,
        0x5d5fe6,
        [
            0x30, 0x43, 0x32, 0xaa, 0x75, 0x6d, 0x9e, 0xe7, 0xc2, 0x14, 0x37, 0xed, 0x6c, 0xb1,
            0x4f, 0x21, 0xda, 0x56, 0x0b, 0xc9, 0x40, 0x2b, 0x4c, 0x32, 0xc2, 0xb0, 0xb7, 0xfa,
            0x9d, 0xd4, 0xf6, 0xb9,
        ],
    ),
    (
        0x5d5fe6,
        0x5d600c,
        [
            0x14, 0xcd, 0x78, 0x61, 0x50, 0x17, 0x62, 0x87, 0xd4, 0x9e, 0x74, 0xf8, 0x77, 0x56,
            0xb1, 0x45, 0x51, 0x89, 0x14, 0x77, 0xd2, 0xd2, 0xa2, 0x82, 0xa1, 0x39, 0x2a, 0x6e,
            0x82, 0xec, 0x09, 0x8c,
        ],
    ),
    (
        0x5d6018,
        0x5d6068,
        [
            0xba, 0x65, 0x21, 0xb1, 0xe4, 0x69, 0xa7, 0x16, 0xc4, 0x90, 0x0c, 0xd1, 0x0a, 0x98,
            0x01, 0xab, 0xbf, 0x7d, 0x14, 0xb4, 0x5c, 0x89, 0xc6, 0x02, 0xff, 0x33, 0x13, 0xe7,
            0x73, 0x57, 0x58, 0x2c,
        ],
    ),
    (
        0x5d6068,
        0x5d60b4,
        [
            0x88, 0x67, 0x4c, 0x8a, 0x8d, 0x8a, 0xd8, 0x48, 0x18, 0x97, 0x30, 0x40, 0xa9, 0x52,
            0x60, 0x92, 0x03, 0x24, 0x1a, 0x4c, 0xbd, 0xa1, 0x2a, 0x42, 0x13, 0xb9, 0x4a, 0x3b,
            0xfa, 0x40, 0xbe, 0xa3,
        ],
    ),
    (
        0x5d60b4,
        0x5d60f8,
        [
            0xc9, 0xf5, 0xb3, 0x60, 0x1a, 0x93, 0x82, 0xbc, 0x09, 0xee, 0x2d, 0x47, 0xdc, 0x4c,
            0xf9, 0x0d, 0xc5, 0x3f, 0x6c, 0xfe, 0x46, 0x01, 0xc7, 0x47, 0x3c, 0x1b, 0x59, 0xd2,
            0x67, 0x10, 0xf3, 0x19,
        ],
    ),
    (
        0x65f142,
        0x65f372,
        [
            0x66, 0xdc, 0xa8, 0xc1, 0xfe, 0x3c, 0x5f, 0x13, 0x4c, 0x65, 0xb2, 0xb5, 0x96, 0xf6,
            0x1b, 0xc6, 0xaa, 0x41, 0x4a, 0x98, 0x8c, 0x5b, 0x4d, 0x93, 0x53, 0x30, 0x8c, 0x1d,
            0x8f, 0xa0, 0x30, 0xf5,
        ],
    ),
    (
        0x65ed70,
        0x65eda9,
        [
            0xc9, 0x2a, 0x24, 0xed, 0xbd, 0x30, 0xae, 0xd9, 0x44, 0xdf, 0x6a, 0xc0, 0x40, 0x61,
            0x2a, 0x15, 0x5d, 0xb0, 0x0b, 0x5a, 0xe1, 0xac, 0xbc, 0x76, 0x6f, 0x0a, 0xd9, 0x68,
            0x2d, 0xf2, 0xea, 0x10,
        ],
    ),
];
const TARGET: &[(u32, u32, [u8; 32])] = &[
    (
        0x5378b6,
        0x537b58,
        [
            0x84, 0x4c, 0xf0, 0x80, 0x23, 0x08, 0x3d, 0x93, 0xcd, 0x73, 0x99, 0x4b, 0x3a, 0x5a,
            0x95, 0x91, 0x5e, 0xdc, 0x3b, 0x19, 0x9c, 0x40, 0xf1, 0x2c, 0x5b, 0x44, 0xc8, 0xfc,
            0x07, 0x96, 0x8c, 0x89,
        ],
    ),
    (
        0x537b58,
        0x537e30,
        [
            0xf1, 0x9d, 0xc3, 0x35, 0x63, 0x8c, 0xec, 0x82, 0x99, 0x0f, 0x79, 0x1e, 0xb9, 0xe6,
            0xdc, 0xa0, 0xc6, 0xe9, 0x3f, 0xc6, 0xc1, 0x7a, 0x2b, 0x36, 0xf8, 0xa4, 0xfe, 0xd3,
            0x55, 0x53, 0x85, 0x0e,
        ],
    ),
    (
        0x537e30,
        0x537f66,
        [
            0xea, 0xbe, 0x3d, 0xb4, 0x72, 0xb0, 0xd7, 0x6e, 0xb8, 0x04, 0x03, 0x23, 0xc1, 0x43,
            0xda, 0x28, 0x4d, 0xdd, 0x0a, 0x12, 0xd6, 0xce, 0xa5, 0x81, 0xb1, 0x55, 0x36, 0xf1,
            0x00, 0x76, 0xdd, 0x66,
        ],
    ),
    (
        0x5a4b54,
        0x5a4d0c,
        [
            0xf2, 0x6b, 0x7d, 0x65, 0xa7, 0x3c, 0x5a, 0x9f, 0x0a, 0x9c, 0x70, 0x82, 0x80, 0x6d,
            0x17, 0x41, 0xaf, 0x4e, 0xa9, 0x3e, 0x07, 0x59, 0x0b, 0x31, 0xdc, 0xb7, 0x0d, 0x80,
            0x5c, 0xa1, 0x3e, 0x51,
        ],
    ),
];

// Unchanged target bootstrap client and its initialized data. Mask-ROM copy
// semantics remain an explicit existing-target service precondition.
const DEFAULT_BOOT: &[(u32, u32, [u8; 32])] = &[
    (
        0x4aef86,
        0x4af096,
        [
            0x5f, 0x43, 0x01, 0xf8, 0x74, 0xf9, 0x5e, 0x39, 0x2b, 0x29, 0x42, 0xed, 0xa2, 0x1e,
            0xfd, 0xdf, 0x81, 0x9c, 0x8e, 0x31, 0x79, 0xba, 0x65, 0xfb, 0x0c, 0x72, 0xbd, 0xf8,
            0xf9, 0x51, 0xab, 0xe5,
        ],
    ),
    (
        0x57cf52,
        0x57cf6a,
        [
            0x15, 0xb6, 0xbe, 0x7e, 0x2e, 0x04, 0x6a, 0xd2, 0x70, 0xc9, 0xe7, 0x64, 0x95, 0x56,
            0xeb, 0xae, 0x17, 0xfa, 0x68, 0x69, 0x2c, 0x2d, 0x39, 0xaf, 0xd7, 0xb8, 0xf8, 0xae,
            0x68, 0xb4, 0x2d, 0x65,
        ],
    ),
    (
        0x580614,
        0x580632,
        [
            0x0d, 0x2f, 0x1d, 0x51, 0xec, 0xf7, 0xdc, 0x41, 0x97, 0xeb, 0x1c, 0xcd, 0xb4, 0x55,
            0x34, 0x58, 0x7d, 0xf6, 0x1d, 0x64, 0x89, 0x33, 0x61, 0xf8, 0x62, 0x9b, 0x24, 0xf0,
            0x5e, 0x4b, 0xbf, 0xd5,
        ],
    ),
    (
        0x5993d6,
        0x5999f2,
        [
            0x20, 0xa6, 0xe7, 0x16, 0xb8, 0x19, 0x67, 0xb6, 0xcf, 0xfb, 0xbc, 0x77, 0x98, 0xcb,
            0x3a, 0x98, 0xd2, 0x89, 0xaa, 0x9f, 0xcd, 0x75, 0x92, 0xc4, 0x55, 0x59, 0x4d, 0x64,
            0x99, 0xdc, 0xcd, 0x42,
        ],
    ),
];

/// Native target service bindings established by the outer controller owner.
#[derive(Clone, Copy, Debug)]
pub struct Services {
    /// Target diagnostic adapters accepting original stack format/arguments,
    /// for source mask0x20000000 and mask0x80000000 respectively.
    pub report: [u32; 2],
    /// Existing target hardware-state object getter (source role5d73fe).
    pub state_getter: u32,
    /// Existing target hardware-mode getter (source role5d7428).
    pub hardware_mode: u32,
}
/// Entry points used by the complete controller composition.
#[derive(Clone, Debug)]
pub struct Plan {
    /// Code and data writes; all destinations must already be owned.
    pub writes: Vec<(Range<usize>, Vec<u8>)>,
    /// Original source-function addresses mapped to the emitted CPU entries.
    pub entries: Vec<(u32, u32)>,
    /// Read targetdefaultindex, derive native selected frequency, run source selector.
    /// Clobbers ER0..ER2/CCR; preserves ER3..ER6 and stack depth.
    pub prepare: u32,
}
/// Exact code and data lengths required by `plan`.
pub const fn lengths() -> [usize; 2] {
    [1550, 618]
}
fn bytes(n: &[u8], a: u32, z: u32) -> Option<&[u8]> {
    n.get((a.checked_sub(BASE)?) as usize..(z.checked_sub(BASE)?) as usize)
}
fn bind(n: &[u8], proof: &[(u32, u32, [u8; 32])]) -> Option<()> {
    let regions = crate::image::regions(n)?;
    for &(a, z, digest) in proof {
        let b = bytes(n, a, z)?;
        let at = (a - BASE) as usize;
        if !regions.stored.iter().any(|r| {
            let start = r.as_ptr() as usize - n.as_ptr() as usize;
            start <= at && at + b.len() <= start + r.len()
        }) || Sha256::digest(b).as_slice() != digest
        {
            return None;
        }
    }
    Some(())
}
fn valid_slot(n: &[u8], r: &Range<usize>, len: usize) -> Option<()> {
    if r.start & 1 != 0 || r.start >= r.end || r.len() != len || BASE as usize + r.end > 0x1000000 {
        return None;
    }
    let regions = crate::image::regions(n)?;
    regions
        .stored
        .iter()
        .any(|b| {
            let at = b.as_ptr() as usize - n.as_ptr() as usize;
            at <= r.start && r.end <= at + b.len()
        })
        .then_some(())
}
fn overlap(a: &Range<usize>, b: &Range<usize>) -> bool {
    a.start < b.end && b.start < a.end
}
fn reemit(
    body: &[u8],
    mapping: &[(u32, u32, u32)],
    services: Services,
    report: usize,
) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut at = 0;
    let mut starts = Vec::new();
    let mut edges = Vec::new();
    while at < body.len() {
        let d = decode_insn(&body[at..], Target::H8S2000, Mode::Advanced).ok()?;
        if encode_insn(d.insn, Target::H8S2000, Mode::Advanced).ok()? != body[at..at + d.len] {
            return None;
        }
        let mut insn = d.insn;
        starts.push(at);
        for op in &mut insn.operands {
            if let Operand::Address(Ea::PcRelative { value, .. }) = *op {
                edges.push((at + d.len).checked_add_signed(value as isize)?);
            }
            let value = match *op {
                Operand::Address(Ea::Absolute { value, .. })
                | Operand::Immediate { value, bits: 32 } => Some(value),
                Operand::Address(Ea::Displacement {
                    value, bits: 32, ..
                }) => Some(value as u32),
                _ => None,
            };
            let Some(value) = value else { continue };
            let mapped = mapping
                .iter()
                .find(|(a, z, _)| (*a..*z).contains(&value))
                .map(|(a, _, to)| to + value - a)
                .or_else(|| match value {
                    0x5f0102 => Some(services.report[report]),
                    0x5d73fe => Some(services.state_getter),
                    0x5d7428 => Some(services.hardware_mode),
                    _ => None,
                });
            if let Some(value) = mapped {
                *op = match *op {
                    Operand::Address(Ea::Absolute { bits, .. }) => {
                        Operand::Address(Ea::Absolute { bits, value })
                    }
                    Operand::Immediate { bits, .. } => Operand::Immediate { bits, value },
                    Operand::Address(Ea::Displacement { base, bits, .. }) => {
                        Operand::Address(Ea::Displacement {
                            base,
                            bits,
                            value: value as i32,
                        })
                    }
                    _ => return None,
                };
            } else if matches!(insn.mnemonic, "JSR" | "JMP") {
                return None;
            }
        }
        let emitted = encode_insn(insn, Target::H8S2000, Mode::Advanced).ok()?;
        if emitted.len() != d.len {
            return None;
        }
        out.extend(emitted);
        at += d.len;
    }
    // These complete native bodies have only internal relative branches.
    if edges.iter().any(|to| !starts.contains(to)) {
        return None;
    }
    Some(out)
}
/// Emit the complete source profile algorithms and exact native tables. The
/// target selector/init/updater and tables establish its two index domains:
/// low0..12 selects lowtable row28+index; high13..81 selects high rowindex-13.
/// The transplanted OEM inverse getter reads the selected row's second word;
/// the unmodified source selector then chooses its own45-row, bias-nine domain.
/// The outer owner must prove common frequency units via native timer services,
/// the `validate_default` client invariant, private-RAM ownership, and each
/// supplied service ABI.
/// `prepare` must precede nonnull constructor; `choose` is only the proved mode1
/// branch. These preconditions are part of the controller's execution proof.
pub fn plan(
    target: &[u8],
    source: &[u8],
    code: Range<usize>,
    data: Range<usize>,
    private_ram: u32,
    services: Services,
) -> Option<Plan> {
    bind(source, SOURCE)?;
    bind(target, TARGET)?;
    valid_slot(target, &code, lengths()[0])?;
    valid_slot(target, &data, lengths()[1])?;
    if overlap(&code, &data)
        || private_ram == 0
        || private_ram.checked_add(3)? > 0x1000000
        || services
            .report
            .into_iter()
            .chain([services.state_getter, services.hardware_mode])
            .any(|a| a & 1 != 0 || a > 0xfffffe)
    {
        return None;
    }
    for &(a, z, _) in TARGET.iter().chain(DEFAULT_BOOT) {
        let span = (a - BASE) as usize..(z - BASE) as usize;
        if overlap(&span, &code) || overlap(&span, &data) {
            return None;
        }
    }
    let code_base = BASE + code.start as u32;
    let data_base = BASE + data.start as u32;
    let mut next = code_base;
    let destinations = [698, 636, 10, 24, 22, 76, 68].map(|length| {
        let entry = next;
        next += length;
        entry
    });
    let (bodies, entries) = emit_graph(
        source,
        destinations,
        [
            data_base,
            data_base + 84,
            data_base + 264,
            data_base + 444,
            data_base + 560,
        ],
        private_ram,
        services,
    )?;
    let emitted: Vec<_> = bodies.into_iter().flatten().collect();
    let mut payload = bytes(source, 0x65f142, 0x65f372)?.to_vec();
    payload.extend_from_slice(bytes(source, 0x65ed70, 0x65eda9)?);
    payload.push(0);
    if emitted.len() != code.len() || payload.len() != data.len() {
        return None;
    }
    Some(Plan {
        writes: alloc::vec![(code, emitted), (data, payload)],
        entries,
        prepare: next,
    })
}

type EmittedGraph = (Vec<Vec<u8>>, Vec<(u32, u32)>);
fn emit_graph(
    source: &[u8],
    destinations: [u32; 7],
    data_entries: [u32; 5],
    private_ram: u32,
    services: Services,
) -> Option<EmittedGraph> {
    let mut raw = Vec::new();
    raw.push((0x5d5aa6, bytes(source, 0x5d5aa6, 0x5d5d60)?.to_vec()));
    raw.push((0x5d5d60, bytes(source, 0x5d5d60, 0x5d5fdc)?.to_vec()));
    raw.push((0x5d5fdc, bytes(source, 0x5d5fdc, 0x5d5fe6)?.to_vec()));
    // Nonnull branch of the complete source constructor: ER2=object, native
    // default-index store and abortflagclear, ER0=object, RTS.
    let mut ctor = bytes(source, 0x5d5fe6, 0x5d5fe8)?.to_vec();
    ctor.extend_from_slice(bytes(source, 0x5d5ff6, 0x5d600c)?);
    raw.push((0x5d5fe6, ctor));
    // Mode1 branch of the native configurator, including original save/restore.
    let mut choose = bytes(source, 0x5d6018, 0x5d601e)?.to_vec();
    choose.extend_from_slice(bytes(source, 0x5d6026, 0x5d6030)?);
    choose.extend_from_slice(bytes(source, 0x5d6062, 0x5d6068)?);
    raw.push((0x5d6018, choose));
    raw.push((0x5d6068, bytes(source, 0x5d6068, 0x5d60b4)?.to_vec()));
    let mut inverse = bytes(source, 0x5d60b4, 0x5d60f8)?.to_vec();
    // Typed native getter fields: selected targetRAM, domainbounds and rowbases.
    let mut at = 0;
    while at < inverse.len() {
        let d = decode_insn(&inverse[at..], Target::H8S2000, Mode::Advanced).ok()?;
        let mut insn = d.insn;
        for op in &mut insn.operands {
            *op = match *op {
                Operand::Address(Ea::Absolute {
                    value: 0x32bf,
                    bits,
                }) => Operand::Address(Ea::Absolute {
                    value: 0x3265,
                    bits,
                }),
                Operand::Address(Ea::Absolute {
                    value: 0x32c0,
                    bits,
                }) => Operand::Address(Ea::Absolute {
                    value: 0x3266,
                    bits,
                }),
                Operand::Immediate { value: 9, bits } => Operand::Immediate { value: 13, bits },
                Operand::Immediate { value: 12, bits } => Operand::Immediate { value: 28, bits },
                Operand::Immediate {
                    value: 0x65f196,
                    bits,
                } => Operand::Immediate {
                    value: 0x5a4bf8,
                    bits,
                },
                Operand::Immediate {
                    value: 0x65f142,
                    bits,
                } => Operand::Immediate {
                    value: 0x5a4b54,
                    bits,
                },
                other => other,
            };
        }
        let b = encode_insn(insn, Target::H8S2000, Mode::Advanced).ok()?;
        if b.len() != d.len {
            return None;
        }
        inverse[at..at + d.len].copy_from_slice(&b);
        at += d.len;
    }
    raw.push((0x5d60b4, inverse));
    let mut entries = Vec::new();
    let mut mapping = Vec::new();
    for ((old, b), next) in raw.iter().zip(destinations) {
        entries.push((*old, next));
        mapping.push((*old, *old + b.len() as u32, next));
    }
    mapping.extend([
        (0x65f142, 0x65f196, data_entries[0]),
        (0x65f196, 0x65f24a, data_entries[1]),
        (0x65f24a, 0x65f2fe, data_entries[2]),
        (0x65f2fe, 0x65f372, data_entries[3]),
        (0x65ed70, 0x65eda9, data_entries[4]),
        (0x32be, 0x32c1, private_ram),
    ]);
    let mut emitted = Vec::new();
    for (i, (_, body)) in raw.iter().enumerate() {
        emitted.push(reemit(body, &mapping, services, usize::from(i == 1))?);
    }
    // Register-only glue: channelone → OEMinverse → E0frequency/channelone →
    // OEMselector. Its RTS returns after the source's private default is stored.
    let mut glue =
        alloc::vec![0xf8, 1, 0x5e, 0, 0, 0, 0x0d, 0x08, 0xf8, 1, 0x5e, 0, 0, 0, 0x54, 0x70];
    crate::filters::phase::native::encoding::retarget_call(&mut glue, 2, entries[6].1)?;
    crate::filters::phase::native::encoding::retarget_call(&mut glue, 10, entries[5].1)?;
    emitted.push(reemit(&glue, &[], services, 0).or_else(|| {
        // The glue's two explicit calls are new bound entries, not donor calls.
        reemit(
            &glue,
            &[
                (entries[6].1, entries[6].1 + 1, entries[6].1),
                (entries[5].1, entries[5].1 + 1, entries[5].1),
            ],
            services,
            0,
        )
    })?);
    Some((emitted, entries))
}

/// Establish the target default-index client invariant without reimplementing
/// unchanged boot services. The complete initializer copies ROM5993D6..5999F2
/// into RAM2E6A..3486 through native57CF52/580614, seeding3265=42,3266=39 and media index3267=19.
/// The existing mask-ROM1058DC service retains its original source/destination/
/// length copy ABI; this function does not claim to possess or prove its body.
/// The only bound runtime stores are the complete native selector, whose loop
/// clamps each resulting channel index to13..81; the media index has no visible
/// runtime writer. Thus every initialized native value
/// used by `prepare` lies in0..81 under that unchanged service precondition.
///
/// Stored and expanded Normal and the exact Kernel must have no unknown visible
/// address references to these bytes (including overlapping word/long accesses
/// and unaligned32-bit pointers). Complete bound code provides instruction
/// boundaries only. Arbitrary runtime address synthesis remains outside this
/// bounded client proof, as in the graph retirement scanner.
pub fn validate_default(target: &[u8], kernel: &[u8]) -> Option<()> {
    if kernel.len() != crate::image::KERNEL_LEN {
        return None;
    }
    bind(target, TARGET)?;
    bind(target, DEFAULT_BOOT)?;
    let initialized = 0x5993d6 + (0x3265 - 0x2e6a);
    if bytes(target, initialized, initialized + 3)? != [42, 39, 19] {
        return None;
    }
    // Exempt only complete exact-bound consumers, never arbitrary byte ranges.
    let bodies: Vec<_> = TARGET[..3]
        .iter()
        .chain(DEFAULT_BOOT[..3].iter())
        .map(|(a, z, _)| (*a - BASE) as usize..(*z - BASE) as usize)
        .collect();
    validate_indices(target, kernel, &bodies)
}
fn validate_indices(target: &[u8], kernel: &[u8], bodies: &[Range<usize>]) -> Option<()> {
    use h8_asm::isa::Size;
    let mut interiors = Vec::new();
    for body in bodies {
        let mut at = body.start;
        while at < body.end {
            let d = decode_insn(&target[at..body.end], Target::H8S2000, Mode::Advanced).ok()?;
            interiors.push(at + 1..at + d.len);
            at += d.len;
        }
    }
    for (component, normal) in [(target, true), (kernel, false)] {
        let regions = crate::image::regions(component)?;
        for (region, offset) in regions
            .stored
            .iter()
            .map(|r| (*r, Some(r.as_ptr() as usize - component.as_ptr() as usize)))
            .chain(regions.expanded.iter().map(|r| (r.as_slice(), None)))
        {
            let bound = |at: usize, len: usize| {
                normal
                    && offset.is_some_and(|origin| {
                        bodies
                            .iter()
                            .any(|b| b.start <= origin + at && origin + at + len <= b.end)
                    })
            };
            for at in (offset.unwrap_or(0) % 2..region.len()).step_by(2) {
                if normal
                    && offset
                        .is_some_and(|origin| interiors.iter().any(|r| r.contains(&(origin + at))))
                {
                    continue;
                }
                let Ok(d) = decode_insn(&region[at..], Target::H8S2000, Mode::Advanced) else {
                    continue;
                };
                if bound(at, d.len) {
                    continue;
                }
                let width = match d.insn.size {
                    Some(Size::Long) => 4,
                    Some(Size::Word) => 2,
                    _ => 1,
                };
                for op in d.insn.operands {
                    let conflict = match op {
                        Operand::Address(Ea::Absolute {
                            value,
                            bits: 16 | 24 | 32,
                        }) => {
                            value < 0x3268
                                && value.checked_add(width).is_some_and(|end| end > 0x3265)
                        }
                        Operand::Immediate { value, bits: 32 } => (0x3262..0x3268).contains(&value),
                        _ => false,
                    };
                    if conflict {
                        return None;
                    }
                }
            }
            for at in 0..region.len().saturating_sub(3) {
                if !bound(at, 4)
                    && h8_asm::image::read_u32(region, at)
                        .is_some_and(|a| (0x3265..0x3268).contains(&a))
                {
                    return None;
                }
            }
        }
    }
    Some(())
}

const SHARED_CLIENTS: &[(u32, u32, [u8; 32])] = &[
    (
        0x5bcc34,
        0x5bcc48,
        [
            0x1, 0x41, 0x53, 0xb, 0xd1, 0x9a, 0xc, 0x5a, 0xfb, 0x48, 0xf8, 0x41, 0xf, 0xc, 0xff,
            0x33, 0x23, 0x81, 0x1d, 0x12, 0xc, 0x55, 0x4, 0xf6, 0xcb, 0xe7, 0xb7, 0x71, 0x84, 0x42,
            0x34, 0x83,
        ],
    ),
    (
        0x5392d2,
        0x539406,
        [
            0x53, 0xb9, 0x6, 0xb2, 0xfc, 0xbb, 0x2b, 0xba, 0x9c, 0x16, 0x8a, 0x72, 0x23, 0x64,
            0xaa, 0x1, 0xc5, 0xfc, 0x8f, 0x1f, 0xcc, 0x61, 0xad, 0xcf, 0x52, 0x51, 0xe8, 0x7f,
            0xb5, 0x6c, 0xa8, 0xd9,
        ],
    ),
    (
        0x539406,
        0x539550,
        [
            0x81, 0xf, 0xd7, 0x62, 0x23, 0x87, 0x3c, 0x33, 0x1f, 0x77, 0xac, 0x9a, 0xaf, 0x6f,
            0x7c, 0x86, 0x2f, 0x96, 0x80, 0xdf, 0xc, 0x6e, 0x6e, 0xba, 0xb8, 0xa7, 0x76, 0x77,
            0xba, 0xa2, 0x86, 0xba,
        ],
    ),
    (
        0x5a4edc,
        0x5a5024,
        [
            0x83, 0xe3, 0x91, 0xc4, 0x1b, 0x9, 0xbc, 0xba, 0x59, 0xb8, 0x4b, 0x30, 0x5, 0x2f, 0xac,
            0xf8, 0x53, 0x8a, 0xfa, 0xfe, 0xa9, 0x79, 0x86, 0xf7, 0x7b, 0xd8, 0x65, 0x90, 0x33,
            0xc8, 0xdd, 0x8a,
        ],
    ),
];

/// Caller-proved storage for the shared native profile implementation. Code
/// order is init, update, constructor, chooser, selector, inverse, prepare,
/// target special init/update, coordinate converter, init/update dispatch,
/// and legacy whole-controller zero-distance guard. Data order is low, forward,
/// reverse, deceleration tables, then diagnostic strings.
#[derive(Clone, Debug)]
pub struct SharedPlacements {
    /// Individually owned executable blocks, in the order above.
    pub code: [Range<usize>; 13],
    /// Individually owned OEM table and string blocks.
    pub data: [Range<usize>; 5],
}
/// Exact independently placeable native blocks; no alignment padding is owned.
pub const fn shared_lengths() -> ([usize; 13], [usize; 5]) {
    (
        [698, 636, 24, 22, 76, 68, 16, 44, 126, 38, 12, 14, 16],
        [84, 180, 180, 116, 57],
    )
}
/// Shared profile writes and explicit whole-controller composition obligation.
#[derive(Clone, Debug)]
pub struct SharedPlan {
    /// Profile graph for the outer bridge composer.
    pub profile: Plan,
    /// Old DSP call that the outer bridge must retire with its complete body.
    pub replaced_by_outer: Range<usize>,
    /// Complete old init/update bodies whose only callers are rewritten.
    pub retired: Vec<Range<usize>>,
}
fn span(a: u32, z: u32) -> Range<usize> {
    (a - BASE) as usize..(z - BASE) as usize
}
/// Reassemble selected complete OEM basic blocks, resolving every branch to an
/// instruction boundary in those blocks. Selection is justified only by the
/// dispatcher precondition; this does not discover or drop arbitrary branches.
fn fragments(n: &[u8], ranges: &[(u32, u32)], entry: u32) -> Option<Vec<u8>> {
    let mut instructions = Vec::new();
    let mut next = entry;
    for &(a, z) in ranges {
        let mut at = a;
        while at < z {
            let d = decode_insn(bytes(n, at, z)?, Target::H8S2000, Mode::Advanced).ok()?;
            if encode_insn(d.insn, Target::H8S2000, Mode::Advanced).ok()?
                != bytes(n, at, at + d.len as u32)?
            {
                return None;
            }
            instructions.push((at, next, d));
            at += d.len as u32;
            next += d.len as u32;
        }
    }
    let mapped = |old| {
        instructions
            .iter()
            .find(|(a, _, _)| *a == old)
            .map(|(_, b, _)| *b)
    };
    let mut out = Vec::new();
    for &(old, new, d) in &instructions {
        let mut insn = d.insn;
        for op in &mut insn.operands {
            *op = match *op {
                Operand::Address(Ea::PcRelative { value, bits }) => {
                    let to = old.checked_add(d.len as u32)?.checked_add_signed(value)?;
                    Operand::Address(Ea::PcRelative {
                        value: (i64::from(mapped(to)?) - i64::from(new + d.len as u32))
                            .try_into()
                            .ok()?,
                        bits,
                    })
                }
                Operand::Address(Ea::Absolute { value, bits })
                    if matches!(insn.mnemonic, "JMP" | "JSR") =>
                {
                    Operand::Address(Ea::Absolute {
                        value: mapped(value)?,
                        bits,
                    })
                }
                other => other,
            };
        }
        let b = encode_insn(insn, Target::H8S2000, Mode::Advanced).ok()?;
        if b.len() != d.len {
            return None;
        }
        out.extend(b);
    }
    Some(out)
}
fn jump(entry: u32) -> Option<Vec<u8>> {
    use h8_asm::isa::Insn;
    encode_insn(
        Insn::new(
            "JMP",
            None,
            [
                Operand::Address(Ea::Absolute {
                    value: entry,
                    bits: 24,
                }),
                Operand::None,
                Operand::None,
            ],
        ),
        Target::H8S2000,
        Mode::Advanced,
    )
    .ok()
}
fn call(entry: u32) -> Option<Vec<u8>> {
    let mut b = jump(entry)?;
    b[0] = 0x5e;
    Some(b)
}
fn checked_glue(b: Vec<u8>) -> Option<Vec<u8>> {
    let mut at = 0;
    while at < b.len() {
        let d = decode_insn(&b[at..], Target::H8S2000, Mode::Advanced).ok()?;
        if encode_insn(d.insn, Target::H8S2000, Mode::Advanced).ok()? != b[at..at + d.len] {
            return None;
        }
        at += d.len;
    }
    Some(b)
}
/// Share the complete source mode-zero algorithm between both native controller
/// clients while retaining the target's nonzero-mode basic blocks and table.
/// The target chooser remains native: conversion reads its actual `object[16]`.
/// Target nonzero mode never passes through the source selector or algorithm.
/// All original init/update callers and legacy controller entry callers must
/// close in stored/expanded Normal and the exact Kernel. The outer owner proves
/// shared timer lifetime, private RAM ownership and native service ABIs.
pub fn shared_plan(
    target: &[u8],
    source: &[u8],
    kernel: &[u8],
    placement: SharedPlacements,
    private_ram: u32,
    services: Services,
) -> Option<SharedPlan> {
    bind(source, SOURCE)?;
    bind(target, TARGET)?;
    bind(target, SHARED_CLIENTS)?;
    validate_default(target, kernel)?;
    if private_ram == 0
        || private_ram.checked_add(3)? > 0x1000000
        || services
            .report
            .into_iter()
            .chain([services.state_getter, services.hardware_mode])
            .any(|a| a & 1 != 0 || a > 0xfffffe)
    {
        return None;
    }
    let (code_lengths, data_lengths) = shared_lengths();
    let slots: Vec<_> = placement
        .code
        .iter()
        .zip(code_lengths)
        .chain(placement.data.iter().zip(data_lengths))
        .collect();
    let protected: Vec<_> = TARGET[2..]
        .iter()
        .chain(DEFAULT_BOOT)
        .chain(SHARED_CLIENTS)
        .map(|(a, z, _)| span(*a, *z))
        .chain([span(0x537e26, 0x537e30)])
        .collect();
    for (i, (r, len)) in slots.iter().enumerate() {
        valid_slot(target, r, *len)?;
        if slots[..i].iter().any(|(other, _)| overlap(r, other))
            || protected.iter().any(|p| overlap(p, r))
        {
            return None;
        }
    }
    let entries: [u32; 13] = core::array::from_fn(|i| BASE + placement.code[i].start as u32);
    let data_entries: [u32; 5] = core::array::from_fn(|i| BASE + placement.data[i].start as u32);
    let source_entries = [
        entries[0], entries[1], 0x537e26, entries[2], entries[3], entries[4], entries[5],
    ];
    let (graph, source_mapping) =
        emit_graph(source, source_entries, data_entries, private_ram, services)?;
    let mut writes = Vec::new();
    for (raw, slot) in [(0, 0), (1, 1), (3, 2), (4, 3), (5, 4), (6, 5), (7, 6)] {
        writes.push((placement.code[slot].clone(), graph[raw].clone()));
    }
    // Reuse the native ten-byte abort setter. Its complete grammar is the same
    // as the source setter, with only its absolute volatile byte relocated.
    let abort = reemit(
        bytes(target, 0x537e26, 0x537e30)?,
        &[(0x3264, 0x3265, private_ram)],
        services,
        0,
    )?;
    if abort != graph[2] {
        return None;
    }
    writes.push((span(0x537e26, 0x537e30), abort));
    writes.push((
        placement.code[7].clone(),
        fragments(
            target,
            &[
                (0x5378b6, 0x5378c2),
                (0x5378c6, 0x5378e0),
                (0x537b52, 0x537b58),
            ],
            entries[7],
        )?,
    ));
    writes.push((
        placement.code[8].clone(),
        fragments(
            target,
            &[
                (0x537b58, 0x537b6a),
                (0x537b70, 0x537bc4),
                (0x537d4a, 0x537d52),
                (0x537e16, 0x537e26),
            ],
            entries[8],
        )?,
    ));
    for (i, body) in shared_glue(entries)?.into_iter().enumerate() {
        writes.push((placement.code[9 + i].clone(), body));
    }
    for (slot, (a, z)) in [
        (0x65f142, 0x65f196),
        (0x65f196, 0x65f24a),
        (0x65f24a, 0x65f2fe),
        (0x65f2fe, 0x65f372),
        (0x65ed70, 0x65eda9),
    ]
    .into_iter()
    .enumerate()
    {
        writes.push((placement.data[slot].clone(), bytes(source, a, z)?.to_vec()));
    }
    let retired = alloc::vec![span(0x5378b6, 0x537e26)];
    let mut replaced = retired.clone();
    for (at, old, new) in [
        (0x539496, 0x5378b6, entries[10]),
        (0x5393f2, 0x537b58, entries[11]),
        (0x53951c, 0x537b58, entries[11]),
        (0x5385d4, 0x539406, entries[12]),
        (0x53898e, 0x539406, entries[12]),
        (0x5389e2, 0x539406, entries[12]),
        (0x539b1a, 0x539406, entries[12]),
    ] {
        if bytes(target, at, at + 4)? != call(old)? {
            return None;
        }
        let r = span(at, at + 4);
        replaced.push(r.clone());
        if at != 0x539b1a {
            writes.push((r, call(new)?));
        }
    }
    let bodies = [
        span(0x5378b6, 0x537b58),
        span(0x537b58, 0x537e26),
        span(0x5392d2, 0x539406),
        span(0x539406, 0x539550),
    ];
    super::retirement::references_clear(target, kernel, &retired, &replaced, &bodies)?;
    // Query original entry references without claiming its retained body as free
    // storage. All four native callers must pass through the zero-distance guard.
    let entry_query = span(0x539406, 0x539407);
    replaced.push(entry_query.clone());
    super::retirement::references_clear(target, kernel, &[entry_query], &replaced, &bodies)?;
    for (i, (r, b)) in writes.iter().enumerate() {
        if r.len() != b.len() || writes[..i].iter().any(|(other, _)| overlap(r, other)) {
            return None;
        }
    }
    Some(SharedPlan {
        profile: Plan {
            writes,
            entries: source_mapping,
            prepare: entries[6],
        },
        retired,
        replaced_by_outer: span(0x539b1a, 0x539b1e),
    })
}

fn shared_glue(entries: [u32; 13]) -> Option<[Vec<u8>; 4]> {
    // Preserve the original caller registers and stack argument. The inverse
    // suffix accepts R0L=index; ER3 holds the live object across OEM lookups.
    let mut converter = alloc::vec![0x01, 0x30, 0x6d, 0xf0, 0x0f, 0x83, 0x6e, 0x08, 0, 0x10];
    converter.extend(call(entries[5] + 18)?);
    converter.extend([0x0d, 0x08, 0xf8, 1]);
    converter.extend(call(entries[4])?);
    converter.extend([0x0f, 0xb0, 0xf9, 1]);
    converter.extend(call(entries[3])?);
    converter.extend([0x01, 0x30, 0x6d, 0x73]);
    converter.extend(jump(entries[0])?);
    let converter = checked_glue(converter)?;
    let mut init_dispatch = alloc::vec![0x0c, 0x99, 0x47, 4];
    init_dispatch.extend(jump(entries[7])?);
    init_dispatch.extend(jump(entries[9])?);
    let init_dispatch = checked_glue(init_dispatch)?;
    // R2H is scratch in both implementations; the phase input R2L is preserved.
    let mut update_dispatch = alloc::vec![0x6e, 0x02, 0, 14, 0x47, 4];
    update_dispatch.extend(jump(entries[8])?);
    update_dispatch.extend(jump(entries[1])?);
    let update_dispatch = checked_glue(update_dispatch)?;
    // Source mode-zero rounds ffff to zero. Guard the entire legacy controller
    // so its existing zero-distance path exits before invoking init or update.
    use h8_asm::isa::{Insn, Reg, Size};
    let mut guard = alloc::vec![0x0c, 0x99, 0x46, 8];
    guard.extend(
        encode_insn(
            Insn::new(
                "CMP",
                Some(Size::Word),
                [
                    Operand::Immediate {
                        value: 0xffff,
                        bits: 16,
                    },
                    Operand::Register(Reg::Word(9)),
                    Operand::None,
                ],
            ),
            Target::H8S2000,
            Mode::Advanced,
        )
        .ok()?,
    );
    guard.extend([0x46, 2, 0x19, 0x99]);
    guard.extend(jump(0x539406)?);
    let guard = checked_glue(guard)?;
    Some([converter, init_dispatch, update_dispatch, guard])
}

/// Source algorithm entries discovered by the enclosing native controller.
#[derive(Clone, Copy, Debug)]
pub struct SharedEntries {
    /// Complete source mode-zero initializer.
    pub init: u32,
    /// Complete source mode-zero updater.
    pub update: u32,
    /// Specialized nonnull constructor.
    pub ctor: u32,
    /// Target-coordinate preparation entry.
    pub prepare: u32,
}
/// Positively recognized emitted graph, independent of any saved patch plan.
#[derive(Clone, Debug)]
pub struct ObservedShared {
    /// Actual code and data locations derived from native operands.
    pub placements: SharedPlacements,
    /// Every emitted body, payload, abort setter and rewritten client call.
    /// The outer observer adds its bodies before checking inbound references.
    pub ranges: Vec<Range<usize>>,
    /// Complete retained native bodies, tables, bootstrap and vtable verified
    /// by this observer. These are protected invariants, not retired storage.
    pub invariants: Vec<Range<usize>>,
    /// Exact typed references to the positively recognized profile payloads.
    pub data_authority: ProfileDataAuthority,
}
fn observed_slot(n: &[u8], entry: u32, len: usize) -> Option<Range<usize>> {
    let start = entry.checked_sub(BASE)? as usize;
    let r = start..start.checked_add(len)?;
    valid_slot(n, &r, len)?;
    Some(r)
}
fn flow(n: &[u8], at: u32, mnemonic: &str) -> Option<u32> {
    let body = bytes(n, at, at.checked_add(4)?)?;
    let d = decode_insn(body, Target::H8S2000, Mode::Advanced).ok()?;
    if d.len != 4
        || d.insn.mnemonic != mnemonic
        || encode_insn(d.insn, Target::H8S2000, Mode::Advanced).ok()? != body
    {
        return None;
    }
    match d.insn.operands {
        [Operand::Address(Ea::Absolute { value, bits: 24 }), Operand::None, Operand::None] => {
            Some(value)
        }
        _ => None,
    }
}
fn pointer(n: &[u8], at: u32) -> Option<u32> {
    let d = decode_insn(
        bytes(n, at, at.checked_add(6)?)?,
        Target::H8S2000,
        Mode::Advanced,
    )
    .ok()?;
    match (d.insn.mnemonic, d.insn.size, d.insn.operands[0]) {
        ("MOV", Some(h8_asm::isa::Size::Long), Operand::Immediate { value, bits: 32 })
            if d.len == 6 =>
        {
            Some(value)
        }
        _ => None,
    }
}
/// Restore only typed relocatable address fields. Complete canonical digests
/// below, rather than a partial instruction signature, establish the semantics.
fn canonical(body: &[u8], mapping: &[(u32, u32, u32)]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut at = 0;
    while at < body.len() {
        let d = decode_insn(&body[at..], Target::H8S2000, Mode::Advanced).ok()?;
        if encode_insn(d.insn, Target::H8S2000, Mode::Advanced).ok()? != body[at..at + d.len] {
            return None;
        }
        let mut insn = d.insn;
        for op in &mut insn.operands {
            let v = match *op {
                Operand::Address(Ea::Absolute { value, .. })
                | Operand::Immediate { value, bits: 32 } => Some(value),
                Operand::Address(Ea::Displacement {
                    value, bits: 32, ..
                }) => Some(value as u32),
                _ => None,
            };
            let Some(v) = v else { continue };
            if let Some(&(a, _, to)) = mapping.iter().find(|(a, z, _)| (*a..*z).contains(&v)) {
                let value = to.checked_add(v - a)?;
                *op = match *op {
                    Operand::Address(Ea::Absolute { bits, .. }) => {
                        Operand::Address(Ea::Absolute { value, bits })
                    }
                    Operand::Immediate { bits, .. } => Operand::Immediate { value, bits },
                    Operand::Address(Ea::Displacement { base, bits, .. }) => {
                        Operand::Address(Ea::Displacement {
                            base,
                            bits,
                            value: value as i32,
                        })
                    }
                    _ => return None,
                };
            }
        }
        let b = encode_insn(insn, Target::H8S2000, Mode::Advanced).ok()?;
        if b.len() != d.len {
            return None;
        }
        out.extend(b);
        at += d.len;
    }
    Some(out)
}
fn digest_is(body: &[u8], digest: &[u8; 32]) -> Option<()> {
    (Sha256::digest(body).as_slice() == digest).then_some(())
}
/// Recognize the actual emitted hybrid with no original target image, donor
/// image, marker, or cached plan. Entry and data locations come from native
/// call/immediate fields; complete typed reverse-relocated bodies must match
/// the OEM provenance hashes. Specialized paths have complete canonical hashes.
/// The enclosing observer still proves private RAM, service ABIs, timer lifetime
/// and inbound references from its own recognized controller graph.
pub fn observe_shared(
    n: &[u8],
    kernel: &[u8],
    roots: SharedEntries,
    services: Services,
    private_ram: u32,
) -> Option<ObservedShared> {
    if kernel.len() != crate::image::KERNEL_LEN
        || private_ram == 0
        || private_ram.checked_add(3)? > 0x1000000
    {
        return None;
    }
    bind(n, &TARGET[2..])?;
    bind(n, DEFAULT_BOOT)?;
    // The retained data and callback vtable remain exact. Callback/controller
    // bodies are checked below after undoing their three call relocations.
    for &(a, z, h) in SHARED_CLIENTS {
        if !matches!(a, 0x5392d2 | 0x539406) {
            bind(n, &[(a, z, h)])?;
        }
    }
    let init_dispatch = flow(n, 0x539496, "JSR")?;
    let update_dispatch = flow(n, 0x5393f2, "JSR")?;
    if flow(n, 0x53951c, "JSR")? != update_dispatch {
        return None;
    }
    let guard = flow(n, 0x5385d4, "JSR")?;
    if [0x53898e, 0x5389e2]
        .into_iter()
        .any(|at| flow(n, at, "JSR") != Some(guard))
    {
        return None;
    }
    let converter = flow(n, init_dispatch.checked_add(8)?, "JMP")?;
    let entries = [
        roots.init,
        roots.update,
        roots.ctor,
        flow(n, converter.checked_add(26)?, "JSR")?,
        flow(n, roots.prepare.checked_add(10)?, "JSR")?,
        flow(n, roots.prepare.checked_add(2)?, "JSR")?,
        roots.prepare,
        flow(n, init_dispatch.checked_add(4)?, "JMP")?,
        flow(n, update_dispatch.checked_add(6)?, "JMP")?,
        converter,
        init_dispatch,
        update_dispatch,
        guard,
    ];
    let data_entries = [
        pointer(n, roots.init.checked_add(0xa6)?)?,
        pointer(n, roots.update.checked_add(0x1f4)?)?,
        pointer(n, roots.update.checked_add(0x82)?)?,
        pointer(n, roots.init.checked_add(0x1fe)?)?,
        pointer(n, roots.update.checked_add(0x26)?)?,
    ];
    let (code_lengths, data_lengths) = shared_lengths();
    let mut code: [Range<usize>; 13] = core::array::from_fn(|_| 0..0);
    let mut data: [Range<usize>; 5] = core::array::from_fn(|_| 0..0);
    for i in 0..13 {
        code[i] = observed_slot(n, entries[i], code_lengths[i])?;
    }
    for i in 0..5 {
        data[i] = observed_slot(n, data_entries[i], data_lengths[i])?;
    }
    let mut ranges: Vec<_> = code.iter().chain(&data).cloned().collect();
    ranges.push(span(0x537e26, 0x537e30));
    for (i, r) in ranges.iter().enumerate() {
        if ranges[..i].iter().any(|s| overlap(r, s)) {
            return None;
        }
    }
    let old_entries = [0x5d5aa6, 0x5d5d60, 0x5d5fe6, 0x5d6018, 0x5d6068, 0x5d60b4];
    let mut mapping: Vec<_> = (0..6)
        .map(|i| {
            (
                entries[i],
                entries[i] + code_lengths[i] as u32,
                old_entries[i],
            )
        })
        .collect();
    for (i, old) in [0x65f142, 0x65f196, 0x65f24a, 0x65f2fe, 0x65ed70]
        .into_iter()
        .enumerate()
    {
        mapping.push((
            data_entries[i],
            data_entries[i] + data_lengths[i] as u32,
            old,
        ));
    }
    mapping.extend([
        (private_ram, private_ram + 3, 0x32be),
        (
            services.report[0],
            services.report[0].checked_add(1)?,
            0x5f0102,
        ),
        (
            services.report[1],
            services.report[1].checked_add(1)?,
            0x5f0102,
        ),
        (
            services.state_getter,
            services.state_getter.checked_add(1)?,
            0x5d73fe,
        ),
        (
            services.hardware_mode,
            services.hardware_mode.checked_add(1)?,
            0x5d7428,
        ),
    ]);
    let bodies: Vec<_> = code
        .iter()
        .take(6)
        .map(|r| canonical(&n[r.clone()], &mapping))
        .collect::<Option<_>>()?;
    digest_is(&bodies[0], &SOURCE[0].2)?;
    let mut update = bodies[1].clone();
    update.extend(canonical(bytes(n, 0x537e26, 0x537e30)?, &mapping)?);
    digest_is(&update, &SOURCE[1].2)?;
    digest_is(&bodies[2], &SPECIALIZED[0])?;
    digest_is(&bodies[3], &SPECIALIZED[1])?;
    digest_is(&bodies[4], &SOURCE[4].2)?;
    let mut inverse = bodies[5].clone();
    let mut at = 0;
    while at < inverse.len() {
        let d = decode_insn(&inverse[at..], Target::H8S2000, Mode::Advanced).ok()?;
        let mut insn = d.insn;
        for op in &mut insn.operands {
            *op = match *op {
                Operand::Address(Ea::Absolute {
                    value: 0x3265,
                    bits,
                }) => Operand::Address(Ea::Absolute {
                    value: 0x32bf,
                    bits,
                }),
                Operand::Address(Ea::Absolute {
                    value: 0x3266,
                    bits,
                }) => Operand::Address(Ea::Absolute {
                    value: 0x32c0,
                    bits,
                }),
                Operand::Immediate { value: 13, bits } => Operand::Immediate { value: 9, bits },
                Operand::Immediate { value: 28, bits } => Operand::Immediate { value: 12, bits },
                Operand::Immediate {
                    value: 0x5a4bf8,
                    bits,
                } => Operand::Immediate {
                    value: 0x65f196,
                    bits,
                },
                Operand::Immediate {
                    value: 0x5a4b54,
                    bits,
                } => Operand::Immediate {
                    value: 0x65f142,
                    bits,
                },
                other => other,
            };
        }
        let b = encode_insn(insn, Target::H8S2000, Mode::Advanced).ok()?;
        if b.len() != d.len {
            return None;
        }
        inverse[at..at + d.len].copy_from_slice(&b);
        at += d.len;
    }
    digest_is(&inverse, &SOURCE[5].2)?;
    let tables: Vec<_> = data[..4]
        .iter()
        .flat_map(|r| n[r.clone()].iter().copied())
        .collect();
    digest_is(&tables, &SOURCE[6].2)?;
    digest_is(&n[data[4].clone()], &SOURCE[7].2)?;
    for i in 7..9 {
        digest_is(
            &fragments(
                n,
                &[(entries[i], entries[i] + code_lengths[i] as u32)],
                0x1000,
            )?,
            &SPECIALIZED[i - 5],
        )?;
    }
    for (i, body) in shared_glue(entries)?.iter().enumerate() {
        if n[code[9 + i].clone()] != *body {
            return None;
        }
    }
    let mut prepare = alloc::vec![0xf8, 1];
    prepare.extend(call(entries[5])?);
    prepare.extend([0x0d, 0x08, 0xf8, 1]);
    prepare.extend(call(entries[4])?);
    prepare.extend([0x54, 0x70]);
    if n[code[6].clone()] != prepare {
        return None;
    }
    let client_mapping = [
        (init_dispatch, init_dispatch + 1, 0x5378b6),
        (update_dispatch, update_dispatch + 1, 0x537b58),
    ];
    let mut index_bodies: Vec<_> = code.to_vec();
    for &(a, z, h) in SHARED_CLIENTS {
        if matches!(a, 0x5392d2 | 0x539406) {
            digest_is(&canonical(bytes(n, a, z)?, &client_mapping)?, &h)?;
            index_bodies.push(span(a, z));
        }
    }
    index_bodies.extend(
        TARGET[2..3]
            .iter()
            .chain(&DEFAULT_BOOT[..3])
            .map(|(a, z, _)| span(*a, *z)),
    );
    validate_indices(n, kernel, &index_bodies)?;
    for at in [0x539496, 0x5393f2, 0x53951c, 0x5385d4, 0x53898e, 0x5389e2] {
        ranges.push(span(at, at + 4));
    }
    let data_authority = profile_data_authority(n, &code, &data)?;
    Some(ObservedShared {
        placements: SharedPlacements { code, data },
        data_authority,
        ranges,
        invariants: TARGET[2..]
            .iter()
            .chain(DEFAULT_BOOT)
            .chain(SHARED_CLIENTS)
            .map(|(a, z, _)| span(*a, *z))
            .collect(),
    })
}

// PR1 specialized nonnull constructor/mode-one chooser; UD04 native special
// init/update fragments, with all internal branch destinations based at1000.
const SPECIALIZED: [[u8; 32]; 4] = [
    [
        0xbc, 0xd8, 0x7c, 0x4e, 0xf4, 0xf8, 0xa6, 0x65, 0x56, 0xe0, 0xcb, 0x57, 0xa1, 0x8a, 0x5c,
        0x7d, 0xcf, 0x2, 0x6f, 0xd0, 0x3c, 0xb9, 0x84, 0xc, 0xcf, 0x72, 0x27, 0x4, 0x90, 0x14,
        0x52, 0x69,
    ],
    [
        0x93, 0x1e, 0x88, 0x68, 0xfa, 0xa9, 0xdb, 0x5a, 0x1b, 0xb3, 0x91, 0x8c, 0x17, 0x30, 0x75,
        0x92, 0x12, 0x3a, 0x1b, 0xc7, 0xbb, 0x7e, 0x13, 0x96, 0x48, 0x88, 0x5b, 0x18, 0xff, 0x8c,
        0xb, 0x58,
    ],
    [
        0x7e, 0xcd, 0x63, 0x51, 0x35, 0x85, 0xd, 0xb2, 0x9e, 0x1c, 0xf3, 0xf0, 0xad, 0x1c, 0x26,
        0xab, 0x7d, 0xb5, 0xc, 0x4, 0x88, 0x9a, 0xff, 0xf5, 0xd7, 0x52, 0x6e, 0x94, 0x44, 0x1d,
        0xff, 0x7a,
    ],
    [
        0x3, 0x58, 0x4a, 0xc2, 0x34, 0x1d, 0xbc, 0x2, 0x33, 0xe1, 0xdb, 0xc5, 0x2b, 0xa1, 0x5b,
        0xbd, 0x85, 0x4c, 0xc7, 0x7d, 0x9b, 0xc2, 0x9, 0xf4, 0xa8, 0x37, 0x94, 0x89, 0x51, 0xb3,
        0x52, 0x9b,
    ],
];

/// Opaque native profile-data classification, available only after complete
/// emitted-graph recognition. It grants authority to exact address operands,
/// never to arbitrary instructions or references merely inside a broad range.
#[derive(Clone, Debug)]
pub struct ProfileDataAuthority {
    image_digest: [u8; 32],
    arrays: [Range<usize>; 5],
    fields: Vec<(usize, usize, usize, usize)>,
}
impl ProfileDataAuthority {
    /// The four native scalar tables followed by the diagnostic-string payload.
    /// Exact reference authority alone does not establish exclusive data use.
    pub fn ranges(&self) -> &[Range<usize>; 5] {
        &self.arrays
    }
    /// Four scalar tables whose data consumers are complete canonical profile
    /// algorithms. Joint ownership still requires checking every external ref.
    pub fn scalar_ranges(&self) -> &[Range<usize>] {
        &self.arrays[..4]
    }
    /// Diagnostic strings passed through the separately proved logger service.
    /// Their references do not establish scalar-table exclusivity.
    pub fn diagnostic_range(&self) -> &Range<usize> {
        &self.arrays[4]
    }
    /// Confirm that this authority belongs to these exact immutable Normal bytes
    /// before combining it with any other code/data classification.
    pub fn is_bound_to(&self, normal: &[u8]) -> bool {
        Sha256::digest(normal).as_slice() == self.image_digest
    }
    /// An exact typed data reference: Normal instruction offset, operand index,
    /// and CPU address. Control-transfer operands are never authorized.
    pub fn allow_typed(&self, at: usize, operand_index: usize, value: usize) -> bool {
        self.fields.iter().any(|&(instruction, index, address, _)| {
            instruction == at && index == operand_index && address == value
        })
    }
    /// An exact four-byte address field belonging to a recognized typed operand.
    /// `at` is a Normal byte offset; all other raw pointers remain unclassified.
    pub fn allow_raw(&self, at: usize, value: usize) -> bool {
        self.fields
            .iter()
            .any(|&(_, _, address, field)| field == at && address == value)
    }
}
fn profile_data_authority(
    normal: &[u8],
    code: &[Range<usize>; 13],
    arrays: &[Range<usize>; 5],
) -> Option<ProfileDataAuthority> {
    let mut fields = Vec::new();
    for body in code {
        let mut at = body.start;
        while at < body.end {
            let d = decode_insn(normal.get(at..body.end)?, Target::H8S2000, Mode::Advanced).ok()?;
            for (index, operand) in d.insn.operands.iter().copied().enumerate() {
                let value = match operand {
                    Operand::Immediate { value, bits: 32 }
                    | Operand::Address(Ea::Absolute { value, bits: 32 }) => value,
                    Operand::Address(Ea::Displacement {
                        value, bits: 32, ..
                    }) => value as u32,
                    _ => continue,
                };
                if !value
                    .checked_sub(BASE)
                    .is_some_and(|v| arrays.iter().any(|r| r.contains(&(v as usize))))
                {
                    continue;
                }
                if d.insn.mnemonic != "MOV" {
                    return None;
                }
                let mut changed = d.insn;
                changed.operands[index] = match operand {
                    Operand::Immediate { bits, .. } => Operand::Immediate {
                        value: !value,
                        bits,
                    },
                    Operand::Address(Ea::Absolute { bits, .. }) => Operand::Address(Ea::Absolute {
                        value: !value,
                        bits,
                    }),
                    Operand::Address(Ea::Displacement { base, bits, .. }) => {
                        Operand::Address(Ea::Displacement {
                            value: (!value) as i32,
                            base,
                            bits,
                        })
                    }
                    _ => return None,
                };
                let encoded = encode_insn(changed, Target::H8S2000, Mode::Advanced).ok()?;
                if encoded.len() != d.len {
                    return None;
                }
                let differences: Vec<_> = encoded
                    .iter()
                    .zip(&normal[at..at + d.len])
                    .enumerate()
                    .filter_map(|(i, (a, b))| (a != b).then_some(i))
                    .collect();
                if differences.len() != 4 || differences[3] != differences[0] + 3 {
                    return None;
                }
                let field = at + differences[0];
                if normal[field..field + 4] != value.to_be_bytes() {
                    return None;
                }
                fields.push((at, index, value as usize, field));
            }
            at += d.len;
        }
    }
    Some(ProfileDataAuthority {
        image_digest: Sha256::digest(normal).into(),
        arrays: arrays.clone(),
        fields,
    })
}
