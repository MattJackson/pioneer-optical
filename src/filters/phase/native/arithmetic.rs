//! Complete native arithmetic service bodies used by phase code.
//! CPU addresses must be resolved against an authoritative resident-code image,
//! not interpreted as offsets into Normal. Matching proves these bodies and
//! their call linkage; division by zero and overflow are not admitted domains.
use core::ops::Range;

/// Offsets within the caller-supplied resident-code image.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Binding {
    /// Low-32-bit multiply body (ER0 times ER1, result ER0).
    pub multiply: Range<usize>,
    /// Signed division wrapper, taking ER0/ER1.
    pub signed_divide: Range<usize>,
    /// Complete unsigned division core called by the wrapper.
    pub unsigned_divide: Range<usize>,
}
const MULTIPLY: &[u8] = &[
    0x01, 0x10, 0x6d, 0xf2, 0x0d, 0x82, 0x52, 0x12, 0x0d, 0x93, 0x52, 0x03, 0x52, 0x10, 0x09, 0x28,
    0x09, 0x38, 0x01, 0x10, 0x6d, 0x73, 0x54, 0x70,
];
const SIGNED: &[u8] = &[
    0x6d, 0xf2, 0x0d, 0x82, 0x0c, 0x2a, 0x4a, 0x02, 0x17, 0xb0, 0x0d, 0x99, 0x4a, 0x04, 0xd2, 0x80,
    0x17, 0xb1, 0x5e, 0x10, 0x55, 0xae, 0x0c, 0x22, 0x4a, 0x02, 0x17, 0xb0, 0x0c, 0xaa, 0x4a, 0x02,
    0x17, 0xb1, 0x6d, 0x72, 0x54, 0x70,
];
const UNSIGNED: &[u8] = &[
    0x01, 0x00, 0x6d, 0xf2, 0x0d, 0x99, 0x46, 0x10, 0x0d, 0x82, 0x17, 0x72, 0x53, 0x12, 0x0d, 0xa8,
    0x53, 0x10, 0x0d, 0x81, 0x0d, 0x28, 0x40, 0x1e, 0x0f, 0x92, 0x0d, 0x81, 0x17, 0x71, 0x79, 0x08,
    0x00, 0x10, 0x12, 0x10, 0x12, 0x31, 0x1a, 0xa1, 0x44, 0x02, 0x0a, 0xa1, 0x1b, 0x58, 0x46, 0xf2,
    0x12, 0x10, 0x17, 0x10, 0x17, 0x70, 0x01, 0x00, 0x6d, 0x72, 0x54, 0x70,
];

fn span(image: &[u8], base: u32, address: u32, length: usize) -> Option<Range<usize>> {
    if base & 1 != 0 || address & 1 != 0 {
        return None;
    }
    let start = address.checked_sub(base)? as usize;
    let end = start.checked_add(length)?;
    if (address as usize).checked_add(length)? > 0x1000000 {
        return None;
    }
    image.get(start..end)?;
    Some(start..end)
}

/// Bind actual service targets, including the wrapper's unsigned-core call.
/// `base` is the CPU address of `image[0]`; establishing that mapping and its
/// applicability to the installed unit belongs to the caller. This is read-only.
pub fn observe(image: &[u8], base: u32, multiply: u32, divide: u32) -> Option<Binding> {
    let multiply = span(image, base, multiply, MULTIPLY.len())?;
    let signed_divide = span(image, base, divide, SIGNED.len())?;
    if &image[multiply.clone()] != MULTIPLY {
        return None;
    }
    let signed = &image[signed_divide.clone()];
    if !signed
        .iter()
        .zip(SIGNED)
        .enumerate()
        .all(|(i, (a, b))| (19..22).contains(&i) || a == b)
    {
        return None;
    }
    let target = u32::from_be_bytes([0, signed[19], signed[20], signed[21]]);
    let unsigned_divide = span(image, base, target, UNSIGNED.len())?;
    if &image[unsigned_divide.clone()] != UNSIGNED {
        return None;
    }
    Some(Binding {
        multiply,
        signed_divide,
        unsigned_divide,
    })
}

/// Provenance of the complete OEM bodies emitted below: decoded PR1 Normal.
/// The committed `phase-generated-arithmetic.json` fixture records these bytes;
/// source CPU entries are 0x623C4A, 0x6238A4 and 0x6238CA, respectively (Normal
/// file offsets 0x213C4A, 0x2138A4 and 0x2138CA at CPU base 0x410000).
/// Only the signed wrapper's absolute unsigned-core JSR is relocated.
pub const OEM_SOURCE_SHA256: &str =
    "8037cdb3ae67e04a82aa3e9b7a0f52202e17f1e39d1f50b894158d9be0cec898";

/// Exact emitted lengths in multiply, signed divide, unsigned divide order.
pub const fn lengths() -> [usize; 3] {
    [MULTIPLY.len(), SIGNED.len(), UNSIGNED.len()]
}

/// Emit complete OEM services at explicit CPU entries. This provides bytes, not
/// executable-storage ownership or a caller ABI proof. Entries must be aligned,
/// nonoverlapping and entirely within the 24-bit H8 address space. All internal
/// relative branches retain their instruction destinations; the signed wrapper
/// calls the supplied unsigned-core entry. No runtime source image is required.
pub fn emit(entries: [u32; 3]) -> Option<[alloc::vec::Vec<u8>; 3]> {
    use h8_asm::{
        isa::{decode_insn, encode_insn, Ea, Operand},
        Mode, Target,
    };
    let lengths = lengths();
    let mut spans = [0..0, 0..0, 0..0];
    for i in 0..3 {
        let end = entries[i].checked_add(lengths[i] as u32)?;
        if entries[i] & 1 != 0 || end > 0x1000000 {
            return None;
        }
        spans[i] = entries[i]..end;
        if spans[..i]
            .iter()
            .any(|s| s.start < end && entries[i] < s.end)
        {
            return None;
        }
    }
    let mut output = [
        alloc::vec::Vec::new(),
        alloc::vec::Vec::new(),
        alloc::vec::Vec::new(),
    ];
    for (i, body) in [MULTIPLY, SIGNED, UNSIGNED].into_iter().enumerate() {
        let mut at = 0;
        let mut starts = alloc::vec::Vec::new();
        let mut branches = alloc::vec::Vec::new();
        let mut calls = 0;
        while at < body.len() {
            let decoded = decode_insn(&body[at..], Target::H8S2000, Mode::Advanced).ok()?;
            let mut insn = decoded.insn;
            starts.push(at);
            let original = encode_insn(insn, Target::H8S2000, Mode::Advanced).ok()?;
            if original != body[at..at + decoded.len] {
                return None;
            }
            for operand in insn.operands {
                if let Operand::Address(Ea::PcRelative { value, .. }) = operand {
                    branches.push((at + decoded.len).checked_add_signed(value as isize)?);
                }
            }
            if insn.mnemonic == "JSR" {
                if i != 1
                    || at != 18
                    || !matches!(
                        insn.operands[0],
                        Operand::Address(Ea::Absolute { bits: 24, .. })
                    )
                {
                    return None;
                }
                insn.operands[0] = Operand::Address(Ea::Absolute {
                    value: entries[2],
                    bits: 24,
                });
                calls += 1;
            }
            let emitted = encode_insn(insn, Target::H8S2000, Mode::Advanced).ok()?;
            if emitted.len() != decoded.len {
                return None;
            }
            output[i].extend(emitted);
            at += decoded.len;
        }
        if calls != usize::from(i == 1) || branches.iter().any(|to| !starts.contains(to)) {
            return None;
        }
    }
    Some(output)
}
