//! Bind the OEM four-mode calibration consumer through its complete byte-sized
//! validation, RAM stores and fallback path. This is a caller ABI proof, not a
//! claim about unobserved indirect callers or persistent data compatibility.
use super::Error;
use alloc::vec::Vec;
use core::ops::Range;
use h8_asm::{
    isa::{decode_insn, Ea, Operand},
    Mode, Target,
};

// Complete OEM caller grammar; address fields are masked below. These bytes
// recognize existing instructions and are never emitted as replacement code.
const BODY: &[u8] = &[
    0x01, 0x20, 0x6d, 0xf4, 0x18, 0x88, 0x5e, 0, 0, 0, 0x0c, 0x8c, 0x0c, 0x84, 0xf8, 1, 0x5e, 0, 0,
    0, 0x0c, 0x86, 0xf8, 2, 0x5e, 0, 0, 0, 0x0c, 0x8e, 0xf8, 3, 0x5e, 0, 0, 0, 0xac, 0xff, 0x47,
    0x34, 0xa6, 0xff, 0x47, 0x30, 0xae, 0xff, 0x47, 0x2c, 0xa8, 0xff, 0x47, 0x28, 0x7a, 5, 0, 0, 0,
    0, 0x68, 0xd4, 0x7a, 4, 0, 0, 0, 0, 0x68, 0xc6, 0x0c, 0xe0, 0x7a, 6, 0, 0, 0, 0, 0x68, 0xe0,
    0x6a, 0xa8, 0, 0, 0, 0, 0x7a, 0, 0, 0, 0, 0, 0x40, 0x26, 0xf8, 8, 0x7a, 5, 0, 0, 0, 0, 0x68,
    0xd8, 0x7a, 4, 0, 0, 0, 0, 0x68, 0xc8, 0x7a, 6, 0, 0, 0, 0, 0x68, 0xe8, 0x6a, 0xa8, 0, 0, 0, 0,
    0x7a, 0, 0, 0, 0, 0, 0x5e, 0, 0, 0, 0x68, 0x58, 0x5e, 0, 0, 0, 0x68, 0x48, 0x5e, 0, 0, 0, 0x68,
    0x68, 0x5e, 0, 0, 0, 0x01, 0x20, 0x6d, 0x76, 0x54, 0x70,
];
const CALLS: &[usize] = &[7, 17, 25, 33, 131, 137, 143, 149];
const DATA: &[usize] = &[54, 62, 72, 80, 86, 96, 104, 112, 120, 126];

/// Positively bound caller and its four low-byte calibration results.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Binding {
    /// Complete stored caller, including acceptance and default branches.
    pub program: Range<usize>,
    /// Four instruction sites invoking the reader for modes 0 through 3.
    pub calls: [usize; 4],
    /// Native reader entry address in decoded Normal.
    pub reader: usize,
    /// Four consecutive byte-sized RAM destinations used by both branches.
    pub bytes: [u32; 4],
    /// Whole-word reader results select the high byte for modes zero and two.
    /// The other two modes always consume the low byte.
    pub high_byte_modes: bool,
}

/// Recognize the full caller independently of model names and image addresses.
/// Both absolute JSR and the OEM short BSR fourth call must reach the bound
/// reader entry. Each consumed byte is bound explicitly, including a whole-word
/// reader specialized to high bytes for modes zero and two.
pub fn observe(normal: &[u8]) -> Result<Binding, Error> {
    observe_optional(normal)?.ok_or(Error::Unresolved)
}

pub(super) fn observe_optional(normal: &[u8]) -> Result<Option<Binding>, Error> {
    let reader = super::bind(normal)?;
    let regions = crate::image::regions(normal).ok_or(Error::Unresolved)?;
    let mut found = None;
    for relative in [false, true] {
        let mut pattern: Vec<_> = BODY.iter().copied().map(Some).collect();
        for (fields, width) in [(CALLS, 3), (DATA, 4)] {
            for at in fields {
                pattern[*at..*at + width].fill(None);
            }
        }
        for at in [11, 13, 29] {
            pattern[at] = None;
        }
        if relative {
            // The existing relative call is two bytes shorter. All later
            // branches keep their displacement because both ends move together.
            pattern.splice(32..36, [Some(0x55), None]);
        }
        for at in crate::filters::phase::bundle::sites(normal, &regions.stored, &pattern) {
            if found.is_some() {
                return Err(Error::Unresolved);
            }
            let high_byte_modes = match [normal[at + 11], normal[at + 13], normal[at + 29]] {
                [0x8c, 0x84, 0x8e] => false,
                [0x0c, 0x04, 0x0e]
                    if reader.convention == super::Convention::WholeWord
                        && !reader.packed_shape =>
                {
                    true
                }
                _ => return Err(Error::Unresolved),
            };
            let mut calls = Vec::new();
            let mut pos = at;
            let end = at + pattern.len();
            while pos < end {
                let d = decode_insn(&normal[pos..end], Target::H8S2000, Mode::Advanced)
                    .map_err(|_| Error::Unresolved)?;
                if matches!(d.insn.mnemonic, "JSR" | "BSR") {
                    let address = match d.insn.operands[0] {
                        Operand::Address(Ea::Absolute { value, bits: 24 }) => value as usize,
                        Operand::Address(Ea::PcRelative { value, .. }) => (0x410000 + pos + d.len)
                            .checked_add_signed(value as isize)
                            .ok_or(Error::Unresolved)?,
                        _ => return Err(Error::Unresolved),
                    };
                    calls.push((pos, address));
                }
                pos += d.len;
            }
            if calls.len() != 8 || calls[..4].iter().any(|(_, to)| *to != 0x410000 + reader.at) {
                return Err(Error::Unresolved);
            }
            let field = |offset: usize| {
                h8_asm::image::read_u32(normal, at + offset - if relative { 2 } else { 0 })
                    .ok_or(Error::Unresolved)
            };
            let bytes = [field(54)?, field(62)?, field(72)?, field(80)?];
            if bytes != [field(96)?, field(104)?, field(112)?, field(120)?]
                || !(0xa00000..0xb00000 - 3).contains(&bytes[0])
                || bytes != [bytes[0], bytes[0] + 1, bytes[0] + 2, bytes[0] + 3]
            {
                return Err(Error::Unresolved);
            }
            found = Some(Binding {
                program: at..end,
                calls: [calls[0].0, calls[1].0, calls[2].0, calls[3].0],
                reader: reader.at,
                bytes,
                high_byte_modes,
            });
        }
    }
    let Some(binding) = found else {
        return Ok(None);
    };
    // Refuse additional direct entries, including relative calls. Searching
    // instruction-shaped candidates is deliberately conservative: an unproved
    // extra reference is not silently treated as data. Indirect entries still
    // require separate provenance; this does not assert their absence.
    for opcode in [0x5e, 0x5a, 0x55, 0x5c] {
        for at in
            crate::filters::phase::bundle::sites(normal, &regions.stored, &[Some(opcode), None])
        {
            let Ok(d) = decode_insn(&normal[at..], Target::H8S2000, Mode::Advanced) else {
                continue;
            };
            let to = match d.insn.operands[0] {
                Operand::Address(Ea::Absolute { value, bits: 24 }) => Some(value as usize),
                Operand::Address(Ea::PcRelative { value, .. }) => {
                    (0x410000 + at + d.len).checked_add_signed(value as isize)
                }
                _ => None,
            };
            if to == Some(0x410000 + reader.at) && !binding.calls.contains(&at) {
                return Err(Error::Unresolved);
            }
        }
    }
    Ok(Some(binding))
}

/// Preserve packed-byte storage using a whole-word OEM reader and the already
/// bound constant-mode caller. Select R0H at the three existing mode-zero/two
/// MOV.B consumers; no instruction is inserted, no entry or helper is moved.
pub(super) fn select_bytes(normal: &[u8], donor: &[u8], high: bool) -> Result<Vec<u8>, Error> {
    use h8_asm::isa::{encode_insn, Reg};
    let reader = super::bind(normal)?;
    let source = super::bind(donor)?;
    let before = observe(normal)?;
    let source_caller = observe(donor)?;
    if reader.convention != super::Convention::WholeWord
        || reader.packed_shape
        || high
            != (source.convention == super::Convention::PackedBytes
                || source_caller.high_byte_modes)
    {
        return Err(Error::Unresolved);
    }
    if before.high_byte_modes == high {
        return Ok(normal.to_vec());
    }
    let mut changed = normal.to_vec();
    for offset in [10, 12, 28] {
        let at = before.program.start + offset;
        let mut insn = decode_insn(&normal[at..], Target::H8S2000, Mode::Advanced)
            .map_err(|_| Error::Unresolved)?
            .insn;
        if insn.mnemonic != "MOV"
            || insn.operands[0]
                != Operand::Register(Reg::Byte(if before.high_byte_modes { 0 } else { 8 }))
        {
            return Err(Error::Unresolved);
        }
        // The complete packed donor reader's existing MOV.B R0H,R0L proves
        // which returned byte belongs to these modes. Retarget the target's
        // existing byte consumers instead of introducing a larger reader.
        let selection_bytes = if source.convention == super::Convention::PackedBytes {
            &source.body.bytes[56..]
        } else {
            &donor[source_caller.program.start + 10..]
        };
        let selection = decode_insn(selection_bytes, Target::H8S2000, Mode::Advanced)
            .map_err(|_| Error::Unresolved)?
            .insn;
        if selection.mnemonic != "MOV"
            || selection.operands[0] != Operand::Register(Reg::Byte(if high { 0 } else { 8 }))
        {
            return Err(Error::Unresolved);
        }
        insn.operands[0] = selection.operands[0];
        let encoded =
            encode_insn(insn, Target::H8S2000, Mode::Advanced).map_err(|_| Error::Unresolved)?;
        if encoded.len() != 2 {
            return Err(Error::Unresolved);
        }
        changed[at..at + 2].copy_from_slice(&encoded);
    }
    if observe(&changed)?
        != (Binding {
            high_byte_modes: high,
            ..before
        })
    {
        return Err(Error::VerificationFailed);
    }
    Ok(changed)
}
