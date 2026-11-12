//! Whole OEM output representation adaptation. Short callers zero control;
//! full callers output bits 7:6 there. Their shared high-byte leaf alone never
//! establishes equivalent waveform encodings.
use super::*;
use core::ops::Range;
use h8_asm::{
    isa::{decode_insn, Ea, Operand, Reg, Size},
    Mode, Target,
};

/// Native output interpretation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Representation {
    /// Zero control and the high byte of the source word.
    HighByte,
    /// Bits 7:6 in control and the high byte in output.
    SplitTenBits,
}
/// Complete paired callers and their stored encoder leaf.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Binding {
    /// Native source assignment.
    pub pair: PairedPhase,
    /// Encoded output convention.
    pub representation: Representation,
    /// Complete caller spans, by source word.
    pub programs: [Vec<Range<usize>>; 2],
    /// High-byte leaf, including an adjacent identity RTS when present.
    pub leaf: Range<usize>,
}
/// A native representation or bounded transplant was not proved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Complete callers or stored leaves are not recognized.
    Unresolved,
    /// A growing caller needs explicitly owned executable space.
    SpaceRequired,
    /// Space is occupied, overlapping, unaligned, or outside stored bytes.
    InvalidSpace,
    /// The output did not reproduce the required native convention.
    VerificationFailed,
}
fn functions(normal: &[u8], stored: &[&[u8]], pair: &PairedPhase) -> Result<[Function; 2], Error> {
    let bind = |at| {
        full(normal, stored, at)
            .or_else(|| short(normal, stored, at))
            .ok_or(Error::Unresolved)
    };
    Ok([bind(pair.functions[0])?, bind(pair.functions[1])?])
}
/// Decode complete native callers and the actual stored helper instructions.
pub fn observe(normal: &[u8]) -> Result<Binding, Error> {
    let Observation::Known(pair) = discover_pair(normal) else {
        return Err(Error::Unresolved);
    };
    let regions = crate::image::regions(normal).ok_or(Error::Unresolved)?;
    let functions = functions(normal, &regions.stored, &pair)?;
    let (representation, low) = match functions[0].encoder {
        Encoder::Full(high, low) if identity_leaf(normal, &regions.stored, high) => {
            (Representation::SplitTenBits, low)
        }
        Encoder::Short(low) => (Representation::HighByte, low),
        _ => return Err(Error::Unresolved),
    };
    let at = low.checked_sub(0x410000).ok_or(Error::Unresolved)? as usize;
    let leaf = normal.get(at..at + 4).ok_or(Error::Unresolved)?;
    let mov = decode_insn(leaf, Target::H8S2000, Mode::Advanced).map_err(|_| Error::Unresolved)?;
    let ret = decode_insn(&leaf[mov.len..], Target::H8S2000, Mode::Advanced)
        .map_err(|_| Error::Unresolved)?;
    if mov.insn.mnemonic != "MOV"
        || mov.insn.size != Some(Size::Byte)
        || mov.insn.operands
            != [
                Operand::Register(Reg::Byte(0)),
                Operand::Register(Reg::Byte(8)),
                Operand::None,
            ]
        || ret.insn.mnemonic != "RTS"
        || mov.len + ret.len != 4
    {
        return Err(Error::Unresolved);
    }
    let start = if low
        .checked_sub(2)
        .is_some_and(|a| identity_leaf(normal, &regions.stored, a))
    {
        at - 2
    } else {
        at
    };
    if !regions.stored.iter().any(|r| {
        let begin = r.as_ptr() as usize - normal.as_ptr() as usize;
        start >= begin && at + 4 <= begin + r.len()
    }) {
        return Err(Error::Unresolved);
    }
    Ok(Binding {
        pair,
        representation,
        programs: functions.map(|f| f.spans),
        leaf: start..at + 4,
    })
}
/// Copy complete donor callers, retaining physical outputs and target leaves.
/// Growing callers use a whole relocated OEM body and an encoded entry JMP.
/// Reservations correspond to the original target source-word functions. Their
/// ownership is a caller obligation, beyond the erasure and bounds checks here.
/// Waveforms, calibration and full-step offsets remain composition obligations.
pub fn transplant(
    target: &[u8],
    donor: &[u8],
    reservations: [Option<Range<usize>>; 2],
) -> Result<Vec<u8>, Error> {
    let before = observe(target)?;
    let wanted = observe(donor)?;
    let regions = crate::image::regions(target).ok_or(Error::Unresolved)?;
    let donor_regions = crate::image::regions(donor).ok_or(Error::Unresolved)?;
    let destination = functions(target, &regions.stored, &before.pair)?;
    let sources = functions(donor, &donor_regions.stored, &wanted.pair)?;
    let low = 0x410000 + before.leaf.end as u32 - 4;
    if wanted.representation == Representation::SplitTenBits && before.leaf.len() != 6 {
        return Err(Error::Unresolved);
    }
    let mut writes: Vec<(Range<usize>, Vec<u8>)> = Vec::new();
    for (index, function) in destination.iter().enumerate() {
        let source = sources
            .iter()
            .find(|s| s.control == function.control && s.output == function.output)
            .ok_or(Error::Unresolved)?;
        let mut body = source.body.clone();
        let mut at = 0;
        let mut count = 0;
        while at < body.len() {
            let d = decode_insn(&body[at..], Target::H8S2000, Mode::Advanced)
                .map_err(|_| Error::Unresolved)?;
            if d.insn.mnemonic == "JSR" {
                let Operand::Address(Ea::Absolute { value, .. }) = d.insn.operands[0] else {
                    return Err(Error::Unresolved);
                };
                let address = match source.encoder {
                    Encoder::Full(high, _) if value == high => low - 2,
                    Encoder::Full(_, old) | Encoder::Short(old) if value == old => low,
                    _ => return Err(Error::Unresolved),
                };
                encoding::retarget_call(&mut body, at, address).ok_or(Error::Unresolved)?;
                count += 1;
            }
            at += d.len;
        }
        let expected_calls = match source.encoder {
            Encoder::Full(_, _) if source.identity_call.is_some() => 2,
            _ => 1,
        };
        if count != expected_calls || function.spans.len() != 1 {
            return Err(Error::Unresolved);
        }
        let original = function.spans[0].clone();
        let mut entry = target[original.clone()].to_vec();
        encoding::nops(&mut entry).ok_or(Error::Unresolved)?;
        if body.len() <= entry.len() {
            entry[..body.len()].copy_from_slice(&body);
        } else {
            let space = reservations[index].clone().ok_or(Error::SpaceRequired)?;
            if space.start > space.end
                || space.start & 1 != 0
                || space.end & 1 != 0
                || space.len() < body.len()
                || !regions.stored.iter().any(|r| {
                    let begin = r.as_ptr() as usize - target.as_ptr() as usize;
                    space.start >= begin && space.end <= begin + r.len()
                })
                || !target
                    .get(space.clone())
                    .is_some_and(|b| b.iter().all(|v| *v == 255))
                || before
                    .programs
                    .iter()
                    .flatten()
                    .chain([&before.leaf])
                    .any(|r| r.start < space.end && space.start < r.end)
                || writes
                    .iter()
                    .any(|(r, _)| r.start < space.end && space.start < r.end)
            {
                return Err(Error::InvalidSpace);
            }
            let address = u32::try_from(space.start)
                .ok()
                .and_then(|a| a.checked_add(0x410000))
                .filter(|a| *a <= 0xffffff)
                .ok_or(Error::InvalidSpace)?;
            let jump = encoding::jump(address).ok_or(Error::InvalidSpace)?;
            if jump.len() > entry.len() {
                return Err(Error::InvalidSpace);
            }
            entry[..jump.len()].copy_from_slice(&jump);
            let mut emitted = alloc::vec![0; space.len()];
            encoding::nops(&mut emitted).ok_or(Error::InvalidSpace)?;
            emitted[..body.len()].copy_from_slice(&body);
            writes.push((space, emitted));
        }
        writes.push((original, entry));
    }
    let mut output = target.to_vec();
    for (span, bytes) in writes {
        output[span].copy_from_slice(&bytes);
    }
    let after = observe(&output)?;
    if after.representation != wanted.representation
        || after.pair.assignment != wanted.pair.assignment
        || after.leaf != before.leaf
    {
        return Err(Error::VerificationFailed);
    }
    Ok(output)
}
