//! Bounded rewriting of the three native parameter-conversion programs.
//!
//! This is one stage of the mechanism correction, not a complete phase change.
//! It copies no installed call addresses or calibration values. Callers own code
//! space reservations and must compose the remaining bundle stages and checksum.
use super::*;
use core::ops::Range;

/// A conversion rewrite could not be proved without modifying its input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// A required native program was absent or ambiguous.
    Unbound(Unbound),
    /// A growing program needs caller-reserved code space.
    SpaceRequired(Element),
    /// A reservation overlaps code, is unaligned, is not stored, or is not erased.
    InvalidSpace,
    /// Call relocation or the detour instruction boundary was not established.
    InvalidProgram,
    /// The output did not bind to the requested native conversions.
    VerificationFailed,
}

struct Program {
    element: Element,
    templates: &'static [Template],
    variant: u8,
    at: usize,
}
fn programs(normal: &[u8]) -> Result<Vec<Program>, Error> {
    let regions = crate::image::regions(normal).ok_or(Error::InvalidProgram)?;
    [
        (Element::CalibrationBase, BASE.as_slice()),
        (Element::CalibrationOffset, OFFSET.as_slice()),
        (Element::CalibrationStep, STEP.as_slice()),
    ]
    .into_iter()
    .map(|(element, templates)| {
        let (variant, at) =
            one_of(normal, &regions.stored, templates, element).map_err(Error::Unbound)?;
        Ok(Program {
            element,
            templates,
            variant,
            at,
        })
    })
    .collect()
}

// Every hole in these complete templates is a 24-bit absolute JSR operand.
// Bind those operands by semantic call order, never by arbitrary byte offsets.
fn calls(template: Template) -> Result<Vec<usize>, Error> {
    let mut found = Vec::new();
    let mut at = 0;
    while at < template.len() {
        if template[at].is_none() {
            if at == 0
                || template[at - 1] != Some(0x5e)
                || template.get(at..at + 3) != Some(&[None, None, None])
            {
                return Err(Error::InvalidProgram);
            }
            found.push(at);
            at += 3;
        } else {
            at += 1;
        }
    }
    Ok(found)
}
fn emit(normal: &[u8], from: &Program, donor: &[u8], desired: &Program) -> Result<Vec<u8>, Error> {
    let before = from.templates[from.variant as usize];
    if from.element != desired.element {
        return Err(Error::InvalidProgram);
    }
    let after = desired.templates[desired.variant as usize];
    let old_calls = calls(before)?;
    let new_calls = calls(after)?;
    if old_calls.len() != new_calls.len() {
        return Err(Error::InvalidProgram);
    }
    // Transplant the actual recognized OEM body. Templates establish its
    // semantics; they are not a source of newly assembled replacement code.
    let mut bytes = donor
        .get(desired.at..desired.at + after.len())
        .ok_or(Error::InvalidProgram)?
        .to_vec();
    for (old, new) in old_calls.into_iter().zip(new_calls) {
        let operand = normal
            .get(from.at + old..from.at + old + 3)
            .ok_or(Error::InvalidProgram)?;
        let address = u32::from_be_bytes([0, operand[0], operand[1], operand[2]]);
        if address & 1 != 0 || address < 0x400000 || address >= 0x410000 + normal.len() as u32 {
            return Err(Error::InvalidProgram);
        }
        bytes[new..new + 3].copy_from_slice(operand);
    }
    Ok(bytes)
}
fn pad_nops(bytes: &mut Vec<u8>, length: usize) -> Result<(), Error> {
    use h8_asm::isa::{encode_insn, Insn, Operand};
    let nop = encode_insn(
        Insn::new("NOP", None, [Operand::None; 3]),
        h8_asm::Target::H8S2000,
        h8_asm::Mode::Advanced,
    )
    .map_err(|_| Error::InvalidProgram)?;
    if length < bytes.len() || (length - bytes.len()) % nop.len() != 0 {
        return Err(Error::InvalidProgram);
    }
    while bytes.len() < length {
        bytes.extend_from_slice(&nop);
    }
    Ok(())
}

fn overlaps(a: &Range<usize>, b: &Range<usize>) -> bool {
    a.start < b.end && b.start < a.end
}

/// Transplant installed base/offset/step routines, retaining target helper calls.
///
/// A growing program requires its corresponding explicit reservation. The
/// reservation's complete range is checked and zero-padded; the original entry
/// becomes a JMP ending at a native instruction boundary. Shrinking programs
/// stay in place, with NOP padding. No checksum or persistent data is changed.
/// Reservations must be independently established as unused executable space;
/// erased bytes alone are not a code-space ownership proof.
pub fn rewrite(
    target: &[u8],
    installed: &[u8],
    reservations: [Option<Range<usize>>; 3],
) -> Result<Vec<u8>, Error> {
    let from = programs(target)?;
    let required = programs(installed)?;
    let regions = crate::image::regions(target).ok_or(Error::InvalidProgram)?;
    let contains = |range: &Range<usize>| {
        regions.stored.iter().any(|r| {
            let start = r.as_ptr() as usize - target.as_ptr() as usize;
            range.start >= start && range.end <= start + r.len()
        })
    };
    let mut writes = Vec::<(Range<usize>, Vec<u8>)>::new();
    for (i, (program, desired)) in from.iter().zip(&required).enumerate() {
        if program.variant == desired.variant {
            continue;
        }
        let bytes = emit(target, program, installed, desired)?;
        let original = program.at..program.at + program.templates[program.variant as usize].len();
        if bytes.len() <= original.len() {
            let mut padded = bytes;
            pad_nops(&mut padded, original.len())?;
            writes.push((original, padded));
        } else {
            let space = reservations[i]
                .clone()
                .ok_or(Error::SpaceRequired(program.element))?;
            if space.start & 1 != 0
                || space.end & 1 != 0
                || space.end < space.start
                || space.len() < bytes.len()
                || !contains(&space)
                || !target
                    .get(space.clone())
                    .is_some_and(|b| b.iter().all(|b| *b == 0xff))
                || from.iter().any(|p| {
                    overlaps(
                        &space,
                        &(p.at..p.at + p.templates[p.variant as usize].len()),
                    )
                })
            {
                return Err(Error::InvalidSpace);
            }
            let mut end = program.at;
            while end < program.at + 4 {
                let instruction = h8_asm::isa::decode_insn(
                    &target[end..original.end],
                    h8_asm::Target::H8S2000,
                    h8_asm::Mode::Advanced,
                )
                .map_err(|_| Error::InvalidProgram)?;
                if instruction.len == 0 {
                    return Err(Error::InvalidProgram);
                }
                end += instruction.len;
            }
            let address = BASE_ADDRESS
                .checked_add(space.start)
                .filter(|a| *a <= 0xffffff)
                .ok_or(Error::InvalidSpace)? as u32;
            use h8_asm::isa::{encode_insn, Ea, Insn, Operand};
            let mut detour = encode_insn(
                Insn::new(
                    "JMP",
                    None,
                    [
                        Operand::Address(Ea::Absolute {
                            value: address,
                            bits: 24,
                        }),
                        Operand::None,
                        Operand::None,
                    ],
                ),
                h8_asm::Target::H8S2000,
                h8_asm::Mode::Advanced,
            )
            .map_err(|_| Error::InvalidProgram)?;
            pad_nops(&mut detour, end - program.at)?;
            let mut relocated = bytes;
            pad_nops(&mut relocated, space.len())?;
            writes.push((program.at..end, detour));
            writes.push((space, relocated));
        }
    }
    for (i, (range, _)) in writes.iter().enumerate() {
        if writes[..i]
            .iter()
            .any(|(earlier, _)| overlaps(range, earlier))
        {
            return Err(Error::InvalidSpace);
        }
    }
    let mut output = target.to_vec();
    for (range, bytes) in writes {
        output[range].copy_from_slice(&bytes);
    }
    let after = programs(&output)?;
    if after
        .iter()
        .zip(&required)
        .any(|(a, b)| a.variant != b.variant)
    {
        return Err(Error::VerificationFailed);
    }
    Ok(output)
}

/// Carry the effective mode-one sign and controller mode convention into target.
/// Both complete native mode branches are bound before the branch polarity can
/// change; the controller's complete ten-byte selection program is also bound.
/// Only these two programs change. Call operands and checksum remain untouched.
pub fn rewrite_controls(target: &[u8], installed: &[u8]) -> Result<Vec<u8>, Error> {
    type ConventionSite = (u8, usize);
    let bind = |normal: &[u8]| -> Result<(ConventionSite, ConventionSite), Error> {
        let regions = crate::image::regions(normal).ok_or(Error::InvalidProgram)?;
        Ok((
            mode_binding(normal, &regions.stored).map_err(Error::Unbound)?,
            one_of(
                normal,
                &regions.stored,
                &CONTROLLER,
                Element::ControllerMode,
            )
            .map_err(Error::Unbound)?,
        ))
    };
    let ((mode, at), (controller, control_at)) = bind(target)?;
    let ((required, _), (required_controller, _)) = bind(installed)?;
    let mut changed = target.to_vec();
    if mode != required {
        changed[at + 6] ^= 1;
    }
    if controller != required_controller {
        let template = CONTROLLER[required_controller as usize];
        for (i, byte) in template.iter().enumerate() {
            changed[control_at + i] = byte.ok_or(Error::InvalidProgram)?;
        }
    }
    let ((after, _), (controller_after, _)) = bind(&changed)?;
    if after != required || controller_after != required_controller {
        return Err(Error::VerificationFailed);
    }
    Ok(changed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(variants: [usize; 3], call_base: u32) -> Vec<u8> {
        let mut normal = alloc::vec![0xff; 0x800];
        for (n, templates) in [BASE.as_slice(), OFFSET.as_slice(), STEP.as_slice()]
            .into_iter()
            .enumerate()
        {
            let template = templates[variants[n]];
            let at = (n + 1) * 0x100;
            let mut bytes: Vec<_> = template.iter().map(|b| b.unwrap_or(0)).collect();
            for (i, operand) in calls(template).unwrap().into_iter().enumerate() {
                bytes[operand..operand + 3]
                    .copy_from_slice(&(call_base + i as u32 * 2).to_be_bytes()[1..]);
            }
            normal[at..at + bytes.len()].copy_from_slice(&bytes);
        }
        normal
    }
    fn spaces() -> [Option<Range<usize>>; 3] {
        [Some(0x500..0x580), Some(0x580..0x600), Some(0x600..0x680)]
    }

    #[test]
    fn every_conversion_form_uses_target_calls_even_when_donor_calls_differ() {
        let conventions = [[0, 0, 0], [1, 1, 1], [1, 2, 2]];
        for a in conventions {
            for b in conventions {
                let target = fixture(a, 0x410600);
                let donor = fixture(b, 0x410700);
                let changed = rewrite(&target, &donor, spaces()).unwrap();
                let actual = programs(&changed).unwrap();
                for (n, p) in actual.iter().enumerate() {
                    assert_eq!(p.variant as usize, b[n], "{a:?} -> {b:?}");
                    for (i, call) in calls(p.templates[p.variant as usize])
                        .unwrap()
                        .into_iter()
                        .enumerate()
                    {
                        assert_eq!(
                            changed[p.at + call..p.at + call + 3],
                            (0x410600 + i as u32 * 2).to_be_bytes()[1..]
                        );
                    }
                }
                let donor_programs = programs(&donor).unwrap();
                for (p, source) in actual.iter().zip(&donor_programs) {
                    let template = source.templates[source.variant as usize];
                    let relocations = calls(template).unwrap();
                    for offset in 0..template.len() {
                        if !relocations
                            .iter()
                            .any(|at| (*at..*at + 3).contains(&offset))
                        {
                            assert_eq!(
                                changed[p.at + offset],
                                donor[source.at + offset],
                                "non-relocation OEM byte {offset}, {a:?} -> {b:?}"
                            );
                        }
                    }
                }
                // The checksum/header bytes belong to the shared composer.
                assert_eq!(changed[..0x100], target[..0x100]);
            }
        }
    }

    #[test]
    fn growth_requires_valid_nonoverlapping_caller_reservations() {
        let target = fixture([0, 0, 0], 0x410600);
        let donor = fixture([1, 1, 1], 0x410700);
        assert_eq!(
            rewrite(&target, &donor, [None, None, None]),
            Err(Error::SpaceRequired(Element::CalibrationBase))
        );
        for bad in [
            [Some(0x501..0x541), Some(0x540..0x584), Some(0x584..0x5b8)],
            [Some(0x500..0x520), Some(0x540..0x584), Some(0x584..0x5b8)],
            [Some(0x500..0x580), Some(0x540..0x584), Some(0x584..0x5b8)],
            [Some(0x100..0x180), Some(0x540..0x584), Some(0x584..0x5b8)],
        ] {
            assert_eq!(rewrite(&target, &donor, bad), Err(Error::InvalidSpace));
        }
        let mut occupied = target.clone();
        occupied[0x510] = 0;
        assert_eq!(
            rewrite(&occupied, &donor, spaces()),
            Err(Error::InvalidSpace)
        );
    }

    #[test]
    fn equal_conversions_are_byte_identical_and_do_not_need_code_space() {
        let target = fixture([1, 2, 2], 0x410600);
        let donor = fixture([1, 2, 2], 0x410700);
        assert_eq!(
            rewrite(&target, &donor, [None, None, None]).unwrap(),
            target
        );
        let mut malformed = target.clone();
        malformed[0x100] ^= 0x80;
        assert!(matches!(
            rewrite(&malformed, &donor, spaces()),
            Err(Error::Unbound(Unbound::Missing(Element::CalibrationBase)))
        ));
        let mut odd_call = target.clone();
        odd_call[0x100 + calls(BASE[1]).unwrap()[0] + 2] |= 1;
        assert_eq!(
            rewrite(&odd_call, &fixture([0, 0, 0], 0x410700), spaces()),
            Err(Error::InvalidProgram)
        );
    }
}
