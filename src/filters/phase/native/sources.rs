//! Native source-word exchange stage, preserving the physical output operands.
//! This composes with step/table/conversion stages; it is not a complete phase
//! correction on its own. Explicit code-space ownership belongs to its caller.
use super::*;
use core::ops::Range;

/// A source-word rewrite could not be proved.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// A complete unambiguous paired program was not bound.
    Unresolved,
    /// A growing function needs caller-reserved executable space.
    SpaceRequired,
    /// The reservation is unaligned, occupied, outside stored bytes or overlaps code.
    InvalidSpace,
    /// The rewritten program did not establish the requested source assignment.
    VerificationFailed,
}

fn bound_functions(normal: &[u8], proof: &PairedPhase) -> Result<Vec<Function>, Error> {
    let regions = crate::image::regions(normal).ok_or(Error::Unresolved)?;
    proof
        .functions
        .iter()
        .map(|at| {
            full(normal, &regions.stored, *at).or_else(|| short(normal, &regions.stored, *at))
        })
        .collect::<Option<Vec<_>>>()
        .ok_or(Error::Unresolved)
}

/// Exchange the two existing OEM source routines, retaining physical outputs
/// and target callees. The donor view changes only the verified output operands;
/// all routine instructions are copied from this image through `transplant`.
pub fn rewrite(
    normal: &[u8],
    target: Assignment,
    reservation: Option<Range<usize>>,
) -> Result<Vec<u8>, Error> {
    let Observation::Known(proof) = discover_pair(normal) else {
        return Err(Error::Unresolved);
    };
    if proof.assignment == target {
        return Ok(normal.to_vec());
    }
    let donor = super::correct_pair(normal, target).map_err(|error| match error {
        CorrectionError::VerificationFailed => Error::VerificationFailed,
        CorrectionError::Unresolved | CorrectionError::InvalidNormal => Error::Unresolved,
    })?;
    transplant(normal, &donor, reservation)
}

/// Copy complete donor channel functions, preserving physical output/control
/// coordinates and relocating helper calls to the target. Both sides must have
/// the same native encoder ABI. Growth reuses the original routine footprint
/// and spills only whole-instruction overflow into caller-owned executable space.
/// A direct call to a verified stored RTS is removed from the copied body.
/// This stage changes no waveform data, persistent values or image integrity.
pub fn transplant(
    normal: &[u8],
    donor: &[u8],
    reservation: Option<Range<usize>>,
) -> Result<Vec<u8>, Error> {
    let Observation::Known(proof) = discover_pair(normal) else {
        return Err(Error::Unresolved);
    };
    let Observation::Known(required) = discover_pair(donor) else {
        return Err(Error::Unresolved);
    };
    // Complete OEM bodies, contiguous or split: legacy synthesized forms are not
    // treated as OEM transplant sources by this entry point.
    let functions = bound_functions(normal, &proof)?;
    let donor_functions = bound_functions(donor, &required)?;
    let regions = crate::image::regions(normal).ok_or(Error::Unresolved)?;
    let contains = |span: &Range<usize>| {
        regions.stored.iter().any(|r| {
            let origin = r.as_ptr() as usize - normal.as_ptr() as usize;
            span.start >= origin && span.end <= origin + r.len()
        })
    };
    let mut output = normal.to_vec();
    let mut used_space = false;
    for function in &functions {
        let source = donor_functions
            .iter()
            .find(|candidate| {
                candidate.control == function.control && candidate.output == function.output
            })
            .ok_or(Error::Unresolved)?;
        let calls: Vec<u32> = match (function.encoder, source.encoder) {
            (Encoder::Full(high, low), Encoder::Full(_, _)) => {
                if source.identity_call.is_some() {
                    alloc::vec![high, low]
                } else if identity_leaf(normal, &regions.stored, high) {
                    alloc::vec![low]
                } else {
                    return Err(Error::Unresolved);
                }
            }
            (Encoder::Short(callee), Encoder::Short(_)) => alloc::vec![callee],
            _ => return Err(Error::Unresolved),
        };
        let mut bytes = source.body.clone();
        let mut next_call = calls.into_iter();
        let mut at = 0;
        while at < bytes.len() {
            let decoded = h8_asm::isa::decode_insn(
                &bytes[at..],
                h8_asm::Target::H8S2000,
                h8_asm::Mode::Advanced,
            )
            .map_err(|_| Error::Unresolved)?;
            if decoded.insn.mnemonic == "JSR" {
                if decoded.len != 4 || bytes[at] != 0x5e {
                    return Err(Error::Unresolved);
                }
                let address = next_call.next().ok_or(Error::Unresolved)?;
                super::encoding::retarget_call(&mut bytes, at, address).ok_or(Error::Unresolved)?;
            }
            at += decoded.len;
        }
        if next_call.next().is_some() {
            return Err(Error::Unresolved);
        }
        if bytes == function.body {
            continue;
        }
        // Elide only a complete direct call whose target is a stored RTS.
        // Remaining bytes are copied OEM instructions; no replacement algorithm.
        if let (Encoder::Full(high, _), Some(call)) = (function.encoder, &source.identity_call) {
            if identity_leaf(normal, &regions.stored, high) {
                bytes.drain(call.clone());
            }
        }
        if bytes == function.body {
            continue;
        }
        let original = function.spans.first().ok_or(Error::Unresolved)?.clone();
        let width = original.len();
        // Retire all previously owned pieces before placing the new OEM body.
        for span in &function.spans {
            super::encoding::nops(&mut output[span.clone()]).ok_or(Error::InvalidSpace)?;
        }
        if bytes.len() <= width {
            output[original.start..original.start + bytes.len()].copy_from_slice(&bytes);
        } else {
            let space = reservation.clone().ok_or(Error::SpaceRequired)?;
            let old_spill = function.spans.get(1);
            if used_space
                || space.start & 1 != 0
                || space.end & 1 != 0
                || space.start >= space.end
                || !contains(&space)
                || functions.iter().flat_map(|f| &f.spans).any(|span| {
                    space.start < span.end && span.start < space.end && Some(span) != old_spill
                })
                || (!normal
                    .get(space.clone())
                    .is_some_and(|b| b.iter().all(|b| *b == 0xff))
                    && old_spill != Some(&space))
            {
                return Err(Error::InvalidSpace);
            }
            let address = u32::try_from(space.start)
                .ok()
                .and_then(|a| a.checked_add(0x410000))
                .filter(|a| *a <= 0xffffff)
                .ok_or(Error::InvalidSpace)?;
            let (prefix, spill) = super::placement::split_closed(
                &bytes,
                0x410000 + original.start as u32,
                width,
                address,
            )
            .ok_or(Error::InvalidSpace)?;
            if spill.len() > space.len() {
                return Err(Error::InvalidSpace);
            }
            output[original].copy_from_slice(&prefix);
            super::encoding::nops(&mut output[space.clone()]).ok_or(Error::InvalidSpace)?;
            output[space.start..space.start + spill.len()].copy_from_slice(&spill);
            used_space = true;
        }
    }
    if !matches!(discover_pair(&output),Observation::Known(p) if p.assignment==required.assignment)
    {
        return Err(Error::VerificationFailed);
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_and_short_functions_exchange_sources_without_changing_outputs_or_callees() {
        for short in [false, true] {
            let mut original = super::super::tests::fixture(short);
            original.resize(0x800, 0xff);
            let Observation::Known(before) = discover_pair(&original) else {
                panic!("fixture");
            };
            let functions = bound_functions(&original, &before).unwrap();
            let changed = rewrite(&original, Assignment::Swapped, Some(0x300..0x340)).unwrap();
            let Observation::Known(after) = discover_pair(&changed) else {
                panic!("rewritten pair");
            };
            assert_eq!(after.assignment, Assignment::Swapped);
            let actual = bound_functions(&changed, &after).unwrap();
            for previous in &functions {
                let next = actual
                    .iter()
                    .find(|f| f.control == previous.control)
                    .unwrap();
                assert_eq!(next.output, previous.output);
                assert_eq!(next.encoder, previous.encoder);
                assert_eq!(next.word, previous.word ^ 1);
            }
            assert_eq!(changed[..24], original[..24]);
            for (i, (a, b)) in original.iter().zip(&changed).enumerate() {
                assert!(
                    a == b
                        || functions.iter().any(|f| (f.start..f.end).contains(&i))
                        || (0x300..0x340).contains(&i)
                );
            }
            assert_eq!(
                rewrite(&changed, Assignment::Swapped, None).unwrap(),
                changed
            );
        }
    }

    #[test]
    fn required_code_space_is_explicit_and_rejects_occupied_or_overlapping_ranges() {
        let mut original = super::super::tests::fixture(false);
        original.resize(0x800, 0xff);
        assert_eq!(
            rewrite(&original, Assignment::Swapped, None),
            Err(Error::SpaceRequired)
        );
        for range in [0x301..0x341, 0x300..0x308, 0x20..0x80, 0x300..0x900] {
            assert_eq!(
                rewrite(&original, Assignment::Swapped, Some(range)),
                Err(Error::InvalidSpace)
            );
        }
        original[0x310] = 0;
        assert_eq!(
            rewrite(&original, Assignment::Swapped, Some(0x300..0x340)),
            Err(Error::InvalidSpace)
        );
    }

    #[test]
    fn donor_view_verification_failure_is_reported_as_such() {
        // Agreeing legacy split-word evidence also fixes this image's
        // assignment, so exchanging only the pair cannot verify.
        let t = super::super::templates::TEMPLATES
            .iter()
            .find(|t| {
                t.interface == Interface::SplitWord
                    && t.assignment == Assignment::Direct
                    && !t.requires_leaf
            })
            .unwrap();
        let mut normal = super::super::tests::fixture(false);
        normal.resize(0x200000, 0xff);
        let at = (t.reference_cpu - 0x410000) as usize;
        normal[at..at + t.bytes.len()].copy_from_slice(t.bytes);
        assert!(matches!(
            discover(&normal),
            Observation::Known(Phase {
                assignment: Assignment::Direct,
                interface: Interface::SplitWord
            })
        ));
        assert_eq!(
            correct_pair(&normal, Assignment::Swapped),
            Err(CorrectionError::VerificationFailed)
        );
        assert_eq!(
            rewrite(&normal, Assignment::Swapped, None),
            Err(Error::VerificationFailed)
        );
    }
}

#[cfg(test)]
mod transplant_tests {
    use super::*;
    #[test]
    fn immediate_return_call_is_removed_and_source_correction_needs_no_spill() {
        use h8_asm::{
            isa::{decode_insn, encode_insn, Insn, Operand},
            Mode, Target,
        };
        let mut original = super::super::tests::fixture(false);
        original.resize(0x800, 0xff);
        let rts = encode_insn(
            Insn::new("RTS", None, [Operand::None; 3]),
            Target::H8S2000,
            Mode::Advanced,
        )
        .unwrap();
        original[398..400].copy_from_slice(&rts);
        for start in [32, 160] {
            let f = full(&original, &[original.as_slice()], start).unwrap();
            let mut at = start;
            let mut high = true;
            while at < f.end {
                let d = decode_insn(&original[at..], Target::H8S2000, Mode::Advanced).unwrap();
                if d.insn.mnemonic == "JSR" {
                    super::super::encoding::retarget_call(
                        &mut original,
                        at,
                        if high { 0x41018e } else { 0x410190 },
                    )
                    .unwrap();
                    high = false;
                }
                at += d.len;
            }
        }
        let Observation::Known(before) = discover_pair(&original) else {
            panic!("pair");
        };
        let mut donor = original.clone();
        for operands in before.operands {
            for at in operands {
                donor[at] ^= 1;
            }
        }
        let changed = transplant(&original, &donor, None).unwrap();
        let Observation::Known(after) = discover_pair(&changed) else {
            panic!("optimized pair");
        };
        let functions = bound_functions(&changed, &after).unwrap();
        assert_eq!(
            functions.iter().map(|f| f.body.len()).collect::<Vec<_>>(),
            [40, 44]
        );
        assert!(functions
            .iter()
            .all(|f| f.identity_call.is_none() && f.spans.len() == 1));
        assert_eq!(transplant(&changed, &donor, None).unwrap(), changed);
        let reversed = transplant(&changed, &original, None).unwrap();
        assert!(
            matches!(discover_pair(&reversed), Observation::Known(p) if p.assignment == before.assignment)
        );
        assert_eq!(&changed[256..], &original[256..]);
        // One actual instruction before RTS means real work: the call stays.
        let mut nonempty = original.clone();
        super::super::encoding::nops(&mut nonempty[398..400]).unwrap();
        assert_eq!(
            transplant(&nonempty, &donor, None),
            Err(Error::SpaceRequired)
        );
        let mut invalid = changed.clone();
        super::super::encoding::nops(&mut invalid[398..400]).unwrap();
        assert!(!matches!(discover_pair(&invalid), Observation::Known(_)));
    }

    #[test]
    fn full_and_short_oem_bodies_spill_only_overflow_and_rebind_both_directions() {
        for short in [false, true] {
            let mut original = super::super::tests::fixture(short);
            original.resize(0x800, 0xff);
            let Observation::Known(before) = discover_pair(&original) else {
                panic!("pair");
            };
            let mut donor = original.clone();
            for operands in before.operands {
                for at in operands {
                    donor[at] ^= 1;
                }
            }
            let spill_len = if short { 6 } else { 10 };
            assert_eq!(
                transplant(&original, &donor, None),
                Err(Error::SpaceRequired)
            );
            assert_eq!(
                transplant(&original, &donor, Some(0x300..0x300 + spill_len - 2)),
                Err(Error::InvalidSpace)
            );
            let changed = transplant(&original, &donor, Some(0x300..0x300 + spill_len)).unwrap();
            let Observation::Known(after) = discover_pair(&changed) else {
                panic!("split pair");
            };
            assert_eq!(after.assignment, Assignment::Swapped);
            let functions = bound_functions(&changed, &after).unwrap();
            let split = functions.iter().find(|f| f.spans.len() == 2).unwrap();
            assert_eq!(split.spans[1], 0x300..0x300 + spill_len);
            assert!(before.functions.contains(&split.start));
            // Split OEM output is also a valid donor, without copying its jump.
            assert_eq!(
                transplant(&original, &changed, Some(0x300..0x300 + spill_len)).unwrap(),
                changed
            );
            let mut jump_at = split.start;
            loop {
                let d = h8_asm::isa::decode_insn(
                    &changed[jump_at..],
                    h8_asm::Target::H8S2000,
                    h8_asm::Mode::Advanced,
                )
                .unwrap();
                if d.insn.mnemonic == "JMP" {
                    break;
                }
                jump_at += d.len;
                assert!(jump_at < split.end);
            }
            for destination in [split.start, split.start + 2, 0x7fe] {
                let mut broken = changed.clone();
                let jump = super::super::encoding::jump(0x410000 + destination as u32).unwrap();
                broken[jump_at..jump_at + jump.len()].copy_from_slice(&jump);
                assert!(!matches!(discover_pair(&broken), Observation::Known(_)));
            }
            if !short {
                let mut broken = changed.clone();
                broken[split.end - 1] = 0xff;
                assert!(!matches!(discover_pair(&broken), Observation::Known(_)));
            }

            assert_eq!(transplant(&changed, &donor, None).unwrap(), changed);
            let reversed = transplant(&changed, &original, Some(0x320..0x320 + spill_len)).unwrap();
            let Observation::Known(back) = discover_pair(&reversed) else {
                panic!("reverse");
            };
            assert_eq!(back.assignment, before.assignment);
            for (a, b) in bound_functions(&reversed, &back)
                .unwrap()
                .iter()
                .zip(bound_functions(&original, &before).unwrap())
            {
                assert_eq!(a.body, b.body);
            }
            assert!(reversed[0x300..0x300 + spill_len].iter().all(|b| *b == 0));
            assert_eq!(
                &changed[0x300 + spill_len..0x320],
                &original[0x300 + spill_len..0x320]
            );
        }
    }
}
