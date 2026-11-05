//! Native source-word exchange stage, preserving the physical output operands.
//! This composes with step/table/conversion stages; it is not a complete phase
//! correction on its own. Explicit code-space ownership belongs to its caller.
use super::*;
use core::ops::Range;

/// A source-word rewrite could not be proved.
#[derive(Clone, Debug, PartialEq, Eq)]
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

fn jsr(output: &mut Vec<u8>, address: u32) {
    output.push(0x5e);
    output.extend_from_slice(&address.to_be_bytes()[1..]);
}
fn load(output: &mut Vec<u8>, word: u8, reg: u8, padded: bool) {
    if word == 0 {
        output.extend_from_slice(&[0x69, reg]);
        if padded {
            output.extend_from_slice(&[0, 0]);
        }
    } else {
        output.extend_from_slice(&[0x6f, reg, 0, 2]);
    }
}

fn emit(function: &Function, desired_word: u8, padded: bool, inline: bool) -> Vec<u8> {
    let mut output = Vec::new();
    match function.encoder {
        Encoder::Full(high, low) => {
            output.extend_from_slice(&[
                1, 0, 0x6d, 0xf3, 0x1a, 0xb3, 0x0c, 0x8b, 0x10, 0x73, 0x0a, 0x93,
            ]);
            load(&mut output, desired_word, 0x30, padded);
            if inline {
                output.extend_from_slice(&[0, 0]);
            } else {
                jsr(&mut output, high);
            }
            output.extend_from_slice(&[
                0x0c,
                0x80,
                0x12,
                0xc0,
                0xe0,
                3,
                0x6a,
                0x80,
                0xf9,
                function.control,
            ]);
            load(&mut output, desired_word, 0x30, padded);
            if inline {
                output.extend_from_slice(&[0x0c, 8]);
            } else {
                jsr(&mut output, low);
            }
            output.extend_from_slice(&[
                0x6a,
                0x88,
                0xf9,
                function.output,
                1,
                0,
                0x6d,
                0x73,
                0x54,
                0x70,
            ]);
        }
        Encoder::Short(callee) => {
            output.extend_from_slice(&[
                0x0c,
                0x8a,
                0x1a,
                0x80,
                0x6a,
                0x80,
                0xf9,
                function.control,
                0x0c,
                0xa8,
                0x10,
                0x70,
                0x0a,
                0x90,
            ]);
            load(&mut output, desired_word, 0, false);
            jsr(&mut output, callee);
            output.extend_from_slice(&[0x6a, 0x88, 0xf9, function.output, 0x54, 0x70]);
        }
    }
    output
}

fn bound_functions(normal: &[u8], proof: &PairedPhase) -> Result<Vec<Function>, Error> {
    let functions: Option<Vec<_>> = proof
        .functions
        .iter()
        .map(|at| full(normal, *at).or_else(|| short(normal, *at)))
        .collect();
    if let Some(functions) = functions {
        return Ok(functions);
    }
    // The padded/inline grammar has already proved its complete two-function
    // body and both leaf entries. Recover its bound calls to emit either source
    // assignment, including a byte-exact return to the unpadded native program.
    let regions = crate::image::regions(normal).ok_or(Error::Unresolved)?;
    let at = proof.functions[0];
    if adapted::paired(normal, at, &regions.stored).as_ref() != Some(proof) {
        return Err(Error::Unresolved);
    }
    let address = |offset: usize| {
        u32::from_be_bytes([0, normal[offset], normal[offset + 1], normal[offset + 2]])
    };
    let encoder = Encoder::Full(address(at + 17), address(at + 35));
    Ok((0..2)
        .map(|word| Function {
            word: word as u8,
            control: normal[proof.operands[word][0]],
            output: normal[proof.operands[word][1]],
            encoder,
            start: proof.functions[word],
            end: proof.functions[word] + if word == 0 { 48 } else { 44 },
            operands: proof.operands[word],
        })
        .collect())
}

/// Exchange the source words read by the paired native output functions.
///
/// Physical output/control registers and existing callees remain unchanged.
/// The complete identity/high-byte leaf permits a bounded padded/inline form
/// when two adjacent full-word functions exchange widths. Otherwise a growing
/// function needs an explicit caller-owned reservation and receives a JMP entry.
/// This changes no checksum, waveform table or persistent data.
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
    let functions = bound_functions(normal, &proof)?;
    let regions = crate::image::regions(normal).ok_or(Error::Unresolved)?;
    let contains = |span: &Range<usize>| {
        regions.stored.iter().any(|r| {
            let origin = r.as_ptr() as usize - normal.as_ptr() as usize;
            span.start >= origin && span.end <= origin + r.len()
        })
    };
    let inline = functions[1].start < functions[0].start
        && functions[1].end == functions[0].start
        && functions[1].end - functions[1].start == 48
        && functions[0].end - functions[0].start == 44
        && proof.assignment == Assignment::Swapped
        && target == Assignment::Direct
        && match functions[0].encoder {
            Encoder::Full(high, low) if low == high + 2 => {
                high.checked_sub(0x410000).is_some_and(|at| {
                    let at = at as usize;
                    contains(&(at..at + 6))
                        && normal.get(at..at + 6) == Some(&[0x54, 0x70, 0x0c, 8, 0x54, 0x70][..])
                })
            }
            _ => false,
        };
    let mut output = normal.to_vec();
    let mut used_space = false;
    for function in &functions {
        let bytes = emit(
            function,
            function.word ^ 1,
            inline && function.word == 1,
            inline && function.word == 0,
        );
        let width = function.end - function.start;
        if bytes.len() <= width {
            crate::filters::phase::native::encoding::nops(
                &mut output[function.start..function.end],
            )
            .ok_or(Error::InvalidSpace)?;
            output[function.start..function.start + bytes.len()].copy_from_slice(&bytes);
        } else {
            let space = reservation.clone().ok_or(Error::SpaceRequired)?;
            if used_space
                || space.start & 1 != 0
                || space.end & 1 != 0
                || space.start > space.end
                || space.len() < bytes.len()
                || !contains(&space)
                || functions
                    .iter()
                    .any(|f| space.start < f.end && f.start < space.end)
                || !normal
                    .get(space.clone())
                    .is_some_and(|b| b.iter().all(|b| *b == 0xff))
            {
                return Err(Error::InvalidSpace);
            }
            let address = 0x410000usize
                .checked_add(space.start)
                .filter(|a| *a <= 0xffffff)
                .ok_or(Error::InvalidSpace)? as u32;
            let mut end = function.start;
            while end < function.start + 4 {
                let decoded = h8_asm::isa::decode_insn(
                    &normal[end..function.end],
                    h8_asm::Target::H8S2000,
                    h8_asm::Mode::Advanced,
                )
                .map_err(|_| Error::Unresolved)?;
                if decoded.len == 0 {
                    return Err(Error::Unresolved);
                }
                end += decoded.len;
            }
            crate::filters::phase::native::encoding::nops(&mut output[function.start..end])
                .ok_or(Error::InvalidSpace)?;
            output[function.start..function.start + 4].copy_from_slice(
                &crate::filters::phase::native::encoding::jump(address)
                    .ok_or(Error::InvalidSpace)?,
            );
            crate::filters::phase::native::encoding::nops(&mut output[space.clone()])
                .ok_or(Error::InvalidSpace)?;
            output[space.start..space.start + bytes.len()].copy_from_slice(&bytes);
            used_space = true;
        }
    }
    if !matches!(discover_pair(&output),Observation::Known(p) if p.assignment==target) {
        return Err(Error::VerificationFailed);
    }
    Ok(output)
}

/// Copy complete donor channel functions, preserving physical output/control
/// coordinates and relocating helper calls to the target. Both sides must have
/// the same native encoder ABI. Growth requires caller-owned executable space.
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
    // Exact original function bodies only: adapted synthesized forms are not
    // treated as OEM transplant sources by this entry point.
    let parse = |image: &[u8], pair: &PairedPhase| {
        pair.functions
            .iter()
            .map(|at| full(image, *at).or_else(|| short(image, *at)))
            .collect::<Option<Vec<_>>>()
            .ok_or(Error::Unresolved)
    };
    let functions = parse(normal, &proof)?;
    let donor_functions = parse(donor, &required)?;
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
            (Encoder::Full(high, low), Encoder::Full(_, _)) => alloc::vec![high, low],
            (Encoder::Short(callee), Encoder::Short(_)) => alloc::vec![callee],
            _ => return Err(Error::Unresolved),
        };
        let mut bytes = donor[source.start..source.end].to_vec();
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
        let width = function.end - function.start;
        if bytes.len() <= width {
            crate::filters::phase::native::encoding::nops(
                &mut output[function.start..function.end],
            )
            .ok_or(Error::InvalidSpace)?;
            output[function.start..function.start + bytes.len()].copy_from_slice(&bytes);
        } else {
            let space = reservation.clone().ok_or(Error::SpaceRequired)?;
            if used_space
                || space.start & 1 != 0
                || space.end & 1 != 0
                || space.start > space.end
                || space.len() < bytes.len()
                || !contains(&space)
                || functions
                    .iter()
                    .any(|f| space.start < f.end && f.start < space.end)
                || !normal
                    .get(space.clone())
                    .is_some_and(|b| b.iter().all(|b| *b == 0xff))
            {
                return Err(Error::InvalidSpace);
            }
            let address = 0x410000usize
                .checked_add(space.start)
                .filter(|a| *a <= 0xffffff)
                .ok_or(Error::InvalidSpace)? as u32;
            let mut end = function.start;
            while end < function.start + 4 {
                let decoded = h8_asm::isa::decode_insn(
                    &normal[end..function.end],
                    h8_asm::Target::H8S2000,
                    h8_asm::Mode::Advanced,
                )
                .map_err(|_| Error::Unresolved)?;
                if decoded.len == 0 {
                    return Err(Error::Unresolved);
                }
                end += decoded.len;
            }
            crate::filters::phase::native::encoding::nops(&mut output[function.start..end])
                .ok_or(Error::InvalidSpace)?;
            output[function.start..function.start + 4].copy_from_slice(
                &crate::filters::phase::native::encoding::jump(address)
                    .ok_or(Error::InvalidSpace)?,
            );
            crate::filters::phase::native::encoding::nops(&mut output[space.clone()])
                .ok_or(Error::InvalidSpace)?;
            output[space.start..space.start + bytes.len()].copy_from_slice(&bytes);
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
        for range in [0x301..0x341, 0x300..0x310, 0x20..0x80, 0x300..0x900] {
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
}
