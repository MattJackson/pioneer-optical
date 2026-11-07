//! Native phase source/output assignment and bounded Normal-code corrections.
//!
//! A correction changes output-register operands in Normal, not servo data or
//! persistent parameters. It does not authorize cross-flashing: platform,
//! layout, other hardware inputs and receiver checks remain separate gates.

/// Native calibration-word reader convention and image-only rewrite.
pub mod calibration;

/// Complete command-relative SAT1 mechanism binding and correction.
pub mod sat1;

/// Native arithmetic services in an explicitly mapped resident-code image.
pub mod arithmetic;

/// Proved native output representations and whole OEM caller adaptation.
pub mod encoders;

/// Bounded source-word exchange stage for complete native paired programs.
pub mod sources;

pub(crate) mod encoding;
pub(crate) mod placement;

use crate::image::layout::{Observation, Unresolved};
use alloc::vec::Vec;

/// Assignment of the two source words to the two output channels.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Assignment {
    /// Source word zero goes to the first output channel.
    Direct,
    /// Source word zero goes to the second output channel.
    Swapped,
}

/// Proven paired native output functions and their correction operands.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PairedPhase {
    /// Source/output assignment, not a physical direction claim.
    pub assignment: Assignment,
    /// Decoded Normal byte offsets of the two complete native functions.
    pub functions: [usize; 2],
    /// Decoded Normal offsets of control/output register operands, by source word.
    pub operands: [[usize; 2]; 2],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Encoder {
    Full(u32, u32),
    Short(u32),
}
#[derive(Clone, Debug)]
struct Function {
    word: u8,
    control: u8,
    output: u8,
    encoder: Encoder,
    start: usize,
    end: usize,
    operands: [usize; 2],
    body: Vec<u8>,
    identity_call: Option<core::ops::Range<usize>>,
    spans: Vec<core::ops::Range<usize>>,
}

fn consume(bytes: &[u8], pos: &mut usize, expected: &[u8]) -> Option<()> {
    let end = pos.checked_add(expected.len())?;
    if bytes.get(*pos..end)? != expected {
        return None;
    }
    *pos = end;
    Some(())
}
fn word(bytes: &[u8], pos: &mut usize, reg: u8) -> Option<u8> {
    if bytes.get(*pos..pos.checked_add(2)?) == Some(&[0x69, reg][..]) {
        *pos += 2;
        Some(0)
    } else {
        consume(bytes, pos, &[0x6f, reg, 0, 2])?;
        Some(1)
    }
}
fn call(bytes: &[u8], pos: &mut usize) -> Option<u32> {
    consume(bytes, pos, &[0x5e])?;
    let b = bytes.get(*pos..pos.checked_add(3)?)?;
    *pos += 3;
    let target = u32::from_be_bytes([0, b[0], b[1], b[2]]);
    (target & 1 == 0).then_some(target)
}
fn identity_leaf(raw: &[u8], address: u32) -> bool {
    let Some(at) = address.checked_sub(0x410000).map(|at| at as usize) else {
        return false;
    };
    let Some(bytes) = raw.get(at..) else {
        return false;
    };
    let Ok(d) = h8_asm::isa::decode_insn(bytes, h8_asm::Target::H8S2000, h8_asm::Mode::Advanced)
    else {
        return false;
    };
    d.insn.mnemonic == "RTS"
        && crate::image::regions(raw).is_some_and(|regions| {
            regions.stored.iter().any(|r| {
                let begin = r.as_ptr() as usize - raw.as_ptr() as usize;
                at >= begin && at + d.len <= begin + r.len()
            })
        })
}

fn full_body(raw: &[u8], b: &[u8], at: usize) -> Option<Function> {
    let mut p = 0;
    consume(
        b,
        &mut p,
        &[
            1, 0, 0x6d, 0xf3, 0x1a, 0xb3, 0x0c, 0x8b, 0x10, 0x73, 0x0a, 0x93,
        ],
    )?;
    let source = word(b, &mut p, 0x30)?;
    let call_start = p;
    let instruction =
        h8_asm::isa::decode_insn(b.get(p..)?, h8_asm::Target::H8S2000, h8_asm::Mode::Advanced)
            .ok()?;
    let high = if instruction.insn.mnemonic == "JSR" {
        Some(call(b, &mut p)?)
    } else {
        None
    };
    let identity_call = high.map(|_| call_start..p);
    consume(
        b,
        &mut p,
        &[0x0c, 0x80, 0x12, 0xc0, 0xe0, 3, 0x6a, 0x80, 0xf9],
    )?;
    let control_at = at + p;
    let control = *b.get(p)?;
    p += 1;
    if word(b, &mut p, 0x30)? != source {
        return None;
    }
    let low = call(b, &mut p)?;
    let high = match high {
        Some(high) => high,
        None => {
            let high = low.checked_sub(2)?;
            if !identity_leaf(raw, high) {
                return None;
            }
            high
        }
    };
    if low != high.checked_add(2)?
        || high < 0x400000
        || usize::try_from(low).ok()? >= 0x410000usize.checked_add(raw.len())?
    {
        return None;
    }
    consume(b, &mut p, &[0x6a, 0x88, 0xf9])?;
    let output_at = at + p;
    let output = *b.get(p)?;
    p += 1;
    consume(b, &mut p, &[1, 0, 0x6d, 0x73, 0x54, 0x70])?;
    Some(Function {
        word: source,
        control,
        output,
        encoder: Encoder::Full(high, low),
        start: at,
        end: at + p,
        operands: [control_at, output_at],
        body: b[..p].to_vec(),
        identity_call,
        spans: alloc::vec![at..at + p],
    })
}
fn short_body(raw: &[u8], b: &[u8], at: usize) -> Option<Function> {
    let mut p = 0;
    consume(b, &mut p, &[0x0c, 0x8a, 0x1a, 0x80, 0x6a, 0x80, 0xf9])?;
    let control_at = at + p;
    let control = *b.get(p)?;
    p += 1;
    consume(b, &mut p, &[0x0c, 0xa8, 0x10, 0x70, 0x0a, 0x90])?;
    let source = word(b, &mut p, 0)?;
    let callee = call(b, &mut p)?;
    let leaf = usize::try_from(callee.checked_sub(0x410000)?).ok()?;
    if raw.get(leaf..leaf.checked_add(4)?) != Some(&[0x0c, 8, 0x54, 0x70][..]) {
        return None;
    }
    consume(b, &mut p, &[0x6a, 0x88, 0xf9])?;
    let output_at = at + p;
    let output = *b.get(p)?;
    p += 1;
    consume(b, &mut p, &[0x54, 0x70])?;
    Some(Function {
        word: source,
        control,
        output,
        encoder: Encoder::Short(callee),
        start: at,
        end: at + p,
        operands: [control_at, output_at],
        body: b[..p].to_vec(),
        identity_call: None,
        spans: alloc::vec![at..at + p],
    })
}

// Existing OEM grammars remain the authority; placement only reconstructs their
// instruction stream across a single typed JMP. Operand coordinates remain physical.
fn split_function(
    raw: &[u8],
    at: usize,
    lengths: &[usize],
    parse: fn(&[u8], &[u8], usize) -> Option<Function>,
) -> Option<Function> {
    let regions = crate::image::regions(raw)?;
    for length in lengths {
        let Some(mut body) = placement::read(raw, &regions.stored, at, &alloc::vec![None; *length])
        else {
            continue;
        };
        if body.spans.len() != 2 {
            continue;
        }
        let Some(mut function) = parse(raw, &body.bytes, at) else {
            continue;
        };
        if function.body.len() != body.bytes.len() {
            continue;
        }
        let prefix = body.spans[0]
            .len()
            .checked_sub(encoding::jump(0x410000)?.len())?;
        for operand in &mut function.operands {
            let logical = operand.checked_sub(at)?;
            *operand = if logical < prefix {
                at + logical
            } else {
                body.spans[1].start + logical - prefix
            };
        }
        // Full-word growth leaves a typed NOP after its detour. Require the
        // complete canonical 44-byte entry footprint so a later replacement
        // can reclaim that padding rather than losing two bytes per rewrite.
        let footprint = *lengths.first()?;
        while body.spans[0].end < at.checked_add(footprint)? {
            let end = body.spans[0].end;
            let nop = h8_asm::isa::decode_insn(
                raw.get(end..)?,
                h8_asm::Target::H8S2000,
                h8_asm::Mode::Advanced,
            )
            .ok()?;
            if nop.insn.mnemonic != "NOP"
                || end + nop.len > at + footprint
                || !regions.stored.iter().any(|r| {
                    let begin = r.as_ptr() as usize - raw.as_ptr() as usize;
                    end >= begin && end + nop.len <= begin + r.len()
                })
            {
                return None;
            }
            body.spans[0].end += nop.len;
        }
        if body.spans[0].start < body.spans[1].end && body.spans[1].start < body.spans[0].end {
            return None;
        }
        function.end = body.spans[0].end;
        function.body = body.bytes;
        function.spans = body.spans;
        return Some(function);
    }
    None
}
fn full(raw: &[u8], at: usize) -> Option<Function> {
    let mut f = full_body(raw, raw.get(at..)?, at)
        .or_else(|| split_function(raw, at, &[44, 48], full_body))?;
    if f.identity_call.is_none() && f.body.len() == 40 {
        let mut end = f.end;
        while end < at + 44 {
            let d = h8_asm::isa::decode_insn(
                raw.get(end..)?,
                h8_asm::Target::H8S2000,
                h8_asm::Mode::Advanced,
            )
            .ok()?;
            if d.insn.mnemonic != "NOP" || end + d.len > at + 44 {
                break;
            }
            end += d.len;
        }
        if end == at + 44 {
            f.end = end;
            f.spans[0].end = end;
        }
    }
    Some(f)
}
fn short(raw: &[u8], at: usize) -> Option<Function> {
    short_body(raw, raw.get(at..)?, at).or_else(|| split_function(raw, at, &[26, 28], short_body))
}

/// Recognize the complete paired output functions in decoded H8 Normal.
/// Both source words must share an encoder and cover opposite output channels.
/// Missing, duplicate, half-swapped or unrelated helpers are unresolved.
pub fn discover_pair(normal: &[u8]) -> Observation<PairedPhase> {
    let Some(regions) = crate::image::regions(normal) else {
        return Observation::Unresolved(Unresolved::ReaderNotRecognized);
    };
    let mut functions = Vec::new();
    let mut inline = Vec::new();
    for region in &regions.stored {
        let start = region.as_ptr() as usize - normal.as_ptr() as usize;
        let end = start + region.len();
        let mut candidates = Vec::new();
        for prefix in [
            &[
                1, 0, 0x6d, 0xf3, 0x1a, 0xb3, 0x0c, 0x8b, 0x10, 0x73, 0x0a, 0x93,
            ][..],
            &[0x0c, 0x8a, 0x1a, 0x80][..],
        ] {
            let pattern: Vec<_> = prefix.iter().copied().map(Some).collect();
            candidates.extend(super::bundle::sites(normal, &[*region], &pattern));
        }
        candidates.sort_unstable();
        candidates.dedup();
        for at in candidates {
            if let Some(pair) = adapted::paired(normal, at, &regions.stored) {
                inline.push(pair);
            }
            let parsed = match normal[at] {
                1 => full(normal, at),
                0x0c => short(normal, at),
                _ => None,
            };
            if let Some(function) = parsed {
                let leaf_is_stored = match function.encoder {
                    Encoder::Short(target) => {
                        let leaf = (target - 0x410000) as usize;
                        regions.stored.iter().any(|r| {
                            let origin = r.as_ptr() as usize - normal.as_ptr() as usize;
                            leaf >= origin && leaf + 4 <= origin + r.len()
                        })
                    }
                    Encoder::Full(_, _) => true,
                };
                if function.end <= end && leaf_is_stored {
                    functions.push(function);
                }
            }
        }
    }
    if !inline.is_empty() {
        return if inline.len() == 1 && functions.is_empty() {
            Observation::Known(inline.remove(0))
        } else {
            Observation::Unresolved(Unresolved::AmbiguousReader)
        };
    }
    if functions.len() != 2 {
        return Observation::Unresolved(if functions.len() > 2 {
            Unresolved::AmbiguousReader
        } else {
            Unresolved::ReaderNotRecognized
        });
    }
    functions.sort_by_key(|f| f.word);
    let (a, b) = (&functions[0], &functions[1]);
    if a.word != 0
        || b.word != 1
        || a.encoder != b.encoder
        || a.spans
            .iter()
            .any(|a| b.spans.iter().any(|b| a.start < b.end && b.start < a.end))
    {
        return Observation::Unresolved(Unresolved::ReaderNotRecognized);
    }
    let assignment = match (a.control, a.output, b.control, b.output) {
        (0x12, 0x10, 0x13, 0x11) => Assignment::Direct,
        (0x13, 0x11, 0x12, 0x10) => Assignment::Swapped,
        _ => return Observation::Unresolved(Unresolved::ReaderNotRecognized),
    };
    Observation::Known(PairedPhase {
        assignment,
        functions: [a.start, b.start],
        operands: [a.operands, b.operands],
    })
}

/// A Normal-only phase correction could not be established.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CorrectionError {
    /// A complete unambiguous binding with an execution-preserving correction
    /// is unavailable. A program can remain observable without such a correction.
    Unresolved,
    /// Normal header, declared length or additive checksum is invalid.
    InvalidNormal,
    /// The corrected bytes did not reproduce the requested native assignment.
    VerificationFailed,
}

/// Correct a copy of decoded Normal to the requested paired phase assignment.
///
/// Changes exactly four register-operand bytes when a swap is needed, and none
/// otherwise. Re-recognizes the result before returning. The caller must rebuild
/// the envelope/checksum and independently pass all cross-flash and receiver
/// gates; this function performs no device I/O or persistent data migration.
pub fn correct_pair(normal: &[u8], target: Assignment) -> Result<Vec<u8>, CorrectionError> {
    let Observation::Known(before) = discover_pair(normal) else {
        return Err(CorrectionError::Unresolved);
    };
    let expected_before = Phase {
        assignment: before.assignment,
        interface: Interface::SplitWord,
    };
    if !matches!(discover(normal), Observation::Known(value) if value == expected_before) {
        return Err(CorrectionError::Unresolved);
    }
    let mut corrected = normal.to_vec();
    if before.assignment != target {
        for offset in before.operands.iter().flatten() {
            encoding::swap_output(&mut corrected, *offset)
                .ok_or(CorrectionError::VerificationFailed)?;
        }
    }
    let Observation::Known(after) = discover_pair(&corrected) else {
        return Err(CorrectionError::VerificationFailed);
    };
    let expected_after = Phase {
        assignment: target,
        interface: Interface::SplitWord,
    };
    if !matches!(discover(&corrected), Observation::Known(value) if value == expected_after) {
        return Err(CorrectionError::VerificationFailed);
    }
    if after.assignment != target
        || before.functions != after.functions
        || before.operands != after.operands
    {
        return Err(CorrectionError::VerificationFailed);
    }
    Ok(corrected)
}

/// Correct a complete checksum-valid H8 Normal image and its header checksum.
///
/// The native header stores the big-endian additive checksum word at byte 16
/// and image length at byte 20. Only that checksum word and the bound native
/// output operands may change. Invalid input is rejected, never repaired into an
/// apparently valid image. Envelope authentication and all other compatibility
/// checks remain the caller's responsibility.
pub fn correct_normal(normal: &[u8], target: Assignment) -> Result<Vec<u8>, CorrectionError> {
    if !crate::image::edits::valid_normal(normal) {
        return Err(CorrectionError::InvalidNormal);
    }
    let Observation::Known(before) = discover(normal) else {
        return Err(CorrectionError::Unresolved);
    };
    let patched = if matches!(discover_pair(normal), Observation::Known(_)) {
        correct_pair(normal, target)?
    } else {
        correct_legacy(normal, target)?
    };
    let edits: Vec<_> = normal
        .iter()
        .zip(&patched)
        .enumerate()
        .filter_map(|(offset, (a, b))| {
            (a != b).then_some(crate::image::edits::Edit {
                offset,
                before: alloc::vec![*a],
                after: alloc::vec![*b],
            })
        })
        .collect();
    let corrected = crate::image::edits::apply_normal(normal, &edits)
        .map_err(|_| CorrectionError::VerificationFailed)?;
    if !matches!(discover(&corrected),Observation::Known(p)if p==Phase{assignment:target,interface:before.interface})
    {
        return Err(CorrectionError::VerificationFailed);
    }
    Ok(corrected)
}

#[cfg(test)]
fn checksum(bytes: &[u8]) -> u32 {
    bytes.chunks_exact(4).fold(0u32, |sum, word| {
        sum.wrapping_add(u32::from_be_bytes(word.try_into().unwrap()))
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use alloc::vec;

    pub(crate) fn fixture(short_form: bool) -> Vec<u8> {
        let mut raw = vec![0xff; 512];
        raw[400..404].copy_from_slice(&[0x0c, 8, 0x54, 0x70]);
        for source in 0..2u8 {
            let mut f = if short_form {
                vec![
                    0x0c,
                    0x8a,
                    0x1a,
                    0x80,
                    0x6a,
                    0x80,
                    0xf9,
                    0x12 + source,
                    0x0c,
                    0xa8,
                    0x10,
                    0x70,
                    0x0a,
                    0x90,
                ]
            } else {
                vec![
                    1, 0, 0x6d, 0xf3, 0x1a, 0xb3, 0x0c, 0x8b, 0x10, 0x73, 0x0a, 0x93,
                ]
            };
            let reg = if short_form { 0 } else { 0x30 };
            let load = if source == 0 {
                vec![0x69, reg]
            } else {
                vec![0x6f, reg, 0, 2]
            };
            f.extend_from_slice(&load);
            if short_form {
                f.extend_from_slice(&[0x5e, 0x41, 1, 0x90]);
            } else {
                f.extend_from_slice(&[
                    0x5e,
                    0x40,
                    0,
                    0x10,
                    0x0c,
                    0x80,
                    0x12,
                    0xc0,
                    0xe0,
                    3,
                    0x6a,
                    0x80,
                    0xf9,
                    0x12 + source,
                ]);
                f.extend_from_slice(&load);
                f.extend_from_slice(&[0x5e, 0x40, 0, 0x12]);
            }
            f.extend_from_slice(&[0x6a, 0x88, 0xf9, 0x10 + source]);
            if !short_form {
                f.extend_from_slice(&[1, 0, 0x6d, 0x73]);
            }
            f.extend_from_slice(&[0x54, 0x70]);
            let at = 32 + source as usize * 128;
            raw[at..at + f.len()].copy_from_slice(&f);
        }
        raw
    }

    #[test]
    fn complete_normal_correction_checks_header_checksum_and_round_trips() {
        for short in [false, true] {
            let mut raw = fixture(short);
            raw[..16].copy_from_slice(b"PIONEER TEST    ");
            raw[16..20].fill(0);
            let len = raw.len() as u32;
            raw[20..24].copy_from_slice(&len.to_be_bytes());
            raw[24..28].copy_from_slice(b"ID01");
            let compensation = 0u32.wrapping_sub(checksum(&raw));
            raw[16..20].copy_from_slice(&compensation.to_be_bytes());
            let swapped = correct_normal(&raw, Assignment::Swapped).unwrap();
            assert_eq!(checksum(&swapped), 0);
            assert_eq!(correct_normal(&swapped, Assignment::Direct).unwrap(), raw);
            assert_eq!(
                correct_normal(&swapped, Assignment::Swapped).unwrap(),
                swapped
            );
            for offset in [16, 20, 24, 26, 480] {
                let mut bad = raw.clone();
                bad[offset] ^= 1;
                assert_eq!(
                    correct_normal(&bad, Assignment::Swapped),
                    Err(CorrectionError::InvalidNormal)
                );
            }
            assert_eq!(
                correct_normal(&raw[..511], Assignment::Swapped),
                Err(CorrectionError::InvalidNormal)
            );
        }
    }

    #[test]
    fn both_native_forms_round_trip_and_change_only_proven_operands() {
        for short in [false, true] {
            let original = fixture(short);
            let Observation::Known(proof) = discover_pair(&original) else {
                panic!("fixture");
            };
            assert_eq!(proof.assignment, Assignment::Direct);
            let swapped = correct_pair(&original, Assignment::Swapped).unwrap();
            let changed: Vec<_> = original
                .iter()
                .zip(&swapped)
                .enumerate()
                .filter_map(|(i, (a, b))| (a != b).then_some(i))
                .collect();
            assert_eq!(
                changed,
                proof.operands.into_iter().flatten().collect::<Vec<_>>()
            );
            assert_eq!(
                correct_pair(&swapped, Assignment::Direct).unwrap(),
                original
            );
            assert_eq!(
                correct_pair(&swapped, Assignment::Swapped).unwrap(),
                swapped
            );
            assert_eq!(
                correct_pair(&original, Assignment::Direct).unwrap(),
                original
            );
        }
    }

    #[test]
    fn partial_swaps_missing_duplicate_and_unrelated_functions_are_rejected() {
        for short in [false, true] {
            let raw = fixture(short);
            let Observation::Known(proof) = discover_pair(&raw) else {
                panic!("fixture");
            };
            for site in proof.operands.into_iter().flatten() {
                let mut bad = raw.clone();
                bad[site] ^= 1;
                assert_eq!(
                    correct_pair(&bad, Assignment::Direct),
                    Err(CorrectionError::Unresolved)
                );
            }
            for end in 0..=proof.operands[1][1] {
                assert!(!matches!(discover_pair(&raw[..end]), Observation::Known(_)));
            }
            let mut duplicate = raw.clone();
            duplicate[256..320].copy_from_slice(&raw[32..96]);
            assert!(!matches!(discover_pair(&duplicate), Observation::Known(_)));
            let mut unrelated = raw.clone();
            // Redirect only the second function's first call.
            let call = (160..220).find(|&i| raw[i] == 0x5e).unwrap();
            unrelated[call + 3] ^= 2;
            assert!(!matches!(discover_pair(&unrelated), Observation::Known(_)));
        }
    }

    #[test]
    fn reverse_mechanism_code_cave_pair_uses_existing_bounded_native_correction() {
        // The reviewed UD04/UD03-to-UD02 programs relocate source one to a
        // cave, replace its original entry with a jump, and load source zero
        // in the second function. Phase correction must leave all of that intact.
        let mut raw = vec![0xff; 0x200000];
        let source_one: &[u8] = &[
            0x01, 0x00, 0x6d, 0xf3, 0x1a, 0xb3, 0x0c, 0x8b, 0x10, 0x73, 0x0a, 0x93, 0x6f, 0x30,
            0x00, 0x02, 0x5e, 0x58, 0x3f, 0xae, 0x0c, 0x80, 0x12, 0xc0, 0xe0, 0x03, 0x6a, 0x80,
            0xf9, 0x12, 0x6f, 0x30, 0x00, 0x02, 0x5e, 0x58, 0x3f, 0xb0, 0x6a, 0x88, 0xf9, 0x10,
            0x01, 0x00, 0x6d, 0x73, 0x54, 0x70,
        ];
        let source_zero: &[u8] = &[
            0x01, 0x00, 0x6d, 0xf3, 0x1a, 0xb3, 0x0c, 0x8b, 0x10, 0x73, 0x0a, 0x93, 0x69, 0x30,
            0x5e, 0x58, 0x3f, 0xae, 0x0c, 0x80, 0x12, 0xc0, 0xe0, 0x03, 0x6a, 0x80, 0xf9, 0x13,
            0x69, 0x30, 0x5e, 0x58, 0x3f, 0xb0, 0x6a, 0x88, 0xf9, 0x11, 0x01, 0x00, 0x6d, 0x73,
            0x54, 0x70,
        ];
        let cave = 0x4fc;
        let original_entry = 1_269_832;
        let second = 1_269_876;
        raw[cave..cave + source_one.len()].copy_from_slice(source_one);
        raw[original_entry..original_entry + source_zero.len()].copy_from_slice(source_zero);
        raw[original_entry..original_entry + 4].copy_from_slice(&[0x5a, 0x41, 0x04, 0xfc]);
        raw[second..second + source_zero.len()].copy_from_slice(source_zero);
        let Observation::Known(proof) = discover_pair(&raw) else {
            panic!("relocated pair");
        };
        assert_eq!(proof.assignment, Assignment::Swapped);
        assert_eq!(proof.functions, [second, cave]);
        let direct = correct_pair(&raw, Assignment::Direct).unwrap();
        let mut differences: Vec<_> = raw
            .iter()
            .zip(&direct)
            .enumerate()
            .filter_map(|(i, (a, b))| (a != b).then_some(i))
            .collect();
        let mut operands: Vec<_> = proof.operands.iter().flatten().copied().collect();
        differences.sort_unstable();
        operands.sort_unstable();
        assert_eq!(differences, operands);
        assert_eq!(
            &direct[original_entry..original_entry + 4],
            &[0x5a, 0x41, 0x04, 0xfc]
        );
        assert_eq!(correct_pair(&direct, Assignment::Swapped).unwrap(), raw);
        raw[..16].copy_from_slice(b"PIONEER TEST    ");
        raw[16..20].fill(0);
        let length = raw.len() as u32;
        raw[20..24].copy_from_slice(&length.to_be_bytes());
        let compensation = 0u32.wrapping_sub(checksum(&raw));
        raw[16..20].copy_from_slice(&compensation.to_be_bytes());
        let direct = correct_normal(&raw, Assignment::Direct).unwrap();
        assert_eq!(correct_normal(&direct, Assignment::Swapped).unwrap(), raw);
    }

    #[test]
    fn malformed_compression_directory_never_falls_back_to_raw_matches() {
        let mut raw = fixture(false);
        raw.resize(0x2000, 0xff);
        raw[0x1000..0x1004].copy_from_slice(b"COMP");
        assert!(!matches!(discover_pair(&raw), Observation::Known(_)));
        assert!(!matches!(discover(&raw), Observation::Known(_)));
        assert_eq!(
            correct_pair(&raw, Assignment::Swapped),
            Err(CorrectionError::Unresolved)
        );
    }

    #[test]
    fn short_encoder_must_be_the_exact_native_leaf() {
        let mut raw = fixture(true);
        raw[400] ^= 1;
        assert!(!matches!(discover_pair(&raw), Observation::Known(_)));
    }
}

mod adapted;
mod legacy;
mod templates;

/// Native representation consumed by the output routine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Interface {
    /// Separate source words encoded onto the two output channels.
    SplitWord,
    /// Byte-pair source handled by a combined output routine.
    BytePair,
}

/// Source assignment and native interface, independent of correction support.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Phase {
    /// Which source element supplies the first output.
    pub assignment: Assignment,
    /// Native source representation; different representations are not equal.
    pub interface: Interface,
}

#[derive(Clone, Copy)]
enum RelocationKind {
    Address,
    Call,
    Jump,
}
struct Relocation {
    start: usize,
    end: usize,
    kind: RelocationKind,
    reference: u32,
}
struct Template {
    bytes: &'static [u8],
    relocations: &'static [Relocation],
    patches: &'static [legacy::Patch],
    reference_cpu: u32,
    assignment: Assignment,
    interface: Interface,
    requires_leaf: bool,
}
fn integer(bytes: &[u8]) -> u32 {
    bytes.iter().fold(0, |v, b| (v << 8) | u32::from(*b))
}
fn template_matches(t: &Template, normal: &[u8], at: usize) -> bool {
    let Some(candidate) = normal.get(at..at + t.bytes.len()) else {
        return false;
    };
    template_matches_bytes(t, normal, at, candidate)
}
fn template_matches_bytes(t: &Template, normal: &[u8], at: usize, candidate: &[u8]) -> bool {
    let mut cursor = 0;
    for r in t.relocations {
        if candidate[cursor..r.start] != t.bytes[cursor..r.start] {
            return false;
        }
        let value = integer(&candidate[r.start..r.end]);
        match r.kind {
            RelocationKind::Call => {
                if value & 1 != 0
                    || value < 0x400000
                    || u64::from(value) >= 0x410000 + normal.len() as u64
                {
                    return false;
                }
                if t.requires_leaf {
                    let Some(offset) = value.checked_sub(0x410000) else {
                        return false;
                    };
                    let offset = offset as usize;
                    if normal.get(offset..offset + 6)
                        != Some(&[0x6a, 0x88, 0xf9, 9, 0x54, 0x70][..])
                    {
                        return false;
                    }
                }
            }
            RelocationKind::Jump => {
                if value & 1 != 0
                    || value < 0x400000
                    || u64::from(value) >= 0x410000 + normal.len() as u64
                {
                    return false;
                }
                if r.reference >= t.reference_cpu
                    && r.reference < t.reference_cpu + t.bytes.len() as u32
                    && u64::from(value)
                        != 0x410000 + at as u64 + u64::from(r.reference - t.reference_cpu)
                {
                    return false;
                }
            }
            RelocationKind::Address => {}
        }
        cursor = r.end;
    }
    if candidate[cursor..] != t.bytes[cursor..] {
        return false;
    }
    // Repeated pointers and adjacent source elements keep their native relation.
    for (i, r) in t.relocations.iter().enumerate() {
        for earlier in &t.relocations[..i] {
            let delta = i64::from(r.reference) - i64::from(earlier.reference);
            if delta.abs() <= 1
                && i64::from(integer(&candidate[r.start..r.end]))
                    - i64::from(integer(&candidate[earlier.start..earlier.end]))
                    != delta
            {
                return false;
            }
        }
    }
    true
}

/// Correct a uniquely bound SAT1 output program without changing shared helpers.
/// Edits operands only; checksum, envelope and other filter gates remain required.
/// Changing assignment refuses for forms requiring a call/inline rewrite because
/// preservation of call timing and temporary stack effects is not established.
/// Their native and previously emitted inline forms remain observable; requesting
/// their current assignment returns an unchanged copy.
pub fn correct_legacy(normal: &[u8], target: Assignment) -> Result<Vec<u8>, CorrectionError> {
    legacy::correct(normal, target)
}

/// Discover source assignment across paired and legacy SAT native output forms.
///
/// Legacy variants bind complete functions and their native output operands.
/// Use `correct_legacy` for bounded legacy edits and `correct_pair` for paired forms.
/// Conflicting positive evidence produces no assignment.
pub fn discover(normal: &[u8]) -> Observation<Phase> {
    let Some(regions) = crate::image::regions(normal) else {
        return Observation::Unresolved(Unresolved::ReaderNotRecognized);
    };
    let mut result = match discover_pair(normal) {
        Observation::Known(p) => Some(Phase {
            assignment: p.assignment,
            interface: Interface::SplitWord,
        }),
        _ => None,
    };
    if let Ok(graph) = sat1::observe_normal(normal) {
        let found = Phase {
            assignment: graph.assignment,
            interface: Interface::SplitWord,
        };
        if result.is_some_and(|value| value != found) {
            return Observation::Conflicting;
        }
        result = Some(found);
    }
    for t in templates::TEMPLATES {
        let prefix = [Some(t.bytes[0]), Some(t.bytes[1])];
        for at in super::bundle::sites(normal, &regions.stored, &prefix) {
            if let Some(found) = legacy::observe(t, normal, at, &regions.stored) {
                if result.is_some_and(|value| value != found) {
                    return Observation::Conflicting;
                }
                result = Some(found);
            }
        }
    }
    result.map_or(
        Observation::Unresolved(Unresolved::ReaderNotRecognized),
        Observation::Known,
    )
}

#[cfg(test)]
mod legacy_tests {
    use super::*;
    use alloc::vec;

    fn fixture(t: &Template) -> (Vec<u8>, usize) {
        let mut raw = vec![0xff; 0x200000];
        let at = (t.reference_cpu - 0x410000) as usize;
        raw[at..at + t.bytes.len()].copy_from_slice(t.bytes);
        if t.requires_leaf {
            for r in t.relocations {
                if matches!(r.kind, RelocationKind::Call) {
                    let offset = (r.reference - 0x410000) as usize;
                    raw[offset..offset + 6].copy_from_slice(&[0x6a, 0x88, 0xf9, 9, 0x54, 0x70]);
                }
            }
        }
        (raw, at)
    }

    #[test]
    fn every_legacy_template_binds_every_nonrelocated_instruction_byte() {
        for t in templates::TEMPLATES {
            let (mut raw, at) = fixture(t);
            assert!(template_matches(t, &raw, at));
            for i in 0..t.bytes.len() {
                if t.relocations.iter().any(|r| (r.start..r.end).contains(&i)) {
                    continue;
                }
                raw[at + i] ^= 1;
                assert!(!template_matches(t, &raw, at), "offset {i}");
                raw[at + i] ^= 1;
            }
            assert!(!template_matches(t, &raw[..at + t.bytes.len() - 1], at));
        }
    }

    #[test]
    fn legacy_requires_bound_leaf_and_repeated_pointer_relationships() {
        for t in templates::TEMPLATES {
            let (mut raw, at) = fixture(t);
            if t.requires_leaf {
                let r = t
                    .relocations
                    .iter()
                    .find(|r| matches!(r.kind, RelocationKind::Call))
                    .unwrap();
                raw[(r.reference - 0x410000) as usize] ^= 1;
                assert!(!template_matches(t, &raw, at));
            }
            let (mut raw, at) = fixture(t);
            if let Some((i, r)) = t.relocations.iter().enumerate().find(|(i, r)| {
                t.relocations[..*i]
                    .iter()
                    .any(|p| (i64::from(r.reference) - i64::from(p.reference)).abs() <= 1)
            }) {
                assert!(i > 0);
                raw[at + r.end - 1] ^= 2;
                assert!(!template_matches(t, &raw, at));
            }
        }
    }

    #[test]
    fn conflicting_legacy_assignments_produce_no_value_or_correction() {
        let direct = templates::TEMPLATES
            .iter()
            .find(|t| t.bytes.len() == 128)
            .unwrap();
        let swapped = templates::TEMPLATES
            .iter()
            .find(|t| t.assignment == Assignment::Swapped)
            .unwrap();
        let (mut raw, _) = fixture(direct);
        let at = (swapped.reference_cpu - 0x410000) as usize;
        raw[at..at + swapped.bytes.len()].copy_from_slice(swapped.bytes);
        assert!(matches!(discover(&raw), Observation::Conflicting));
        assert_eq!(
            correct_pair(&raw, Assignment::Direct),
            Err(CorrectionError::Unresolved)
        );
    }
}
