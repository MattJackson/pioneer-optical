//! Paired V850 source loads bound to the complete indexed writer.
//! Native operand correction is separate from full image/update admission.
use super::{Interface, Observation, Phase, Unresolved};
use crate::image::phase::{Assignment, CorrectionError};
use alloc::collections::BTreeSet;
use alloc::vec::Vec;
struct Shape {
    bytes: &'static [u8],
    fixed: &'static [u8],
    calls: [usize; 2],
    sources: &'static [u8],
}
mod shapes {
    // Complete paired-load programs and indexed writers from native disassembly.
    // Only JARL displacements and GP-relative source coordinates vary.
    use super::Shape;
    pub(super) const SHAPES: &[Shape] = &[
        Shape {
            bytes: &[
                32, 54, 143, 0, 27, 104, 194, 106, 36, 238, 0, 0, 205, 233, 253, 63, 1, 0, 0, 0, 0, 0,
                32, 54, 142, 0, 253, 63, 3, 0, 0, 0, 0, 0,
            ],
            fixed: &[
                1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1,
                1, 0, 0, 0, 0,
            ],
            calls: [18, 30],
            sources: &[10],
        },
        Shape {
            bytes: &[
                32, 54, 143, 0, 26, 104, 36, 63, 0, 0, 194, 106, 205, 57, 231, 63, 1, 0, 0, 0, 0, 0,
                32, 54, 142, 0, 26, 128, 36, 63, 0, 0, 194, 130, 208, 57, 231, 63, 3, 0, 0, 0, 0, 0,
            ],
            fixed: &[
                1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1,
                1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0,
            ],
            calls: [18, 40],
            sources: &[8, 30],
        },
        Shape {
            bytes: &[
                32, 54, 143, 0, 26, 128, 194, 130, 36, 238, 0, 0, 208, 233, 253, 63, 1, 0, 0, 0, 0, 0,
                32, 54, 142, 0, 253, 63, 3, 0, 0, 0, 0, 0,
            ],
            fixed: &[
                1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1,
                1, 0, 0, 0, 0,
            ],
            calls: [18, 30],
            sources: &[10],
        },
    ];
    pub(super) const WRITERS: &[&[u8]] = &[
        &[
            92, 26, 198, 0, 199, 0, 0, 80, 92, 26, 99, 143, 1, 0, 229, 143, 64, 0, 224, 7, 96, 1, 115,
            143, 1, 0, 68, 154, 35, 143, 1, 0, 68, 26, 222, 199, 129, 1, 234, 95, 0, 0, 97, 90, 170, 5,
            1, 82, 222, 135, 129, 1, 99, 63, 2, 0, 222, 199, 8, 1, 194, 5, 222, 199, 8, 1, 234, 253, 6,
            6, 1, 255, 199, 5, 222, 7, 7, 1, 181, 5, 222, 135, 7, 1, 6, 96, 140, 0, 94, 103, 6, 1, 3,
            111, 2, 0, 94, 111, 4, 1, 3, 119, 3, 0, 94, 119, 5, 1, 222, 199, 8, 1, 194, 5, 222, 199, 8,
            1, 234, 253, 224, 81, 178, 5, 222, 7, 129, 1, 224, 7, 96, 1, 92, 26, 99, 143, 1, 0, 4, 10,
            161, 153, 51, 143, 1, 0, 241, 47, 32, 0, 35, 143, 1, 0, 68, 26, 66, 6, 31, 0,
        ],
        &[
            92, 26, 198, 0, 199, 0, 0, 80, 224, 7, 0, 1, 224, 7, 96, 1, 222, 199, 129, 1, 234, 95, 0,
            0, 97, 90, 170, 5, 1, 82, 222, 135, 129, 1, 99, 63, 2, 0, 222, 199, 8, 1, 194, 5, 222, 199,
            8, 1, 234, 253, 6, 6, 1, 255, 215, 5, 222, 7, 7, 1, 197, 5, 0, 0, 222, 135, 7, 1, 6, 96,
            140, 0, 94, 103, 6, 1, 3, 111, 2, 0, 94, 111, 4, 1, 3, 119, 3, 0, 94, 119, 5, 1, 222, 199,
            8, 1, 194, 5, 222, 199, 8, 1, 234, 253, 224, 81, 178, 5, 222, 7, 129, 1, 224, 7, 96, 1, 4,
            10, 161, 153, 51, 143, 1, 0, 241, 47, 32, 0, 66, 6, 31, 0,
        ],
    ];
}

pub(super) fn call(normal: &[u8], at: usize) -> Option<usize> {
    let b = normal.get(at..at.checked_add(4)?)?;
    let word = u16::from_le_bytes([b[0], b[1]]);
    if word & 0xffc0 != 0xff80 {
        return None;
    }
    let mut disp =
        ((u32::from(word & 63) << 16) | u32::from(u16::from_le_bytes([b[2], b[3]]))) as i32;
    if disp & (1 << 21) != 0 {
        disp -= 1 << 22;
    }
    let target = at.checked_add_signed(disp as isize)?;
    (target & 1 == 0 && target < normal.len()).then_some(target)
}
fn matched(b: &[u8], s: &Shape) -> bool {
    b.len() == s.bytes.len()
        && b.iter()
            .zip(s.bytes)
            .zip(s.fixed)
            .all(|((&a, &b), &fixed)| fixed == 0 || a == b)
        && s.sources.windows(2).all(|pair| {
            let (a, b_at) = (usize::from(pair[0]), usize::from(pair[1]));
            b[a..a + 2] == b[b_at..b_at + 2]
        })
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct Pair {
    offset: usize,
    writer: usize,
    assignment: Assignment,
}
/// Linear membership check; its comparisons are what the offset guard bounds.
fn present<T: PartialEq>(found: &[T], value: &T) -> bool {
    #[cfg(test)]
    tests::COMPARISONS.with(|c| c.set(c.get() + found.len()));
    found.contains(value)
}
fn pairs(normal: &[u8]) -> Vec<Pair> {
    let mut found = Vec::new();
    let mut offsets = BTreeSet::new();
    for s in shapes::SHAPES {
        for (at, b) in normal.windows(s.bytes.len()).enumerate().step_by(2) {
            if b[..2] != [0x20, 0x36] {
                continue;
            }
            let assignment = match (b[2], b[24]) {
                (0x8f, 0x8e) => Assignment::Swapped,
                (0x8e, 0x8f) => Assignment::Direct,
                _ => continue,
            };
            let mut canonical = b.to_vec();
            canonical[2] = 0x8f;
            canonical[24] = 0x8e;
            if !matched(&canonical, s) {
                continue;
            }
            let Some(target) = call(normal, at + s.calls[0]) else {
                continue;
            };
            if call(normal, at + s.calls[1]) != Some(target) {
                continue;
            }
            if shapes::WRITERS
                .iter()
                .any(|w| normal.get(target..target + w.len()) == Some(*w))
            {
                let pair = Pair {
                    offset: at,
                    writer: target,
                    assignment,
                };
                // Pairs at distinct offsets never compare equal; only a
                // repeated offset (another shape at one site) needs comparison.
                if !offsets.insert(at) && present(&found, &pair) {
                    continue;
                }
                found.push(pair);
            }
        }
    }
    found
}
#[cfg(test)]
fn paired(normal: &[u8]) -> bool {
    !pairs(normal).is_empty()
}

/// Swap the two channel operands in a uniquely bound V850 output program.
/// This low-level operation does not repair image checksums or authorize an
/// update. The full planner must validate Kernel, interface and all other filters.
pub fn correct_pair(normal: &[u8], target: Assignment) -> Result<Vec<u8>, CorrectionError> {
    let before = pairs(normal);
    if before.len() != 1 {
        return Err(CorrectionError::Unresolved);
    }
    let pair = &before[0];
    let mut result = normal.to_vec();
    if pair.assignment != target {
        result[pair.offset + 2] ^= 1;
        result[pair.offset + 24] ^= 1;
    }
    let expected = Pair {
        assignment: target,
        ..pair.clone()
    };
    if pairs(&result) != [expected] {
        return Err(CorrectionError::VerificationFailed);
    }
    Ok(result)
}
/// Correct stored bus-order V850 operands with an exact Kernel interface proof.
/// Envelope checksums/authentication and all other family gates remain required.
/// Missing Kernel evidence is rejected even for an otherwise recognizable pair.
pub fn correct_bus(
    normal: &[u8],
    kernel: &[u8],
    target: Assignment,
) -> Result<Vec<u8>, CorrectionError> {
    use crate::image::layout::{decode_v850_bus, encode_v850_bus};
    let decoded = decode_v850_bus(normal).ok_or(CorrectionError::InvalidNormal)?;
    let kernel = decode_v850_bus(kernel).ok_or(CorrectionError::Unresolved)?;
    let Observation::Known(before) = native(&decoded, Some(&kernel)) else {
        return Err(CorrectionError::Unresolved);
    };
    let corrected = correct_pair(&decoded, target)?;
    let encoded = encode_v850_bus(&corrected).ok_or(CorrectionError::VerificationFailed)?;
    let check = decode_v850_bus(&encoded).ok_or(CorrectionError::VerificationFailed)?;
    if check != corrected
        || !matches!(native(&check, Some(&kernel)), Observation::Known(p)
        if p.assignment == target && p.interface == before.interface)
    {
        return Err(CorrectionError::VerificationFailed);
    }
    Ok(encoded)
}

/// Correct stored V850 phase and its native flash checksum using the exact Kernel.
/// The outer envelope must still be repacked and verified by the receiver.
pub fn correct_normal_bus(
    normal: &[u8],
    kernel: &[u8],
    target: Assignment,
) -> Result<Vec<u8>, CorrectionError> {
    use crate::image::layout::{decode_v850_bus, encode_v850_bus};
    let decoded = decode_v850_bus(normal).ok_or(CorrectionError::InvalidNormal)?;
    let kernel = decode_v850_bus(kernel).ok_or(CorrectionError::Unresolved)?;
    let proof =
        super::v850_integrity::discover(&decoded, &kernel).ok_or(CorrectionError::Unresolved)?;
    let Observation::Known(before) = native(&decoded, Some(&kernel)) else {
        return Err(CorrectionError::Unresolved);
    };
    let mut corrected = correct_pair(&decoded, target)?;
    super::v850_integrity::compensate(&mut corrected, &kernel, &proof)
        .ok_or(CorrectionError::VerificationFailed)?;
    if super::v850_integrity::discover(&corrected, &kernel) != Some(proof)
        || !matches!(native(&corrected,Some(&kernel)),Observation::Known(p) if p.assignment==target && p.interface==before.interface)
    {
        return Err(CorrectionError::VerificationFailed);
    }
    let encoded = encode_v850_bus(&corrected).ok_or(CorrectionError::VerificationFailed)?;
    if decode_v850_bus(&encoded).as_deref() != Some(corrected.as_slice()) {
        return Err(CorrectionError::VerificationFailed);
    }
    Ok(encoded)
}

/// Recover the native source assignment and the absolute indexed bus
/// coordinate. Both calls must reach the same complete native writer. The exact
/// paired Kernel supplies EP; no model or sibling-firmware fallback is used.
pub fn native(normal: &[u8], kernel: Option<&[u8]>) -> Observation<Phase> {
    let found = pairs(normal);
    if found.is_empty() {
        return Observation::Unresolved(Unresolved::ReaderNotRecognized);
    }
    if found.iter().any(|p| p.assignment != found[0].assignment) {
        return Observation::Conflicting;
    }
    let Some(kernel) = kernel else {
        return Observation::Unresolved(Unresolved::ResidentCodeRequired(0));
    };
    match super::v850_host::ep(kernel) {
        Observation::Known(base) => Observation::Known(Phase {
            assignment: found[0].assignment,
            interface: Interface::Indexed16 {
                window: base + 0x100,
                channels: [0x8e, 0x8f],
            },
        }),
        Observation::Unresolved(reason) => Observation::Unresolved(reason),
        Observation::Conflicting => Observation::Conflicting,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    fn fixture() -> Vec<u8> {
        let s = &shapes::SHAPES[0];
        let mut b = vec![0xff; 0x400];
        b[..s.bytes.len()].copy_from_slice(s.bytes);
        for at in s.calls {
            let disp = 0x100 - at;
            b[at..at + 2].copy_from_slice(&(0xff80u16 | ((disp >> 16) as u16)).to_le_bytes());
            b[at + 2..at + 4].copy_from_slice(&(disp as u16).to_le_bytes());
        }
        let w = shapes::WRITERS[0];
        b[0x100..0x100 + w.len()].copy_from_slice(w);
        b
    }
    #[test]
    fn native_channel_edits_are_bidirectional_and_reject_ambiguous_programs() {
        let original = fixture();
        let direct = correct_pair(&original, Assignment::Direct).unwrap();
        let changed: Vec<_> = original
            .iter()
            .zip(&direct)
            .enumerate()
            .filter_map(|(i, (a, b))| (a != b).then_some(i))
            .collect();
        assert_eq!(changed, [2, 24]);
        assert_eq!(pairs(&direct)[0].assignment, Assignment::Direct);
        assert_eq!(correct_pair(&direct, Assignment::Direct).unwrap(), direct);
        assert_eq!(
            correct_pair(&direct, Assignment::Swapped).unwrap(),
            original
        );
        let mut malformed = original.clone();
        malformed[24] = malformed[2];
        assert_eq!(
            correct_pair(&malformed, Assignment::Direct),
            Err(CorrectionError::Unresolved)
        );
        let mut ambiguous = original.clone();
        ambiguous.extend_from_slice(&original);
        assert_eq!(
            correct_pair(&ambiguous, Assignment::Direct),
            Err(CorrectionError::Unresolved)
        );
    }
    std::thread_local! {
        pub(super) static COMPARISONS: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
    }
    #[test]
    fn tiled_pairs_are_deduplicated_without_quadratic_comparisons() {
        let s = &shapes::SHAPES[0];
        let w = shapes::WRITERS[0];
        let stride = (s.bytes.len() + 3) & !1;
        let count = 2000;
        let writer = count * stride;
        let mut b = vec![0xff; writer + w.len()];
        b[writer..].copy_from_slice(w);
        for k in 0..count {
            let base = k * stride;
            b[base..base + s.bytes.len()].copy_from_slice(s.bytes);
            for at in s.calls {
                let disp = writer - (base + at);
                b[base + at..base + at + 2]
                    .copy_from_slice(&(0xff80u16 | ((disp >> 16) as u16)).to_le_bytes());
                b[base + at + 2..base + at + 4].copy_from_slice(&(disp as u16).to_le_bytes());
            }
        }
        COMPARISONS.with(|c| c.set(0));
        let found = pairs(&b);
        assert_eq!(found.len(), count);
        assert!(found.iter().all(|p| p.writer == writer));
        assert!(COMPARISONS.with(core::cell::Cell::get) < 4 * count);
    }
    #[test]
    fn stored_normal_correction_moves_only_operands_and_checksum_and_round_trips() {
        use super::super::v850_integrity::{compensate, discover, flash_sum, install};
        use crate::image::layout::{decode_v850_bus, encode_v850_bus};
        let mut normal = vec![0xff; 8192];
        let mut kernel = vec![0xff; 0x10000];
        // Table data spans 0x418..0x818 and carries the phase program and writer.
        let proof = install(&mut normal, &mut kernel, 0x400);
        assert_eq!(proof.checksum, 0x8fc);
        normal[0x418..0x818].fill(0);
        let s = &shapes::SHAPES[0];
        let (program, writer) = (0x420, 0x600);
        normal[program..program + s.bytes.len()].copy_from_slice(s.bytes);
        for at in s.calls {
            let disp = writer - (program + at);
            normal[program + at..program + at + 2]
                .copy_from_slice(&(0xff80u16 | ((disp >> 16) as u16)).to_le_bytes());
            normal[program + at + 2..program + at + 4]
                .copy_from_slice(&(disp as u16).to_le_bytes());
        }
        let w = shapes::WRITERS[0];
        normal[writer..writer + w.len()].copy_from_slice(w);
        // Reset JR to an EP prefix setting EP = 0x200000.
        kernel[..4].copy_from_slice(&[0x80, 7, 0, 1]);
        kernel[0x100..0x110].copy_from_slice(&[
            0x25, 6, 0, 0, 0, 0, 0x24, 6, 0, 0x70, 0xff, 3, 0x40, 0xf6, 0x20, 0,
        ]);
        compensate(&mut normal, &kernel, &proof).unwrap();
        assert_eq!(discover(&normal, &kernel), Some(proof.clone()));
        let phase = |normal: &[u8], assignment| {
            matches!(native(normal, Some(&kernel)), Observation::Known(p) if p == Phase {
                assignment,
                interface: Interface::Indexed16 { window: 0x200100, channels: [0x8e, 0x8f] },
            })
        };
        assert!(phase(&normal, Assignment::Swapped));
        let stored = encode_v850_bus(&normal).unwrap();
        let stored_kernel = encode_v850_bus(&kernel).unwrap();

        let corrected = correct_normal_bus(&stored, &stored_kernel, Assignment::Direct).unwrap();
        let decoded = decode_v850_bus(&corrected).unwrap();
        assert_eq!(flash_sum(&decoded, &kernel), Some(0));
        assert_eq!(discover(&decoded, &kernel), Some(proof.clone()));
        assert!(phase(&decoded, Assignment::Direct));
        let changed: Vec<_> = (0..normal.len())
            .filter(|&i| normal[i] != decoded[i])
            .collect();
        assert!(changed.starts_with(&[program + 2, program + 24]));
        assert!(changed[2..].iter().all(|i| (0x8fc..0x900).contains(i)));
        assert!(changed.len() > 2);
        assert_eq!(
            correct_normal_bus(&corrected, &stored_kernel, Assignment::Swapped).unwrap(),
            stored
        );
        assert_eq!(
            correct_bus(&stored, &stored_kernel, Assignment::Swapped).unwrap(),
            stored
        );
        // Without the boot check the checksum field is unproven.
        let mut unbound = kernel.clone();
        unbound[0x1000] ^= 1;
        assert_eq!(
            correct_normal_bus(
                &stored,
                &encode_v850_bus(&unbound).unwrap(),
                Assignment::Direct
            ),
            Err(CorrectionError::Unresolved)
        );
    }
    #[test]
    fn paired_loads_require_the_same_complete_writer() {
        let b = fixture();
        assert!(paired(&b));
        assert!(matches!(
            native(&b, None),
            Observation::Unresolved(Unresolved::ResidentCodeRequired(0))
        ));
        let mut wrong = b.clone();
        wrong[shapes::SHAPES[0].calls[1] + 2] ^= 2;
        assert!(!paired(&wrong));
        for offset in 0..shapes::WRITERS[0].len() {
            let mut wrong = b.clone();
            wrong[0x100 + offset] ^= 1;
            assert!(!paired(&wrong), "writer byte {offset}");
        }
    }
    #[test]
    fn fixed_source_program_and_repeated_pointer_are_required() {
        for s in shapes::SHAPES {
            assert!(matched(s.bytes, s));
            for (at, fixed) in s.fixed.iter().enumerate() {
                if *fixed == 0 {
                    continue;
                }
                let mut wrong = s.bytes.to_vec();
                wrong[at] ^= 1;
                assert!(!matched(&wrong, s));
            }
            if s.sources.len() == 2 {
                let mut wrong = s.bytes.to_vec();
                wrong[usize::from(s.sources[1])] ^= 1;
                assert!(!matched(&wrong, s));
            }
        }
    }
    #[test]
    fn phase_owner_treats_an_undecodable_kernel_as_missing_resident_code() {
        use crate::filters::Firmware;
        let mut native = fixture();
        native.resize(8192, 0xff);
        let normal = crate::image::layout::encode_v850_bus(&native).unwrap();
        let firmware = |kernel| Firmware {
            hardware: "",
            normal: &normal,
            kernel,
        };
        let missing = |kernel| {
            matches!(
                crate::filters::phase::observe(firmware(kernel)),
                Observation::Unresolved(Unresolved::ResidentCodeRequired(0))
            )
        };
        assert!(missing(None));
        // A supplied Kernel that is not a bus-order image is no more usable.
        assert!(missing(Some(&[0xff; 100])));
    }
}
