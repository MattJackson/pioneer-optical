//! Full-function M32C phase assignment with native indexed-bus target binding.
use super::{unique, Interface, Observation, Phase, Unresolved};
use crate::image::phase::Assignment;
use alloc::collections::BTreeSet;
use alloc::vec::Vec;
#[path = "m32c_phase_shapes.rs"]
mod shapes;
struct Shape {
    bytes: &'static [u8],
    masks: &'static [(usize, usize, u8)],
    interface: Interface,
    assignment: Assignment,
}
fn integer(b: &[u8]) -> u32 {
    b.iter().rev().fold(0, |v, b| (v << 8) | u32::from(*b))
}
fn matches(body: &[u8], at: usize, s: &Shape, base: u32) -> bool {
    let Some(b) = body.get(at..at + s.bytes.len()) else {
        return false;
    };
    matches_bytes(b, s, base, body.len())
}
fn matches_bytes(b: &[u8], s: &Shape, base: u32, image_len: usize) -> bool {
    let mut cursor = 0;
    for (i, &(offset, width, kind)) in s.masks.iter().enumerate() {
        if b[cursor..offset] != s.bytes[cursor..offset] {
            return false;
        }
        let value = integer(&b[offset..offset + width]);
        if (kind == 0 && (value < base || u64::from(value) >= u64::from(base) + image_len as u64))
            || (kind == 1 && !(0x2000..0x8000).contains(&value))
            || (kind == 2 && value == 0)
        {
            return false;
        }
        let reference = integer(&s.bytes[offset..offset + width]);
        for &(other, len, other_kind) in &s.masks[..i] {
            if kind != other_kind {
                continue;
            }
            let reference_delta =
                i64::from(reference) - i64::from(integer(&s.bytes[other..other + len]));
            if reference_delta.abs() <= 2
                && i64::from(value) - i64::from(integer(&b[other..other + len])) != reference_delta
            {
                return false;
            }
        }
        cursor = offset + width;
    }
    b[cursor..] == s.bytes[cursor..]
}
fn channel_operands(s: &Shape) -> Vec<usize> {
    s.bytes
        .windows(4)
        .enumerate()
        .filter_map(|(at, b)| {
            (b[0] == 5 && matches!(b[1], 0x8e | 0x8f) && b[2..] == [0, 0xcd]).then_some(at + 1)
        })
        .collect()
}
fn direct_operands(s: &Shape) -> Vec<usize> {
    let mut out = Vec::new();
    for (at, b) in s.bytes.windows(3).enumerate() {
        if b == [0x10, 0x19, 1] {
            out.push(at + 1);
        }
    }
    for (at, b) in s.bytes.windows(4).enumerate() {
        if b[0] == 0xc6 && matches!(b[1], 0xcb | 0xfb) && matches!(b[2], 0x18 | 0x19) && b[3] == 1 {
            out.push(at + 2);
        }
    }
    for (at, b) in s.bytes.windows(7).enumerate() {
        if b[..2] == [0xb6, 0xcb] && matches!(b[5], 0x18 | 0x19) && b[6] == 1 {
            out.push(at + 5);
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}
fn legacy_direct_operands(s: &Shape) -> Vec<usize> {
    s.bytes
        .windows(7)
        .enumerate()
        .filter_map(|(at, b)| {
            (b[..2] == [0xb6, 0xcb] && matches!(b[5], 0xca | 0xcb) && b[6] == 0x54)
                .then_some(at + 5)
        })
        .collect()
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct Binding {
    offset: usize,
    operands: Vec<usize>,
    phase: Phase,
}
fn bindings(normal: &[u8], normal_base: u32) -> Vec<Binding> {
    let mut found = Vec::new();
    let mut offsets = BTreeSet::new();
    for s in shapes::CONSUMERS {
        for at in 0..normal.len().saturating_sub(s.bytes.len() - 1) {
            if normal[at..at + 4] != s.bytes[..4] {
                continue;
            }
            let mut operands = Vec::new();
            let mut assignment = s.assignment;
            let mut canonical = normal[at..at + s.bytes.len()].to_vec();
            match s.interface {
                Interface::Indexed16 { .. } => {
                    operands = channel_operands(s);
                    if operands.len() != 3 {
                        continue;
                    }
                }
                Interface::Direct8 {
                    channels: [0x118, 0x119],
                } => {
                    operands = direct_operands(s);
                    if !matches!(operands.len(), 3 | 4) {
                        continue;
                    }
                }
                Interface::Direct8 {
                    channels: [0x54ca, 0x54cb],
                } => {
                    operands = legacy_direct_operands(s);
                    if operands.len() != 7 {
                        continue;
                    }
                }
                _ => {}
            }
            if !operands.is_empty() {
                let flipped = canonical[operands[0]] != s.bytes[operands[0]];
                if operands
                    .iter()
                    .any(|&p| canonical[p] != s.bytes[p] ^ u8::from(flipped))
                {
                    continue;
                }
                if flipped {
                    assignment = match assignment {
                        Assignment::Direct => Assignment::Swapped,
                        Assignment::Swapped => Assignment::Direct,
                    };
                }
                for &p in &operands {
                    canonical[p] = s.bytes[p];
                }
            }
            if !matches_bytes(&canonical, s, normal_base, normal.len()) {
                continue;
            }
            if matches!(s.interface, Interface::Indexed16 { .. }) {
                let targets: Vec<_> = s
                    .masks
                    .iter()
                    .filter(|(_, _, k)| *k == 0)
                    .map(|&(p, z, _)| integer(&normal[at + p..at + p + z]))
                    .collect();
                if targets.is_empty() || targets.iter().any(|target| *target != targets[0]) {
                    continue;
                }
                let writer = (targets[0] - normal_base) as usize;
                if !shapes::BUSES.iter().any(|bus| {
                    bus.interface == s.interface && matches(normal, writer, bus, normal_base)
                }) {
                    continue;
                }
            }
            let value = Binding {
                offset: at,
                operands: operands.into_iter().map(|p| at + p).collect(),
                phase: Phase {
                    assignment,
                    interface: s.interface,
                },
            };
            // Bindings at distinct offsets never compare equal; only repeated
            // offsets (different shapes at one site) need the full comparison.
            if !offsets.insert(at) {
                #[cfg(test)]
                tests::COMPARISONS.with(|c| c.set(c.get() + found.len()));
                if found.contains(&value) {
                    continue;
                }
            }
            found.push(value);
        }
    }
    found
}
/// Recognize source assignment and complete native M32C output interface.
/// Indexed variants bind all calls to the same complete writer, including the
/// opposite assignment produced by the verified operand correction.
pub fn discover(normal: &[u8], normal_base: u32) -> Observation<Phase> {
    if normal_base
        .checked_add(u32::try_from(normal.len()).unwrap_or(u32::MAX))
        .is_none()
    {
        return Observation::Unresolved(Unresolved::TruncatedEvidence);
    }
    unique(
        bindings(normal, normal_base)
            .into_iter()
            .map(|b| b.phase)
            .collect(),
    )
}
/// Correct a uniquely bound indexed M32C phase function's three channel loads.
/// Does not repair image checksums, rebuild envelopes or authorize flashing.
/// Direct-byte interfaces require a separate proof and remain unsupported here.
pub fn correct_indexed(
    normal: &[u8],
    normal_base: u32,
    target: Assignment,
) -> Result<Vec<u8>, crate::image::phase::CorrectionError> {
    correct_program(normal, normal_base, target, true)
}
/// Correct a uniquely bound indexed or direct M32C output program.
/// This edits operands only. Firmware checksum and envelope validation remain
/// mandatory. Every native output path in the recognized function is swapped.
pub fn correct_pair(
    normal: &[u8],
    normal_base: u32,
    target: Assignment,
) -> Result<Vec<u8>, crate::image::phase::CorrectionError> {
    correct_program(normal, normal_base, target, false)
}
fn correct_program(
    normal: &[u8],
    normal_base: u32,
    target: Assignment,
    indexed_only: bool,
) -> Result<Vec<u8>, crate::image::phase::CorrectionError> {
    use crate::image::phase::CorrectionError;
    if normal_base
        .checked_add(u32::try_from(normal.len()).map_err(|_| CorrectionError::Unresolved)?)
        .is_none()
    {
        return Err(CorrectionError::Unresolved);
    }
    let before = bindings(normal, normal_base);
    if before.len() != 1
        || before[0].operands.is_empty()
        || (indexed_only && !matches!(before[0].phase.interface, Interface::Indexed16 { .. }))
    {
        return Err(CorrectionError::Unresolved);
    }
    let mut result = normal.to_vec();
    if before[0].phase.assignment != target {
        for &p in &before[0].operands {
            result[p] ^= 1;
        }
    }
    let mut expected = before;
    expected[0].phase.assignment = target;
    if bindings(&result, normal_base) != expected {
        return Err(CorrectionError::VerificationFailed);
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn indexed_phase_round_trip_preserves_writer_and_rejects_partial_or_duplicate_programs() {
        let s = &shapes::CONSUMERS[0];
        let base = 0xf00000;
        let mut original = alloc::vec![255;0x100000];
        original[0x1000..0x1000 + s.bytes.len()].copy_from_slice(s.bytes);
        let &(p, n, _) = s.masks.iter().find(|(_, _, k)| *k == 0).unwrap();
        let writer = (integer(&s.bytes[p..p + n]) - base) as usize;
        let bus = shapes::BUSES
            .iter()
            .find(|b| b.interface == s.interface)
            .unwrap();
        original[writer..writer + bus.bytes.len()].copy_from_slice(bus.bytes);
        let direct = correct_indexed(&original, base, Assignment::Direct).unwrap();
        assert_eq!(
            correct_indexed(&direct, base, Assignment::Swapped).unwrap(),
            original
        );
        assert_eq!(
            correct_indexed(&direct, base, Assignment::Direct).unwrap(),
            direct
        );
        let operands = channel_operands(s);
        assert_eq!(operands.len(), 3);
        let changed: Vec<_> = original
            .iter()
            .zip(&direct)
            .enumerate()
            .filter_map(|(i, (a, b))| (a != b).then_some(i))
            .collect();
        assert_eq!(
            changed,
            operands.iter().map(|p| 0x1000 + p).collect::<Vec<_>>()
        );
        let mut bad = original.clone();
        bad[0x1000 + operands[0]] ^= 1;
        assert!(correct_indexed(&bad, base, Assignment::Direct).is_err());
        let mut bad = original.clone();
        bad[writer] ^= 1;
        assert!(correct_indexed(&bad, base, Assignment::Direct).is_err());
        let mut duplicate = original.clone();
        duplicate[0x2000..0x2000 + s.bytes.len()].copy_from_slice(s.bytes);
        assert!(correct_indexed(&duplicate, base, Assignment::Direct).is_err());
    }
    use crate::image::phase::CorrectionError;
    std::thread_local! {
        pub(super) static COMPARISONS: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
    }
    fn direct_shapes() -> impl Iterator<Item = &'static Shape> {
        shapes::CONSUMERS
            .iter()
            .filter(|s| matches!(s.interface, Interface::Direct8 { .. }))
    }
    // Operand sites and the exact count each direct form must bind.
    fn operands_of(s: &Shape) -> (Vec<usize>, &'static [usize]) {
        match s.interface {
            Interface::Direct8 {
                channels: [0x54ca, 0x54cb],
            } => (legacy_direct_operands(s), &[7]),
            _ => (direct_operands(s), &[3, 4]),
        }
    }
    #[test]
    fn direct_program_correction_is_pair_only_and_edits_exactly_its_operands() {
        let base = 0xf00000;
        for s in direct_shapes() {
            let mut original = alloc::vec![0xff; 0x10000];
            original[0x1000..0x1000 + s.bytes.len()].copy_from_slice(s.bytes);
            // Every audited direct form (three- and four-operand) binds alone.
            assert_eq!(bindings(&original, base).len(), 1);
            for target in [Assignment::Direct, Assignment::Swapped] {
                assert_eq!(
                    correct_indexed(&original, base, target),
                    Err(CorrectionError::Unresolved)
                );
            }
            let other = match s.assignment {
                Assignment::Direct => Assignment::Swapped,
                Assignment::Swapped => Assignment::Direct,
            };
            let corrected = correct_pair(&original, base, other).unwrap();
            let (operands, counts) = operands_of(s);
            assert!(counts.contains(&operands.len()));
            let changed: Vec<_> = original
                .iter()
                .zip(&corrected)
                .enumerate()
                .filter_map(|(i, (a, b))| (a != b).then_some(i))
                .collect();
            assert_eq!(
                changed,
                operands.iter().map(|p| 0x1000 + p).collect::<Vec<_>>()
            );
            assert_eq!(
                correct_pair(&corrected, base, s.assignment).unwrap(),
                original
            );
            let mut bad = original.clone();
            bad[0x1000 + operands[0]] ^= 1;
            assert!(correct_pair(&bad, base, other).is_err());
        }
    }
    #[test]
    fn tiled_programs_are_deduplicated_without_quadratic_comparisons() {
        let s = direct_shapes()
            .find(|s| {
                s.interface
                    == Interface::Direct8 {
                        channels: [0x118, 0x119],
                    }
            })
            .unwrap();
        let mut body = alloc::vec![0xff; 0x80000];
        let stride = s.bytes.len() + 1;
        let count = (body.len() - 0x1000) / stride;
        for k in 0..count {
            let at = 0x1000 + k * stride;
            body[at..at + s.bytes.len()].copy_from_slice(s.bytes);
        }
        COMPARISONS.with(|c| c.set(0));
        let found = bindings(&body, 0xf00000);
        assert!(found.len() >= count);
        assert!(found.windows(2).all(|w| w[0] != w[1]));
        assert!(COMPARISONS.with(core::cell::Cell::get) < 4 * count);
    }
    #[test]
    fn every_nonrelocated_phase_instruction_is_required() {
        for s in shapes::CONSUMERS {
            let mut body = alloc::vec![0xff;0x1000000];
            body[..s.bytes.len()].copy_from_slice(s.bytes);
            assert!(matches(&body, 0, s, 0));
            for i in 0..s.bytes.len() {
                if s.masks.iter().any(|&(p, z, _)| (p..p + z).contains(&i)) {
                    continue;
                }
                body[i] ^= 1;
                assert!(!matches(&body, 0, s, 0));
                body[i] ^= 1;
            }
        }
    }
}
