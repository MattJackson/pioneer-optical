//! Native output pair emitted by the existing certified mechanism adaptation.
//! Only the four output operands vary. Mechanism math and source encoding stay fixed.

use super::{Assignment, CorrectionError, Interface, Observation, Phase};
use alloc::vec::Vec;

const PAIR: &[u8] = &[
    0x01, 0x00, 0x6d, 0xf3, 0x1a, 0xb3, 0x0c, 0x8b, 0x10, 0x73, 0x0a, 0x93, 0x69, 0x30, 0x00, 0x00,
    0x5e, 0x57, 0xcf, 0x0c, 0x0c, 0x80, 0x12, 0xc0, 0xe0, 0x03, 0x6a, 0x80, 0xf9, 0x12, 0x69, 0x30,
    0x00, 0x00, 0x5e, 0x57, 0xcf, 0x0e, 0x6a, 0x88, 0xf9, 0x10, 0x01, 0x00, 0x6d, 0x73, 0x54, 0x70,
    0x01, 0x00, 0x6d, 0xf3, 0x1a, 0xb3, 0x0c, 0x8b, 0x10, 0x73, 0x0a, 0x93, 0x6f, 0x30, 0x00, 0x02,
    0x00, 0x00, 0x0c, 0x80, 0x12, 0xc0, 0xe0, 0x03, 0x6a, 0x80, 0xf9, 0x13, 0x6f, 0x30, 0x00, 0x02,
    0x0c, 0x08, 0x6a, 0x88, 0xf9, 0x11, 0x01, 0x00, 0x6d, 0x73, 0x54, 0x70,
];

const OPERANDS: [usize; 4] = [29, 41, 75, 85];

#[derive(Clone, Debug, PartialEq, Eq)]
struct Binding {
    at: usize,
    leaf: usize,
    assignment: Assignment,
}

fn bind(normal: &[u8], at: usize, stored: &[&[u8]]) -> Option<Binding> {
    let bytes = normal.get(at..at.checked_add(PAIR.len())?)?;
    let swapped = bytes[OPERANDS[0]] ^ PAIR[OPERANDS[0]];
    if swapped > 1
        || !bytes.iter().zip(PAIR).enumerate().all(|(i, (a, b))| {
            if (17..20).contains(&i) || (35..38).contains(&i) {
                true
            } else if OPERANDS.contains(&i) {
                *a == *b ^ swapped
            } else {
                a == b
            }
        })
    {
        return None;
    }
    let high = u32::from_be_bytes([0, bytes[17], bytes[18], bytes[19]]);
    let low = u32::from_be_bytes([0, bytes[35], bytes[36], bytes[37]]);
    if high & 1 != 0 || low != high.checked_add(2)? {
        return None;
    }
    let leaf = high.checked_sub(0x410000)? as usize;
    let contains = |start: usize, len: usize| {
        stored.iter().any(|region| {
            let origin = region.as_ptr() as usize - normal.as_ptr() as usize;
            start >= origin && start.saturating_add(len) <= origin + region.len()
        })
    };
    if !contains(at, PAIR.len())
        || !contains(leaf, 6)
        || normal.get(leaf..leaf.checked_add(6)?) != Some(&[0x54, 0x70, 0x0c, 0x08, 0x54, 0x70][..])
    {
        return None;
    }
    Some(Binding {
        at,
        leaf,
        assignment: if swapped == 0 {
            Assignment::Direct
        } else {
            Assignment::Swapped
        },
    })
}

pub(super) fn observe(normal: &[u8], at: usize, stored: &[&[u8]]) -> Option<Phase> {
    bind(normal, at, stored).map(|b| Phase {
        assignment: b.assignment,
        interface: Interface::SplitWord,
    })
}

pub(super) fn correct(normal: &[u8], target: Assignment) -> Result<Vec<u8>, CorrectionError> {
    let regions = crate::image::regions(normal).ok_or(CorrectionError::Unresolved)?;
    let mut bindings = Vec::new();
    for region in &regions.stored {
        let start = region.as_ptr() as usize - normal.as_ptr() as usize;
        for at in (start + (start & 1)..start + region.len()).step_by(2) {
            if let Some(binding) = bind(normal, at, &regions.stored) {
                bindings.push(binding);
            }
        }
    }
    let [before] = bindings.as_slice() else {
        return Err(CorrectionError::Unresolved);
    };
    if !matches!(super::discover(normal), Observation::Known(p) if p == Phase { assignment: before.assignment, interface: Interface::SplitWord })
    {
        return Err(CorrectionError::Unresolved);
    }
    let mut corrected = normal.to_vec();
    if before.assignment != target {
        for offset in OPERANDS {
            corrected[before.at + offset] ^= 1;
        }
    }
    let regions = crate::image::regions(&corrected).ok_or(CorrectionError::VerificationFailed)?;
    let after =
        bind(&corrected, before.at, &regions.stored).ok_or(CorrectionError::VerificationFailed)?;
    if after.at != before.at
        || after.leaf != before.leaf
        || after.assignment != target
        || !matches!(super::discover(&corrected), Observation::Known(p) if p == Phase { assignment: target, interface: Interface::SplitWord })
    {
        return Err(CorrectionError::VerificationFailed);
    }
    Ok(corrected)
}

#[cfg(test)]
mod tests {
    use super::super::*;
    use super::*;
    #[test]
    fn complete_adapted_pair_requires_every_instruction_and_bound_leaf() {
        let mut raw = alloc::vec![0xff; 512];
        let mut pair = PAIR.to_vec();
        pair[17..20].copy_from_slice(&[0x41, 1, 0x80]);
        pair[35..38].copy_from_slice(&[0x41, 1, 0x82]);
        raw[32..32 + PAIR.len()].copy_from_slice(&pair);
        raw[384..390].copy_from_slice(&[0x54, 0x70, 0x0c, 8, 0x54, 0x70]);
        assert!(observe(&raw, 32, &[&raw]).is_some());
        assert_eq!(
            discover(&raw).compare(&Observation::Known(Phase {
                assignment: Assignment::Direct,
                interface: Interface::SplitWord
            })),
            Some(true)
        );
        assert_eq!(
            correct_pair(&raw, Assignment::Swapped),
            Err(CorrectionError::Unresolved)
        );
        for offset in (32..32 + PAIR.len()).chain(384..390) {
            raw[offset] ^= 1;
            assert!(observe(&raw, 32, &[&raw]).is_none(), "offset {offset}");
            raw[offset] ^= 1;
        }
        assert!(observe(&raw, 32, &[&raw[..384]]).is_none());
    }
    #[test]
    fn output_only_correction_is_reversible_bounded_and_idempotent() {
        let mut raw = alloc::vec![0xff; 512];
        raw[32..32 + PAIR.len()].copy_from_slice(PAIR);
        raw[49..52].copy_from_slice(&[0x41, 1, 0x80]);
        raw[67..70].copy_from_slice(&[0x41, 1, 0x82]);
        raw[384..390].copy_from_slice(&[0x54, 0x70, 0x0c, 8, 0x54, 0x70]);
        let swapped = correct_adapted(&raw, Assignment::Swapped).unwrap();
        let changed: Vec<_> = raw
            .iter()
            .zip(&swapped)
            .enumerate()
            .filter_map(|(i, (a, b))| (a != b).then_some(i))
            .collect();
        assert_eq!(changed, OPERANDS.map(|x| x + 32));
        assert_eq!(correct_adapted(&swapped, Assignment::Direct).unwrap(), raw);
        assert_eq!(
            correct_adapted(&swapped, Assignment::Swapped).unwrap(),
            swapped
        );
        assert_eq!(correct_adapted(&raw, Assignment::Direct).unwrap(), raw);
        for offset in OPERANDS {
            let mut partial = raw.clone();
            partial[32 + offset] ^= 1;
            assert_eq!(
                correct_adapted(&partial, Assignment::Direct),
                Err(CorrectionError::Unresolved)
            );
        }
        let mut duplicate = raw.clone();
        duplicate[160..160 + PAIR.len()].copy_from_slice(&raw[32..32 + PAIR.len()]);
        assert_eq!(
            correct_adapted(&duplicate, Assignment::Swapped),
            Err(CorrectionError::Unresolved)
        );
        raw[..16].copy_from_slice(b"PIONEER TEST    ");
        raw[16..20].fill(0);
        raw[20..24].copy_from_slice(&512u32.to_be_bytes());
        raw[24..28].copy_from_slice(b"ID01");
        let compensation = 0u32.wrapping_sub(super::super::checksum(&raw));
        raw[16..20].copy_from_slice(&compensation.to_be_bytes());
        let checked = correct_normal(&raw, Assignment::Swapped).unwrap();
        assert_eq!(super::super::checksum(&checked), 0);
        assert_eq!(correct_normal(&checked, Assignment::Direct).unwrap(), raw);
    }
}
