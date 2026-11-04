//! Read-only observation of the output pair left on drives by the removed
//! pre-1.6 mechanism adaptation. Only the four output operands vary. This
//! identifies installed firmware; it never prepares or corrects such an image.

use super::{Assignment, Interface, Phase};

const PAIR: &[u8] = &[
    0x01, 0x00, 0x6d, 0xf3, 0x1a, 0xb3, 0x0c, 0x8b, 0x10, 0x73, 0x0a, 0x93, 0x69, 0x30, 0x00, 0x00,
    0x5e, 0x57, 0xcf, 0x0c, 0x0c, 0x80, 0x12, 0xc0, 0xe0, 0x03, 0x6a, 0x80, 0xf9, 0x12, 0x69, 0x30,
    0x00, 0x00, 0x5e, 0x57, 0xcf, 0x0e, 0x6a, 0x88, 0xf9, 0x10, 0x01, 0x00, 0x6d, 0x73, 0x54, 0x70,
    0x01, 0x00, 0x6d, 0xf3, 0x1a, 0xb3, 0x0c, 0x8b, 0x10, 0x73, 0x0a, 0x93, 0x6f, 0x30, 0x00, 0x02,
    0x00, 0x00, 0x0c, 0x80, 0x12, 0xc0, 0xe0, 0x03, 0x6a, 0x80, 0xf9, 0x13, 0x6f, 0x30, 0x00, 0x02,
    0x0c, 0x08, 0x6a, 0x88, 0xf9, 0x11, 0x01, 0x00, 0x6d, 0x73, 0x54, 0x70,
];

const OPERANDS: [usize; 4] = [29, 41, 75, 85];

fn bind(normal: &[u8], at: usize, stored: &[&[u8]]) -> Option<Assignment> {
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
    Some(if swapped == 0 {
        Assignment::Direct
    } else {
        Assignment::Swapped
    })
}

pub(super) fn observe(normal: &[u8], at: usize, stored: &[&[u8]]) -> Option<Phase> {
    bind(normal, at, stored).map(|assignment| Phase {
        assignment,
        interface: Interface::SplitWord,
    })
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
    fn observed_adapted_pair_is_never_corrected() {
        let mut raw = alloc::vec![0xff; 512];
        raw[32..32 + PAIR.len()].copy_from_slice(PAIR);
        raw[49..52].copy_from_slice(&[0x41, 1, 0x80]);
        raw[67..70].copy_from_slice(&[0x41, 1, 0x82]);
        raw[384..390].copy_from_slice(&[0x54, 0x70, 0x0c, 8, 0x54, 0x70]);
        raw[..16].copy_from_slice(b"PIONEER TEST    ");
        raw[16..20].fill(0);
        raw[20..24].copy_from_slice(&512u32.to_be_bytes());
        raw[24..28].copy_from_slice(b"ID01");
        let compensation = 0u32.wrapping_sub(super::super::checksum(&raw));
        raw[16..20].copy_from_slice(&compensation.to_be_bytes());
        assert!(matches!(discover(&raw), Observation::Known(_)));
        for target in [Assignment::Direct, Assignment::Swapped] {
            assert_eq!(
                correct_normal(&raw, target),
                Err(CorrectionError::Unresolved)
            );
        }
    }
}
