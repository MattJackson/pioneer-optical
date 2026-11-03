//! Bounded M7900 resident checksum and exact Normal-header acceptance gate.
//!
//! This observes the image-pair gate, not downstream startup or hardware identity.
use super::scsi_shapes::*;
use crate::image::layout::{Observation, Unresolved};

const NORMAL_BASE: u32 = 0x3800;
const KERNEL_BASE: u32 = 0x8000;
const ADD_AND_ADVANCE: &[u8] = &[0x11, 0x22, 0x01, 0x51, 0x83, 0x01, 2, 0, 0, 0];

/// Native acceptance semantics and their source coordinates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Evidence {
    /// CPU byte intervals, summed as little-endian words with wrapping ADD16.
    pub ranges: [(u32, u32); 3],
    /// Initial and required final sixteen-bit accumulator values.
    pub accumulator: (u16, u16),
    /// Exact comparison bytes read from the associated Kernel's table.
    pub expected_header: [u8; 16],
    /// Normal and Kernel CPU addresses of the sixteen-byte header operands.
    pub header_addresses: (u32, u32),
    /// Actual checksum of the supplied Normal under the native contract.
    pub normal_checksum: u16,
    /// Whether the supplied Normal satisfies the exact header comparison.
    pub normal_header_matches: bool,
    /// Reset entry, checksum entry, header entry, rejection and Normal entry.
    pub control_addresses: [u32; 5],
    /// RAM byte cleared on reset and set after the checksum succeeds.
    pub checksum_cache: u16,
    /// Exact bounded resident program spans, including reset's copy/clear callees.
    pub source_spans: [(u32, u32); 4],
}

fn kernel_at(kernel: &[u8], address: u32, length: usize) -> Option<&[u8]> {
    let at = usize::try_from(address.checked_sub(KERNEL_BASE)?).ok()?;
    kernel.get(at..at.checked_add(length)?)
}

fn pointer(code: &[u8]) -> u32 {
    u32::from_le_bytes([code[1], code[2], code[5], code[6]])
}

fn pointer_load(code: &[u8]) -> bool {
    code.len() == 8 && code[0] == 0x86 && code[3..5] == [1, 0x86] && code[7] == 3
}

fn loop_end(code: &[u8]) -> Option<u32> {
    if code.len() != 89
        || !code[..80]
            .chunks_exact(10)
            .all(|instruction| instruction == ADD_AND_ADVANCE)
        || code[80..83] != [0x51, 0xa3, 1]
        || code[87..89] != [0x90, 0xa7]
    {
        return None;
    }
    Some(u32::from_le_bytes(code[83..87].try_into().ok()?))
}

/// Bind the complete supported resident reset path through its final jump.
///
/// Source addresses identify this compiler form; no model string, firmware hash
/// or sibling image substitutes for its instructions. The copied/cleared memory
/// helpers are bound in full. The observation stops at rejection entry 0x8391
/// and successful transfer to Normal 0x4054; it makes no recursive boot claim.
pub fn discover(normal: &[u8], kernel: Option<&[u8]>) -> Observation<Evidence> {
    let missing = || Observation::Unresolved(Unresolved::ReaderNotRecognized);
    let Some(kernel) = kernel else {
        return Observation::Unresolved(Unresolved::ResidentCodeRequired(0x8010));
    };
    if kernel_at(kernel, 0xfffe, 2) != Some(&[0x10, 0x80][..])
        || kernel_at(kernel, 0x8010, RESET_PREFIX.len()) != Some(RESET_PREFIX)
        || kernel_at(kernel, 0xdbf3, CLEAR.len()) != Some(CLEAR)
        || kernel_at(kernel, 0xdc19, COPY.len()) != Some(COPY)
        || kernel_at(kernel, 0x8342, GATE_SUFFIX.len()) != Some(GATE_SUFFIX)
    {
        return missing();
    }
    let Some(prefix) = kernel_at(kernel, 0x8210, GATE_PREFIX.len()) else {
        return missing();
    };
    if prefix[..15] != GATE_PREFIX[..15] || !pointer_load(&prefix[15..23]) {
        return missing();
    }
    let mut ranges = [(0, 0); 3];
    for (i, (load_at, loop_at)) in [(0x821f, 0x8227), (0x8280, 0x8288), (0x82e1, 0x82e9)]
        .into_iter()
        .enumerate()
    {
        let Some(load) = kernel_at(kernel, load_at, 8) else {
            return missing();
        };
        let Some(code) = kernel_at(kernel, loop_at, 89) else {
            return missing();
        };
        let Some(end) = loop_end(code) else {
            return missing();
        };
        if !pointer_load(load) {
            return missing();
        }
        let start = pointer(load);
        // Each iteration adds exactly eight words. Reject ranges that do not
        // terminate on a full iteration or escape the supplied Normal mapping.
        if start < NORMAL_BASE || start & 1 != 0 || end <= start || (end - start) % 16 != 0 {
            return missing();
        }
        ranges[i] = (start, end);
    }
    let Some(expected) = kernel_at(kernel, 0x83a6, 16) else {
        return missing();
    };
    let Some(header) = normal.get(..16) else {
        return Observation::Unresolved(Unresolved::TruncatedEvidence);
    };
    if normal.get((0x4054 - NORMAL_BASE) as usize..(0x4059 - NORMAL_BASE) as usize)
        != Some(&[0x2c, 0xa0, 0x0b, 0, 0][..])
    {
        return missing();
    }
    let mut normal_checksum = 0u16;
    for (start, end) in ranges {
        let Some(bytes) = normal.get((start - NORMAL_BASE) as usize..(end - NORMAL_BASE) as usize)
        else {
            return Observation::Unresolved(Unresolved::TruncatedEvidence);
        };
        for word in bytes.chunks_exact(2) {
            normal_checksum = normal_checksum.wrapping_add(u16::from_le_bytes([word[0], word[1]]));
        }
    }
    Observation::Known(Evidence {
        ranges,
        accumulator: (0, 0),
        expected_header: expected.try_into().expect("bounded header"),
        header_addresses: (NORMAL_BASE, 0x83a6),
        normal_checksum,
        normal_header_matches: header == expected,
        control_addresses: [0x8010, 0x8210, 0x835f, 0x8391, 0x4054],
        checksum_cache: 0x08e9,
        source_spans: [
            (0x8010, 0x8391),
            (0xdbf3, 0xdc19),
            (0xdc19, 0xdc48),
            (0xfffe, 0x10000),
        ],
    })
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use alloc::{vec, vec::Vec};

    pub(crate) fn fixture() -> (Vec<u8>, Vec<u8>) {
        let mut kernel = vec![0xff; 0x8000];
        for (at, bytes) in [
            (0x8010, RESET_PREFIX),
            (0x8210, GATE_PREFIX),
            (0x8342, GATE_SUFFIX),
            (0xdbf3, CLEAR),
            (0xdc19, COPY),
            (0xfffe, &[0x10, 0x80][..]),
        ] {
            let at = at - 0x8000;
            kernel[at..at + bytes.len()].copy_from_slice(bytes);
        }
        for (at, start, end) in [
            (0x8227usize, 0x3900u32, 0x8000u32),
            (0x8288, 0x10000, 0x40000),
            (0x82e9, 0x80000, 0xf8000),
        ] {
            let at = at - 0x8000;
            let value = start.to_le_bytes();
            kernel[at - 8..at]
                .copy_from_slice(&[0x86, value[0], value[1], 1, 0x86, value[2], value[3], 3]);
            for n in 0..8 {
                kernel[at + n * 10..at + (n + 1) * 10].copy_from_slice(ADD_AND_ADVANCE);
            }
            kernel[at + 80..at + 89].copy_from_slice(&[0x51, 0xa3, 1, 0, 0, 0, 0, 0x90, 0xa7]);
            kernel[at + 83..at + 87].copy_from_slice(&end.to_le_bytes());
        }
        let header = *b"Example Header!!";
        kernel[0x3a6..0x3b6].copy_from_slice(&header);
        let mut normal = vec![0; 0xf8000 - 0x3800];
        normal[..16].copy_from_slice(&header);
        normal[0x854..0x859].copy_from_slice(&[0x2c, 0xa0, 0x0b, 0, 0]);
        (normal, kernel)
    }

    fn known(normal: &[u8], kernel: &[u8]) -> Evidence {
        match discover(normal, Some(kernel)) {
            Observation::Known(e) => e,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn native_contract_has_ranges_header_and_actual_acceptance() {
        let (normal, kernel) = fixture();
        let value = known(&normal, &kernel);
        assert_eq!(
            value.ranges,
            [(0x3900, 0x8000), (0x10000, 0x40000), (0x80000, 0xf8000)]
        );
        assert!(value.normal_header_matches);
        assert!(matches!(
            discover(&normal, None),
            Observation::Unresolved(Unresolved::ResidentCodeRequired(0x8010))
        ));
        assert!(matches!(
            discover(&[], Some(&kernel)),
            Observation::Unresolved(_)
        ));
    }

    #[test]
    fn native_scalars_are_extracted_and_checksum_boundaries_are_observed() {
        let (mut normal, mut kernel) = fixture();
        let original = known(&normal, &kernel);
        for (start, end) in original.ranges {
            for cpu in [start, start + 1, end - 2, end - 1] {
                let at = (cpu - NORMAL_BASE) as usize;
                normal[at] ^= 1;
                assert_ne!(
                    known(&normal, &kernel).normal_checksum,
                    original.normal_checksum
                );
                normal[at] ^= 1;
            }
        }
        normal[0] ^= 1;
        assert!(!known(&normal, &kernel).normal_header_matches);
        assert_eq!(
            known(&normal, &kernel).normal_checksum,
            original.normal_checksum
        );
        kernel[0x3a6] ^= 1;
        assert!(known(&normal, &kernel).normal_header_matches);
        assert_ne!(
            known(&normal, &kernel).expected_header,
            original.expected_header
        );
        kernel[0x220] = 0x10;
        assert_eq!(known(&normal, &kernel).ranges[0].0, 0x3910);
        kernel[0x27a] = 0x10;
        assert_eq!(known(&normal, &kernel).ranges[0].1, 0x8010);
    }

    #[test]
    fn all_control_instructions_and_resident_helpers_fail_closed_on_mutation() {
        let (normal, mut kernel) = fixture();
        for (a, z) in [(0x10, 0x391), (0x5bf3, 0x5c48), (0x7ffe, 0x8000)] {
            for at in a..z {
                // Only native range operands are deliberately variable.
                if [0x21fusize, 0x280, 0x2e1]
                    .iter()
                    .any(|p| [p + 1, p + 2, p + 5, p + 6].contains(&at))
                    || [0x227usize, 0x288, 0x2e9]
                        .iter()
                        .any(|p| (p + 83..p + 87).contains(&at))
                {
                    continue;
                }
                kernel[at] ^= 1;
                assert!(
                    !matches!(discover(&normal, Some(&kernel)), Observation::Known(_)),
                    "byte {at:x}"
                );
                kernel[at] ^= 1;
            }
        }
        for end in [0, 0x390, 0x3b5, 0x5c47, 0x7fff] {
            assert!(!matches!(
                discover(&normal, Some(&kernel[..end])),
                Observation::Known(_)
            ));
        }
    }
}
