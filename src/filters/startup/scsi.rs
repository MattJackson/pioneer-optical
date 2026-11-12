//! Bounded M7900 resident checksum and exact Normal-header acceptance gate.
//!
//! This observes the image-pair gate, not downstream startup or hardware identity.
use crate::image::layout::{Observation, Unresolved};
use shapes::*;

const NORMAL_BASE: u32 = 0x3800;
const KERNEL_BASE: u32 = 0x8000;
/// End of the resident Kernel ROM window, which no Normal byte occupies.
const KERNEL_END: u32 = 0x10000;
/// Bound resident coordinates: reset vector and entry, checksum gate entry,
/// gate suffix, header comparison entry and expected-header table.
const VECTOR: u32 = 0xfffe;
const RESET: u32 = 0x8010;
const CHECKSUM_GATE: u32 = 0x8210;
const GATE_SUFFIX_AT: u32 = 0x8342;
const HEADER_GATE: u32 = 0x835f;
const EXPECTED_HEADER: u32 = 0x83a6;
/// Rejection entry, directly after the bound gate suffix.
const REJECT: u32 = GATE_SUFFIX_AT + GATE_SUFFIX.len() as u32;
/// Reset's bound memory clear and copy helpers.
const CLEAR_AT: u32 = 0xdbf3;
const COPY_AT: u32 = 0xdc19;
/// Normal entry the accepted gate transfers to.
const NORMAL_ENTRY: u32 = 0x4054;
/// Exact instruction bytes the accepted gate expects at the Normal entry.
const NORMAL_ENTRY_BYTES: [u8; 5] = [0x2c, 0xa0, 0x0b, 0, 0];
/// Address of the RAM byte cleared on reset and set after the checksum succeeds.
const CHECKSUM_CACHE: u16 = 0x08e9;
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
    /// Address of the RAM byte cleared on reset and set after the checksum succeeds.
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
        return Observation::Unresolved(Unresolved::ResidentCodeRequired(RESET));
    };
    if kernel_at(kernel, VECTOR, 2) != Some(&RESET.to_le_bytes()[..2])
        || kernel_at(kernel, RESET, RESET_PREFIX.len()) != Some(RESET_PREFIX)
        || kernel_at(kernel, CLEAR_AT, CLEAR.len()) != Some(CLEAR)
        || kernel_at(kernel, COPY_AT, COPY.len()) != Some(COPY)
        || kernel_at(kernel, GATE_SUFFIX_AT, GATE_SUFFIX.len()) != Some(GATE_SUFFIX)
    {
        return missing();
    }
    let Some(prefix) = kernel_at(kernel, CHECKSUM_GATE, GATE_PREFIX.len()) else {
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
        // terminate on a full iteration or escape the supplied Normal mapping,
        // including the resident Kernel ROM window the CPU reads instead.
        if start < NORMAL_BASE
            || start & 1 != 0
            || end <= start
            || (end - start) % 16 != 0
            || (start < KERNEL_END && end > KERNEL_BASE)
        {
            return missing();
        }
        ranges[i] = (start, end);
    }
    let Some(expected) = kernel_at(kernel, EXPECTED_HEADER, 16) else {
        return missing();
    };
    let Some(header) = normal.get(..16) else {
        return Observation::Unresolved(Unresolved::TruncatedEvidence);
    };
    let entry_at = (NORMAL_ENTRY - NORMAL_BASE) as usize;
    let Some(entry) = normal.get(entry_at..entry_at + NORMAL_ENTRY_BYTES.len()) else {
        return Observation::Unresolved(Unresolved::TruncatedEvidence);
    };
    if entry != NORMAL_ENTRY_BYTES {
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
        header_addresses: (NORMAL_BASE, EXPECTED_HEADER),
        normal_checksum,
        normal_header_matches: header == expected,
        control_addresses: [RESET, CHECKSUM_GATE, HEADER_GATE, REJECT, NORMAL_ENTRY],
        checksum_cache: CHECKSUM_CACHE,
        source_spans: [
            (RESET, REJECT),
            (CLEAR_AT, CLEAR_AT + CLEAR.len() as u32),
            (COPY_AT, COPY_AT + COPY.len() as u32),
            (VECTOR, VECTOR + 2),
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
        normal[0x854..0x859].copy_from_slice(&NORMAL_ENTRY_BYTES);
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
        // Reported coordinates are the verified ones.
        assert_eq!(value.header_addresses, (0x3800, 0x83a6));
        assert_eq!(
            value.control_addresses,
            [0x8010, 0x8210, 0x835f, 0x8391, 0x4054]
        );
        assert_eq!(value.checksum_cache, 0x08e9);
        assert_eq!(
            value.source_spans,
            [
                (0x8010, 0x8391),
                (0xdbf3, 0xdc19),
                (0xdc19, 0xdc48),
                (0xfffe, 0x10000)
            ]
        );
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
        kernel[0x27b] = 0x70;
        assert_eq!(known(&normal, &kernel).ranges[0].1, 0x7000);
    }

    #[test]
    fn checksum_ranges_over_the_resident_kernel_window_are_refused() {
        // CPU 0x8000..0x10000 reads Kernel ROM, not the Normal file's bytes.
        // Each case is refused by the window predicate itself; a range that
        // only touches the window boundary is still Known.
        let end = |end: u32| {
            let (normal, mut kernel) = fixture();
            kernel[0x227 + 83..0x227 + 87].copy_from_slice(&end.to_le_bytes());
            discover(&normal, Some(&kernel))
        };
        let start = |start: u32| {
            let (normal, mut kernel) = fixture();
            let value = start.to_le_bytes();
            kernel[0x288 - 8..0x288]
                .copy_from_slice(&[0x86, value[0], value[1], 1, 0x86, value[2], value[3], 3]);
            discover(&normal, Some(&kernel))
        };
        for refused in [end(0x8010), end(0x10000), start(0xfff0), start(0x8000)] {
            assert!(matches!(
                refused,
                Observation::Unresolved(Unresolved::ReaderNotRecognized)
            ));
        }
        assert!(matches!(end(0x8000), Observation::Known(_)));
        assert!(matches!(start(0x10000), Observation::Known(_)));
    }

    #[test]
    fn a_normal_without_its_entry_bytes_is_truncated_evidence() {
        let (normal, kernel) = fixture();
        assert!(matches!(
            discover(&normal[..0x858], Some(&kernel)),
            Observation::Unresolved(Unresolved::TruncatedEvidence)
        ));
        let mut changed = normal.clone();
        changed[0x854] ^= 1;
        assert!(matches!(
            discover(&changed, Some(&kernel)),
            Observation::Unresolved(Unresolved::ReaderNotRecognized)
        ));
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

mod shapes {
    // Complete bounded M7900 reset and image-pair gate compiler forms.
    // Tables and checksum-range immediates are extracted by scsi.rs.
    pub(super) const RESET_PREFIX: &[u8] = &[
        0x05, 0x31, 0x4a, 0x00, 0xb9, 0x21, 0x5e, 0x00, 0xb9, 0x84, 0x5f, 0x00, 0xb9, 0x05, 0xbc,
        0x00, 0xb9, 0x55, 0x62, 0x00, 0xb9, 0x01, 0x62, 0x00, 0xb9, 0x79, 0x64, 0x00, 0xb9, 0x50,
        0x64, 0x00, 0x98, 0x38, 0x16, 0x0f, 0x1b, 0x31, 0x82, 0xb9, 0x8e, 0x80, 0x00, 0xb9, 0x03,
        0x81, 0x00, 0xb9, 0x08, 0x8a, 0x00, 0xb9, 0x87, 0x82, 0x00, 0xb9, 0x01, 0x83, 0x00, 0xb9,
        0x10, 0x8c, 0x00, 0xb9, 0x85, 0x84, 0x00, 0xb9, 0x09, 0x85, 0x00, 0xb9, 0x12, 0x8e, 0x00,
        0xb9, 0x8e, 0x86, 0x00, 0xb9, 0x01, 0x87, 0x00, 0xb9, 0x14, 0x90, 0x00, 0xb9, 0x0a, 0x92,
        0x00, 0xb9, 0x20, 0x02, 0x00, 0xb9, 0xbf, 0x04, 0x00, 0xb9, 0x2f, 0x06, 0x00, 0xb9, 0xff,
        0x08, 0x00, 0xc7, 0x07, 0x00, 0xb9, 0xff, 0x09, 0x00, 0xb9, 0xf8, 0x0a, 0x00, 0xb9, 0xff,
        0x0c, 0x00, 0xb9, 0x6c, 0x0b, 0x00, 0xb9, 0xef, 0x0d, 0x00, 0xc7, 0x0e, 0x00, 0xb9, 0x01,
        0x10, 0x00, 0xc7, 0x0f, 0x00, 0xb9, 0xc0, 0x11, 0x00, 0xb9, 0xde, 0x12, 0x00, 0xb9, 0xab,
        0x14, 0x00, 0xc7, 0x94, 0x00, 0xb9, 0xa0, 0x02, 0x00, 0xb9, 0x00, 0x60, 0x00, 0x16, 0x5e,
        0x01, 0xb3, 0xd0, 0xfd, 0x28, 0xff, 0xcc, 0x80, 0x10, 0x12, 0x28, 0x00, 0xcc, 0x80, 0x10,
        0x12, 0x28, 0xff, 0xcc, 0x84, 0x10, 0x12, 0x28, 0x42, 0xcc, 0xee, 0x20, 0x12, 0x28, 0x10,
        0xcc, 0xa0, 0x20, 0x12, 0x28, 0x9a, 0xcc, 0xfd, 0x20, 0x12, 0x28, 0x48, 0xcc, 0xa2, 0x20,
        0x12, 0x28, 0x25, 0xcc, 0xa3, 0x20, 0x12, 0x16, 0x81, 0x02, 0xdc, 0x0e, 0x20, 0x12, 0xc7,
        0xe9, 0x08, 0xc7, 0xeb, 0x08, 0xc7, 0xec, 0x08, 0x16, 0x31, 0x00, 0xcc, 0x40, 0x11, 0x12,
        0x98, 0x38, 0x16, 0x0f, 0x1b, 0x31, 0x82, 0x2c, 0x54, 0x00, 0x00, 0x00, 0x81, 0x85, 0x85,
        0x2c, 0xa0, 0x1f, 0x00, 0x00, 0x81, 0x85, 0x85, 0x2c, 0xb6, 0x83, 0x00, 0x00, 0x81, 0x85,
        0x85, 0xad, 0x19, 0xdc, 0x00, 0xc7, 0xea, 0x08, 0x2c, 0xb0, 0x00, 0x00, 0x00, 0x81, 0x85,
        0x85, 0x2c, 0x0f, 0x08, 0x00, 0x00, 0x81, 0x85, 0x85, 0xad, 0xf3, 0xdb, 0x00, 0x2c, 0x2a,
        0x00, 0x00, 0x00, 0x81, 0x85, 0x85, 0x2c, 0xbf, 0x08, 0x00, 0x00, 0x81, 0x85, 0x85, 0xad,
        0xf3, 0xdb, 0x00, 0x16, 0x0f, 0x1b, 0x31, 0x82, 0x2c, 0x0e, 0x00, 0x00, 0x00, 0x81, 0x85,
        0x85, 0x2c, 0x00, 0x08, 0x00, 0x00, 0x81, 0x85, 0x85, 0x2c, 0x34, 0x84, 0x00, 0x00, 0x81,
        0x85, 0x85, 0xad, 0x19, 0xdc, 0x00, 0x2c, 0x01, 0x00, 0x00, 0x00, 0x81, 0x85, 0x85, 0x2c,
        0x0e, 0x08, 0x00, 0x00, 0x81, 0x85, 0x85, 0x2c, 0x42, 0x84, 0x00, 0x00, 0x81, 0x85, 0x85,
        0xad, 0x19, 0xdc, 0x00, 0x16, 0x0f, 0x1b, 0x31, 0x82, 0x2c, 0x24, 0x1b, 0x00, 0x00, 0x81,
        0x85, 0x85, 0x2c, 0x23, 0x00, 0x14, 0x00, 0x81, 0x85, 0x85, 0xad, 0xf3, 0xdb, 0x00, 0x2c,
        0x35, 0x03, 0x00, 0x00, 0x81, 0x85, 0x85, 0x2c, 0x47, 0x1b, 0x14, 0x00, 0x81, 0x85, 0x85,
        0xad, 0xf3, 0xdb, 0x00, 0x16, 0x0f, 0x1b, 0x31, 0x82, 0x2c, 0x18, 0x00, 0x00, 0x00, 0x81,
        0x85, 0x85, 0x2c, 0x00, 0x00, 0x14, 0x00, 0x81, 0x85, 0x85, 0x2c, 0x43, 0x84, 0x00, 0x00,
        0x81, 0x85, 0x85, 0xad, 0x19, 0xdc, 0x00, 0x2c, 0x0b, 0x00, 0x00, 0x00, 0x81, 0x85, 0x85,
        0x2c, 0x18, 0x00, 0x14, 0x00, 0x81, 0x85, 0x85, 0x2c, 0x5b, 0x84, 0x00, 0x00, 0x81, 0x85,
        0x85, 0xad, 0x19, 0xdc, 0x00, 0x16, 0x0f, 0x1b, 0x31, 0x82, 0x2c, 0x10, 0x1b, 0x00, 0x00,
        0xec, 0xb7, 0x08, 0x00, 0xec, 0xbb, 0x08, 0x00, 0x2c, 0x90, 0x04, 0x00, 0x00, 0xec, 0x43,
        0x1b, 0x14,
    ];
    pub(super) const COPY: &[u8] = &[
        0x83, 0x31, 0x40, 0x31, 0x4a, 0x00, 0x31, 0x70, 0x8a, 0x0f, 0xf0, 0x1d, 0x11, 0x02, 0x07,
        0x11, 0xc2, 0x0b, 0x51, 0x93, 0x0f, 0x01, 0x00, 0x00, 0x00, 0x51, 0x83, 0x0b, 0x01, 0x00,
        0x00, 0x00, 0x51, 0x83, 0x07, 0x01, 0x00, 0x00, 0x00, 0x20, 0xdf, 0x31, 0x50, 0x98, 0x30,
        0x77, 0x1c,
    ];
    pub(super) const CLEAR: &[u8] = &[
        0x83, 0x31, 0x40, 0x31, 0x4a, 0x00, 0x31, 0x70, 0x8a, 0x0b, 0xf0, 0x14, 0x44, 0x11, 0xc2,
        0x07, 0x51, 0x93, 0x0b, 0x01, 0x00, 0x00, 0x00, 0x51, 0x83, 0x07, 0x01, 0x00, 0x00, 0x00,
        0x20, 0xe8, 0x31, 0x50, 0x98, 0x30, 0x77, 0x1c,
    ];
    pub(super) const GATE_PREFIX: &[u8] = &[
        0x0e, 0xe9, 0x08, 0xf0, 0x03, 0xa7, 0x40, 0x01, 0x83, 0x31, 0x0b, 0x04, 0x31, 0x70, 0x54,
        0x86, 0x00, 0x39, 0x01, 0x86, 0x00, 0x00, 0x03,
    ];
    pub(super) const GATE_SUFFIX: &[u8] = &[
        0xb6, 0x00, 0x00, 0x03, 0x54, 0x20, 0x03, 0x16, 0x01, 0x00, 0x31, 0x0a, 0x04, 0x93, 0xb6,
        0x00, 0x00, 0x3d, 0xb9, 0x01, 0xe9, 0x08, 0xb9, 0x00, 0x60, 0x00, 0x99, 0x30, 0xe4, 0x1d,
        0x00, 0x38, 0x00, 0x11, 0x4d, 0xa6, 0x83, 0x00, 0xd0, 0x27, 0xc3, 0xe6, 0x10, 0xd0, 0xf0,
        0x98, 0x30, 0x2c, 0x54, 0x00, 0x00, 0x00, 0x81, 0x85, 0x85, 0x2c, 0xa0, 0x1f, 0x00, 0x00,
        0x81, 0x85, 0x85, 0x2c, 0x00, 0x40, 0x00, 0x00, 0x81, 0x85, 0x85, 0xad, 0x19, 0xdc, 0x00,
        0xac, 0x54, 0x40, 0x00,
    ];
}
