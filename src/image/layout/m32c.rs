//! Recognition of the traced M32C flash parameter readers.
use super::{m32c_shapes::*, *};
use alloc::vec;

fn matches_at(body: &[u8], at: usize, expected: &[u8], calls: &[usize]) -> bool {
    let Some(actual) = at
        .checked_add(expected.len())
        .and_then(|end| body.get(at..end))
    else {
        return false;
    };
    for &call in calls {
        let target = u32::from_le_bytes([actual[call + 1], actual[call + 2], actual[call + 3], 0]);
        // These native runtime entrypoints live in the final 4 KiB CPU page.
        // This bounds the relocation; it does not execute the runtime helper.
        if actual[call] != 0xcd || !(0xfff000..0xffffff).contains(&target) {
            return false;
        }
    }
    actual
        .iter()
        .zip(expected)
        .enumerate()
        .all(|(i, (a, b))| a == b || calls.iter().any(|&call| (call + 1..call + 4).contains(&i)))
}

/// Recognize M32C two- and three-region appended-record readers in decoded Normal.
///
/// Binds geometry, width, header calculation, complete header scan and payload
/// copier, including their relative call destinations. Only absolute arithmetic
/// runtime call operands may relocate. This is not whole-image identification,
/// hardware execution, a write permission, or a migration recipe.
///
/// Serial M32C storage formats currently return unresolved here; callers must
/// not substitute a default layout for a missing reader.
pub fn discover_m32c_records(body: &[u8]) -> Observation<ParameterLayout> {
    let (has_three, has_two) = anchors(body);
    if has_three && has_two {
        return Observation::Conflicting;
    }
    if has_two {
        return discover_two(body);
    }
    discover_three(body)
}

fn anchors(body: &[u8]) -> (bool, bool) {
    (
        body.windows(GEOMETRY.len()).any(|b| b == GEOMETRY),
        body.windows(TWO_WIDTH.len()).any(|b| b == TWO_WIDTH),
    )
}

/// Whether a flash-record reader's geometry anchor is present, bound or not.
pub(crate) fn records_present(body: &[u8]) -> bool {
    let (three, two) = anchors(body);
    three || two
}

fn discover_two(body: &[u8]) -> Observation<ParameterLayout> {
    let mut found = false;
    for (at, candidate) in body.windows(TWO_WIDTH.len()).enumerate() {
        if candidate != TWO_WIDTH {
            continue;
        }
        if !matches_at(body, at + 0x28, TWO_HEADER_BYTES, &[])
            || !matches_at(body, at + 0xbc, TWO_RECORD_COPIER, &[60])
            || !matches_at(body, at + 0x68a, TWO_HEADER_SCANNER, &[])
        {
            return Observation::Unresolved(Unresolved::ReaderNotRecognized);
        }
        if found {
            return Observation::Unresolved(Unresolved::AmbiguousReader);
        }
        found = true;
    }
    if !found {
        return Observation::Unresolved(Unresolved::ReaderNotRecognized);
    }
    Observation::Known(ParameterLayout::FlashRecords {
        regions: [(0xffa000, 32, 8), (0xffb000, 64, 62)]
            .into_iter()
            .map(|(address, record_bytes, record_count)| RecordRegion {
                address,
                basis: AddressBasis::Absolute,
                allocation_bytes: None,
                record_bytes,
                record_count,
                header_bytes: 2 * record_count,
                header_test: HeaderTest::ByteFf,
            })
            .collect(),
        encoding: WordEncoding::LittleEndian,
        domains: vec![],
    })
}

fn discover_three(body: &[u8]) -> Observation<ParameterLayout> {
    let mut found = false;
    for (at, candidate) in body.windows(GEOMETRY.len()).enumerate() {
        if candidate != GEOMETRY {
            continue;
        }
        if !matches_at(body, at + 0x46, WIDTH, &[])
            || !matches_at(body, at + 0x82, HEADER, &[14])
            || !matches_at(body, at + 0x9c, SCANNER, &[])
            || !matches_at(body, at + 0xce, PAYLOAD_COPIER, &[73])
        {
            // A second, incomplete matching geometry cannot be silently ignored.
            return Observation::Unresolved(Unresolved::ReaderNotRecognized);
        }
        if found {
            // We cannot establish which duplicated reader is selected at runtime.
            return Observation::Unresolved(Unresolved::AmbiguousReader);
        }
        found = true;
    }
    if !found {
        return Observation::Unresolved(Unresolved::ReaderNotRecognized);
    }
    let regions = [
        (0xffa000, 0xa20, 320, 8),
        (0xffaa20, 0x5e0, 160, 9),
        (0xffb000, 0x1000, 64, 62),
    ]
    .into_iter()
    .map(|(address, size, record_bytes, record_count)| RecordRegion {
        address,
        basis: AddressBasis::Absolute,
        allocation_bytes: Some(size),
        record_bytes,
        record_count,
        header_bytes: 2 * record_count,
        header_test: HeaderTest::ByteFf,
    })
    .collect();
    Observation::Known(ParameterLayout::FlashRecords {
        regions,
        encoding: WordEncoding::LittleEndian,
        domains: vec![],
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn fixture() -> Vec<u8> {
        let mut body = vec![0; 0xce + PAYLOAD_COPIER.len()];
        for (at, bytes) in [
            (0, GEOMETRY),
            (0x46, WIDTH),
            (0x82, HEADER),
            (0x9c, SCANNER),
            (0xce, PAYLOAD_COPIER),
        ] {
            body[at..at + bytes.len()].copy_from_slice(bytes);
        }
        body
    }

    fn two_fixture() -> Vec<u8> {
        let mut body = vec![0; 0x68a + TWO_HEADER_SCANNER.len()];
        for (at, bytes) in [
            (0, TWO_WIDTH),
            (0x28, TWO_HEADER_BYTES),
            (0xbc, TWO_RECORD_COPIER),
            (0x68a, TWO_HEADER_SCANNER),
        ] {
            body[at..at + bytes.len()].copy_from_slice(bytes);
        }
        body
    }

    #[test]
    fn two_region_reader_is_distinct_and_does_not_invent_allocation_size() {
        let two = two_fixture();
        let Observation::Known(ParameterLayout::FlashRecords { regions, .. }) =
            discover_m32c_records(&two)
        else {
            panic!("two-region reader not bound")
        };
        assert_eq!(regions.len(), 2);
        assert_eq!(regions[0].record_bytes, 32);
        assert_eq!(regions[0].header_bytes, 16);
        assert_eq!(regions[1].record_bytes, 64);
        assert_eq!(regions[1].header_bytes, 124);
        assert!(regions.iter().all(|r| r.allocation_bytes.is_none()));
        assert_eq!(
            discover_m32c_records(&two).compare(&discover_m32c_records(&fixture())),
            Some(false)
        );
        let mut mixed = two.clone();
        mixed.extend_from_slice(&fixture());
        assert!(matches!(
            discover_m32c_records(&mixed),
            Observation::Conflicting
        ));
    }

    #[test]
    fn two_region_reader_requires_full_copier_and_distant_scanner() {
        let original = two_fixture();
        for (start, bytes, calls) in [
            (0, TWO_WIDTH, &[][..]),
            (0x28, TWO_HEADER_BYTES, &[][..]),
            (0xbc, TWO_RECORD_COPIER, &[60][..]),
            (0x68a, TWO_HEADER_SCANNER, &[][..]),
        ] {
            for offset in 0..bytes.len() {
                if calls
                    .iter()
                    .any(|call| (call + 1..call + 4).contains(&offset))
                {
                    continue;
                }
                for bit in 0..8 {
                    let mut changed = original.clone();
                    changed[start + offset] ^= 1 << bit;
                    assert!(
                        !matches!(discover_m32c_records(&changed), Observation::Known(_)),
                        "accepted two-region byte {:#x}, bit {bit}",
                        start + offset
                    );
                }
            }
        }
        for end in 0..original.len() {
            assert!(!matches!(
                discover_m32c_records(&original[..end]),
                Observation::Known(_)
            ));
        }
    }

    #[test]
    fn native_reader_extracts_three_regions() {
        let Observation::Known(ParameterLayout::FlashRecords {
            regions,
            encoding,
            domains,
        }) = discover_m32c_records(&fixture())
        else {
            panic!("reader not bound")
        };
        assert_eq!(
            regions
                .iter()
                .map(|r| (r.address, r.record_bytes, r.record_count, r.header_bytes))
                .collect::<Vec<_>>(),
            vec![
                (0xffa000, 320, 8, 16),
                (0xffaa20, 160, 9, 18),
                (0xffb000, 64, 62, 124)
            ]
        );
        assert_eq!(encoding, WordEncoding::LittleEndian);
        assert!(domains.is_empty());
    }

    #[test]
    fn every_fixed_reader_byte_is_required() {
        let original = fixture();
        for (start, bytes, calls) in [
            (0, GEOMETRY, &[][..]),
            (0x46, WIDTH, &[][..]),
            (0x82, HEADER, &[14][..]),
            (0x9c, SCANNER, &[][..]),
            (0xce, PAYLOAD_COPIER, &[73][..]),
        ] {
            for offset in 0..bytes.len() {
                if calls
                    .iter()
                    .any(|call| (call + 1..call + 4).contains(&offset))
                {
                    continue;
                }
                for bit in 0..8 {
                    let mut changed = original.clone();
                    changed[start + offset] ^= 1 << bit;
                    assert!(
                        !matches!(discover_m32c_records(&changed), Observation::Known(_)),
                        "accepted changed reader byte {:#x}, bit {bit}",
                        start + offset
                    );
                }
            }
        }
    }

    #[test]
    fn relocation_is_bounded_and_layout_invariant() {
        let original = fixture();
        let mut changed = original.clone();
        changed[0x82 + 15..0x82 + 18].copy_from_slice(&[0x90, 0xf0, 0xff]);
        changed[0xce + 74..0xce + 77].copy_from_slice(&[0x92, 0xf1, 0xff]);
        assert_eq!(
            discover_m32c_records(&original).compare(&discover_m32c_records(&changed)),
            Some(true)
        );
        changed[0xce + 74..0xce + 77].fill(0);
        assert!(matches!(
            discover_m32c_records(&changed),
            Observation::Unresolved(_)
        ));
    }

    #[test]
    fn truncation_and_duplicate_reader_fail_closed() {
        let original = fixture();
        for end in 0..original.len() {
            assert!(!matches!(
                discover_m32c_records(&original[..end]),
                Observation::Known(_)
            ));
        }
        let mut duplicate = original.clone();
        duplicate.extend_from_slice(&original);
        assert!(matches!(
            discover_m32c_records(&duplicate),
            Observation::Unresolved(Unresolved::AmbiguousReader)
        ));
        let mut moved = vec![0; 137];
        moved.extend_from_slice(&original);
        assert_eq!(
            discover_m32c_records(&original).compare(&discover_m32c_records(&moved)),
            Some(true)
        );
    }
}
