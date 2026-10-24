use super::{layout::*, Error};
use crate::CodedError;

#[test]
fn conflicting_loader_destinations_reject_layout_instead_of_losing_occupied_memory() {
    use std::io::Write;
    let fixture = crate::comp_runtime::fixture();
    let mut image = vec![0xff; 0x2300];
    image[..fixture.len()].copy_from_slice(&fixture);
    image[0x1000..0x1004].copy_from_slice(b"COMP");
    for index in 0..3 {
        let offset = 0x2000 + index * 0x100;
        let mut encoder =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&[index as u8; 32]).unwrap();
        let compressed = encoder.finish().unwrap();
        image[offset..offset + 4].copy_from_slice(&32u32.to_be_bytes());
        image[offset + 4..offset + 4 + compressed.len()].copy_from_slice(&compressed);
        let entry = 0x1004 + index * 8;
        let start = 0x410000 + offset as u32;
        image[entry..entry + 4].copy_from_slice(&start.to_be_bytes());
        image[entry + 4..entry + 8]
            .copy_from_slice(&(start + compressed.len() as u32).to_be_bytes());
    }
    let layout = inspect(&image).unwrap();
    assert_eq!(layout.overlay_ranges.len(), 3);
    let mut second = fixture.clone();
    second[0xb1] = 0xd1;
    image[fixture.len()..fixture.len() + second.len()].copy_from_slice(&second);
    assert!(matches!(
        inspect(&image),
        Err(Error::Ambiguous {
            context: "COMP runtime destination",
            ..
        })
    ));
}

#[test]
fn intervals_reject_invalid_construction_and_deserialization() {
    for (start, length) in [(0, 0), (u32::MAX, 1)] {
        assert!(Range::new(start, length).is_err());
    }
    for json in [r#"{"start":8,"end":8}"#, r#"{"start":9,"end":8}"#] {
        assert!(serde_json::from_str::<Range>(json).is_err());
    }
    let range: Range = serde_json::from_str(r#"{"start":8,"end":24}"#).unwrap();
    assert_eq!((range.start(), range.end(), range.length()), (8, 24, 16));
    assert_eq!(
        serde_json::to_value(&range).unwrap(),
        serde_json::json!({"start":8,"end":24})
    );
}

#[test]
fn caller_selects_conflict_range_and_unknown_lengths_are_conservative() {
    let mut layout = inspect(&[]).unwrap();
    layout.buffer_tables.push(BufferTable {
        image_offset: 0,
        reference_offsets: vec![],
        entries: vec![
            BufferEntry {
                id: 1,
                controller_start: Some(0x200),
                length: Some(0x100),
            },
            BufferEntry {
                id: 2,
                controller_start: Some(0x800),
                length: None,
            },
            BufferEntry {
                id: 3,
                controller_start: None,
                length: Some(0x100),
            },
        ],
    });
    let base = 0xa00000;
    assert!(layout
        .buffer_conflicts(&Range::new(base, 0x200).unwrap(), base, 0x1000)
        .unwrap()
        .is_empty());
    let conflicts = layout
        .buffer_conflicts(&Range::new(base + 0x250, 0x600).unwrap(), base, 0x1000)
        .unwrap();
    assert_eq!(
        conflicts,
        vec![
            Range::new(base + 0x200, 0x100).unwrap(),
            Range::new(base + 0x800, 0x800).unwrap()
        ]
    );
    assert!(layout.buffer_tables[0].entries[0]
        .range(u32::MAX, 0x1000)
        .is_err());
    assert!(layout.buffer_tables[0].entries[0]
        .range(base, 0x250)
        .is_err());
}

#[test]
fn inspection_failures_have_typed_categories_and_stable_codes() {
    let absent = super::callbacks::read_buffer_site(&[], 0x410000).unwrap_err();
    assert!(matches!(absent, Error::Unsupported { .. }));
    assert_eq!(absent.code(), "pioneer.firmware.unsupported");
    let ambiguous = super::error::unique(vec![1, 2], "fixture").unwrap_err();
    assert!(matches!(ambiguous, Error::Ambiguous { candidates: 2, .. }));
    assert_eq!(ambiguous.code(), "pioneer.firmware.ambiguous");
    let malformed = Range::new(0, 0).unwrap_err();
    assert_eq!(malformed.code(), "pioneer.firmware.malformed");
    let overflow = Range::new(u32::MAX, 1).unwrap_err();
    assert_eq!(overflow.code(), "pioneer.firmware.out_of_range");
    assert_eq!(
        crate::settings::CodecError::InvalidRequest.code(),
        "pioneer.settings.codec.invalid_request"
    );
    assert_eq!(
        inspect(&[]).unwrap().limitations,
        vec![LayoutLimitation::NoCompDirectory]
    );
}

#[test]
fn interval_operations_match_finite_address_sets() {
    for a in 0..12 {
        for b in a + 1..=12 {
            let left = Range::from_bounds(a, b).unwrap();
            let left_bytes: std::collections::BTreeSet<_> = (a..b).collect();
            for c in 0..12 {
                for d in c + 1..=12 {
                    let right = Range::from_bounds(c, d).unwrap();
                    let right_bytes: std::collections::BTreeSet<_> = (c..d).collect();
                    assert_eq!(left.overlaps(&right), !left_bytes.is_disjoint(&right_bytes));
                    assert_eq!(left.contains(&right), right_bytes.is_subset(&left_bytes));
                }
            }
        }
    }
}

#[test]
fn free_ranges_match_an_independent_byte_occupancy_map() {
    let window_sets = [
        vec![(1, 15)],
        vec![(1, 6), (6, 15)],
        vec![(1, 10), (4, 15)],
        vec![(12, 15), (1, 6)],
    ];
    for windows in window_sets {
        for a in 0..16 {
            for b in a + 1..=16 {
                for second in [None, Some((0, 3)), Some((5, 12)), Some((13, 16))] {
                    let mut blocks = vec![(a, b)];
                    blocks.extend(second);
                    for alignment in [2, 4, 8] {
                        let mut free = [false; 16];
                        for (at, is_free) in free.iter_mut().enumerate() {
                            *is_free = windows.iter().any(|&(s, e)| (s..e).contains(&at))
                                && !blocks.iter().any(|&(s, e)| (s..e).contains(&at));
                        }
                        let mut expected = Vec::new();
                        let mut at = 0;
                        while at < 16 {
                            if !free[at] {
                                at += 1;
                                continue;
                            }
                            let mut start = at;
                            while at < 16 && free[at] {
                                at += 1;
                            }
                            while start % alignment != 0 {
                                start += 1;
                            }
                            if start < at {
                                expected.push((start as u32, at as u32));
                            }
                        }
                        let make = |v: &[(usize, usize)]| {
                            v.iter()
                                .map(|&(s, e)| Range::from_bounds(s as u32, e as u32).unwrap())
                                .collect::<Vec<_>>()
                        };
                        let actual =
                            free_ranges(&make(&windows), &make(&blocks), alignment as u32).unwrap();
                        assert_eq!(
                            actual
                                .iter()
                                .map(|r| (r.start(), r.end()))
                                .collect::<Vec<_>>(),
                            expected,
                            "windows={windows:?}, occupied={blocks:?}, alignment={alignment}"
                        );
                    }
                }
            }
        }
    }
    for alignment in [0, 1, 3, 6, u32::MAX] {
        assert!(free_ranges(&[], &[], alignment).is_err());
    }
    let top = Range::new(u32::MAX - 1, 1).unwrap();
    assert!(free_ranges(&[top], &[], 4).unwrap().is_empty());
}

fn zlib(data: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}

/// Three COMP streams at base 0x410000 behind the runtime loader fixture.
fn three_stream_image(len: usize) -> Vec<u8> {
    let fixture = crate::comp_runtime::fixture();
    let mut image = vec![0xff; len];
    image[..fixture.len()].copy_from_slice(&fixture);
    image[0x1000..0x1004].copy_from_slice(b"COMP");
    for index in 0..3 {
        let offset = 0x2000 + index * 0x100;
        let compressed = zlib(&[index as u8; 32]);
        image[offset..offset + 4].copy_from_slice(&32u32.to_be_bytes());
        image[offset + 4..offset + 4 + compressed.len()].copy_from_slice(&compressed);
        let entry = 0x1004 + index * 8;
        let start = 0x410000 + offset as u32;
        image[entry..entry + 4].copy_from_slice(&start.to_be_bytes());
        image[entry + 4..entry + 8]
            .copy_from_slice(&(start + compressed.len() as u32).to_be_bytes());
    }
    image
}

#[test]
fn global_copy_bound_does_not_overflow_for_high_comp_base() {
    let mut image = vec![0xff; 0x3000];
    image[0x1000..0x1004].copy_from_slice(b"COMP");
    let compressed = zlib(&[0x11; 32]);
    image[0x1100..0x1104].copy_from_slice(&32u32.to_be_bytes());
    image[0x1104..0x1104 + compressed.len()].copy_from_slice(&compressed);
    let start = 0xFFFF_F100u32;
    image[0x1004..0x1008].copy_from_slice(&start.to_be_bytes());
    image[0x1008..0x100c].copy_from_slice(&(start + compressed.len() as u32).to_be_bytes());
    image[0x2000..0x200a]
        .copy_from_slice(&[0x79, 1, 0xa5, 0xa5, 0x6b, 0xa1, 0x00, 0xa0, 0x00, 0x10]);
    image[0x2100..0x2112].copy_from_slice(&[
        0x7a, 0, 0xff, 0xff, 0xe0, 0x00, 0x7a, 1, 0xff, 0xff, 0xe0, 0x10, 0x7a, 2, 0x00, 0xa0,
        0x00, 0x00,
    ]);
    let layout = inspect(&image).unwrap();
    assert_eq!(layout.image_base, Some(0xFFFF_E000));
    assert_eq!(layout.global_copy_end, Some(0xa00010));
}

#[test]
fn unspecified_buffer_length_still_bounds_the_structural_gap() {
    let mut image = three_stream_image(0x2a00);
    let mut table = Vec::new();
    table.extend([1, 0, 0, 0, 0, 0, 0x10, 0, 0xff, 0xff, 0xff, 0xff]);
    table.extend([2, 0, 0, 0, 0, 0, 0x80, 0, 0, 0, 1, 0]);
    table.extend([0xff, 0]);
    table.extend([0xff; 10]);
    image[0x2400..0x2400 + table.len()].copy_from_slice(&table);
    image[0x2380..0x2382].copy_from_slice(&[0x7a, 0]);
    image[0x2382..0x2386].copy_from_slice(&(0x410000u32 + 0x2400).to_be_bytes());
    image[0x2300..0x230a]
        .copy_from_slice(&[0x79, 1, 0xa5, 0xa5, 0x6b, 0xa1, 0x00, 0xa0, 0x04, 0x00]);
    let mut copy = vec![0x7a, 0];
    copy.extend(0x412500u32.to_be_bytes());
    copy.extend([0x7a, 1]);
    copy.extend(0x412900u32.to_be_bytes());
    copy.extend([0x7a, 2, 0, 0xa0, 0, 0]);
    image[0x2340..0x2340 + copy.len()].copy_from_slice(&copy);
    let layout = inspect(&image).unwrap();
    assert_eq!(layout.global_copy_end, Some(0xa00400));
    assert_eq!(
        layout.structural_gaps,
        vec![Range::from_bounds(0xa00420, 0xa01000).unwrap()]
    );
}

#[test]
fn inspection_decodes_comp_streams_once_and_matches_is_uhd() {
    const SIG0: [u8; 24] = [
        0x5E, 0x40, 0x83, 0xB8, 0x7A, 0x00, 0x41, 0x00, 0x03, 0x89, 0x01, 0x00, 0x6F, 0xE0, 0x00,
        0xC4, 0x01, 0x00, 0x69, 0xE3, 0x5E, 0x40, 0x87, 0xD0,
    ];
    let plain = three_stream_image(0x2300);
    let mut stored = plain.clone();
    stored[0x1800..0x1818].copy_from_slice(&SIG0);
    let mut non_comp = vec![0; 0x100];
    non_comp[0x20..0x38].copy_from_slice(&SIG0);
    for (image, uhd) in [(plain, false), (stored, true), (non_comp, true)] {
        crate::comp_streams::READS.with(|reads| reads.set(0));
        let layout = inspect(&image).unwrap();
        assert!(crate::comp_streams::READS.with(|reads| reads.get()) <= 1);
        assert_eq!(layout.is_uhd, uhd);
        assert_eq!(layout.is_uhd, crate::image::is_uhd(&image));
    }
    crate::comp_streams::READS.with(|reads| reads.set(0));
    inspect(&three_stream_image(0x2300)).unwrap();
    assert_eq!(crate::comp_streams::READS.with(|reads| reads.get()), 1);
}

#[test]
fn unlocated_overlay_destinations_are_reported_not_read_as_absence() {
    let image = three_stream_image(0x2300);
    let layout = inspect(&image).unwrap();
    assert_eq!(layout.overlay_ranges.len(), 3);
    assert!(!layout
        .limitations
        .contains(&LayoutLimitation::OverlayDestinationsUnresolved));
    let mut unknown = image.clone();
    unknown[0xc4] ^= 1;
    let layout = inspect(&unknown).unwrap();
    assert!(layout.overlay_ranges.is_empty());
    assert!(layout
        .limitations
        .contains(&LayoutLimitation::OverlayDestinationsUnresolved));
    assert_eq!(
        LayoutLimitation::OverlayDestinationsUnresolved.code(),
        "pioneer.layout.overlay_destinations_unresolved"
    );
}
