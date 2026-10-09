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
