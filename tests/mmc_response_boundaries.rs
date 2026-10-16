//! MMC wire-format invariants: lengths are declared by the device, not the
//! host's allocation, and flags cannot change adjacent fields.
#![cfg(feature = "drive")]
use pioneer_optical::device::info::{Feature, Inquiry, Mechanical};

#[test]
fn inquiry_honors_declared_length_and_retains_identification() {
    let mut bytes = vec![b' '; 128];
    bytes[0] = 5;
    bytes[4] = 91;
    bytes[8..16].copy_from_slice(b"PIONEER ");
    bytes[16..32].copy_from_slice(b"BD-RW BDR-206   ");
    bytes[32..36].copy_from_slice(b"1.06");
    bytes[36..56].copy_from_slice(b"2010/06/10          ");
    let parsed = Inquiry::parse(&bytes).unwrap();
    assert_eq!(parsed.vendor(), "PIONEER");
    assert_eq!(parsed.product(), "BD-RW BDR-206");
    assert_eq!(parsed.revision(), "1.06");
    assert_eq!(parsed.extra(), "2010/06/10");
    assert_eq!(parsed.raw(), &bytes[..96]);
    for length in 0..36 {
        assert!(Inquiry::parse(&bytes[..length]).is_none());
    }
    for declared in 0..31 {
        bytes[4] = declared;
        assert!(Inquiry::parse(&bytes).is_none());
    }
    bytes[4] = 31;
    let parsed = Inquiry::parse(&bytes).unwrap();
    assert_eq!(parsed.raw(), &bytes[..36]);
    assert_eq!(parsed.extra(), "");
    bytes[4] = 255;
    assert_eq!(Inquiry::parse(&bytes[..40]).unwrap().raw(), &bytes[..40]);
    for device_type in [0, 4, 6, 31] {
        bytes[0] = device_type;
        assert!(Inquiry::parse(&bytes).is_none());
    }
}

fn feature(code: u16, payload: &[u8], flags: u8) -> Vec<u8> {
    let mut bytes = vec![0; 12 + payload.len()];
    let declared = (bytes.len() - 4) as u32;
    bytes[..4].copy_from_slice(&declared.to_be_bytes());
    bytes[8..10].copy_from_slice(&code.to_be_bytes());
    bytes[10] = flags;
    bytes[11] = payload.len() as u8;
    bytes[12..].copy_from_slice(payload);
    bytes
}

#[test]
fn single_feature_parser_rejects_short_wrong_and_inconsistent_responses() {
    let bytes = feature(3, &[0x29, 0x11, 0x22, 0x33], 0x3f);
    let parsed = Feature::parse(&bytes, 3).unwrap().unwrap();
    assert_eq!(parsed.raw(), &bytes[8..]);
    assert_eq!(parsed.payload(), &[0x29, 0x11, 0x22, 0x33]);
    assert_eq!(parsed.version(), 15);
    for length in 0..bytes.len() {
        assert!(Feature::parse(&bytes[..length], 3).is_err());
    }
    assert!(Feature::parse(&bytes, 4).is_err());
    for declared in [0, 1, 3, 5, 7, 9, 11, 13, u32::MAX] {
        let mut bad = bytes.clone();
        bad[..4].copy_from_slice(&declared.to_be_bytes());
        assert!(Feature::parse(&bad, 3).is_err());
    }
    let mut absent = vec![0; 8];
    absent[..4].copy_from_slice(&4u32.to_be_bytes());
    assert!(Feature::parse(&absent, 3).unwrap().is_none());
    for version in 0..16 {
        for flags in 0..4 {
            let bytes = feature(0x0108, &[1, 2, 3, 4], (version << 2) | flags);
            assert_eq!(
                Feature::parse(&bytes, 0x0108).unwrap().unwrap().version(),
                version
            );
        }
    }
    let max = feature(0x0108, &[0x55; 255], 0);
    assert_eq!(
        Feature::parse(&max, 0x0108).unwrap().unwrap().payload(),
        &[0x55; 255]
    );
}

#[test]
fn mechanical_page_skips_block_descriptors_and_preserves_loader_bits() {
    for descriptors in [0, 8, 16] {
        let mut bytes = vec![0; 8 + descriptors + 16];
        let length = bytes.len() - 2;
        bytes[..2].copy_from_slice(&(length as u16).to_be_bytes());
        bytes[6..8].copy_from_slice(&(descriptors as u16).to_be_bytes());
        let page = 8 + descriptors;
        bytes[page] = 0x2a;
        bytes[page + 1] = 14;
        bytes[page + 12..page + 14].copy_from_slice(&0x1234u16.to_be_bytes());
        for loader in 0..8 {
            bytes[page + 6] = (loader << 5) | 0x1f;
            let parsed = Mechanical::parse(&bytes).unwrap();
            assert_eq!(parsed.loader(), loader);
            assert_eq!(parsed.buffer_kib(), Some(0x1234));
        }
        for length in 0..bytes.len() {
            assert!(Mechanical::parse(&bytes[..length]).is_none());
        }
        bytes[page + 12..page + 14].fill(0);
        assert_eq!(Mechanical::parse(&bytes).unwrap().buffer_kib(), None);
        bytes[page + 1] = 13;
        assert!(Mechanical::parse(&bytes).is_none());
        bytes[page + 1] = 15;
        assert!(Mechanical::parse(&bytes).is_none());
        bytes[page + 1] = 14;
        bytes[page] = 0x29;
        assert!(Mechanical::parse(&bytes).is_none());
    }
}
