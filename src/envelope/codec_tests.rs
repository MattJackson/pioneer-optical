use super::*;

fn normal_header() -> Vec<u8> {
    let mut data = vec![0; 0x200];
    let text = format!(
        "{}\r\nID : PIONEER TEST\r\nFile Type : Normal\r\n",
        String::from_utf8_lossy(BANNER)
    );
    data[..text.len()].copy_from_slice(text.as_bytes());
    data
}

#[test]
fn load_distinguishes_bad_header_from_unknown_layout() {
    assert_eq!(
        Envelope::load(b"not firmware").unwrap_err(),
        DecodeError::InvalidHeader
    );
    assert_eq!(
        Envelope::load(&normal_header()).unwrap_err(),
        DecodeError::UnsupportedLayout
    );
}

#[test]
fn multiple_key_locations_are_rejected_even_with_valid_prefixes() {
    let mut bytes = normal_header();
    bytes.resize(0x22200, 0);
    // The first key is zero. Its decoded payload is directly recognizable.
    bytes[0x10200..0x10208].copy_from_slice(b"PIONEER ");
    bytes[0x10214..0x10218].copy_from_slice(&0x12000u32.to_be_bytes());
    // The alternate key location is the first payload. Encode another valid
    // Normal prefix against it, making the two payload positions conflict.
    let alternate_key = bytes[0x10200..0x20200].to_vec();
    let mut alternate = vec![0; 0x2000];
    alternate[..8].copy_from_slice(b"PIONEER ");
    alternate[20..24].copy_from_slice(&0x2000u32.to_be_bytes());
    bytes[0x20200..].copy_from_slice(&transform(&alternate, &alternate_key, true).unwrap());
    assert_eq!(
        Envelope::load(&bytes).unwrap_err(),
        DecodeError::AmbiguousLayout
    );
    assert!(decode_envelope(&bytes).is_none());
}

#[test]
fn recognized_payload_with_inconsistent_length_has_explicit_error() {
    let mut bytes = normal_header();
    bytes.resize(0x12200, 0);
    bytes[0x10200..0x10208].copy_from_slice(b"PIONEER ");
    bytes[0x10214..0x10218].copy_from_slice(&0x4000u32.to_be_bytes());
    assert_eq!(
        Envelope::load(&bytes).unwrap_err(),
        DecodeError::PayloadLengthMismatch {
            layout: Layout::Normal,
            payload_offset: 0x10200,
            declared: 0x4000,
            actual: 0x2000,
        }
    );
}
