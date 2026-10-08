use super::*;
use crate::envelope::{build_header, Envelope, HeaderOpaque};

fn fixture() -> (Vec<u8>, Vec<u8>) {
    let header = HeaderInfo {
        id: "UNKNOWN SAMPLE".into(),
        model: "SAMPLE".into(),
        hardware_version: "XYZ 6789".into(),
        kind: Some(ComponentKind::Normal),
        revision: "1.00".into(),
        kernel_version: "CUSTOM".into(),
        destination: "CUSTOM".into(),
        generated_date: "2026/10/07".into(),
        kernel_version2: "0001".into(),
    };
    let mut bytes = vec![0x95; CONTAINER_SIZE];
    bytes[..0x200].copy_from_slice(&build_header(&header, &HeaderOpaque::default()).unwrap());
    bytes[ROM_START..ROM_START + 8].copy_from_slice(header.hardware_version.as_bytes());
    let key = super::super::super::make_key(0xabcdef, KEY_SIZE);
    bytes[KEY_START..KEY_END].copy_from_slice(&key);
    let mut image = vec![0x53; PAYLOAD_SIZE];
    image[..PREFIX.len()].copy_from_slice(PREFIX);
    let sum = payload_checksum(&image).unwrap();
    image[CHECKSUM..CHECKSUM + WORD].copy_from_slice(&sum.to_le_bytes());
    bytes[PAYLOAD_START..PAYLOAD_END]
        .copy_from_slice(&TailKey.transform(&image, &key, true, &[]).unwrap());
    (bytes, image)
}

#[test]
fn detects_unknown_hardware_and_preserves_every_container_byte() {
    let (bytes, image) = fixture();
    let envelope = Envelope::load(&bytes).unwrap();
    assert_eq!(envelope.info().layout, Layout::NormalTailKey);
    assert_eq!(envelope.image, image);
    assert_eq!(envelope.repack(&image).unwrap(), bytes);
    assert!(envelope.normal_transfer_image().is_none());
}

#[test]
fn checksum_covers_code_data_and_checksum_word() {
    let (bytes, _) = fixture();
    for offset in [
        0x100,
        XOR_EXCEPTIONS[0] as usize,
        XOR_EXCEPTIONS[1] as usize,
        DATA_START,
        CHECKSUM,
    ] {
        let mut corrupt = bytes.clone();
        corrupt[PAYLOAD_START + offset] ^= 1;
        assert!(matches!(
            Envelope::load(&corrupt),
            Err(DecodeError::ChecksumMismatch {
                layout: Layout::NormalTailKey,
                ..
            })
        ));
    }
}

#[test]
fn excluded_bytes_are_preserved_without_inventing_checksum_coverage() {
    let (bytes, _) = fixture();
    for offset in [CODE_END, DATA_END, CHECKSUM + WORD] {
        let mut changed = bytes.clone();
        changed[PAYLOAD_START + offset] ^= 1;
        let envelope = Envelope::load(&changed).unwrap();
        assert_eq!(envelope.repack(&envelope.image).unwrap(), changed);
    }
}

#[test]
fn repacking_modified_image_requires_valid_checksum_to_load_again() {
    let (bytes, mut image) = fixture();
    let envelope = Envelope::load(&bytes).unwrap();
    image[DATA_START] ^= 1;
    assert!(Envelope::load(&envelope.repack(&image).unwrap()).is_err());
    let checksum = payload_checksum(&image).unwrap();
    image[CHECKSUM..CHECKSUM + WORD].copy_from_slice(&checksum.to_le_bytes());
    let rebuilt = envelope.repack(&image).unwrap();
    assert_eq!(Envelope::load(&rebuilt).unwrap().image, image);
    assert_eq!(rebuilt[..PAYLOAD_START], bytes[..PAYLOAD_START]);
    assert_eq!(rebuilt[PAYLOAD_END..], bytes[PAYLOAD_END..]);
}

#[test]
fn wrong_role_size_rom_tag_and_payload_prefix_are_not_this_format() {
    let (bytes, _) = fixture();
    for offset in [0x110, ROM_START, PAYLOAD_START] {
        let mut changed = bytes.clone();
        changed[offset] ^= 1;
        assert!(Envelope::load(&changed).is_err());
    }
    assert!(Envelope::load(&bytes[..bytes.len() - 1]).is_err());
}

#[test]
fn word_vectors_apply_rotation_but_skip_xor_only_at_the_two_receiver_offsets() {
    let key = 0x11223344u32.to_le_bytes();
    let mut image = vec![0; XOR_EXCEPTIONS[1] as usize + WORD * 2];
    for word in image.chunks_exact_mut(WORD) {
        word.copy_from_slice(&0x12345678u32.to_le_bytes());
    }
    let encoded = TailKey.transform(&image, &key, true, &[]).unwrap();
    for offset in [0, 0x7ffc, 0x8000, 0x8004, 0x6fffc, 0x70000, 0x70004] {
        let expected: u32 = if [0x8000, 0x70000].contains(&offset) {
            0x23456781
        } else {
            0x326754c5
        };
        assert_eq!(encoded[offset..offset + WORD], expected.to_le_bytes());
    }
    assert_eq!(
        TailKey.transform(&encoded, &key, false, &[]).unwrap(),
        image
    );
}
