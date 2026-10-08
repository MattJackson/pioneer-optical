use super::*;
use crate::envelope::{build_header, HeaderOpaque};

fn fixture() -> (Envelope, Vec<u8>, Vec<u8>) {
    let mut header = HeaderInfo {
        id: "UNKNOWN SAMPLE".into(),
        model: "SAMPLE".into(),
        revision: "1.00".into(),
        hardware_version: "XYZ 6789".into(),
        kernel_version: "CUSTOM".into(),
        destination: "CUSTOM".into(),
        generated_date: "2026/10/07".into(),
        kernel_version2: "0001".into(),
        kind: Some(ComponentKind::Kernel),
    };
    let mut bytes = vec![0xff; CONTAINER_SIZE];
    bytes[..0x200].copy_from_slice(&build_header(&header, &HeaderOpaque::default()).unwrap());
    for (i, byte) in bytes[ROM_START..ROM_START + BLOCK].iter_mut().enumerate() {
        *byte = i as u8;
    }
    bytes[ROM_START + BLOCK..ROM_START + BLOCK + 16].copy_from_slice(b"XYZ 6789CUSTOM  ");
    bytes[ROM_START + BLOCK * 2..ROM_START + BLOCK * 2 + DECODER.len()].copy_from_slice(DECODER);
    bytes[ROM_START + 0x400..ROM_START + 0x400 + CHECKSUM.len()].copy_from_slice(CHECKSUM);
    for word in bytes[ROM_END - 8..ROM_END].chunks_exact_mut(2) {
        word.copy_from_slice(&(ROM_START as u16).to_le_bytes());
    }
    let kernel = Envelope::load(&bytes).unwrap();
    header.kind = Some(ComponentKind::Normal);
    let mut normal = vec![0x73; CONTAINER_SIZE];
    normal[..0x200].copy_from_slice(&build_header(&header, &HeaderOpaque::default()).unwrap());
    let mut image = vec![0; IMAGE_SIZE];
    image[..PREFIX.len()].copy_from_slice(PREFIX);
    image[0x8000 - PAYLOAD_START..0x10000 - PAYLOAD_START].fill(0x29);
    let key: Vec<u8> = kernel.image[..BLOCK].iter().map(|b| !b).collect();
    normal[PAYLOAD_START..PAYLOAD_END]
        .copy_from_slice(&BootKeyM7900.transform(&image, &key, true, &[]).unwrap());
    (kernel, normal, image)
}

#[test]
fn kernel_context_detects_codec_and_roundtrips_every_byte() {
    let (kernel, normal, image) = fixture();
    assert_eq!(
        Envelope::load(&normal).unwrap_err(),
        DecodeError::UnsupportedLayout
    );
    let decoded = Envelope::load_with_kernel(&normal, &kernel).unwrap();
    assert_eq!(decoded.info().layout, Layout::NormalBootKeyM7900);
    assert_eq!(decoded.image, image);
    assert_eq!(decoded.repack(&image).unwrap(), normal);
    assert!(decoded.normal_transfer_image().is_none());
}

#[test]
fn altered_key_or_decoder_does_not_establish_a_policy() {
    let (kernel, normal, _) = fixture();
    let mut changed = kernel.clone();
    changed.image[BLOCK - 1] ^= 1;
    assert!(Envelope::load_with_kernel(&normal, &changed).is_err());
    for i in 0..DECODER.len() {
        let mut changed = kernel.clone();
        changed.image[BLOCK * 2 + i] ^= 1;
        assert!(Envelope::load_with_kernel(&normal, &changed).is_err());
    }
}

#[test]
fn checksum_errors_identify_codec_width_and_sum() {
    let (kernel, normal, mut image) = fixture();
    let decoded = Envelope::load_with_kernel(&normal, &kernel).unwrap();
    image[CHECKSUM_RANGES[0].0] = 1;
    let corrupted = decoded.repack(&image).unwrap();
    assert_eq!(
        Envelope::load_with_kernel(&corrupted, &kernel).unwrap_err(),
        DecodeError::DecodedChecksum {
            layout: Layout::NormalBootKeyM7900,
            word_bits: 16,
            sum: 1
        }
    );
    image[CHECKSUM_RANGES[2].0..CHECKSUM_RANGES[2].0 + 2].copy_from_slice(&u16::MAX.to_le_bytes());
    let repaired = decoded.repack(&image).unwrap();
    assert_eq!(
        Envelope::load_with_kernel(&repaired, &kernel)
            .unwrap()
            .image,
        image
    );
}

#[test]
fn update_preparation_reports_missing_transfer_support_after_contextual_decoding() {
    use crate::envelope::{Update, UpdateError};
    let (kernel, normal, _) = fixture();
    let kernel_bytes = kernel.repack(&kernel.image).unwrap();
    assert!(matches!(
        Update::load(&kernel_bytes, &normal),
        Err(UpdateError::Representation {
            component: ComponentKind::Kernel,
            layout: Layout::KernelRom,
        })
    ));
}

#[test]
fn ambiguous_decoder_and_non_kernel_context_are_rejected() {
    let (kernel, normal, _) = fixture();
    let mut duplicate = kernel.clone();
    duplicate.image[BLOCK * 3..BLOCK * 3 + DECODER.len()].copy_from_slice(DECODER);
    assert!(Envelope::load_with_kernel(&normal, &duplicate).is_err());
    let normal_context = Envelope::load_with_kernel(&normal, &kernel).unwrap();
    assert!(Envelope::load_with_kernel(&normal, &normal_context).is_err());
}

#[test]
fn every_checksummed_region_is_validated_and_geometry_is_bounded() {
    let mut image = vec![0; IMAGE_SIZE];
    for (start, end) in CHECKSUM_RANGES {
        for offset in [start, end - 2] {
            image[offset] = 1;
            assert!(matches!(
                BootKeyM7900.validate_decoded(&image),
                Err(DecodeError::DecodedChecksum { sum: 1, .. })
            ));
            image[offset] = 0;
        }
    }
    assert_eq!(
        BootKeyM7900.validate_decoded(&image[..IMAGE_SIZE - 1]),
        Err(DecodeError::InvalidPayload)
    );
    assert!(BootKeyM7900
        .transform(&image, &[0; BLOCK - 1], false, &[])
        .is_none());
    assert!(BootKeyM7900
        .transform(&image[..IMAGE_SIZE - 1], &[0; BLOCK], false, &[])
        .is_none());
}

#[test]
fn checksum_policy_must_be_established_from_rom_code() {
    let (kernel, normal, _) = fixture();
    for i in 0..CHECKSUM.len() {
        let mut changed = kernel.clone();
        changed.image[0x400 + i] ^= 1;
        assert!(Envelope::load_with_kernel(&normal, &changed).is_err());
    }
    let mut duplicate = kernel.clone();
    duplicate.image[0x800..0x800 + CHECKSUM.len()].copy_from_slice(CHECKSUM);
    assert!(Envelope::load_with_kernel(&normal, &duplicate).is_err());
}

#[test]
fn truncated_containers_and_kernel_context_fail_without_partial_images() {
    let (kernel, normal, _) = fixture();
    for end in [0, 0x200, PAYLOAD_START, PAYLOAD_END, CONTAINER_SIZE - 1] {
        assert!(Envelope::load_with_kernel(&normal[..end], &kernel).is_err());
    }
    for end in [0, BLOCK - 1, 0x400 + CHECKSUM.len(), kernel.image.len() - 1] {
        let mut truncated = kernel.clone();
        truncated.image.truncate(end);
        assert!(Envelope::load_with_kernel(&normal, &truncated).is_err());
    }
}

#[test]
fn routine_locations_are_not_a_firmware_profile() {
    let (mut kernel, normal, image) = fixture();
    kernel.image[BLOCK * 2..BLOCK * 2 + DECODER.len()].fill(0xff);
    kernel.image[0x400..0x400 + CHECKSUM.len()].fill(0xff);
    kernel.image[0x1200..0x1200 + DECODER.len()].copy_from_slice(DECODER);
    kernel.image[0x2000..0x2000 + CHECKSUM.len()].copy_from_slice(CHECKSUM);
    let decoded = Envelope::load_with_kernel(&normal, &kernel).unwrap();
    assert_eq!(decoded.image, image);
    assert_eq!(decoded.repack(&image).unwrap(), normal);
}
