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
    bytes[ROM_END - 4..ROM_END].copy_from_slice(&0xffc000u32.to_le_bytes());
    let kernel = Envelope::load(&bytes).unwrap();
    header.kind = Some(ComponentKind::Normal);
    let mut normal = vec![0x73; CONTAINER_SIZE];
    normal[..0x200].copy_from_slice(&build_header(&header, &HeaderOpaque::default()).unwrap());
    let mut image = vec![0; IMAGE_SIZE];
    image[..PREFIX.len()].copy_from_slice(PREFIX);
    image[CODE_END..DATA_START].fill(0x29);
    let key: Vec<u8> = kernel.image[..BLOCK].iter().map(|b| !b).collect();
    normal[PAYLOAD_START..PAYLOAD_END]
        .copy_from_slice(&BootKey.transform(&image, &key, true, &[]).unwrap());
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
    assert_eq!(decoded.info().layout, Layout::NormalBootKey);
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
    image[CHECKSUM_START] = 1;
    let corrupted = decoded.repack(&image).unwrap();
    assert_eq!(
        Envelope::load_with_kernel(&corrupted, &kernel).unwrap_err(),
        DecodeError::DecodedChecksum {
            layout: Layout::NormalBootKey,
            word_bits: 16,
            sum: 1
        }
    );
    image[DATA_START..DATA_START + 2].copy_from_slice(&u16::MAX.to_le_bytes());
    let repaired = decoded.repack(&image).unwrap();
    assert_eq!(
        Envelope::load_with_kernel(&repaired, &kernel)
            .unwrap()
            .image,
        image
    );
}

#[test]
fn reversal_rotation_and_xor_have_an_independent_byte_vector() {
    let input = [0x12; BLOCK];
    let key = [0x23; BLOCK];
    let mut output = [0; BLOCK];
    transform_block(&input, &mut output, &key, false);
    assert_eq!(output, [0xb3; BLOCK]); // rol8(0x12, 3) XOR 0x23
    let mut encoded = [0; BLOCK];
    transform_block(&output, &mut encoded, &key, true);
    assert_eq!(encoded, input);
    let mut input = [0; BLOCK];
    input[0] = 1;
    transform_block(&input, &mut output, &[0; BLOCK], false);
    assert_eq!(output[BLOCK - 1], 1);
    assert!(output[..BLOCK - 1].iter().all(|&b| b == 0));
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
