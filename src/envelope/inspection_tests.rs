use super::{builder::*, signature::*, synthetic_roundtrip_tests::*, *};

fn pair(seed: u32, signed: bool) -> (Envelope, Envelope) {
    let kernel = front_kernel();
    let normal = normal_image(0x2000);
    let signing = SigningKey::from_bytes([1; 20]).unwrap();
    let input = BuildInputs {
        kernel_image: &kernel,
        normal_image: &normal,
        envelope_id: "PIONEER BDR-TEST",
        normal_revision: "1.00",
        normal_date: "17/06/22",
        kernel: KernelBuild::from_seed(seed),
        normal_key_seed: seed,
    };
    let encoded = encode_encrypted_pair(
        &input,
        if signed {
            NormalSignature::Sign(&signing)
        } else {
            NormalSignature::Zeroed
        },
    )
    .unwrap();
    let kernel = decode_envelope(&encoded.kernel).unwrap();
    let normal = decode_envelope_with_kernel(&encoded.normal, &kernel).unwrap();
    (kernel, normal)
}

#[test]
fn recognizes_only_combined_placeholder_markers() {
    let (kernel, normal) = pair(0, false);
    assert_eq!(
        kernel.reconstruction_placeholder(),
        Some(ReconstructionPlaceholder::Kernel)
    );
    assert_eq!(
        normal.reconstruction_placeholder(),
        Some(ReconstructionPlaceholder::Normal)
    );
    let (kernel, normal) = pair(1, false);
    assert_eq!(kernel.reconstruction_placeholder(), None);
    assert_eq!(normal.reconstruction_placeholder(), None);
    let (_, normal) = pair(0, true);
    assert_eq!(normal.reconstruction_placeholder(), None);
}

#[test]
fn exposes_header_key_and_signature_facts() {
    let (kernel, normal) = pair(0x47d001, false);
    let header = normal.header().unwrap();
    assert_eq!(header.revision, "1.00");
    assert_eq!(header.generated_date, "17/06/22");
    assert_eq!(normal.encoding_key(), make_key(0x47d001, normal.key.len()));
    assert_eq!(normal.signature_status(), SignatureStatus::Absent);
    assert_eq!(kernel.signature_bytes(), None);
    assert_eq!(kernel.signature_status(), SignatureStatus::Unsupported);
}

#[test]
fn verification_detects_edits_to_current_image() {
    let (_, mut normal) = pair(0, true);
    assert_eq!(
        normal.signature_status(),
        SignatureStatus::Present(SignatureCheck::ValidKeyAndCiphertext)
    );
    let last = normal.image.len() - 1;
    normal.image[last] ^= 1;
    assert_eq!(
        normal.signature_status(),
        SignatureStatus::Present(SignatureCheck::Invalid)
    );
}

#[test]
fn raw_key_without_seed_is_not_a_placeholder() {
    let (mut kernel, _) = pair(0, false);
    kernel.key[20] ^= 1;
    assert_eq!(kernel.encoding_seed(), None);
    assert_eq!(kernel.reconstruction_placeholder(), None);
}

#[test]
fn kernel_requires_both_placeholder_header_fields() {
    let (kernel, _) = pair(0, false);
    for (revision, date) in [("1.11", "00/00/00"), ("0000", "17/06/22")] {
        let mut changed = kernel.clone();
        let mut header = changed.header().unwrap();
        header.revision = revision.into();
        header.generated_date = date.into();
        changed.header = build_header(&header, &HeaderOpaque::default())
            .unwrap()
            .to_vec();
        assert_eq!(changed.reconstruction_placeholder(), None);
    }
}

#[test]
fn reports_ciphertext_only_coverage_without_trust_claim() {
    let (kernel, normal) = pair(0, false);
    let mut bytes = normal.repack(&normal.image).unwrap();
    SigningKey::from_bytes([1; 20])
        .unwrap()
        .sign_normal_ciphertext_only(&mut bytes)
        .unwrap();
    let normal = decode_envelope_with_kernel(&bytes, &kernel).unwrap();
    assert_eq!(
        normal.signature_status(),
        SignatureStatus::Present(SignatureCheck::ValidCiphertextOnly)
    );
}

#[test]
fn unrecognized_public_point_and_layout_remain_unsupported() {
    let (_, mut normal) = pair(0, false);
    let start = builder::NORMAL_SIGNATURE_RANGE.start - HEADER_LEN;
    normal.prefix[start] = 1;
    assert_eq!(
        normal.signature_status(),
        SignatureStatus::Present(SignatureCheck::Unsupported)
    );
    assert_eq!(normal.reconstruction_placeholder(), None);
    normal.info.layout = Layout::Plain;
    assert_eq!(normal.signature_status(), SignatureStatus::Unsupported);
    assert_eq!(normal.reconstruction_placeholder(), None);
}
