use super::{Update, UpdateError};
use crate::envelope::{
    builder::{encode_encrypted_pair, BuildInputs, EncryptedPair, KernelBuild, NormalSignature},
    signature::SigningKey,
    synthetic_roundtrip_tests::{front_kernel, normal_image},
};
use crate::ComponentKind;

fn pair(signed: bool) -> EncryptedPair {
    let kernel = front_kernel();
    let normal = normal_image(0x2000);
    let mut scalar = [0; 20];
    scalar[19] = 5;
    let signer = SigningKey::from_bytes(scalar).unwrap();
    encode_encrypted_pair(
        &BuildInputs {
            kernel_image: &kernel,
            normal_image: &normal,
            envelope_id: "PIONEER BDR-TEST",
            normal_revision: "1.00",
            normal_date: "00/00/00",
            kernel: KernelBuild::from_seed(0x123456),
            normal_key_seed: 0x47d001,
        },
        if signed {
            NormalSignature::Sign(&signer)
        } else {
            NormalSignature::Zeroed
        },
    )
    .unwrap()
}

#[test]
fn prepares_authenticated_pair_without_claiming_drive_compatibility() {
    let pair = pair(true);
    let update = Update::load(&pair.kernel, &pair.normal).unwrap();
    assert_eq!(update.kernel().image, front_kernel());
    assert_eq!(update.normal().image, normal_image(0x2000));
    assert_eq!(update.kernel_transfer(), pair.kernel);
    assert_eq!(update.normal_transfer(), pair.normal);
    assert_eq!(update.family(), None);
}

#[test]
fn component_roles_are_checked_before_pair_preparation() {
    let pair = pair(true);
    assert_eq!(
        Update::load(&pair.normal, &pair.kernel).unwrap_err(),
        UpdateError::Role {
            expected: ComponentKind::Kernel,
            actual: ComponentKind::Normal,
        }
    );
    assert_eq!(
        Update::load(&pair.kernel, &pair.kernel).unwrap_err(),
        UpdateError::Role {
            expected: ComponentKind::Normal,
            actual: ComponentKind::Kernel,
        }
    );
}

#[test]
fn malformed_input_retains_component_and_underlying_error() {
    use std::error::Error;
    let pair = pair(true);
    let error = Update::load(&pair.kernel, &[]).unwrap_err();
    assert!(matches!(
        error,
        UpdateError::Decode {
            component: ComponentKind::Normal,
            ..
        }
    ));
    assert!(error.source().is_some());
    assert!(error.to_string().contains("Normal"));
}

#[test]
fn valid_checksums_do_not_substitute_for_authentication() {
    let pair = pair(false);
    assert_eq!(
        Update::load(&pair.kernel, &pair.normal).unwrap_err(),
        UpdateError::Authentication
    );
}

#[test]
fn pair_identity_errors_name_the_typed_field_and_both_values() {
    use super::PairField;
    let pair = pair(true);
    for (field, start, width) in [
        (PairField::HardwareVersion, 0xb0, 8),
        (PairField::Destination, 0xf0, 8),
        (PairField::KernelVersion, 0xd0, 8),
        (PairField::KernelVersion2, 0x150, 4),
    ] {
        for missing in [false, true] {
            let mut normal = pair.normal.clone();
            if missing {
                normal[start..start + width].fill(b' ');
            } else {
                normal[start] = b'X';
            }
            let error = Update::load(&pair.kernel, &normal).unwrap_err();
            let UpdateError::Header {
                field: actual,
                kernel,
                normal,
            } = &error
            else {
                panic!("expected {field}, got {error:?}");
            };
            assert_eq!(*actual, field);
            assert!(!kernel.is_empty());
            assert_ne!(kernel, normal);
            assert_eq!(normal.is_empty(), missing);
            let message = error.to_string();
            assert!(message.contains(&field.to_string()));
            assert!(message.contains("Kernel=") && message.contains("Normal="));
        }
    }
}

#[test]
fn kernel_policy_loading_preserves_decode_errors_and_reports_layouts() {
    use crate::envelope::{DecodeError, Envelope, Layout};
    let pair = pair(true);
    let mut kernel = Envelope::load(&pair.kernel).unwrap();
    assert!(matches!(
        Envelope::load_with_kernel(&[], &kernel),
        Err(DecodeError::InvalidHeader)
    ));
    let decoded = Envelope::load_with_kernel(&pair.normal, &kernel).unwrap();
    assert_eq!(decoded.image, normal_image(0x2000));
    kernel.image[0x100..0x180].fill(0);
    assert!(matches!(
        Envelope::load_with_kernel(&pair.normal, &kernel),
        Err(DecodeError::ReceiverPolicy {
            kernel_layout: Layout::KernelFront,
            normal_layout: Layout::Normal
        })
    ));
}
