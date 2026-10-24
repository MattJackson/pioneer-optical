use super::CodedError;

#[cfg(feature = "drive")]
#[test]
fn transport_codes_do_not_require_display_or_debug_and_preserve_values() {
    struct Cause;
    let error = crate::drive::Error::Transport(Cause);
    assert_eq!(error.code(), "pioneer.drive.transport");
    let error = crate::drive::Error::<Cause>::Short {
        expected: 32,
        actual: 7,
    };
    assert_eq!(error.code(), "pioneer.drive.short");
    assert!(matches!(
        error,
        crate::drive::Error::Short {
            expected: 32,
            actual: 7
        }
    ));
    let error = crate::drive::UpdateError::Transfer {
        role: crate::Role::Kernel,
        offset: 0x11200,
        length: 4096,
        source: crate::drive::Error::Transport(Cause),
    };
    assert_eq!(error.code(), "pioneer.transfer.transfer");
}

#[cfg(feature = "image")]
#[test]
fn identity_code_is_stable() {
    assert_eq!(
        crate::ident::IdentError::Ambiguous.code(),
        "pioneer.identity.ambiguous"
    );
}

#[cfg(feature = "envelope")]
#[test]
fn envelope_and_receiver_codes_preserve_nested_errors_and_parameters() {
    use crate::{envelope, receiver, ComponentKind};
    let source = envelope::DecodeError::PayloadLengthMismatch {
        layout: envelope::Layout::KernelRom,
        payload_offset: 0x100,
        declared: 0x2000,
        actual: 0x1000,
    };
    assert_eq!(source.code(), "pioneer.decode.payload_length_mismatch");
    let error = envelope::UpdateError::Decode {
        component: ComponentKind::Kernel,
        source,
    };
    assert_eq!(error.code(), "pioneer.update.decode");
    let error = receiver::PreparationError::Target(error);
    assert_eq!(error.code(), "pioneer.preparation.target");
    if let receiver::PreparationError::Target(envelope::UpdateError::Decode { source, .. }) = error
    {
        assert_eq!(source.code(), "pioneer.decode.payload_length_mismatch");
    } else {
        panic!("nested typed cause lost");
    }
    assert_eq!(
        envelope::Error::KernelBodySize { got: 3 }.code(),
        "pioneer.envelope.kernel_body_size"
    );
    assert_eq!(
        receiver::Error::UnknownTargetFamily.code(),
        "pioneer.receiver.unknown_target_family"
    );
}

#[cfg(feature = "envelope")]
#[test]
fn envelope_error_catalogue_has_stable_codes_and_actionable_text() {
    use crate::envelope::Error;
    let cases = [
        (Error::UnknownRotation, "pioneer.envelope.unknown_rotation"),
        (Error::InvalidHeader, "pioneer.envelope.invalid_header"),
        (Error::InvalidFilename, "pioneer.envelope.invalid_filename"),
        (Error::MissingModel, "pioneer.envelope.missing_model"),
        (
            Error::HeaderFieldsDoNotFit,
            "pioneer.envelope.header_fields_do_not_fit",
        ),
        (Error::KernelStructure, "pioneer.envelope.kernel_structure"),
        (
            Error::KernelIncomplete,
            "pioneer.envelope.kernel_incomplete",
        ),
        (
            Error::AmbiguousKernelLayout,
            "pioneer.envelope.ambiguous_kernel_layout",
        ),
        (Error::RawKeyLength, "pioneer.envelope.raw_key_length"),
        (
            Error::RawKeyNotAllowed,
            "pioneer.envelope.raw_key_not_allowed",
        ),
        (Error::KernelEncode, "pioneer.envelope.kernel_encode"),
        (Error::ImageStructure, "pioneer.envelope.image_structure"),
        (Error::ImageIncomplete, "pioneer.envelope.image_incomplete"),
        (Error::InvalidDate, "pioneer.envelope.invalid_date"),
        (
            Error::XorPolicyNotUnique,
            "pioneer.envelope.xor_policy_not_unique",
        ),
        (
            Error::XorExceptionOutOfRange,
            "pioneer.envelope.xor_exception_out_of_range",
        ),
        (Error::NormalEncode, "pioneer.envelope.normal_encode"),
        (
            Error::UnknownAuthentication,
            "pioneer.envelope.unknown_authentication",
        ),
        (
            Error::SignatureBlockLength,
            "pioneer.envelope.signature_block_length",
        ),
        (
            Error::InvalidSignedEnvelope,
            "pioneer.envelope.invalid_signed_envelope",
        ),
        (Error::AbiMismatch, "pioneer.envelope.abi_mismatch"),
        (
            Error::KernelUndecodable,
            "pioneer.envelope.kernel_undecodable",
        ),
        (
            Error::NormalUndecodable,
            "pioneer.envelope.normal_undecodable",
        ),
        (
            Error::RoundTripMismatch,
            "pioneer.envelope.round_trip_mismatch",
        ),
        (
            Error::NotSignableNormal,
            "pioneer.envelope.not_signable_normal",
        ),
        (Error::NotAscii, "pioneer.envelope.not_ascii"),
        (
            Error::EntropyUnavailable,
            "pioneer.envelope.entropy_unavailable",
        ),
        (Error::Randomness, "pioneer.envelope.randomness"),
        (Error::InvalidPoint, "pioneer.envelope.invalid_point"),
        (Error::OperandTooLarge, "pioneer.envelope.operand_too_large"),
        (
            Error::SelfVerification,
            "pioneer.envelope.self_verification",
        ),
        (
            Error::KernelFillNotFound,
            "pioneer.envelope.kernel_fill_not_found",
        ),
        (
            Error::DriveNameNotFound,
            "pioneer.envelope.drive_name_not_found",
        ),
    ];
    for (error, code) in cases {
        assert_eq!(error.code(), code);
        assert!(!error.to_string().is_empty());
    }
    for error in [
        Error::KernelBodySize { got: 3 },
        Error::UnknownMarker { marker: 0x42 },
    ] {
        assert!(!error.code().is_empty());
        assert!(!error.to_string().is_empty());
    }
}

#[cfg(feature = "envelope")]
#[test]
fn normal_layout_error_catalogue_preserves_every_failure_class() {
    use crate::envelope::NormalLayoutError as E;
    let cases = [
        (E::NotKernel, "pioneer.normal_layout.not_kernel"),
        (E::InvalidKernel, "pioneer.normal_layout.invalid_kernel"),
        (E::Unsupported, "pioneer.normal_layout.unsupported"),
        (E::Ambiguous, "pioneer.normal_layout.ambiguous"),
        (
            E::ConflictingGeometry,
            "pioneer.normal_layout.conflicting_geometry",
        ),
        (
            E::ShortHeader {
                expected: 8,
                actual: 3,
            },
            "pioneer.normal_layout.short_header",
        ),
        (
            E::DescriptorMismatch,
            "pioneer.normal_layout.descriptor_mismatch",
        ),
        (
            E::InvalidLength { length: 3 },
            "pioneer.normal_layout.invalid_length",
        ),
        (
            E::ImageLength {
                expected: 8,
                actual: 3,
            },
            "pioneer.normal_layout.image_length",
        ),
        (E::ImageChecksum, "pioneer.normal_layout.image_checksum"),
    ];
    for (error, code) in cases {
        assert_eq!(error.code(), code);
        assert!(!error.to_string().is_empty());
    }
}

#[cfg(all(feature = "envelope", feature = "drive"))]
#[test]
fn flash_code_is_independent_of_pass_and_retains_pass_for_presentation() {
    use crate::receiver::{FlashError, FlashPass};
    for pass in [FlashPass::Initial, FlashPass::Restoration] {
        let error = FlashError::<()>::ReadbackMismatch {
            pass,
            address: 0x400020,
        };
        assert_eq!(error.code(), "pioneer.flash.readback_mismatch");
        assert!(
            matches!(error, FlashError::ReadbackMismatch { pass: p, address: 0x400020 } if p == pass)
        );
    }
}

#[cfg(feature = "image")]
#[test]
fn kernel_handoff_startup_and_protocol_codes() {
    use crate::image::KernelHandoffError as K;
    assert_eq!(
        K::UnknownInstalled.code(),
        "pioneer.kernel_handoff.unknown_installed"
    );
    assert_eq!(
        K::UnknownTarget.code(),
        "pioneer.kernel_handoff.unknown_target"
    );
    assert_eq!(
        K::Mismatch {
            installed: 1,
            target: 2
        }
        .code(),
        "pioneer.kernel_handoff.mismatch"
    );
    assert_eq!(
        crate::startup::Ambiguous.code(),
        "pioneer.startup.ambiguous"
    );
}

#[test]
fn protocol_incomplete_code() {
    assert_eq!(
        crate::protocol::Incomplete.code(),
        "pioneer.protocol.incomplete"
    );
}

#[cfg(feature = "envelope")]
#[test]
fn plan_error_code_and_display() {
    use crate::receiver::transport::PlanError;
    assert_eq!(
        PlanError::KernelLayout.code(),
        "pioneer.transport.kernel_layout"
    );
    assert!(!PlanError::KernelLayout.to_string().is_empty());
}
