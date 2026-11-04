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
        envelope::UpdateError::Abi { missing: vec![1] }.code(),
        "pioneer.update.abi_mismatch"
    );
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
            Error::KernelUndecodable { source: None },
            "pioneer.envelope.kernel_undecodable",
        ),
        (
            Error::NormalUndecodable { source: None },
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
        (
            Error::KernelBodySize { got: 3 },
            "pioneer.envelope.kernel_body_size",
        ),
        (
            Error::UnknownMarker { marker: 0x42 },
            "pioneer.envelope.unknown_marker",
        ),
    ];
    for (error, code) in cases {
        assert_eq!(error.code(), code);
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
    use crate::receiver::{FlashError, FlashStage};
    for stage in [FlashStage::Initial, FlashStage::Continuation(1)] {
        let error = FlashError::<()>::ReadbackMismatch {
            stage,
            address: 0x400020,
        };
        assert_eq!(error.code(), "pioneer.flash.readback_mismatch");
        assert!(
            matches!(error, FlashError::ReadbackMismatch { stage: p, address: 0x400020 } if p == stage)
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

#[cfg(all(feature = "envelope", feature = "drive"))]
#[test]
fn plan_error_code_and_display() {
    use crate::receiver::transport::PlanError;
    assert_eq!(
        PlanError::KernelLayout.code(),
        "pioneer.transport.kernel_layout"
    );
    assert!(!PlanError::KernelLayout.to_string().is_empty());
}

#[cfg(feature = "envelope")]
#[test]
fn decode_and_update_error_catalogues_have_stable_codes() {
    use crate::envelope::{DecodeError as D, Layout, PairField, UpdateError as U};
    use crate::ComponentKind;
    let layout = Layout::Normal;
    let decode = [
        (D::InvalidHeader, "pioneer.decode.invalid_header"),
        (D::UnsupportedLayout, "pioneer.decode.unsupported_layout"),
        (D::AmbiguousLayout, "pioneer.decode.ambiguous_layout"),
        (D::InvalidPayload, "pioneer.decode.invalid_payload"),
        (
            D::ReceiverPolicy {
                kernel_layout: layout,
                normal_layout: layout,
            },
            "pioneer.decode.receiver_policy",
        ),
        (
            D::PayloadAlignment {
                layout,
                alignment: 2,
                actual: 3,
            },
            "pioneer.decode.payload_alignment",
        ),
        (
            D::ChecksumMismatch {
                layout,
                checksum_offset: 0,
                stored: 1,
                calculated: 2,
            },
            "pioneer.decode.checksum_mismatch",
        ),
        (
            D::DecodedChecksum {
                layout,
                word_bits: 16,
                sum: 1,
            },
            "pioneer.decode.decoded_checksum",
        ),
        (
            D::PayloadLengthMismatch {
                layout,
                payload_offset: 0,
                declared: 2,
                actual: 1,
            },
            "pioneer.decode.payload_length_mismatch",
        ),
    ];
    for (error, code) in decode {
        assert_eq!(error.code(), code);
    }
    let kernel = ComponentKind::Kernel;
    let update = [
        (
            U::Decode {
                component: kernel,
                source: D::InvalidHeader,
            },
            "pioneer.update.decode",
        ),
        (
            U::Role {
                expected: kernel,
                actual: ComponentKind::Normal,
            },
            "pioneer.update.role",
        ),
        (
            U::Header {
                field: PairField::HardwareVersion,
                kernel: "a".into(),
                normal: "b".into(),
            },
            "pioneer.update.header",
        ),
        (
            U::Checksum {
                component: kernel,
                sum: 1,
                bytes: 2,
            },
            "pioneer.update.checksum",
        ),
        (
            U::Roundtrip { component: kernel },
            "pioneer.update.roundtrip",
        ),
        (
            U::UnrecoveredTail {
                offset: 0,
                length: 1,
            },
            "pioneer.update.unrecovered_tail",
        ),
        (
            U::Representation {
                component: kernel,
                layout,
            },
            "pioneer.update.representation",
        ),
        (U::Authentication, "pioneer.update.authentication"),
        (U::Abi { missing: vec![1] }, "pioneer.update.abi_mismatch"),
    ];
    for (error, code) in update {
        assert_eq!(error.code(), code);
    }
}

#[cfg(feature = "envelope")]
#[test]
fn receiver_and_preparation_error_catalogues_have_stable_codes() {
    use crate::receiver::{Error as R, PreparationError as P};
    use crate::ComponentKind;
    let a = crate::image::matrix::test_family(0x12);
    let b = crate::image::matrix::test_family(0x13);
    let receiver = [
        (
            R::Component {
                actual: ComponentKind::Kernel,
            },
            "pioneer.receiver.component",
        ),
        (
            R::KernelComponent {
                actual: ComponentKind::Normal,
            },
            "pioneer.receiver.kernel_component",
        ),
        (
            R::InstalledPairMismatch,
            "pioneer.receiver.installed_pair_mismatch",
        ),
        (R::InvalidDescriptor, "pioneer.receiver.invalid_descriptor"),
        (R::Unsupported, "pioneer.receiver.unsupported"),
        (
            R::DescriptorMismatch,
            "pioneer.receiver.descriptor_mismatch",
        ),
        (
            R::UnknownInstalledFamily,
            "pioneer.receiver.unknown_installed_family",
        ),
        (
            R::UnknownTargetFamily,
            "pioneer.receiver.unknown_target_family",
        ),
        (
            R::FamilyMismatch {
                installed: a,
                target: b,
            },
            "pioneer.receiver.family_mismatch",
        ),
    ];
    for (error, code) in receiver {
        assert_eq!(error.code(), code);
    }
    let preparation = [
        (
            P::UnresolvedStartup,
            "pioneer.preparation.unresolved_startup",
        ),
        (P::AmbiguousStartup, "pioneer.preparation.ambiguous_startup"),
        (
            P::UnknownStartupAccess,
            "pioneer.preparation.unknown_startup_access",
        ),
        (
            P::Target(crate::envelope::UpdateError::Authentication),
            "pioneer.preparation.target",
        ),
        (
            P::KernelHandoff(crate::image::KernelHandoffError::UnknownTarget),
            "pioneer.preparation.kernel_handoff",
        ),
        (
            P::MissingInstalledKernel,
            "pioneer.preparation.missing_installed_kernel",
        ),
        (
            P::InstalledKernelRepresentation,
            "pioneer.preparation.installed_kernel_representation",
        ),
        (
            P::Compatibility(R::Unsupported),
            "pioneer.preparation.compatibility",
        ),
        (
            P::UnknownInstalledKernel,
            "pioneer.preparation.unknown_installed_kernel",
        ),
        (P::RejectedMarker, "pioneer.preparation.rejected_marker"),
        (
            P::UnsupportedFinalStage,
            "pioneer.preparation.unsupported_restoration",
        ),
        (
            P::FinalStageEntry(R::Unsupported),
            "pioneer.preparation.restoration_entry",
        ),
        (
            P::PatchedRepresentation,
            "pioneer.preparation.patched_representation",
        ),
        (
            P::UnsupportedDialect,
            "pioneer.preparation.unsupported_dialect",
        ),
        (
            P::UnsupportedTransport,
            "pioneer.preparation.unsupported_transport",
        ),
        // Wrapped causes that surface their own stable code.
        (
            P::Startup(crate::startup::checks::Error::AmbiguousWord),
            "pioneer.preparation.ambiguous_startup",
        ),
        (
            P::PhaseCorrection(crate::compatibility::Error::PersistentLayoutOverlap {
                start: 0,
                end: 1,
            }),
            "pioneer.compatibility.persistent_layout_overlap",
        ),
        (
            P::PhaseCorrection(crate::compatibility::Error::Unsupported),
            "pioneer.phase.correction_unproven",
        ),
    ];
    for (error, code) in preparation {
        assert_eq!(error.code(), code);
    }
}

#[cfg(all(feature = "envelope", feature = "drive"))]
#[test]
fn flash_error_catalogue_has_stable_codes() {
    use crate::drive::{Error as D, UpdateError as U};
    use crate::receiver::{FlashError as F, FlashStage};
    let stage = FlashStage::Initial;
    let cases = [
        (
            F::Preflight { stage, source: () },
            "pioneer.flash.preflight",
        ),
        (
            F::DescriptorRead {
                stage,
                source: D::Locked,
            },
            "pioneer.flash.descriptor_read",
        ),
        (
            F::DescriptorChanged { stage },
            "pioneer.flash.descriptor_changed",
        ),
        (
            F::DescriptorMismatch { stage },
            "pioneer.flash.descriptor_mismatch",
        ),
        (
            F::Update {
                stage,
                source: U::Finish(D::Locked),
            },
            "pioneer.flash.update",
        ),
        (
            F::Readback {
                stage,
                source: D::Locked,
            },
            "pioneer.flash.readback",
        ),
        (
            F::ReadbackMismatch { stage, address: 0 },
            "pioneer.flash.readback_mismatch",
        ),
        (
            F::UnsupportedTransport { stage },
            "pioneer.flash.unsupported_transport",
        ),
    ];
    for (error, code) in cases {
        assert_eq!(error.code(), code);
    }
}

#[cfg(feature = "drive")]
#[test]
fn drive_and_device_error_catalogues_have_stable_codes() {
    use crate::drive::{Error as D, UpdateError as U};
    use crate::Role;
    let drive = [
        (D::Transport(()), "pioneer.drive.transport"),
        (D::Locked, "pioneer.drive.locked"),
        (
            D::Short {
                expected: 2,
                actual: 1,
            },
            "pioneer.drive.short",
        ),
        (
            D::ReadbackMismatch {
                expected: 1,
                actual: 2,
            },
            "pioneer.drive.readback_mismatch",
        ),
        (D::Oversize(1 << 24), "pioneer.drive.oversize"),
        (D::Challenge, "pioneer.drive.challenge"),
        (D::InvalidProtocol, "pioneer.drive.invalid_protocol"),
        (D::UnknownClass, "pioneer.drive.unknown_class"),
    ];
    for (error, code) in drive {
        assert_eq!(error.code(), code);
    }
    let update = [
        (
            U::InvalidSpan {
                role: Role::Kernel,
                length: 0,
            },
            "pioneer.transfer.invalid_span",
        ),
        (U::Entry(D::<()>::Locked), "pioneer.transfer.entry"),
        (
            U::EntryStateRead(D::Locked),
            "pioneer.transfer.entry_state_read",
        ),
        (
            U::EntryState { revision: [0; 4] },
            "pioneer.transfer.entry_state",
        ),
        (
            U::Transfer {
                role: Role::Normal,
                offset: 0,
                length: 1,
                source: D::Locked,
            },
            "pioneer.transfer.transfer",
        ),
        (U::Finish(D::Locked), "pioneer.transfer.finish"),
        (U::ReadyTimeout(D::Locked), "pioneer.transfer.ready_timeout"),
    ];
    for (error, code) in update {
        assert_eq!(error.code(), code);
    }
    use crate::device::Error as V;
    let device = [
        (
            V::Transport {
                source: (),
                sense: None,
            },
            "pioneer.device.transport",
        ),
        (V::Unsupported, "pioneer.device.unsupported"),
        (V::NotReported, "pioneer.device.not_reported"),
        (V::Malformed, "pioneer.device.malformed"),
        (V::InvalidValue, "pioneer.device.invalid_value"),
        (V::RegionLocked, "pioneer.device.region_locked"),
    ];
    for (error, code) in device {
        assert_eq!(error.code(), code);
    }
}

#[cfg(feature = "image")]
#[test]
fn identity_error_catalogue_has_stable_codes() {
    use crate::ident::IdentError as I;
    let cases = [
        (I::NoModel, "pioneer.identity.no_model"),
        (
            I::IncompleteIdentity,
            "pioneer.identity.incomplete_identity",
        ),
        (I::NotFound, "pioneer.identity.not_found"),
        (I::Ambiguous, "pioneer.identity.ambiguous"),
    ];
    for (error, code) in cases {
        assert_eq!(error.code(), code);
    }
}

#[test]
fn settings_codec_error_catalogue_has_stable_codes() {
    use crate::settings::CodecError as C;
    let cases = [
        (C::Malformed, "pioneer.settings.codec.malformed"),
        (C::Unsupported, "pioneer.settings.codec.unsupported"),
        (C::InvalidRequest, "pioneer.settings.codec.invalid_request"),
    ];
    for (error, code) in cases {
        assert_eq!(error.code(), code);
    }
}
