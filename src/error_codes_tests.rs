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
