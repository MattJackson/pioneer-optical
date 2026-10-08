//! Stable, language-independent identifiers for typed library errors.

/// Machine-readable error identity for diagnostics and translation catalogs.
///
/// Codes are stable across compatible releases and never contain runtime values.
/// Match the concrete error variant to obtain structured parameters; do not parse
/// its `Display` text. Wrapper errors identify their stage and retain their typed
/// cause, which may have its own code. Unknown future codes should use a generic
/// application message while retaining diagnostic details.
pub trait CodedError {
    /// Stable namespaced code, independent of English diagnostic wording.
    fn code(&self) -> &'static str;
}

#[cfg(feature = "envelope")]
impl CodedError for crate::envelope::NormalLayoutError {
    fn code(&self) -> &'static str {
        match self {
            Self::NotKernel => "pioneer.normal_layout.not_kernel",
            Self::InvalidKernel => "pioneer.normal_layout.invalid_kernel",
            Self::Unsupported => "pioneer.normal_layout.unsupported",
            Self::Ambiguous => "pioneer.normal_layout.ambiguous",
            Self::ConflictingGeometry => "pioneer.normal_layout.conflicting_geometry",
            Self::ShortHeader { .. } => "pioneer.normal_layout.short_header",
            Self::DescriptorMismatch => "pioneer.normal_layout.descriptor_mismatch",
            Self::InvalidLength { .. } => "pioneer.normal_layout.invalid_length",
            Self::ImageLength { .. } => "pioneer.normal_layout.image_length",
            Self::ImageChecksum => "pioneer.normal_layout.image_checksum",
        }
    }
}

#[cfg(feature = "envelope")]
impl CodedError for crate::envelope::Error {
    fn code(&self) -> &'static str {
        match self {
            Self::InvalidFilename => "pioneer.envelope.invalid_filename",
            Self::MissingModel => "pioneer.envelope.missing_model",
            Self::HeaderFieldsDoNotFit => "pioneer.envelope.header_fields_do_not_fit",
            Self::KernelStructure => "pioneer.envelope.kernel_structure",
            Self::KernelIncomplete => "pioneer.envelope.kernel_incomplete",
            Self::AmbiguousKernelLayout => "pioneer.envelope.ambiguous_kernel_layout",
            Self::RawKeyLength => "pioneer.envelope.raw_key_length",
            Self::RawKeyNotAllowed => "pioneer.envelope.raw_key_not_allowed",
            Self::KernelEncode => "pioneer.envelope.kernel_encode",
            Self::ImageStructure => "pioneer.envelope.image_structure",
            Self::ImageIncomplete => "pioneer.envelope.image_incomplete",
            Self::InvalidDate => "pioneer.envelope.invalid_date",
            Self::XorPolicyNotUnique => "pioneer.envelope.xor_policy_not_unique",
            Self::XorExceptionOutOfRange => "pioneer.envelope.xor_exception_out_of_range",
            Self::NormalEncode => "pioneer.envelope.normal_encode",
            Self::UnknownAuthentication => "pioneer.envelope.unknown_authentication",
            Self::SignatureBlockLength => "pioneer.envelope.signature_block_length",
            Self::InvalidSignedEnvelope => "pioneer.envelope.invalid_signed_envelope",
            Self::KernelBodySize { .. } => "pioneer.envelope.kernel_body_size",
            Self::UnknownMarker { .. } => "pioneer.envelope.unknown_marker",
            Self::AbiMismatch => "pioneer.envelope.abi_mismatch",
            Self::KernelUndecodable => "pioneer.envelope.kernel_undecodable",
            Self::NormalUndecodable => "pioneer.envelope.normal_undecodable",
            Self::RoundTripMismatch => "pioneer.envelope.round_trip_mismatch",
            Self::NotSignableNormal => "pioneer.envelope.not_signable_normal",
            Self::NotAscii => "pioneer.envelope.not_ascii",
            Self::EntropyUnavailable => "pioneer.envelope.entropy_unavailable",
            Self::Randomness => "pioneer.envelope.randomness",
            Self::InvalidPoint => "pioneer.envelope.invalid_point",
            Self::OperandTooLarge => "pioneer.envelope.operand_too_large",
            Self::SelfVerification => "pioneer.envelope.self_verification",
        }
    }
}

#[cfg(feature = "envelope")]
impl CodedError for crate::envelope::DecodeError {
    fn code(&self) -> &'static str {
        match self {
            Self::InvalidHeader => "pioneer.decode.invalid_header",
            Self::UnsupportedLayout => "pioneer.decode.unsupported_layout",
            Self::AmbiguousLayout => "pioneer.decode.ambiguous_layout",
            Self::InvalidPayload => "pioneer.decode.invalid_payload",
            Self::ReceiverPolicy { .. } => "pioneer.decode.receiver_policy",
            Self::PayloadAlignment { .. } => "pioneer.decode.payload_alignment",
            Self::ChecksumMismatch { .. } => "pioneer.decode.checksum_mismatch",
            Self::DecodedChecksum { .. } => "pioneer.decode.decoded_checksum",
            Self::PayloadLengthMismatch { .. } => "pioneer.decode.payload_length_mismatch",
        }
    }
}

#[cfg(feature = "envelope")]
impl CodedError for crate::envelope::UpdateError {
    fn code(&self) -> &'static str {
        match self {
            Self::Decode { .. } => "pioneer.update.decode",
            Self::Role { .. } => "pioneer.update.role",
            Self::Header { .. } => "pioneer.update.header",
            Self::Checksum { .. } => "pioneer.update.checksum",
            Self::Roundtrip { .. } => "pioneer.update.roundtrip",
            Self::UnrecoveredTail { .. } => "pioneer.update.unrecovered_tail",
            Self::Representation { .. } => "pioneer.update.representation",
            Self::Authentication => "pioneer.update.authentication",
        }
    }
}

#[cfg(feature = "envelope")]
impl CodedError for crate::receiver::Error {
    fn code(&self) -> &'static str {
        match self {
            Self::Component { .. } => "pioneer.receiver.component",
            Self::KernelComponent { .. } => "pioneer.receiver.kernel_component",
            Self::InstalledPairMismatch => "pioneer.receiver.installed_pair_mismatch",
            Self::InvalidDescriptor => "pioneer.receiver.invalid_descriptor",
            Self::Unsupported => "pioneer.receiver.unsupported",
            Self::DescriptorMismatch => "pioneer.receiver.descriptor_mismatch",
            Self::UnknownInstalledFamily => "pioneer.receiver.unknown_installed_family",
            Self::UnknownTargetFamily => "pioneer.receiver.unknown_target_family",
            Self::FamilyMismatch { .. } => "pioneer.receiver.family_mismatch",
        }
    }
}

#[cfg(feature = "envelope")]
impl CodedError for crate::receiver::PreparationError {
    fn code(&self) -> &'static str {
        match self {
            Self::Target(..) => "pioneer.preparation.target",
            Self::MissingInstalledKernel => "pioneer.preparation.missing_installed_kernel",
            Self::InstalledKernelRepresentation => {
                "pioneer.preparation.installed_kernel_representation"
            }
            Self::Compatibility(..) => "pioneer.preparation.compatibility",
            Self::UnknownInstalledKernel => "pioneer.preparation.unknown_installed_kernel",
            Self::UnsupportedRestoration => "pioneer.preparation.unsupported_restoration",
            Self::RestorationEntry(..) => "pioneer.preparation.restoration_entry",
            Self::PatchedRepresentation => "pioneer.preparation.patched_representation",
        }
    }
}

#[cfg(all(feature = "envelope", feature = "drive"))]
impl<E> CodedError for crate::receiver::FlashError<E> {
    fn code(&self) -> &'static str {
        match self {
            Self::Preflight { .. } => "pioneer.flash.preflight",
            Self::DescriptorRead { .. } => "pioneer.flash.descriptor_read",
            Self::DescriptorChanged { .. } => "pioneer.flash.descriptor_changed",
            Self::DescriptorMismatch { .. } => "pioneer.flash.descriptor_mismatch",
            Self::Update { .. } => "pioneer.flash.update",
            Self::Readback { .. } => "pioneer.flash.readback",
            Self::ReadbackMismatch { .. } => "pioneer.flash.readback_mismatch",
        }
    }
}

#[cfg(feature = "drive")]
impl<E> CodedError for crate::drive::Error<E> {
    fn code(&self) -> &'static str {
        match self {
            Self::Transport(..) => "pioneer.drive.transport",
            Self::Locked => "pioneer.drive.locked",
            Self::Short { .. } => "pioneer.drive.short",
            Self::ReadbackMismatch { .. } => "pioneer.drive.readback_mismatch",
            Self::Oversize(..) => "pioneer.drive.oversize",
            Self::Challenge => "pioneer.drive.challenge",
            Self::UnknownClass => "pioneer.drive.unknown_class",
        }
    }
}

#[cfg(feature = "drive")]
impl<E> CodedError for crate::drive::UpdateError<E> {
    fn code(&self) -> &'static str {
        match self {
            Self::InvalidSpan { .. } => "pioneer.transfer.invalid_span",
            Self::Entry(..) => "pioneer.transfer.entry",
            Self::EntryStateRead(..) => "pioneer.transfer.entry_state_read",
            Self::EntryState { .. } => "pioneer.transfer.entry_state",
            Self::Transfer { .. } => "pioneer.transfer.transfer",
            Self::Finish(..) => "pioneer.transfer.finish",
            Self::ReadyTimeout(..) => "pioneer.transfer.ready_timeout",
        }
    }
}

#[cfg(feature = "image")]
impl CodedError for crate::ident::IdentError {
    fn code(&self) -> &'static str {
        match self {
            Self::NoModel => "pioneer.identity.no_model",
            Self::IncompleteIdentity => "pioneer.identity.incomplete_identity",
            Self::NotFound => "pioneer.identity.not_found",
            Self::Ambiguous => "pioneer.identity.ambiguous",
        }
    }
}

#[cfg(test)]
#[path = "error_codes_tests.rs"]
mod tests;
