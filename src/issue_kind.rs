//! Stable code classification; additions must carry an explicit host category.

pub(super) fn kind_for_code(code: &str) -> crate::operation::IssueKind {
    use crate::operation::IssueKind;
    match code {
        "pioneer.execute.verification_incomplete"
        | "pioneer.execute.normal_mismatch"
        | "pioneer.envelope.self_verification"
        | "pioneer.flash.readback_mismatch"
        | "pioneer.drive.readback_mismatch" => IssueKind::Verification,
        "pioneer.execute.plan"
        | "pioneer.startup.preflight_refused"
        | "pioneer.startup.parameter_change_failed"
        | "pioneer.startup.flash_state_uncertain"
        | "pioneer.startup.flash_failed_before_transfer"
        | "pioneer.flash.preflight"
        | "pioneer.flash.update"
        | "pioneer.flash.readback"
        | "pioneer.transfer.invalid_span"
        | "pioneer.transfer.entry"
        | "pioneer.transfer.entry_state_read"
        | "pioneer.transfer.entry_state"
        | "pioneer.transfer.transfer"
        | "pioneer.transfer.finish"
        | "pioneer.transfer.ready_timeout" => IssueKind::Update,
        "pioneer.execute.identity_read"
        | "pioneer.startup.parameter_read_failed"
        | "pioneer.protocol.incomplete"
        | "pioneer.drive.invalid_protocol"
        | "pioneer.device.transport"
        | "pioneer.device.not_reported"
        | "pioneer.flash.descriptor_read"
        | "pioneer.drive.transport"
        | "pioneer.drive.locked"
        | "pioneer.drive.short"
        | "pioneer.identity.not_found" => IssueKind::Connection,
        "pioneer.settings.prerequisite_mismatch"
        | "pioneer.execute.identity_mismatch"
        | "pioneer.receiver.installed_pair_mismatch"
        | "pioneer.receiver.descriptor_mismatch"
        | "pioneer.flash.descriptor_changed"
        | "pioneer.flash.descriptor_mismatch" => IssueKind::ReceiverMismatch,
        "pioneer.settings.adaptation_registry_invalid"
        | "pioneer.settings.adaptation_guard_failed" => IssueKind::Unexpected,
        "pioneer.settings.adaptation_representation_failed"
        | "pioneer.settings.original_hardware_required"
        | "pioneer.device.unsupported"
        | "pioneer.kernel_handoff.unknown_installed"
        | "pioneer.kernel_handoff.unknown_target"
        | "pioneer.transport.kernel_layout"
        | "pioneer.settings.codec.unsupported"
        | "pioneer.settings.compatibility_unresolved"
        | "pioneer.settings.conversion_unavailable"
        | "pioneer.normal_layout.unsupported"
        | "pioneer.envelope.unknown_rotation"
        | "pioneer.envelope.unknown_authentication"
        | "pioneer.decode.unsupported_layout"
        | "pioneer.receiver.unsupported"
        | "pioneer.receiver.unknown_installed_family"
        | "pioneer.receiver.unknown_target_family"
        | "pioneer.preparation.unknown_startup_access"
        | "pioneer.preparation.kernel_handoff"
        | "pioneer.preparation.unknown_installed_kernel"
        | "pioneer.preparation.unsupported_restoration"
        | "pioneer.preparation.unsupported_dialect"
        | "pioneer.preparation.unsupported_transport"
        | "pioneer.flash.unsupported_transport"
        | "pioneer.drive.unknown_class" => IssueKind::UnsupportedFirmware,
        "pioneer.device.malformed"
        | "pioneer.startup.ambiguous"
        | "pioneer.startup.parameter_out_of_range"
        | "pioneer.kernel_handoff.mismatch"
        | "pioneer.update.abi_mismatch"
        | "pioneer.device.invalid_value"
        | "pioneer.device.region_locked"
        | "pioneer.settings.conflicting_parameters"
        | "pioneer.settings.codec.malformed"
        | "pioneer.settings.codec.invalid_request"
        | "pioneer.normal_layout.not_kernel"
        | "pioneer.normal_layout.invalid_kernel"
        | "pioneer.normal_layout.ambiguous"
        | "pioneer.normal_layout.conflicting_geometry"
        | "pioneer.normal_layout.short_header"
        | "pioneer.normal_layout.descriptor_mismatch"
        | "pioneer.normal_layout.invalid_length"
        | "pioneer.normal_layout.image_length"
        | "pioneer.normal_layout.image_checksum"
        | "pioneer.envelope.invalid_header"
        | "pioneer.envelope.invalid_filename"
        | "pioneer.envelope.missing_model"
        | "pioneer.envelope.header_fields_do_not_fit"
        | "pioneer.envelope.kernel_structure"
        | "pioneer.envelope.kernel_incomplete"
        | "pioneer.envelope.ambiguous_kernel_layout"
        | "pioneer.envelope.raw_key_length"
        | "pioneer.envelope.raw_key_not_allowed"
        | "pioneer.envelope.kernel_encode"
        | "pioneer.envelope.image_structure"
        | "pioneer.envelope.image_incomplete"
        | "pioneer.envelope.invalid_date"
        | "pioneer.envelope.xor_policy_not_unique"
        | "pioneer.envelope.xor_exception_out_of_range"
        | "pioneer.envelope.normal_encode"
        | "pioneer.envelope.signature_block_length"
        | "pioneer.envelope.invalid_signed_envelope"
        | "pioneer.envelope.kernel_body_size"
        | "pioneer.envelope.unknown_marker"
        | "pioneer.envelope.abi_mismatch"
        | "pioneer.envelope.kernel_undecodable"
        | "pioneer.envelope.normal_undecodable"
        | "pioneer.envelope.round_trip_mismatch"
        | "pioneer.envelope.not_signable_normal"
        | "pioneer.envelope.not_ascii"
        | "pioneer.envelope.entropy_unavailable"
        | "pioneer.envelope.randomness"
        | "pioneer.envelope.invalid_point"
        | "pioneer.envelope.operand_too_large"
        | "pioneer.envelope.kernel_fill_not_found"
        | "pioneer.envelope.drive_name_not_found"
        | "pioneer.decode.invalid_header"
        | "pioneer.decode.ambiguous_layout"
        | "pioneer.decode.invalid_payload"
        | "pioneer.decode.receiver_policy"
        | "pioneer.decode.payload_alignment"
        | "pioneer.decode.checksum_mismatch"
        | "pioneer.decode.decoded_checksum"
        | "pioneer.decode.payload_length_mismatch"
        | "pioneer.update.decode"
        | "pioneer.update.role"
        | "pioneer.update.header"
        | "pioneer.update.checksum"
        | "pioneer.update.roundtrip"
        | "pioneer.update.unrecovered_tail"
        | "pioneer.update.representation"
        | "pioneer.update.authentication"
        | "pioneer.receiver.component"
        | "pioneer.receiver.kernel_component"
        | "pioneer.receiver.invalid_descriptor"
        | "pioneer.preparation.ambiguous_startup"
        | "pioneer.preparation.target"
        | "pioneer.preparation.missing_installed_kernel"
        | "pioneer.preparation.installed_kernel_representation"
        | "pioneer.preparation.compatibility"
        | "pioneer.preparation.restoration_entry"
        | "pioneer.preparation.patched_representation"
        | "pioneer.drive.oversize"
        | "pioneer.drive.challenge"
        | "pioneer.identity.no_model"
        | "pioneer.identity.incomplete_identity"
        | "pioneer.identity.ambiguous" => IssueKind::InvalidFirmware,
        "pioneer.settings.original_hardware_mismatch" | "pioneer.receiver.family_mismatch" => {
            IssueKind::HardwareMismatch
        }
        _ => IssueKind::Unexpected,
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn known_settings_refusals_are_not_unexpected_or_hardware_mismatches() {
        for code in [
            "pioneer.settings.compatibility_unresolved",
            "pioneer.settings.conversion_unavailable",
        ] {
            assert_eq!(
                super::kind_for_code(code),
                crate::operation::IssueKind::UnsupportedFirmware
            );
        }
        assert_eq!(
            super::kind_for_code("pioneer.settings.conflicting_parameters"),
            crate::operation::IssueKind::InvalidFirmware
        );
    }
    #[test]
    fn every_declared_code_has_a_deliberate_host_category() {
        for source in [
            include_str!("error_codes.rs"),
            include_str!("receiver/execution_safe.rs"),
            include_str!("startup/migration.rs"),
            include_str!("settings/adaptation.rs"),
        ] {
            for code in source.split('"').filter(|s| {
                s.starts_with("pioneer.")
                    && s.bytes()
                        .all(|b| b.is_ascii_lowercase() || b == b'.' || b == b'_')
            }) {
                if matches!(
                    code,
                    "pioneer.settings.adaptation_registry_invalid"
                        | "pioneer.settings.adaptation_guard_failed"
                ) {
                    assert_eq!(
                        super::kind_for_code(code),
                        crate::operation::IssueKind::Unexpected
                    );
                    continue;
                }
                assert_ne!(
                    super::kind_for_code(code),
                    crate::operation::IssueKind::Unexpected,
                    "unclassified error code: {code}"
                );
            }
        }
    }
}
