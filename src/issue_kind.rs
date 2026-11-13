//! Stable code classification; additions must carry an explicit host category.

pub(crate) fn kind_for_code(code: &str) -> crate::operation::IssueKind {
    use crate::operation::IssueKind;
    match code {
        "pioneer.execute.verification_incomplete"
        | "pioneer.execute.normal_mismatch"
        | "pioneer.flash.readback"
        | "pioneer.flash.readback_mismatch"
        | "pioneer.drive.readback_mismatch" => IssueKind::Verification,
        "pioneer.startup.parameter_change_failed"
        | "pioneer.startup.flash_state_uncertain"
        | "pioneer.flash.update"
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
        "pioneer.execute.identity_mismatch"
        | "pioneer.receiver.installed_pair_mismatch"
        | "pioneer.receiver.descriptor_mismatch"
        | "pioneer.flash.descriptor_changed"
        | "pioneer.flash.descriptor_mismatch" => IssueKind::ReceiverMismatch,
        // Host-owned or caller-initiated causes. Typed wrappers report a known cause.
        "pioneer.flash.preflight"
        | "pioneer.startup.preflight_refused"
        | "pioneer.startup.flash_failed_before_transfer"
        | "pioneer.analysis.cancelled" => IssueKind::Unexpected,
        "pioneer.startup.bank_unknown_installed"
        | "pioneer.startup.bank_unknown_target"
        | "pioneer.startup.bank_conversion_required"
        | "pioneer.startup.capacity_relation_unproved"
        | "pioneer.device.unsupported"
        | "pioneer.kernel_handoff.unknown_installed"
        | "pioneer.kernel_handoff.unknown_target"
        | "pioneer.transport.kernel_layout"
        | "pioneer.settings.codec.unsupported"
        | "pioneer.phase.correction_unproven"
        | "pioneer.compatibility.unresolved_identity"
        | "pioneer.compatibility.unsupported_correction"
        | "pioneer.compatibility.phase_correction"
        | "pioneer.compatibility.unresolved_startup"
        | "pioneer.prepare.unresolved_startup"
        | "pioneer.normal_layout.unsupported"
        | "pioneer.envelope.unknown_rotation"
        | "pioneer.envelope.unknown_authentication"
        | "pioneer.decode.unsupported_layout"
        | "pioneer.receiver.unsupported"
        | "pioneer.receiver.unknown_installed_family"
        | "pioneer.receiver.unknown_target_family"
        | "pioneer.prepare.unknown_startup_access"
        | "pioneer.prepare.kernel_handoff"
        | "pioneer.prepare.unknown_installed_kernel"
        | "pioneer.prepare.unsupported_restoration"
        | "pioneer.prepare.rejected_marker"
        | "pioneer.prepare.unsupported_dialect"
        | "pioneer.prepare.unsupported_transport"
        | "pioneer.flash.unsupported_transport"
        | "pioneer.drive.unknown_class"
        | "pioneer.execute.plan"
        | "pioneer.analysis.resource_limit"
        | "pioneer.layout.no_comp_directory"
        | "pioneer.layout.runtime_ownership_unproven"
        | "pioneer.layout.overlay_destinations_unresolved" => IssueKind::UnsupportedFirmware,
        "pioneer.device.malformed"
        | "pioneer.compatibility.component_mismatch"
        | "pioneer.compatibility.representation_failed"
        | "pioneer.compatibility.verification_failed"
        | "pioneer.compatibility.authentication_failed"
        | "pioneer.compatibility.ambiguous_startup"
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
        | "pioneer.prepare.ambiguous_startup"
        | "pioneer.prepare.target"
        | "pioneer.prepare.missing_installed_kernel"
        | "pioneer.prepare.installed_kernel_representation"
        | "pioneer.prepare.compatibility"
        | "pioneer.prepare.restoration_entry"
        | "pioneer.prepare.patched_representation"
        | "pioneer.drive.oversize"
        | "pioneer.drive.challenge"
        | "pioneer.identity.no_model"
        | "pioneer.identity.incomplete_identity"
        | "pioneer.identity.ambiguous"
        | "pioneer.envelope.self_verification"
        | "pioneer.transfer.invalid_span" => IssueKind::InvalidFirmware,
        "pioneer.receiver.family_mismatch"
        | "pioneer.compatibility.incompatible"
        | "pioneer.compatibility.persistent_layout_overlap" => IssueKind::HardwareMismatch,
        _ => IssueKind::Unexpected,
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn conflicting_settings_plans_are_invalid_firmware() {
        assert_eq!(
            super::kind_for_code("pioneer.settings.conflicting_parameters"),
            crate::operation::IssueKind::InvalidFirmware
        );
    }
    #[test]
    fn codes_without_a_write_boundary_report_their_offline_or_typed_cause() {
        use crate::operation::IssueKind::*;
        for (code, kind) in [
            ("pioneer.execute.plan", UnsupportedFirmware),
            ("pioneer.transfer.invalid_span", InvalidFirmware),
            ("pioneer.flash.readback", Verification),
            ("pioneer.envelope.self_verification", InvalidFirmware),
            ("pioneer.flash.preflight", Unexpected),
            ("pioneer.startup.preflight_refused", Unexpected),
            ("pioneer.startup.flash_failed_before_transfer", Unexpected),
            ("pioneer.startup.flash_state_uncertain", Update),
            ("pioneer.compatibility.verification_failed", InvalidFirmware),
        ] {
            assert_eq!(super::kind_for_code(code), kind, "{code}");
        }
    }
    /// Literals that look like codes but are not `CodedError` codes.
    const NOT_ERROR_CODES: &[&str] = &[
        // Nonfatal analysis `Diagnostic` identifiers.
        "pioneer.analysis.invalid_directory",
        "pioneer.analysis.ambiguous_comp",
        "pioneer.analysis.invalid_comp",
        "pioneer.analysis.overlapping_streams",
        "pioneer.analysis.semantic_coverage",
        "pioneer.analysis.startup_ambiguous",
        "pioneer.analysis.unrecovered_tail",
        "pioneer.analysis.ambiguous_runtime_destination",
        // Settings action identifiers and test-only identifiers.
        "pioneer.startup.word",
        "pioneer.first",
        "pioneer.second",
        "pioneer.invalid",
        "pioneer.valid",
    ];
    /// Codes whose host owns the cause, or which the caller initiated.
    const DELIBERATELY_UNEXPECTED: &[&str] = &[
        "pioneer.flash.preflight",
        "pioneer.startup.preflight_refused",
        "pioneer.startup.flash_failed_before_transfer",
        "pioneer.analysis.cancelled",
    ];
    #[test]
    fn every_declared_code_has_a_deliberate_host_category() {
        for source in [
            include_str!("error_codes.rs"),
            include_str!("receiver/execution_safe.rs"),
            include_str!("startup/migration.rs"),
            include_str!("startup/bank.rs"),
            include_str!("startup/checks.rs"),
            include_str!("settings/update.rs"),
            include_str!("compatibility.rs"),
            include_str!("compatibility/kernel.rs"),
            include_str!("compatibility/startup.rs"),
            include_str!("analysis/mod.rs"),
        ] {
            for code in source.split('"').filter(|s| {
                s.starts_with("pioneer.")
                    && s.bytes()
                        .all(|b| b.is_ascii_lowercase() || b == b'.' || b == b'_')
                    && !NOT_ERROR_CODES.contains(s)
            }) {
                if DELIBERATELY_UNEXPECTED.contains(&code) {
                    assert_eq!(
                        super::kind_for_code(code),
                        crate::operation::IssueKind::Unexpected,
                        "{code}"
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
