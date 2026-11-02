//! Offline generated-byte execution without a proprietary archive dependency.
//! Public image/receipt validation is separately tested against exact archives.
use crate as pioneer;
#[path = "../../../tests/support/bank_bridge_execution.rs"]
mod execution;
fn source() -> Vec<u8> {
    let mut image = vec![0xff; 0x1c9200];
    for (at, bytes) in [
        (
            0x410000usize,
            include_bytes!("../../../tests/fixtures/pioneer-212u-bridge-header.bin").as_slice(),
        ),
        (
            0x44ba96,
            include_bytes!("../../../tests/fixtures/pioneer-212u-bridge-ff-hooks.bin").as_slice(),
        ),
        (
            0x57e8fc,
            include_bytes!("../../../tests/fixtures/pioneer-212u-bridge-flash-vectors.bin")
                .as_slice(),
        ),
        (
            0x4b6418,
            include_bytes!("../../../tests/fixtures/pioneer-212u-sha-code.bin").as_slice(),
        ),
        (
            0x59be6e,
            include_bytes!("../../../tests/fixtures/pioneer-212u-sha-constants.bin").as_slice(),
        ),
        (
            0x57ec28,
            include_bytes!("../../../tests/fixtures/pioneer-212u-sha-shl.bin").as_slice(),
        ),
        (
            0x57ecc8,
            include_bytes!("../../../tests/fixtures/pioneer-212u-sha-shr.bin").as_slice(),
        ),
    ] {
        image[at - 0x410000..at - 0x410000 + bytes.len()].copy_from_slice(bytes);
    }
    image
}
fn run(base: u32, selected: usize, fault: Option<usize>) {
    let source = source();
    let banks = execution::fixture_banks(selected);
    let converted = super::super::conversion::fixture_conversion([&banks[0], &banks[1]]).unwrap();
    let bridge = super::generate(
        &source,
        [&banks[0], &banks[1]],
        base,
        base + selected as u32 * 0x10000,
        converted.clone(),
    )
    .unwrap();
    execution::execute_bridge(
        &source, &bridge, &converted, banks, base, selected, fault, None,
    );
}
#[test]
fn native_payload_preserves_all_geometry_and_active_bank_cases() {
    for base in [0x5e0000, 0x7d0000] {
        for selected in [0, 1] {
            run(base, selected, None);
        }
    }
}
#[test]
fn native_payload_stops_after_partial_erase_program_and_footer() {
    for fault in [1, 2, 770, 771, 772] {
        run(0x5e0000, 0, Some(fault));
    }
}
#[test]
fn native_payload_clone_failure_retains_valid_source_and_runtime_pointer() {
    for fault in [1, 2, 1026, 1028, 1029, 1030] {
        run(0x5e0000, 1, Some(fault));
    }
}

#[test]
fn installed_bridge_is_independent_of_fresh_bank_capture() {
    let source = source();
    for base in [0x5e0000, 0x7d0000] {
        let bridges: Vec<_> = [0, 1]
            .into_iter()
            .map(|selected| {
                let banks = execution::fixture_banks(selected);
                let converted =
                    super::super::conversion::fixture_conversion([&banks[0], &banks[1]]).unwrap();
                super::generate(
                    &source,
                    [&banks[0], &banks[1]],
                    base,
                    base + selected as u32 * 0x10000,
                    converted,
                )
                .unwrap()
            })
            .collect();
        assert_eq!(bridges[0].image(), bridges[1].image());
        assert_ne!(bridges[0].control(), bridges[1].control());
    }
}

#[test]
fn native_payload_refuses_changed_runtime_vectors_before_flash() {
    run(0x5e0000, 0, Some(0));
}

#[test]
fn native_payload_restore_tag_and_unknown_tags_do_not_mutate_banks() {
    let source = source();
    for tag in [
        0x424e4b30,
        0x424e4b2f,
        0x424e4b33,
        0,
        0x424e4b32,
        0xffff_ffff,
    ] {
        let banks = execution::fixture_banks(0);
        let converted =
            super::super::conversion::fixture_conversion([&banks[0], &banks[1]]).unwrap();
        let bridge = super::generate(
            &source,
            [&banks[0], &banks[1]],
            0x5e0000,
            0x5e0000,
            converted.clone(),
        )
        .unwrap();
        execution::execute_bridge(
            &source,
            &bridge,
            &converted,
            banks,
            0x5e0000,
            0,
            None,
            Some(tag),
        );
    }
}

#[test]
fn native_payload_extended_geometry_faults_preserve_source() {
    for fault in [1, 2, 770] {
        run(0x7d0000, 1, Some(fault));
    }
    run(0x7d0000, 0, Some(1030));
}

#[test]
fn extended_competing_target_header_is_checked_after_clone_mapping() {
    let source = source();
    for selected in [0, 1] {
        let mut banks = execution::fixture_banks(selected);
        banks[selected][0x7ffa..0x7ffe].copy_from_slice(&0xfedc4322u32.to_be_bytes());
        let converted =
            super::super::conversion::fixture_conversion([&banks[0], &banks[1]]).unwrap();
        assert!(matches!(
            super::generate(
                &source,
                [&banks[0], &banks[1]],
                0x7d0000,
                0x7d0000 + selected as u32 * 0x10000,
                converted
            ),
            Err(super::Error::CompetingTarget)
        ));
    }
    let mut banks = execution::fixture_banks(0);
    banks[1][0x7ffa..0x7ffe].copy_from_slice(&0xfedc4322u32.to_be_bytes());
    let converted = super::super::conversion::fixture_conversion([&banks[0], &banks[1]]).unwrap();
    assert!(
        super::generate(
            &source,
            [&banks[0], &banks[1]],
            0x7d0000,
            0x7d0000,
            converted
        )
        .is_ok(),
        "stale inactive B header is replaced by complete clean A clone"
    );
}

#[test]
fn native_payload_refuses_tampered_footer_before_flash() {
    let source = source();
    for offset in [192, 200, 202, 206] {
        let banks = execution::fixture_banks(0);
        let converted =
            super::super::conversion::fixture_conversion([&banks[0], &banks[1]]).unwrap();
        let bridge = super::generate(
            &source,
            [&banks[0], &banks[1]],
            0x5e0000,
            0x5e0000,
            converted.clone(),
        )
        .unwrap();
        execution::execute_bridge(
            &source,
            &bridge,
            &converted,
            banks,
            0x5e0000,
            0,
            None,
            Some(0xff00_0000 | offset),
        );
    }
}
