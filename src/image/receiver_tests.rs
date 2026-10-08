use super::*;
use alloc::vec;
use alloc::vec::Vec;

const FINALIZER: usize = 0x100;
const GATE: usize = 0x1000;

fn call(bytes: &mut [u8], offset: usize, target: usize) {
    let address = (KERNEL_BASE + target as u32).to_be_bytes();
    bytes[offset + 1..offset + 4].copy_from_slice(&address[1..]);
}

pub(crate) fn fixture(gated: bool) -> Vec<u8> {
    let mut image = vec![0u8; KERNEL_LEN];
    let template = if gated {
        GATED_FINALIZER
    } else {
        UNGATED_FINALIZER
    };
    image[FINALIZER..FINALIZER + template.len()].copy_from_slice(template);
    call(&mut image, FINALIZER + DECODER_CALL, 0x2000);
    call(&mut image, FINALIZER + CHECKSUM_CALL, 0x2200);
    if gated {
        call(&mut image, FINALIZER + MARKER_CALL, GATE);
        image[GATE..GATE + MARKER_CHECK.len()].copy_from_slice(MARKER_CHECK);
    }
    image
}

#[test]
fn marker_edit_does_not_change_receiver_classification() {
    for (gated, expected) in [
        (false, KernelMarkerPolicy::NoMarkerCheck),
        (true, KernelMarkerPolicy::RejectZeroAndErased),
    ] {
        let mut image = fixture(gated);
        for marker in [0, 1, 0xff, 0x55] {
            image[0xfe] = marker;
            assert_eq!(kernel_marker_policy(&image), Some(expected));
        }
    }
}

#[test]
fn follows_relocated_gate_and_does_not_pin_recovery_ram_address() {
    let mut image = fixture(true);
    let relocated = 0x3000;
    image[relocated..relocated + MARKER_CHECK.len()].copy_from_slice(MARKER_CHECK);
    image[GATE..GATE + MARKER_CHECK.len()].fill(0);
    call(&mut image, FINALIZER + MARKER_CALL, relocated);
    image[relocated + RECOVERY_FLAG_ADDRESS..relocated + RECOVERY_FLAG_ADDRESS + ADDRESS_LEN]
        .copy_from_slice(&0x1234u32.to_be_bytes());
    assert_eq!(
        kernel_marker_policy(&image),
        Some(KernelMarkerPolicy::RejectZeroAndErased)
    );
}

#[test]
fn changing_a_gate_instruction_is_not_accepted() {
    for offset in 0..MARKER_CHECK.len() {
        if (RECOVERY_FLAG_ADDRESS..RECOVERY_FLAG_ADDRESS + ADDRESS_LEN).contains(&offset) {
            continue;
        }
        let mut image = fixture(true);
        image[GATE + offset] ^= 1;
        assert_eq!(kernel_marker_policy(&image), None, "offset={offset:#x}");
    }
}

#[test]
fn duplicate_finalizers_are_ambiguous() {
    let mut image = fixture(false);
    let duplicate = image[FINALIZER..FINALIZER + UNGATED_FINALIZER.len()].to_vec();
    image[0x3000..0x3000 + duplicate.len()].copy_from_slice(&duplicate);
    assert_eq!(kernel_marker_policy(&image), None);
}

#[test]
fn invalid_calls_and_truncated_images_are_unknown() {
    for call_offset in [DECODER_CALL, CHECKSUM_CALL, MARKER_CALL] {
        let mut image = fixture(true);
        image[FINALIZER + call_offset + 1..FINALIZER + call_offset + 4].fill(0xff);
        assert_eq!(kernel_marker_policy(&image), None);
    }
    let image = fixture(true);
    for end in [0, 1, FINALIZER, GATE + 10, KERNEL_LEN - 1] {
        assert_eq!(kernel_marker_policy(&image[..end]), None);
    }
    assert_eq!(kernel_marker_policy(&vec![0; KERNEL_LEN]), None);
}

#[test]
fn every_fixed_finalizer_byte_is_required() {
    for gated in [false, true] {
        let template = if gated {
            GATED_FINALIZER
        } else {
            UNGATED_FINALIZER
        };
        let calls: &[usize] = if gated {
            &[DECODER_CALL, CHECKSUM_CALL, MARKER_CALL]
        } else {
            &[DECODER_CALL, CHECKSUM_CALL]
        };
        for offset in 0..template.len() {
            if calls.iter().any(|c| (*c + 1..*c + 4).contains(&offset)) {
                continue;
            }
            let mut image = fixture(gated);
            image[FINALIZER + offset] ^= 1;
            assert_eq!(
                kernel_marker_policy(&image),
                None,
                "gated={gated} offset={offset:#x}"
            );
        }
    }
}

#[test]
fn odd_call_target_is_rejected() {
    let mut image = fixture(false);
    call(&mut image, FINALIZER + DECODER_CALL, 0x2001);
    assert_eq!(kernel_marker_policy(&image), None);
}

#[test]
fn earlier_inline_checksum_variants_are_marker_independent() {
    for &(template, scratch) in LEGACY_FINALIZERS {
        let mut image = vec![0; KERNEL_LEN];
        image[FINALIZER..FINALIZER + template.len()].copy_from_slice(template);
        call(&mut image, FINALIZER + LEGACY_DECODER_CALL, 0x2000);
        call(&mut image, FINALIZER + LEGACY_COPY_CALL, 0x2200);
        image[FINALIZER + scratch..FINALIZER + scratch + ADDRESS_LEN]
            .copy_from_slice(&0x1234u32.to_be_bytes());
        for marker in [0, 1, 255] {
            image[0xfe] = marker;
            assert_eq!(
                kernel_marker_policy(&image),
                Some(KernelMarkerPolicy::NoMarkerCheck)
            );
        }
        for offset in 0..template.len() {
            if (scratch..scratch + ADDRESS_LEN).contains(&offset)
                || [LEGACY_DECODER_CALL, LEGACY_COPY_CALL]
                    .iter()
                    .any(|c| (*c + 1..*c + 4).contains(&offset))
            {
                continue;
            }
            image[FINALIZER + offset] ^= 1;
            assert_eq!(kernel_marker_policy(&image), None, "offset={offset:#x}");
            image[FINALIZER + offset] ^= 1;
        }
    }
}
