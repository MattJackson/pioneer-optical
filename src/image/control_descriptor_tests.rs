use super::*;
use crate::image::{receiver_control, ReceiverControl};
use alloc::vec;
use alloc::vec::Vec;

fn fixture(startup: &[u8], register: u8) -> Vec<u8> {
    let mut body = vec![0; 512];
    body[..DESCRIPTOR_LOOP.len()].copy_from_slice(DESCRIPTOR_LOOP);
    body[FLAG_REGISTER] = register;
    body[FLAG_STORE] = 0x88 | (register << 4);
    for (position, width) in POINTERS {
        let target = (NORMAL_BASE + 400).to_be_bytes();
        body[position..position + width].copy_from_slice(&target[4 - width..]);
    }
    body[DESCRIPTOR_LOOP.len()..DESCRIPTOR_LOOP.len() + startup.len()].copy_from_slice(startup);
    body
}

#[test]
fn descriptor_only_entry_requires_the_complete_transition() {
    for startup in STARTUP {
        for register in [1, 2] {
            let body = fixture(startup, register);
            assert_eq!(
                receiver_control(&body),
                Some(ReceiverControl::DescriptorOnly)
            );
            for end in 0..DESCRIPTOR_LOOP.len() + startup.len() {
                assert_eq!(receiver_control(&body[..end]), None);
            }
            assert_eq!(receiver_control(&[body.clone(), body].concat()), None);
        }
    }
}

#[test]
fn descriptor_and_key_candidates_are_ambiguous() {
    let mut body = fixture(STARTUP[1], 2);
    body.extend_from_slice(&[
        0x7a, 0x20, 0x9a, 0x78, 0x23, 0x61, 0x47, 8, 0x7a, 0x20, 1, 2, 3, 4, 0x46, 0x4e,
    ]);
    assert_eq!(receiver_control(&body), None);
}

#[test]
fn loop_count_branches_descriptor_address_and_entry_flags_are_not_wildcards() {
    let body = fixture(STARTUP[1], 2);
    for position in [
        0, 8, 10, 12, 14, 28, 30, 32, 34, 35, 42, 46, 50, 52, 53, 54, 55, 62, 63, 64, 65, 71, 77,
        84, 98, 110,
    ] {
        let mut bad = body.clone();
        bad[position] ^= 1;
        assert_eq!(receiver_control(&bad), None, "altered byte {position}");
    }
}

#[test]
fn variable_operands_must_remain_consistent_and_point_into_the_image() {
    let body = fixture(STARTUP[1], 2);
    for position in [
        BUFFER_STACK,
        ERROR_STACK,
        FLAG_REGISTER,
        FLAG_STORE,
        RECOVERY_FLAGS[0],
    ] {
        let mut bad = body.clone();
        bad[position] ^= 1;
        assert_eq!(receiver_control(&bad), None, "altered byte {position}");
    }
    for (position, width) in POINTERS {
        for target in [NORMAL_BASE - 2, NORMAL_BASE + 401, NORMAL_BASE + 512] {
            let mut bad = body.clone();
            bad[position..position + width].copy_from_slice(&target.to_be_bytes()[4 - width..]);
            assert_eq!(receiver_control(&bad), None);
        }
    }
}
