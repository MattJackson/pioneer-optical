use super::*;
use alloc::vec::Vec;

fn dispatcher(key: [u8; 4]) -> Vec<u8> {
    let mut bytes = ACCEPT_COMPARE.to_vec();
    bytes.push(22);
    bytes.extend_from_slice(&[0x79, 1, 0, 0x10, 1, 0, 0x6f, 0x70, 0, 0x74, 0x5d, 0x40]);
    bytes.extend_from_slice(&KEY_COMPARE);
    bytes.extend_from_slice(&key);
    bytes.extend_from_slice(&REJECT_BRANCH);
    bytes.extend_from_slice(&[5, 0xba]);
    bytes
}

#[test]
fn key_comes_from_the_second_comparison_in_wire_order() {
    for key in [[0x42, 0x66, 0x23, 0xfd], [1, 2, 3, 4], [0; 4]] {
        assert_eq!(receiver_control_key(&dispatcher(key)), Some(key));
    }
}

#[test]
fn missing_truncated_and_duplicate_code_has_no_default() {
    let bytes = dispatcher([1, 2, 3, 4]);
    for end in 0..bytes.len() {
        assert_eq!(receiver_control_key(&bytes[..end]), None);
    }
    assert_eq!(receiver_control_key(&[bytes.clone(), bytes].concat()), None);
}

#[test]
fn accept_and_reject_branches_must_converge() {
    let bytes = dispatcher([1, 2, 3, 4]);
    for offset in [6, 7, 26, 27] {
        let mut wrong = bytes.clone();
        wrong[offset] ^= 1;
        assert_eq!(receiver_control_key(&wrong), None);
    }
}

#[test]
fn backward_accept_branch_cannot_be_mistaken_for_forward_key_data() {
    let mut bytes = dispatcher([1, 2, 3, 4]);
    bytes[7] = 0xff;
    bytes.resize(300, 0);
    assert_eq!(receiver_control_key(&bytes), None);
}
