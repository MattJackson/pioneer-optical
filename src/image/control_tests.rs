use super::*;
use alloc::vec;
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
        assert_eq!(
            receiver_control(&dispatcher(key)),
            Some(ReceiverControl::Key(key))
        );
    }
}

#[test]
fn missing_truncated_and_duplicate_code_has_no_default() {
    let bytes = dispatcher([1, 2, 3, 4]);
    for end in 0..bytes.len() {
        assert_eq!(receiver_control(&bytes[..end]), None);
    }
    assert_eq!(receiver_control(&[bytes.clone(), bytes].concat()), None);
    assert_eq!(
        receiver_control(&[vec![0], dispatcher([1, 2, 3, 4])].concat()),
        None
    );
}

#[test]
fn accept_and_reject_branches_must_converge() {
    let bytes = dispatcher([1, 2, 3, 4]);
    for offset in [6, 7, 26, 27] {
        let mut wrong = bytes.clone();
        wrong[offset] ^= 1;
        assert_eq!(receiver_control(&wrong), None);
    }
}

#[test]
fn backward_accept_branch_cannot_be_mistaken_for_forward_key_data() {
    let mut bytes = dispatcher([1, 2, 3, 4]);
    bytes[7] = 0xff;
    bytes.resize(300, 0);
    assert_eq!(receiver_control(&bytes), None);
}

#[test]
fn short_reject_branch_uses_the_same_control_key_contract() {
    let bytes = [
        0x7a, 0x20, 0x9a, 0x78, 0x23, 0x61, 0x47, 8, 0x7a, 0x20, 1, 2, 3, 4, 0x46, 0x4e,
    ];
    assert_eq!(
        receiver_control(&bytes),
        Some(ReceiverControl::Key([1, 2, 3, 4]))
    );
    for end in 0..bytes.len() {
        assert_eq!(receiver_control(&bytes[..end]), None);
    }
    for offset in [6, 7, 8, 9, 14] {
        let mut changed = bytes;
        changed[offset] ^= 1;
        assert_eq!(receiver_control(&changed), None);
    }
    assert_eq!(
        receiver_control(&[bytes.to_vec(), dispatcher([1, 2, 3, 4])].concat()),
        None
    );
}
