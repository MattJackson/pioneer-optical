use super::*;
const BASE: u32 = 0x500000;
const MAIN: u32 = BASE + 0x100;
const HELPER: u32 = BASE + 0x600;
const INVALID: u32 = BASE + 0x800;

// Synthetic compiler layouts with deliberately unrelated addresses. All values
// are reconstructed from CDB bytes, then moved through different locals/registers.
fn handler(
    object_reg: Option<u8>,
    address_reg: Option<u8>,
    length_reg: Option<u8>,
    write: bool,
    short_branch: bool,
) -> Vec<u8> {
    let mut image = vec![0; 0x1000];
    let mut code = vec![
        1, 0, 0x6d, 0xf3, 1, 0x20, 0x6d, 0xf4, 0x79, 0x37, 1, 0, 0x0f, 0x93,
    ]; // ER3=CDB
    if let Some(r) = object_reg {
        code.extend([0x0f, 0x80 | r]);
    } else {
        code.extend([1, 0, 0x6f, 0xf0, 0, 0x70]);
    }
    // Stack locals: big-endian 24-bit address and length, with zero high bytes.
    for (slot, first) in [(0x40, 3), (0x44, 6)] {
        code.extend([0x18, 0x88, 0x6e, 0xf8, 0, slot]);
        for n in 0..3 {
            code.extend([0x6e, 0x38, 0, first + n, 0x6e, 0xf8, 0, slot + 1 + n]);
        }
    }
    if let Some(r) = address_reg {
        code.extend([1, 0, 0x6f, 0x70 | r, 0, 0x40]);
    }
    if let Some(r) = length_reg {
        code.extend([1, 0, 0x6f, 0x70 | r, 0, 0x44]);
    }
    code.extend([0x6e, 0x31, 0, 2, 0xa1, 0x93]);
    if short_branch {
        code.extend([0x47, 2, 0xff, 0xff]);
    } else {
        code.extend([0x58, 0x70, 0, 2, 0xff, 0xff]);
    }
    if let Some(r) = length_reg {
        code.extend([1, 0, 0x69, 0xf0 | r]);
    } else {
        code.extend([1, 0, 0x6f, 0x72, 0, 0x44, 1, 0, 0x69, 0xf2]);
    }
    if write {
        code.extend([0xf9, 1]);
    } else {
        code.extend([0x18, 0x99]);
    }
    if let Some(r) = object_reg {
        code.extend([0x0f, 0x80 | (r << 4)]);
    } else {
        code.extend([1, 0, 0x6f, 0x70, 0, 0x70]);
    }
    if let Some(r) = address_reg {
        code.extend([0x0f, 0x82 | (r << 4)]);
    } else {
        code.extend([1, 0, 0x6f, 0x72, 0, 0x40]);
    }
    code.extend([0x5e, 0x50, 6, 0]);
    image[0x100..0x100 + code.len()].copy_from_slice(&code);
    image
}
#[test]
fn traces_register_and_stack_argument_layouts_without_address_tables() {
    for (object, address, length) in [
        (Some(6), None, None),
        (Some(5), None, None),
        (None, None, None),
        (None, Some(6), Some(4)),
        (Some(6), None, Some(4)),
        (None, Some(5), Some(4)),
    ] {
        for write in [false, true] {
            for short in [false, true] {
                let image = handler(object, address, length, write, short);
                assert_eq!(
                    memory_call(&image, BASE, MAIN, 0x93, write).unwrap(),
                    HELPER
                );
            }
        }
    }
}
#[test]
fn rejects_unproven_object_direction_address_length_and_selector() {
    let original = handler(Some(6), None, None, false, false);
    for (pattern, index, replacement) in [
        (vec![0x0f, 0xe0], 1, 0xd0),                // wrong object register
        (vec![0x18, 0x99], 0, 0xf9),                // direction is 0x99, not read
        (vec![1, 0, 0x6f, 0x72, 0, 0x40], 5, 0x44), // address becomes length
        (vec![1, 0, 0x6f, 0x72, 0, 0x44], 5, 0x40), // length becomes address
        (vec![0x6e, 0x31, 0, 2], 3, 3),             // dispatch tests an address byte
    ] {
        let mut bad = original.clone();
        let at = bad
            .windows(pattern.len())
            .position(|b| b == pattern)
            .unwrap();
        bad[at + index] = replacement;
        assert!(memory_call(&bad, BASE, MAIN, 0x93, false).is_err());
    }
    for len in [0, 1, 0x100, 0x104] {
        assert!(memory_call(&original[..len], BASE, MAIN, 0x93, false).is_err());
    }
    assert!(memory_call(&original, BASE, MAIN + 1, 0x93, false).is_err());
    assert!(memory_call(&original, BASE, BASE - 2, 0x93, false).is_err());
}
fn controller(long_save: bool, far_error: bool) -> Vec<u8> {
    let mut image = vec![0; 0x1000];
    let mut code = if long_save {
        vec![1, 0, 0x6d, 0xf3]
    } else {
        vec![0x6d, 0xf3]
    };
    code.extend([
        1,
        0x20,
        0x6d,
        0xf4,
        0x0f,
        if long_save { 0xa3 } else { 0xa4 },
        0x0c,
        if long_save { 0x9c } else { 0x9b },
        0x0f,
        0x85,
        0x0f,
        0xa1,
        1,
        0,
        0x6f,
        0x76,
        0,
        if long_save { 20 } else { 18 },
        0x0a,
        0xe2,
        0x0f,
        0xa0,
        0x7a,
        0x22,
        0,
        0x40,
        0,
        0,
    ]);
    if far_error {
        let displacement = 0x700 - (0x600 + code.len() + 4);
        code.extend([0x58, 0x20]);
        code.extend((displacement as u16).to_be_bytes());
    } else {
        code.extend([0x43, 8, 0x5e, 0x50, 8, 0, 0x5a, 0x50, 7, 4]);
    }
    image[0x600..0x600 + code.len()].copy_from_slice(&code);
    let mut tail = vec![0x5e, 0x50, 8, 0, 0xf8, 1, 1, 0x20, 0x6d, 0x76];
    if long_save {
        tail.extend([1, 0, 0x6d, 0x73]);
    } else {
        tail.extend([0x6d, 0x73]);
    }
    tail.extend([0x54, 0x70]);
    image[0x700..0x700 + tail.len()].copy_from_slice(&tail);
    image[0x800..0x808].copy_from_slice(&[0xf8, 0xcc, 0x5e, 0x50, 9, 0, 0x54, 0x70]);
    image
}
#[test]
fn derives_error_target_for_both_save_and_bounds_branch_forms() {
    for long in [false, true] {
        for far in [false, true] {
            assert_eq!(
                controller_error(&controller(long, far), BASE, HELPER).unwrap(),
                INVALID
            );
        }
    }
}
#[test]
fn rejects_wrong_stack_slot_error_thunk_and_unbalanced_return() {
    for long in [false, true] {
        let original = controller(long, true);
        for pattern in [
            vec![1, 0, 0x6f, 0x76, 0, if long { 20 } else { 18 }],
            vec![0xf8, 0xcc],
            vec![1, 0x20, 0x6d, 0x76],
        ] {
            let mut bad = original.clone();
            let at = bad
                .windows(pattern.len())
                .position(|b| b == pattern)
                .unwrap();
            bad[at + pattern.len() - 1] ^= 1;
            assert!(controller_error(&bad, BASE, HELPER).is_err());
        }
    }
}
