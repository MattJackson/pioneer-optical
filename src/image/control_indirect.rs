//! Descriptor-only entry through the Normal's buffer reader and warm-start helpers.
//!
//! Unlike the inline implementation, the entry flags live behind Kernel exports.
//! Require both captured components and follow the calls before accepting it.

use super::super::{kernel_startup_entry, KERNEL_BASE, KERNEL_LEN};

const BASE: u32 = KERNEL_BASE + KERNEL_LEN as u32;
const LOOP: &[u8] = &[
    0x18, 0xbb, 0x1a, 0x91, 0x0c, 0xb9, 0x7a, 0x11, 0x00, 0x41, 0x00, 0x00, 0x0f, 0x94, 0x0c, 0xb9,
    0x17, 0x51, 0x0f, 0xe0, 0x5e, 0, 0, 0, 0x68, 0x49, 0x1c, 0x98, 0x58, 0x60, 0, 0, 0x0a, 0x0b,
    0xab, 0x10, 0x45, 0xdc, 0x04, 0x80, 0xf8, 0x01, 0x5e, 0, 0, 0, 0xf8, 0x01, 0x5e, 0, 0, 0, 0x18,
    0x88, 0x5e, 0, 0, 0, 0x5a, 0, 0, 0,
];
const LOOP_VARIABLES: &[(usize, usize)] = &[(21, 3), (30, 2), (43, 3), (49, 3), (55, 3), (59, 3)];
const READ: &[u8] = &[
    0x6d, 0xf3, 0x0d, 0x13, 0xf8, 0x01, 0x5e, 0, 0, 0, 0x0f, 0x81, 0x0d, 0x30, 0x17, 0x70, 0x0a,
    0x90, 0x5e, 0, 0, 0, 0x6d, 0x73, 0x54, 0x70,
];
const TRANSITION: &[u8] = &[
    0x01, 0x10, 0x6d, 0xf4, 0x0c, 0x8c, 0x5e, 0, 0, 0, 0x0f, 0x85, 0xac, 0x01, 0x46, 0x12, 0xf8,
    0x01, 0x5e, 0, 0, 0, 0x18, 0x88, 0x5e, 0, 0, 0, 0x0f, 0xd0, 0x5e, 0, 0, 0, 0x0f, 0xd0, 0x5e, 0,
    0, 0, 0x0c, 0x88, 0x47, 0x06, 0xf8, 0x01, 0x5e, 0, 0, 0, 0x18, 0x88, 0x5e, 0, 0, 0, 0xf8, 0x01,
    0x6a, 0x88, 0xfe, 0x68, 0xf8, 0x23, 0x6a, 0x88, 0xfe, 0x69, 0xf9, 0x80, 0x03, 0x09, 0x55, 0,
    0x01, 0x10, 0x6d, 0x75, 0x54, 0x70,
];
const TRANSITION_CALLS: &[usize] = &[6, 18, 24, 30, 36, 46, 52];

fn pattern(code: &[u8], expected: &[u8], operands: &[(usize, usize)]) -> bool {
    code.len() == expected.len()
        && code.iter().zip(expected).enumerate().all(|(i, (a, b))| {
            a == b
                || operands
                    .iter()
                    .any(|&(start, n)| (start..start + n).contains(&i))
        })
}

fn address(code: &[u8], at: usize, opcode: u8) -> Option<u32> {
    let b = code.get(at..at.checked_add(4)?)?;
    (b[0] == opcode).then(|| u32::from_be_bytes([0, b[1], b[2], b[3]]))
}

fn offset(image: &[u8], base: u32, address: u32, length: usize) -> Option<usize> {
    let at = address.checked_sub(base)? as usize;
    (at % 2 == 0 && image.get(at..at.checked_add(length)?).is_some()).then_some(at)
}

fn code(image: &[u8], base: u32, address: u32, length: usize) -> Option<&[u8]> {
    let at = offset(image, base, address, length)?;
    image.get(at..at + length)
}

fn call<'a>(
    body: &'a [u8],
    instruction: &[u8],
    at: usize,
    length: usize,
) -> Option<(u32, &'a [u8])> {
    let target = address(instruction, at, 0x5e)?;
    Some((target, code(body, BASE, target, length)?))
}

// Normal thunk -> Kernel export thunk -> bit-store function. Both setters must
// write the captured Kernel's update-state byte, with the caller's low bit.
fn flag(body: &[u8], kernel: &[u8], target: u32, bit: u8) -> Option<()> {
    let thunk = code(body, BASE, target, 6)?;
    if thunk[4..] != [0x54, 0x70] {
        return None;
    }
    let export = code(kernel, KERNEL_BASE, address(thunk, 0, 0x5e)?, 6)?;
    if export[4..] != [0x54, 0x70] {
        return None;
    }
    let setter = code(kernel, KERNEL_BASE, address(export, 0, 0x5e)?, 18)?;
    let expected = [
        0x17,
        0xd0,
        0x0d,
        0x02,
        0x17,
        0xf2,
        0x77,
        0x0a,
        0x6a,
        0x38,
        0,
        0,
        1,
        0x44,
        0x67,
        bit << 4,
        0x54,
        0x70,
    ];
    (setter == expected).then_some(())
}

fn candidate(body: &[u8], kernel: &[u8], at: usize) -> Option<()> {
    let entry = body.get(at..at.checked_add(LOOP.len())?)?;
    if !pattern(entry, LOOP, LOOP_VARIABLES) {
        return None;
    }
    let done_address = address(entry, 58, 0x5a)?;
    if code(body, BASE, done_address, 6)? != [0x18, 0x88, 0x40, 2, 0xf8, 1] {
        return None;
    }
    let reject =
        (at + 32).checked_add_signed(i16::from_be_bytes([entry[30], entry[31]]) as isize)?;
    if reject < at + LOOP.len() || reject % 2 != 0 {
        return None;
    }
    let error = body.get(reject..reject.checked_add(6)?)?;
    call(body, error, 0, 2)?;
    if error[4] != 0x40
        || (reject + 6).checked_add_signed(error[5] as i8 as isize)?
            != offset(body, BASE, done_address.checked_add(4)?, 2)?
    {
        return None;
    }

    let (_, reader) = call(body, entry, 20, READ.len())?;
    if !pattern(reader, READ, &[(7, 3), (19, 3)]) {
        return None;
    }
    call(body, reader, 6, 2)?;
    // The reader adds the loop index to the received-buffer offset, then reads
    // one byte from the mapped buffer. Do not accept an arbitrary read helper.
    let (_, load) = call(body, reader, 18, 24)?;
    let load_shape = [
        1, 0, 0x6d, 0xf3, 0x0f, 0x83, 0x5e, 0, 0, 0, 0x78, 0x30, 0x6a, 0x28, 0, 0xa0, 0, 0, 1, 0,
        0x6d, 0x73, 0x54, 0x70,
    ];
    if !pattern(load, &load_shape, &[(7, 3)]) {
        return None;
    }
    call(body, load, 6, 2)?;

    let flag6 = address(entry, 42, 0x5e)?;
    let flag7 = address(entry, 48, 0x5e)?;
    flag(body, kernel, flag6, 6)?;
    flag(body, kernel, flag7, 7)?;
    let (transition_address, transition) = call(body, entry, 54, TRANSITION.len())?;
    let operands = [
        (7, 3),
        (19, 3),
        (25, 3),
        (31, 3),
        (37, 3),
        (47, 3),
        (53, 3),
        (73, 1),
    ];
    if !pattern(transition, TRANSITION, &operands)
        || address(transition, 18, 0x5e)? != flag6
        || address(transition, 24, 0x5e)? != flag7
    {
        return None;
    }
    for &at in TRANSITION_CALLS {
        call(body, transition, at, 2)?;
    }
    let reset_address = transition_address
        .checked_add(74)?
        .checked_add_signed(transition[73] as i8 as i32)?;
    let reset = code(body, BASE, reset_address, 12)?;
    if !pattern(
        reset,
        &[0xf8, 0x80, 3, 8, 0x5e, 0, 0, 0, 0x5a, 0, 0, 0],
        &[(5, 3), (9, 3)],
    ) {
        return None;
    }
    call(body, reset, 4, 2)?;
    let thunk = code(body, BASE, address(reset, 8, 0x5a)?, 6)?;
    if thunk[4..] != [0x54, 0x70] {
        return None;
    }
    let export = code(kernel, KERNEL_BASE, address(thunk, 0, 0x5e)?, 4)?;
    (address(export, 0, 0x5a)? == kernel_startup_entry(kernel)?).then_some(())
}

pub(super) fn matches<'a>(body: &'a [u8], kernel: &'a [u8]) -> impl Iterator<Item = ()> + 'a {
    body.windows(LOOP.len())
        .enumerate()
        .step_by(2)
        .filter_map(move |(at, bytes)| {
            (bytes[..6] == LOOP[..6])
                .then(|| candidate(body, kernel, at))
                .flatten()
        })
}

#[cfg(test)]
#[path = "control_indirect_tests.rs"]
mod tests;
