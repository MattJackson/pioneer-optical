//! Complete native arithmetic service bodies used by phase code.
//! CPU addresses must be resolved against an authoritative resident-code image,
//! not interpreted as offsets into Normal. Matching proves these bodies and
//! their call linkage; division by zero and overflow are not admitted domains.
use core::ops::Range;

/// Offsets within the caller-supplied resident-code image.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Binding {
    /// Low-32-bit multiply body (ER0 times ER1, result ER0).
    pub multiply: Range<usize>,
    /// Signed division wrapper, taking ER0/ER1.
    pub signed_divide: Range<usize>,
    /// Complete unsigned division core called by the wrapper.
    pub unsigned_divide: Range<usize>,
}
const MULTIPLY: &[u8] = &[
    0x01, 0x10, 0x6d, 0xf2, 0x0d, 0x82, 0x52, 0x12, 0x0d, 0x93, 0x52, 0x03, 0x52, 0x10, 0x09, 0x28,
    0x09, 0x38, 0x01, 0x10, 0x6d, 0x73, 0x54, 0x70,
];
const SIGNED: &[u8] = &[
    0x6d, 0xf2, 0x0d, 0x82, 0x0c, 0x2a, 0x4a, 0x02, 0x17, 0xb0, 0x0d, 0x99, 0x4a, 0x04, 0xd2, 0x80,
    0x17, 0xb1, 0x5e, 0x10, 0x55, 0xae, 0x0c, 0x22, 0x4a, 0x02, 0x17, 0xb0, 0x0c, 0xaa, 0x4a, 0x02,
    0x17, 0xb1, 0x6d, 0x72, 0x54, 0x70,
];
const UNSIGNED: &[u8] = &[
    0x01, 0x00, 0x6d, 0xf2, 0x0d, 0x99, 0x46, 0x10, 0x0d, 0x82, 0x17, 0x72, 0x53, 0x12, 0x0d, 0xa8,
    0x53, 0x10, 0x0d, 0x81, 0x0d, 0x28, 0x40, 0x1e, 0x0f, 0x92, 0x0d, 0x81, 0x17, 0x71, 0x79, 0x08,
    0x00, 0x10, 0x12, 0x10, 0x12, 0x31, 0x1a, 0xa1, 0x44, 0x02, 0x0a, 0xa1, 0x1b, 0x58, 0x46, 0xf2,
    0x12, 0x10, 0x17, 0x10, 0x17, 0x70, 0x01, 0x00, 0x6d, 0x72, 0x54, 0x70,
];

fn span(image: &[u8], base: u32, address: u32, length: usize) -> Option<Range<usize>> {
    if base & 1 != 0 || address & 1 != 0 {
        return None;
    }
    let start = address.checked_sub(base)? as usize;
    let end = start.checked_add(length)?;
    if (address as usize).checked_add(length)? > 0x1000000 {
        return None;
    }
    image.get(start..end)?;
    Some(start..end)
}

/// Bind actual service targets, including the wrapper's unsigned-core call.
/// `base` is the CPU address of `image[0]`; establishing that mapping and its
/// applicability to the installed unit belongs to the caller. This is read-only.
pub fn observe(image: &[u8], base: u32, multiply: u32, divide: u32) -> Option<Binding> {
    let multiply = span(image, base, multiply, MULTIPLY.len())?;
    let signed_divide = span(image, base, divide, SIGNED.len())?;
    if &image[multiply.clone()] != MULTIPLY {
        return None;
    }
    let signed = &image[signed_divide.clone()];
    if !signed
        .iter()
        .zip(SIGNED)
        .enumerate()
        .all(|(i, (a, b))| (19..22).contains(&i) || a == b)
    {
        return None;
    }
    let target = u32::from_be_bytes([0, signed[19], signed[20], signed[21]]);
    let unsigned_divide = span(image, base, target, UNSIGNED.len())?;
    if &image[unsigned_divide.clone()] != UNSIGNED {
        return None;
    }
    Some(Binding {
        multiply,
        signed_divide,
        unsigned_divide,
    })
}
