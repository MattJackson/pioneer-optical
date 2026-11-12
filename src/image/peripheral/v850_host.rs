//! V850 relative signature writes bound to a supplied native Kernel reset entry.
use super::{unique, HostSignature, Observation, Unresolved};
use alloc::vec::Vec;
fn u16le(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(at..at + 2)?.try_into().ok()?))
}
pub(super) fn ep(kernel: &[u8]) -> Observation<u32> {
    let mut values = Vec::new();
    for reset in [0usize, 4] {
        let Some(word) = u16le(kernel, reset) else {
            continue;
        };
        if word & 0xffc0 != 0x0780 {
            continue;
        }
        let Some(low) = u16le(kernel, reset + 2) else {
            continue;
        };
        let mut displacement = ((u32::from(word & 0x3f) << 16) | u32::from(low)) as i32;
        if displacement & (1 << 21) != 0 {
            displacement -= 1 << 22;
        }
        let Some(target) = reset.checked_add_signed(displacement as isize) else {
            continue;
        };
        if target & 1 != 0 {
            continue;
        }
        let prefixes: &[&[u8]] = &[
            &[0x25, 6, 0, 0, 0, 0, 0x24, 6, 0, 0x70, 0xff, 3],
            &[
                0xc0, 0x3f, 8, 0xf4, 0xc0, 0xbf, 8, 0xf4, 0x25, 6, 0, 0, 0, 0, 0x24, 6, 0, 0x80,
                0xff, 3,
            ],
        ];
        for prefix in prefixes {
            if kernel.get(target..target + prefix.len()) != Some(*prefix) {
                continue;
            }
            let at = target + prefix.len();
            if kernel.get(at..at + 2) != Some(&[0x40, 0xf6][..]) {
                continue;
            }
            if let Some(upper) = u16le(kernel, at + 2) {
                values.push(u32::from(upper) << 16);
            }
        }
    }
    unique(values)
}
fn signature(normal: &[u8]) -> bool {
    normal.windows(20).step_by(2).any(|b| {
        let load = u16::from_le_bytes([b[0], b[1]]);
        let byte_reg = (load >> 11) & 31;
        if load & 0x7ff != 0x201 || byte_reg == 0 {
            return false;
        }
        if u16::from_le_bytes([b[2], b[3]]) != (byte_reg << 11) | 0x75e
            || b[4..6] != [0xd5, 0]
            || u16::from_le_bytes([b[6], b[7]]) != (byte_reg << 11) | 0x75e
            || b[8..10] != [0xd4, 0]
        {
            return false;
        }
        let reg = b[10] & 31;
        (0x20..=0x3f).contains(&b[10])
            && reg != 0
            && b[11..16] == [6, 0x14, 0xeb, 0, 0]
            && b[16..20] == [0x7e, (reg << 3) | 7, 0xd2, 0]
    })
}
/// Recover V850 signature coordinates from native-order code and the associated
/// Kernel's recognized reset prefix. Missing Kernel never implies an EP base.
/// This is the reset-bound signature coordinate, not a complete host register map.
pub fn native(normal: &[u8], kernel: Option<&[u8]>) -> Observation<HostSignature> {
    if !signature(normal) {
        return Observation::Unresolved(Unresolved::ReaderNotRecognized);
    }
    let Some(kernel) = kernel else {
        return Observation::Unresolved(Unresolved::ResidentCodeRequired(0));
    };
    // ep() yields `upper << 16`, so these offsets cannot overflow.
    match ep(kernel) {
        Observation::Known(base) => Observation::Known(HostSignature {
            coordinate: base + 0xd2,
            signature_low: base + 0xd2,
            signature_high: base + 0xd3,
            initial_one: [base + 0xd4, base + 0xd5],
        }),
        Observation::Unresolved(reason) => Observation::Unresolved(reason),
        Observation::Conflicting => Observation::Conflicting,
    }
}
/// Read-only bus decoding followed by native V850 signature/Kernel binding.
pub fn bus(normal: &[u8], kernel: Option<&[u8]>) -> Observation<HostSignature> {
    let Some(normal) = crate::image::layout::decode_v850_bus(normal) else {
        return Observation::Unresolved(Unresolved::TruncatedEvidence);
    };
    let kernel = match kernel {
        Some(k) => match crate::image::layout::decode_v850_bus(k) {
            Some(k) => Some(k),
            None => return Observation::Unresolved(Unresolved::TruncatedEvidence),
        },
        None => None,
    };
    native(&normal, kernel.as_deref())
}
#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    fn fixture() -> (Vec<u8>, Vec<u8>) {
        let normal = vec![
            1, 0x6a, 0x5e, 0x6f, 0xd5, 0, 0x5e, 0x6f, 0xd4, 0, 0x2e, 6, 0x14, 0xeb, 0, 0, 0x7e,
            0x77, 0xd2, 0,
        ];
        let mut kernel = vec![0xff; 0x200];
        kernel[..4].copy_from_slice(&[0x80, 7, 0, 1]);
        kernel[0x100..0x110].copy_from_slice(&[
            0x25, 6, 0, 0, 0, 0, 0x24, 6, 0, 0x70, 0xff, 3, 0x40, 0xf6, 0x20, 0,
        ]);
        (normal, kernel)
    }
    #[test]
    fn relative_signature_is_not_an_absolute_address_without_kernel_binding() {
        let (normal, kernel) = fixture();
        assert!(matches!(
            native(&normal, None),
            Observation::Unresolved(Unresolved::ResidentCodeRequired(0))
        ));
        assert!(matches!(
            native(&normal, Some(&kernel)),
            Observation::Known(HostSignature {
                coordinate: 0x2000d2,
                ..
            })
        ));
        let mut wrong = kernel.clone();
        wrong[0x102] ^= 1;
        assert!(matches!(
            native(&normal, Some(&wrong)),
            Observation::Unresolved(_)
        ));
        let mut wrong = kernel;
        wrong[2] = 4;
        assert!(matches!(
            native(&normal, Some(&wrong)),
            Observation::Unresolved(_)
        ));
    }
    #[test]
    fn second_reset_prefix_and_reset_offset_four_bind_the_ep_base() {
        let (normal, _) = fixture();
        // Second audited prefix form, reached from the reset vector at zero.
        let mut kernel = vec![0xff; 0x200];
        kernel[..4].copy_from_slice(&[0x80, 7, 0, 1]);
        kernel[0x100..0x118].copy_from_slice(&[
            0xc0, 0x3f, 8, 0xf4, 0xc0, 0xbf, 8, 0xf4, 0x25, 6, 0, 0, 0, 0, 0x24, 6, 0, 0x80, 0xff,
            3, 0x40, 0xf6, 0x30, 0,
        ]);
        assert!(matches!(
            native(&normal, Some(&kernel)),
            Observation::Known(HostSignature {
                coordinate: 0x3000d2,
                ..
            })
        ));
        // No JR at offset zero; the JR at offset four reaches the first form.
        let (_, mut kernel) = fixture();
        kernel[..4].fill(0xff);
        kernel[4..8].copy_from_slice(&[0x80, 7, 0xfc, 0]);
        assert!(matches!(
            native(&normal, Some(&kernel)),
            Observation::Known(HostSignature {
                coordinate: 0x2000d2,
                ..
            })
        ));
    }
    #[test]
    fn reset_byte_writes_and_signature_register_must_use_defined_values() {
        let (normal, kernel) = fixture();
        for p in [0usize, 2, 4, 6, 8, 10, 12, 16, 18] {
            let mut bad = normal.clone();
            bad[p] ^= 1;
            assert!(
                matches!(native(&bad, Some(&kernel)), Observation::Unresolved(_)),
                "{p}"
            );
        }
    }
}
