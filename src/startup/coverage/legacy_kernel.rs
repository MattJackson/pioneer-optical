//! Immutable SAT1 paired authority. The held native boundary includes the
//! resident copy/clear implementations, formatter and rejection transfer.
use super::legacy_sinks::Profile;
use sha2::{Digest, Sha256};

/// Exact resident component and the Normal operands consumed by its native gates.
/// This is a local boundary receipt, not a cold-start or host READY theorem.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KernelBoundary {
    identity: [u8; 32],
    normal_length: usize,
    descriptor: usize,
    normal_root_call: core::ops::Range<usize>,
    descriptor_compare: core::ops::Range<usize>,
    destination_compare: core::ops::Range<usize>,
    length_gate: core::ops::Range<usize>,
    image_sum: core::ops::Range<usize>,
    copied_ram: core::ops::Range<u32>,
    rejection_entry: core::ops::Range<usize>,
}

impl KernelBoundary {
    pub(super) fn bind(normal: &[u8], kernel: &[u8], profile: &Profile) -> Option<Self> {
        let identity: [u8; 32] = Sha256::digest(kernel).into();
        if kernel.len() != 0x10000 || identity != profile.kernel_hash {
            return None;
        }
        let result = Self {
            identity,
            normal_length: profile.length,
            descriptor: profile.descriptor,
            normal_root_call: 0x1a4..0x1a8,
            descriptor_compare: 0x11a..0x142,
            destination_compare: 0x142..0x174,
            length_gate: 0x174..0x1a4,
            image_sum: if profile.name == "w26" {
                0x555a..0x5588
            } else {
                0x555e..0x558c
            },
            copied_ram: 0x670..0xa72,
            rejection_entry: 0x1d8..0x220,
        };
        result.accepts(normal, kernel).then_some(result)
    }

    /// Check the actual final descriptor/destination and bounded checksum extent.
    /// Normal's checksum may still await the existing integrity repair owner.
    pub fn accepts(&self, normal: &[u8], kernel: &[u8]) -> bool {
        let identity: [u8; 32] = Sha256::digest(kernel).into();
        if kernel.len() != 0x10000
            || identity != self.identity
            || normal.len() != self.normal_length
            || normal.len() & 3 != 0
            || normal.len() > 0x3c0000
        {
            return false;
        }
        let Some(length) = normal.get(0x14..0x18) else {
            return false;
        };
        if u32::from_be_bytes(length.try_into().unwrap()) as usize != normal.len() {
            return false;
        }
        // Native Normal bytes are sign extended, resident bytes zero extended.
        // High-bit bytes must not acquire equality from a byte-only comparison.
        let equal = |a: &[u8], b: &[u8]| {
            a.len() == b.len()
                && a.iter()
                    .zip(b)
                    .all(|(&x, &y)| i32::from(x as i8) == i32::from(y))
        };
        equal(
            &normal[..16],
            &kernel[self.descriptor..self.descriptor + 16],
        ) && equal(&normal[0x18..0x20], &kernel[0x1008..0x1010])
            && kernel[0x1a4..0x1a8] == [0x5e, 0x41, 0, 0x28]
    }

    /// Required after established checksum repair and authenticated paired decode.
    /// Authentication itself belongs to the actual envelope receiver authority.
    pub fn final_integrity(&self, normal: &[u8], kernel: &[u8]) -> bool {
        self.accepts(normal, kernel) && zero_sum(kernel) && zero_sum(normal)
    }
}

fn zero_sum(bytes: &[u8]) -> bool {
    bytes.len() & 3 == 0
        && bytes.chunks_exact(4).fold(0u32, |sum, word| {
            sum.wrapping_add(u32::from_be_bytes(word.try_into().unwrap()))
        }) == 0
}
