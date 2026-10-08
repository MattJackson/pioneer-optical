//! Locate the installed Normal using evidence in its captured H8 Kernel.

use super::{be32_sum_zero, builder};
use crate::image::{KERNEL_BASE, KERNEL_LEN};
use core::fmt;

const DESCRIPTOR_LEN: usize = 16;
const LENGTH_OFFSET: usize = 20;
const HEADER_LEN: usize = LENGTH_OFFSET + 4;
const ADDRESS_END: u32 = 0x100_0000;
const MIN_IMAGE_LEN: u32 = 0x2000;
const MAX_IMAGE_LEN: u32 = 0x80_0000;
const IMAGE_ALIGNMENT: u32 = 0x100;
const DESCRIPTOR_PREFIX: &[u8] = b"PIONEER ";

/// Failure to establish or validate a captured Kernel's companion Normal.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum NormalLayoutError {
    /// The envelope is not a Kernel component.
    NotKernel,
    /// The captured Kernel is incomplete or has an invalid checksum.
    InvalidKernel,
    /// No supported instruction sequence establishes the layout.
    Unsupported,
    /// More than one checksum or descriptor sequence was found.
    Ambiguous,
    /// Independent evidence disagrees, or the physical layout is unsupported.
    ConflictingGeometry,
    /// The header response is shorter than required.
    ShortHeader {
        /// Minimum required prefix length.
        expected: usize,
        /// Received prefix length.
        actual: usize,
    },
    /// Normal's descriptor differs from the Kernel's expected descriptor.
    DescriptorMismatch,
    /// The declared image length is invalid or exceeds supported bounds.
    InvalidLength {
        /// Rejected image length in bytes.
        length: u32,
    },
    /// The complete image has a different length than its resolved extent.
    ImageLength {
        /// Resolved image length.
        expected: usize,
        /// Captured image length.
        actual: usize,
    },
    /// The complete Normal image fails its checksum.
    ImageChecksum,
}

impl fmt::Display for NormalLayoutError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotKernel => f.write_str("Normal layout requires a Kernel envelope"),
            Self::InvalidKernel => f.write_str("captured Kernel is incomplete or has an invalid checksum"),
            Self::Unsupported => f.write_str("captured Kernel does not establish a supported Normal layout"),
            Self::Ambiguous => f.write_str("captured Kernel contains ambiguous Normal layout evidence"),
            Self::ConflictingGeometry => f.write_str("captured Kernel contains conflicting or unsupported firmware geometry"),
            Self::ShortHeader { expected, actual } => write!(f, "short Normal header: expected {expected} bytes, received {actual}"),
            Self::DescriptorMismatch => f.write_str("Normal descriptor does not match the captured Kernel"),
            Self::InvalidLength { length } => write!(f, "invalid Normal image length {length:#x}"),
            Self::ImageLength { expected, actual } => write!(f, "Normal image length differs from its header: expected {expected} bytes, received {actual}"),
            Self::ImageChecksum => f.write_str("captured Normal image has an invalid checksum"),
        }
    }
}
impl std::error::Error for NormalLayoutError {}

/// A validated address and byte count for a firmware read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NormalRegion {
    address: u32,
    length: usize,
}
impl NormalRegion {
    /// Drive address (not an offset into an encoded envelope).
    pub fn address(&self) -> u32 {
        self.address
    }
    /// Number of bytes to read.
    pub fn length(&self) -> usize {
        self.length
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LengthRule {
    Header,
    Fixed(u32),
}

/// Rules recovered from a Kernel for locating and validating its Normal image.
///
/// Analysis performs no I/O and does not establish flash compatibility. Unknown
/// or ambiguous instruction layouts are rejected, without model-name lookups.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NormalLayout {
    base: u32,
    descriptor: [u8; DESCRIPTOR_LEN],
    length: LengthRule,
}

impl NormalLayout {
    /// Analyze a complete decoded H8 Kernel captured at `address`.
    ///
    /// The supported layout has a 64 KiB Kernel followed by Normal. Addresses
    /// are recovered from checksum and descriptor-check instructions and must
    /// agree with the capture. This does not support other Pioneer architectures.
    pub fn from_kernel(kernel: &[u8], address: u32) -> Result<Self, NormalLayoutError> {
        if kernel.len() != KERNEL_LEN || !be32_sum_zero(kernel) {
            return Err(NormalLayoutError::InvalidKernel);
        }
        if address != KERNEL_BASE {
            return Err(NormalLayoutError::ConflictingGeometry);
        }
        let mut checksum = None;
        let mut descriptor = None;
        for offset in (0..kernel.len()).step_by(2) {
            if let Some(value) = checksum_at(&kernel[offset..]) {
                if checksum.replace(value).is_some() {
                    return Err(NormalLayoutError::Ambiguous);
                }
            }
            if let Some(value) = descriptor_at(kernel, offset, address) {
                if descriptor.replace(value).is_some() {
                    return Err(NormalLayoutError::Ambiguous);
                }
            }
        }
        let (start, limit) = checksum.ok_or(NormalLayoutError::Unsupported)?;
        let (base, descriptor) = descriptor.ok_or(NormalLayoutError::Unsupported)?;
        if start != address || address.checked_add(kernel.len() as u32) != Some(base) {
            return Err(NormalLayoutError::ConflictingGeometry);
        }
        let length = match limit {
            Limit::Header {
                base: checksum_base,
                field,
            } => {
                if checksum_base != base || base.checked_add(LENGTH_OFFSET as u32) != Some(field) {
                    return Err(NormalLayoutError::ConflictingGeometry);
                }
                LengthRule::Header
            }
            Limit::Fixed(end) => {
                let length = end
                    .checked_sub(base)
                    .ok_or(NormalLayoutError::ConflictingGeometry)?;
                let geometry = builder::scaled_normal_geometry_from_kernel(kernel)
                    .ok_or(NormalLayoutError::ConflictingGeometry)?;
                if geometry.image_len != length as usize {
                    return Err(NormalLayoutError::ConflictingGeometry);
                }
                LengthRule::Fixed(length)
            }
        };
        let layout = Self {
            base,
            descriptor,
            length,
        };
        if let LengthRule::Fixed(length) = length {
            layout.region(length)?;
        }
        Ok(layout)
    }

    /// The bounded prefix to read before resolving the full image extent.
    pub fn header_region(&self) -> NormalRegion {
        NormalRegion {
            address: self.base,
            length: match self.length {
                LengthRule::Header => HEADER_LEN,
                LengthRule::Fixed(_) => DESCRIPTOR_LEN,
            },
        }
    }

    /// Validate the prefix and resolve the complete Normal image extent.
    pub fn resolve(&self, header: &[u8]) -> Result<NormalRegion, NormalLayoutError> {
        let expected = self.header_region().length;
        if header.len() < expected {
            return Err(NormalLayoutError::ShortHeader {
                expected,
                actual: header.len(),
            });
        }
        if header[..DESCRIPTOR_LEN] != self.descriptor {
            return Err(NormalLayoutError::DescriptorMismatch);
        }
        let length = match self.length {
            LengthRule::Header => {
                word(header, LENGTH_OFFSET).ok_or(NormalLayoutError::Unsupported)?
            }
            LengthRule::Fixed(length) => length,
        };
        self.region(length)
    }

    /// Check complete length, descriptor and checksum after reading Normal.
    pub fn validate(&self, image: &[u8]) -> Result<(), NormalLayoutError> {
        let region = self.resolve(image)?;
        if image.len() != region.length {
            return Err(NormalLayoutError::ImageLength {
                expected: region.length,
                actual: image.len(),
            });
        }
        if !be32_sum_zero(image) {
            return Err(NormalLayoutError::ImageChecksum);
        }
        Ok(())
    }

    fn region(&self, length: u32) -> Result<NormalRegion, NormalLayoutError> {
        if !(MIN_IMAGE_LEN..=MAX_IMAGE_LEN).contains(&length)
            || length % IMAGE_ALIGNMENT != 0
            || self
                .base
                .checked_add(length)
                .map_or(true, |end| end > ADDRESS_END)
        {
            return Err(NormalLayoutError::InvalidLength { length });
        }
        Ok(NormalRegion {
            address: self.base,
            length: length as usize,
        })
    }
}

enum Limit {
    Header { base: u32, field: u32 },
    Fixed(u32),
}

fn word(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_be_bytes(
        bytes.get(offset..offset.checked_add(4)?)?.try_into().ok()?,
    ))
}

fn checksum_at(bytes: &[u8]) -> Option<(u32, Limit)> {
    // SUB.L ER2,ER2; MOV.L #start,ER1. Both loops sum MOV.L @ER1+,ER0.
    if bytes.get(..4)? != [0x1a, 0xa2, 0x7a, 0x01] {
        return None;
    }
    let start = word(bytes, 4)?;
    if bytes.get(8..12)? == [0x01, 0x00, 0x6b, 0x23]
        && bytes.get(16..18)? == [0x7a, 0x13]
        // BRA to comparison; load/add; CMP.L ER3,ER1; BNE back to load.
        && bytes.get(22..34)? == [0x40, 0x06, 0x01, 0x00, 0x6d, 0x10, 0x0a, 0x82, 0x1f, 0xb1, 0x46, 0xf6]
    {
        return Some((
            start,
            Limit::Header {
                base: word(bytes, 18)?,
                field: word(bytes, 12)?,
            },
        ));
    }
    // Load/add; CMP.L #end,ER1; BNE back to load; test accumulated sum.
    if bytes.get(8..16)? == [0x01, 0x00, 0x6d, 0x10, 0x0a, 0x82, 0x7a, 0x21]
        && bytes.get(20..26)? == [0x46, 0xf2, 0x0f, 0xa2, 0x47, 0x02]
    {
        return Some((start, Limit::Fixed(word(bytes, 16)?)));
    }
    None
}

fn kernel_call(bytes: &[u8], offset: usize, address: u32, size: usize) -> bool {
    word(bytes, offset).is_some_and(|call| {
        call >> 24 == 0x5e
            && (call & 0xffffff)
                .checked_sub(address)
                .is_some_and(|target| target % 2 == 0 && (target as usize) < size)
    })
}

fn descriptor_at(
    kernel: &[u8],
    offset: usize,
    address: u32,
) -> Option<(u32, [u8; DESCRIPTOR_LEN])> {
    let b = kernel.get(offset..)?;
    // Four observed compiler forms of the same 16-byte descriptor comparison.
    // Prefixes initialize the index/count; suffixes verify the exact loop back edge.
    let (reference_offset, valid) = if b.get(..4)? == [0x78, 0x10, 0x6a, 0x2a] {
        (
            12,
            offset.checked_sub(6).and_then(|p| kernel.get(p..offset))
                == Some(&[0x18, 0xbb, 0x1a, 0x91, 0x0c, 0xb9][..])
                && b.get(8..12) == Some(&[0x78, 0x10, 0x6a, 0x28][..])
                && b.get(16..20) == Some(&[0x1c, 0x8a, 0x47, 0x04][..])
                && kernel_call(b, 20, address, kernel.len())
                && b.get(24..30) == Some(&[0x0a, 0x0b, 0xab, 0x10, 0x45, 0xde][..]),
        )
    } else if b.get(..4)? == [0x78, 0x20, 0x6a, 0x29] {
        (
            14,
            offset.checked_sub(6).and_then(|p| kernel.get(p..offset))
                == Some(&[0x18, 0xbb, 0x1a, 0xa2, 0x0c, 0xba][..])
                && b.get(8..14) == Some(&[0x17, 0xd1, 0x78, 0x20, 0x6a, 0x28][..])
                && b.get(18..24) == Some(&[0x17, 0x50, 0x1d, 0x01, 0x47, 0x04][..])
                && kernel_call(b, 24, address, kernel.len())
                && b.get(28..34) == Some(&[0x0a, 0x0b, 0xab, 0x10, 0x45, 0xda][..]),
        )
    } else if b.get(..4)? == [0x78, 0x30, 0x6a, 0x21] {
        (
            12,
            offset.checked_sub(4).and_then(|p| kernel.get(p..offset))
                == Some(&[0xfc, 0x10, 0x1a, 0xb3][..])
                && b.get(8..12) == Some(&[0x78, 0x30, 0x6a, 0x29][..])
                && b.get(16..20) == Some(&[0x1c, 0x91, 0x47, 0x04][..])
                && kernel_call(b, 20, address, kernel.len())
                && b.get(24..30) == Some(&[0x0b, 0x73, 0x1a, 0x0c, 0x46, 0xe2][..]),
        )
    } else if b.get(..4)? == [0x78, 0x20, 0x6a, 0x21] {
        (
            12,
            offset.checked_sub(4).and_then(|p| kernel.get(p..offset))
                == Some(&[0xfb, 0x10, 0x1a, 0xa2][..])
                && b.get(8..12) == Some(&[0x78, 0x20, 0x6a, 0x29][..])
                && b.get(16..26)
                    == Some(&[0x1c, 0x91, 0x46, 0x0c, 0x0b, 0x72, 0x1a, 0x0b, 0x46, 0xe6][..])
                && word(b, 26)? == (0x5e00_0000 | word(b, 4)?.checked_add(LENGTH_OFFSET as u32)?),
        )
    } else {
        return None;
    };
    if !valid {
        return None;
    }
    let reference = word(b, reference_offset)?.checked_sub(address)? as usize;
    let descriptor: [u8; DESCRIPTOR_LEN] = kernel
        .get(reference..reference.checked_add(DESCRIPTOR_LEN)?)?
        .try_into()
        .ok()?;
    if !descriptor.starts_with(DESCRIPTOR_PREFIX)
        || !descriptor
            .iter()
            .all(|b| b.is_ascii_graphic() || *b == b' ')
    {
        return None;
    }
    Some((word(b, 4)?, descriptor))
}

#[cfg(test)]
#[path = "normal_layout_tests.rs"]
mod tests;
