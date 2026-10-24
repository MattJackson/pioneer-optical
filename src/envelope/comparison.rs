//! Exact decoded-byte comparison, separate from envelope naming and transport.
use super::Envelope;

/// Exact comparison; no identity, checksum, fill or compressed bytes are masked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ByteComparison {
    /// Every byte and the lengths match.
    Equal,
    /// First differing byte, or the end of the shorter matching prefix.
    Different {
        /// Offset relative to these slices.
        offset: usize,
        /// Expected decoded length.
        expected_len: usize,
        /// Observed decoded length.
        observed_len: usize,
    },
}

/// Compare complete images or equally bounded readback chunks.
/// Callers must account for unavailable/short reads separately; a matching
/// partial slice does not establish that the complete image was read.
pub fn compare_bytes(expected: &[u8], observed: &[u8]) -> ByteComparison {
    let offset = expected
        .iter()
        .zip(observed)
        .position(|(a, b)| a != b)
        .or_else(|| {
            (expected.len() != observed.len()).then_some(expected.len().min(observed.len()))
        });
    match offset {
        None => ByteComparison::Equal,
        Some(offset) => ByteComparison::Different {
            offset,
            expected_len: expected.len(),
            observed_len: observed.len(),
        },
    }
}

/// Independent differences: a renamed envelope can contain identical firmware.
/// This comparison establishes neither device compatibility nor OEM provenance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvelopeComparison {
    /// Exact decoded bytes, including checksums and padding.
    pub bytes: ByteComparison,
    /// Vendor or model fields differ.
    pub name_changed: bool,
    /// Advertised revision differs.
    pub revision_changed: bool,
    /// Kernel versus Normal role differs.
    pub component_changed: bool,
    /// Advertised hardware differs.
    pub hardware_changed: bool,
    /// Advertised destination/Kernel tag differs.
    pub destination_changed: bool,
}
impl Envelope {
    /// Compare decoded contents and envelope identity without conflating them.
    /// Signatures and transfer encoding are not installed firmware contents.
    pub fn compare(&self, other: &Self) -> EnvelopeComparison {
        let a = self.info();
        let b = other.info();
        EnvelopeComparison {
            bytes: compare_bytes(&self.image, &other.image),
            name_changed: a.vendor != b.vendor || a.model != b.model,
            revision_changed: a.revision != b.revision,
            component_changed: a.kind != b.kind,
            hardware_changed: a.hardware_version != b.hardware_version,
            destination_changed: a.kernel_version != b.kernel_version,
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn missing_tail_and_changed_byte_are_not_equal() {
        assert_eq!(compare_bytes(b"abc", b"abc"), ByteComparison::Equal);
        assert_eq!(
            compare_bytes(b"abc", b"ab"),
            ByteComparison::Different {
                offset: 2,
                expected_len: 3,
                observed_len: 2
            }
        );
        assert_eq!(
            compare_bytes(b"abc", b"axc"),
            ByteComparison::Different {
                offset: 1,
                expected_len: 3,
                observed_len: 3
            }
        );
    }
}
