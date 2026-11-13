//! The Pioneer whole-image checksum: big-endian 32-bit words summing to zero.

/// Wrapping sum of the image's big-endian 32-bit words (a trailing partial
/// word is ignored).
pub fn be32_sum(image: &[u8]) -> u32 {
    image.chunks_exact(4).fold(0u32, |sum, word| {
        sum.wrapping_add(u32::from_be_bytes([word[0], word[1], word[2], word[3]]))
    })
}

/// True for a non-empty, word-aligned image whose BE32 words sum to zero. An
/// empty body is not a valid zero-checksum body (a degenerate decode must not
/// pass this gate), and a trailing partial word fails.
pub fn be32_sum_zero(image: &[u8]) -> bool {
    !image.is_empty() && image.len() % 4 == 0 && be32_sum(image) == 0
}
