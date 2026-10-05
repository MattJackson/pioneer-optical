//! Shared parsing of the `COMP` stream directory found in decoded bodies.

use alloc::vec::Vec;

/// Offset of the `COMP` marker in a decoded body.
pub(crate) const COMP_OFFSET: usize = 0x1000;
/// Largest expanded size accepted for one stream, in bytes.
pub(crate) const MAX_EXPANDED: usize = 64 * 1024 * 1024;
/// Largest total expanded size accepted across the streams of one image.
#[cfg(feature = "envelope")]
pub(crate) const MAX_TOTAL_EXPANDED: usize = 256 * 1024 * 1024;
/// Policy cap on directory address entries (two per stream). The directory
/// region itself can hold more.
const MAX_ENTRIES: usize = 32;

/// Big-endian `u32` at `off`; `None` if the slice is too short.
pub(crate) fn be_u32(bytes: &[u8], off: usize) -> Option<u32> {
    let s = bytes.get(off..off.checked_add(4)?)?;
    Some(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

/// The `(start, end)` address pairs of the `COMP` directory, or `None` when the
/// marker is absent or the directory is empty, odd-sized or oversized.
pub(crate) fn comp_pairs(body: &[u8]) -> Option<Vec<(u32, u32)>> {
    if body.get(COMP_OFFSET..COMP_OFFSET + 4)? != b"COMP" {
        return None;
    }
    let mut addrs = Vec::new();
    for off in (COMP_OFFSET + 4..COMP_OFFSET + 0x100).step_by(4) {
        let v = be_u32(body, off)?;
        if v == u32::MAX {
            break;
        }
        addrs.push(v);
    }
    if addrs.is_empty() || addrs.len() % 2 != 0 || addrs.len() > MAX_ENTRIES {
        return None;
    }
    Some(addrs.chunks_exact(2).map(|p| (p[0], p[1])).collect())
}
