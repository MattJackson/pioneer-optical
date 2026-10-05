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

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn body(entries: &[u32], terminate: bool) -> Vec<u8> {
        let mut b = vec![0u8; COMP_OFFSET + 0x104];
        b[COMP_OFFSET..COMP_OFFSET + 4].copy_from_slice(b"COMP");
        let mut off = COMP_OFFSET + 4;
        for e in entries {
            b[off..off + 4].copy_from_slice(&e.to_be_bytes());
            off += 4;
        }
        if terminate {
            b[off..off + 4].copy_from_slice(&u32::MAX.to_be_bytes());
        }
        b
    }

    #[test]
    fn be_u32_bounds() {
        assert_eq!(be_u32(&[1, 2, 3, 4], 0), Some(0x0102_0304));
        assert_eq!(be_u32(&[0, 1, 2, 3, 4], 1), Some(0x0102_0304));
        assert_eq!(be_u32(&[1, 2, 3], 0), None);
        assert_eq!(be_u32(&[1, 2, 3, 4], usize::MAX), None);
    }

    #[test]
    fn pairs_from_directory() {
        assert_eq!(
            comp_pairs(&body(&[1, 2, 3, 4], true)),
            Some(vec![(1, 2), (3, 4)])
        );
    }

    #[test]
    fn directory_must_be_even_nonempty_and_within_cap() {
        assert_eq!(comp_pairs(&body(&[], true)), None);
        assert_eq!(comp_pairs(&body(&[1, 2, 3], true)), None);
        let ok: Vec<u32> = (0..MAX_ENTRIES as u32).collect();
        assert_eq!(comp_pairs(&body(&ok, true)).map(|p| p.len()), Some(16));
        let over: Vec<u32> = (0..MAX_ENTRIES as u32 + 2).collect();
        assert_eq!(comp_pairs(&body(&over, true)), None);
    }

    #[test]
    fn marker_and_bounds_are_checked() {
        let mut b = body(&[1, 2], true);
        b[COMP_OFFSET] = b'X';
        assert_eq!(comp_pairs(&b), None);
        assert_eq!(comp_pairs(&[]), None);
        // Marker present but the directory region is truncated, no terminator.
        let mut short = body(&[1, 2], false);
        short.truncate(COMP_OFFSET + 0x20);
        assert_eq!(comp_pairs(&short), None);
        // A marker that ends exactly at the end of the body.
        let mut tiny = vec![0u8; COMP_OFFSET + 4];
        tiny[COMP_OFFSET..].copy_from_slice(b"COMP");
        assert_eq!(comp_pairs(&tiny), None);
    }
}
