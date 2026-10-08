//! Shared checked COMP decoding for the codec and analysis consumers.
use super::{sha, uniform_ranges, CompStream, CompStreamInfo};
use std::io::{Read, Write};

const BASE_ALIGNMENT: u32 = 0x1000;
const SIZE_PREFIX: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StreamError {
    Directory,
    Invalid,
    Ambiguous,
    Limit,
    Cancelled,
}

pub(crate) fn read(
    image: &[u8],
    total_limit: usize,
    proceed: &mut dyn FnMut() -> bool,
) -> Result<Option<(u32, Vec<CompStream>)>, StreamError> {
    let off = crate::comp::COMP_OFFSET;
    if image.get(off..off + 4) != Some(b"COMP") {
        return Ok(None);
    }
    let pairs = crate::comp::comp_pairs(image).ok_or(StreamError::Directory)?;
    let first = pairs[0].0;
    let len = u32::try_from(image.len()).map_err(|_| StreamError::Limit)?;
    let min_base = first.saturating_sub(len);
    let mut valid = None;
    let mut limit_seen = false;
    for base in ((min_base & !(BASE_ALIGNMENT - 1))..=(first & !(BASE_ALIGNMENT - 1)))
        .step_by(BASE_ALIGNMENT as usize)
    {
        if !proceed() {
            return Err(StreamError::Cancelled);
        }
        let mut streams = Vec::new();
        let mut total_expanded = 0usize;
        for &(start, end) in &pairs {
            if !proceed() {
                return Err(StreamError::Cancelled);
            }
            if start < base || end <= start {
                break;
            }
            let offset = (start - base) as usize;
            let end_offset = (end - base) as usize;
            let Some(prefix) = image.get(offset..offset + SIZE_PREFIX) else {
                break;
            };
            let Some(compressed) = image.get(offset + SIZE_PREFIX..end_offset + SIZE_PREFIX) else {
                break;
            };
            if compressed.first() != Some(&0x78) {
                break;
            }
            let expanded_size =
                u32::from_be_bytes(prefix.try_into().expect("four-byte prefix")) as usize;
            if expanded_size == 0 {
                break;
            }
            total_expanded = total_expanded
                .checked_add(expanded_size)
                .ok_or(StreamError::Limit)?;
            if expanded_size > crate::comp::MAX_EXPANDED
                || total_expanded > total_limit.min(crate::comp::MAX_TOTAL_EXPANDED)
            {
                limit_seen = true;
                break;
            }
            let mut decoder = flate2::read::ZlibDecoder::new(compressed);
            let mut expanded = Vec::new();
            if decoder
                .by_ref()
                .take((expanded_size + 1) as u64)
                .read_to_end(&mut expanded)
                .is_err()
                || expanded.len() != expanded_size
                || decoder.total_in() as usize != compressed.len()
            {
                break;
            }
            let mut encoder =
                flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::new(6));
            let recompresses_exactly = encoder.write_all(&expanded).is_ok()
                && encoder.finish().is_ok_and(|rebuilt| rebuilt == compressed);
            streams.push(CompStream {
                info: CompStreamInfo {
                    address_start: start,
                    address_end: end,
                    image_offset: offset,
                    compressed_size: compressed.len(),
                    expanded_size,
                    expanded_sha256: sha(&expanded),
                    expanded_uniform_ranges: uniform_ranges(&expanded, 256),
                    recompresses_exactly,
                },
                expanded,
            });
        }
        if streams.len() == pairs.len() {
            if valid.is_some() {
                return Err(StreamError::Ambiguous);
            }
            valid = Some((base, streams));
        }
    }
    valid.map(Some).ok_or(if limit_seen {
        StreamError::Limit
    } else {
        StreamError::Invalid
    })
}
