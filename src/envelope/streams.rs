//! Rich codec reports built from shared bounded COMP decoding.
use super::{sha, uniform_ranges, CompStream, CompStreamInfo};
pub(crate) use crate::comp_streams::StreamError;
use std::io::Write;

pub(crate) fn read(
    image: &[u8],
    total_limit: usize,
    proceed: &mut dyn FnMut() -> bool,
) -> Result<Option<(u32, Vec<CompStream>)>, StreamError> {
    let Some((base, streams)) = crate::comp_streams::read(image, total_limit, proceed)? else {
        return Ok(None);
    };
    let streams = streams
        .into_iter()
        .map(|stream| {
            if !proceed() {
                return Err(StreamError::Cancelled);
            }
            let compressed =
                &image[stream.image_offset + 4..stream.image_offset + 4 + stream.compressed_size];
            let mut encoder =
                flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::new(6));
            let recompresses_exactly = encoder.write_all(&stream.expanded).is_ok()
                && encoder.finish().is_ok_and(|rebuilt| rebuilt == compressed);
            let report = CompStream {
                info: CompStreamInfo {
                    address_start: stream.address_start,
                    address_end: stream.address_end,
                    image_offset: stream.image_offset,
                    compressed_size: stream.compressed_size,
                    expanded_size: stream.expanded.len(),
                    expanded_sha256: sha(&stream.expanded),
                    expanded_uniform_ranges: uniform_ranges(&stream.expanded, 256),
                    recompresses_exactly,
                },
                expanded: stream.expanded,
            };
            if !proceed() {
                return Err(StreamError::Cancelled);
            }
            Ok(report)
        })
        .collect::<Result<Vec<_>, StreamError>>()?;
    Ok(Some((base, streams)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancellation_is_checked_again_before_rich_stream_reporting() {
        let mut encoder =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&[0x5a; 32]).unwrap();
        let compressed = encoder.finish().unwrap();
        let mut image = vec![0xff; 0x2200];
        image[0x1000..0x1004].copy_from_slice(b"COMP");
        image[0x1004..0x1008].copy_from_slice(&0x412000u32.to_be_bytes());
        image[0x1008..0x100c].copy_from_slice(&(0x412000 + compressed.len() as u32).to_be_bytes());
        image[0x2000..0x2004].copy_from_slice(&32u32.to_be_bytes());
        image[0x2004..0x2004 + compressed.len()].copy_from_slice(&compressed);
        let mut decoding_checks = 0;
        assert!(crate::comp_streams::read(&image, 1024, &mut || {
            decoding_checks += 1;
            true
        })
        .unwrap()
        .is_some());
        let mut calls = 0;
        let result = read(&image, 1024, &mut || {
            calls += 1;
            calls <= decoding_checks
        });
        assert!(matches!(result, Err(StreamError::Cancelled)));
        assert_eq!(calls, decoding_checks + 1);
    }
}
