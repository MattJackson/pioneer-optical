//! Runtime destinations derived from a validated COMP loader instruction path.
//! No model names, stream-purpose assumptions or fixed destination addresses.
use alloc::{vec, vec::Vec};

#[derive(Debug)]
pub(crate) struct Destination {
    pub stream: usize,
    pub address: u32,
    #[cfg(feature = "analysis")]
    pub evidence: core::ops::Range<usize>,
}
const LOAD_DIRECTORY: &[u8] = &[0x01, 0x00, 0x6b, 0x20];
const CHECK_MAGIC: &[u8] = &[0x7a, 0x20, b'C', b'O', b'M', b'P'];
const SELECTOR_WINDOW: usize = 192;
const DESTINATION_WINDOW: usize = 160;

pub(crate) fn discover(
    image: &[u8],
    base: u32,
    sizes: &[(usize, usize)],
) -> Result<Vec<Destination>, usize> {
    let Some(directory) = base.checked_add(crate::comp::COMP_OFFSET as u32) else {
        return Ok(Vec::new());
    };
    let mut candidates = Vec::new();
    for start in (0..image.len().saturating_sub(14)).step_by(2) {
        if image.get(start..start + 4) != Some(LOAD_DIRECTORY)
            || image.get(start + 4..start + 8) != Some(directory.to_be_bytes().as_slice())
            || image.get(start + 8..start + 14) != Some(CHECK_MAGIC)
        {
            continue;
        }
        let end = (start + SELECTOR_WINDOW).min(image.len());
        // Establish that directory entries are indexed in eight-byte pairs,
        // the selected source is dereferenced, and its size word is skipped.
        let mut source = vec![
            0x0d, 0x39, 0x10, 0x19, 0x0d, 0x90, 0x0b, 0x50, 0x17, 0xf0, 0x10, 0x70, 0x7a, 0x05,
        ];
        source.extend_from_slice(&directory.to_be_bytes());
        source.extend_from_slice(&[0x0a, 0xd0, 0x01, 0x00, 0x69, 0x04, 0x0f, 0xc0, 0x0b, 0x90]);
        if !image[start..end].windows(source.len()).any(|w| w == source) {
            continue;
        }
        for selector in (start + 14..end.saturating_sub(16)).step_by(2) {
            let s = &image[selector..];
            if s[0] != 0xa8
                || s[2] != 0x47
                || s[4] != 0xa8
                || s[6] != 0x47
                || s[8] != 0xa8
                || s[10..12] != [0x58, 0x60]
                || s[14..16] != [0x7a, 0x04]
            {
                continue;
            }
            let indices = [s[1] as usize, s[5] as usize, s[9] as usize];
            if indices[0] == indices[1] || indices[1] == indices[2] || indices[0] == indices[2] {
                continue;
            }
            let positions = [
                (selector as i64 + 4 + i64::from(s[3] as i8)),
                (selector as i64 + 8 + i64::from(s[7] as i8)),
                (selector + 14) as i64,
            ];
            let mut found = Vec::new();
            for (index, position) in indices.into_iter().zip(positions) {
                let Ok(position) = usize::try_from(position) else {
                    break;
                };
                let Some(bytes) = image.get(position..position + 8) else {
                    break;
                };
                if bytes[..2] != [0x7a, 0x04] {
                    break;
                }
                let address = u32::from_be_bytes(bytes[2..6].try_into().unwrap());
                let join = if bytes[6] == 0x40 {
                    usize::try_from(position as i64 + 8 + i64::from(bytes[7] as i8)).ok()
                } else {
                    Some(position + 6)
                };
                let Some(join) = join else { break };
                if image.get(join..join + 4) != Some(&[0x01, 0x00, 0x6f, 0xf5]) {
                    break;
                }
                let stop = (join + DESTINATION_WINDOW).min(image.len());
                if !image[join..stop]
                    .windows(3)
                    .any(|w| w == [0x0f, 0xc0, 0x5e])
                {
                    break;
                }
                let Some((_, size)) = sizes.iter().find(|(stream, _)| *stream == index) else {
                    break;
                };
                if u32::try_from(*size)
                    .ok()
                    .and_then(|size| address.checked_add(size))
                    .is_none()
                    || address & 1 != 0
                {
                    break;
                }
                found.push((index, address, start..stop, join));
            }
            if found.len() == 3 && found.iter().all(|r| r.3 == found[0].3) {
                candidates.extend(found.into_iter().map(|(i, a, e, _)| (i, a, e)));
            }
        }
    }
    let mut destinations = Vec::new();
    for &(index, _) in sizes {
        let matches: Vec<_> = candidates.iter().filter(|(i, _, _)| *i == index).collect();
        if let Some(first) = matches.first() {
            if !matches.iter().all(|m| m.1 == first.1) {
                return Err(index);
            }
            destinations.push(Destination {
                stream: index,
                address: first.1,
                #[cfg(feature = "analysis")]
                evidence: first.2.clone(),
            });
        }
    }
    Ok(destinations)
}

#[cfg(test)]
pub(crate) fn fixture() -> alloc::vec::Vec<u8> {
    let mut image = vec![0xff; 512];
    image[0x40..0x4e].copy_from_slice(&[
        1, 0, 0x6b, 0x20, 0, 0x41, 0x10, 0, 0x7a, 0x20, b'C', b'O', b'M', b'P',
    ]);
    image[0x60..0x80].copy_from_slice(&[
        0x0d, 0x39, 0x10, 0x19, 0x0d, 0x90, 0x0b, 0x50, 0x17, 0xf0, 0x10, 0x70, 0x7a, 0x05, 0,
        0x41, 0x10, 0, 0x0a, 0xd0, 1, 0, 0x69, 4, 0x0f, 0xc0, 0x0b, 0x90, 0, 0, 0, 0,
    ]);
    // Destination selectors and addresses deliberately differ from held images.
    image[0xa0..0xc4].copy_from_slice(&[
        0xa8, 0, 0x47, 0x1a, 0xa8, 1, 0x47, 0x0e, 0xa8, 2, 0x58, 0x60, 0, 0x70, 0x7a, 4, 0, 0xd0,
        0x30, 0, 0x40, 0x0e, 0x7a, 4, 0, 0xd0, 0x20, 0, 0x40, 6, 0x7a, 4, 0, 0xd0, 0x10, 0,
    ]);
    image[0xc4..0xc8].copy_from_slice(&[1, 0, 0x6f, 0xf5]);
    image[0xd0..0xd6].copy_from_slice(&[0x0f, 0xc0, 0x5e, 0x41, 0x20, 0]);
    image
}
