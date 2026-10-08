//! Direct boot ROM storage, identified by its reset vector and matching ROM tags.

use super::{EnvelopeCodec, HeaderInfo, Layout, SelectedLayout};
use crate::ComponentKind;

const HEADER_END: usize = 0x200;
const ROM_END: usize = 0x10000;
const CONTAINER_SIZE: usize = 0x100000;
const VECTOR32: usize = ROM_END - 4;
const VECTOR16: usize = ROM_END - 2;
const ROM_BANK: u32 = 0xff0000;
const BLOCK_ALIGNMENT: usize = 0x100;
const TAG_WIDTH: usize = 8;
const VECTOR16_COUNT: usize = 4;
const ERASED: u8 = 0xff;

pub(super) struct KernelRom;

impl EnvelopeCodec for KernelRom {
    fn layout(&self) -> Layout {
        Layout::KernelRom
    }

    fn detect(&self, data: &[u8], header: &HeaderInfo) -> Option<SelectedLayout> {
        if header.kind != Some(ComponentKind::Kernel)
            || data.len() != CONTAINER_SIZE
            || !data[ROM_END..].iter().all(|&byte| byte == ERASED)
        {
            return None;
        }
        let start = HEADER_END
            + data[HEADER_END..ROM_END]
                .iter()
                .position(|&b| b != ERASED)?;
        if start % BLOCK_ALIGNMENT != 0 || start >= VECTOR32 {
            return None;
        }
        let vector = u32::from_le_bytes(data[VECTOR32..ROM_END].try_into().ok()?);
        let entry = if (ROM_BANK..ROM_BANK + ROM_END as u32).contains(&vector) {
            (vector - ROM_BANK) as usize
        } else {
            if !data[ROM_END - VECTOR16_COUNT * 2..ROM_END]
                .chunks_exact(2)
                .all(|word| {
                    let address = u16::from_le_bytes([word[0], word[1]]) as usize;
                    (start..VECTOR32).contains(&address)
                })
            {
                return None;
            }
            u16::from_le_bytes(data[VECTOR16..ROM_END].try_into().ok()?) as usize
        };
        if !(start..VECTOR32).contains(&entry)
            || data.get(entry..entry + 2)?.iter().all(|&b| b == ERASED)
            || !matching_tags(&data[start..VECTOR32], header)
        {
            return None;
        }
        Some((
            self.layout(),
            start,
            ROM_END,
            Vec::new(),
            data[ROM_END..].to_vec(),
        ))
    }

    fn transform(&self, bytes: &[u8], _: &[u8], _: bool, _: &[u32]) -> Option<Vec<u8>> {
        Some(bytes.to_vec())
    }
}

fn matching_tags(rom: &[u8], header: &HeaderInfo) -> bool {
    if header.hardware_version.len() != TAG_WIDTH
        || header.kernel_version.is_empty()
        || header.kernel_version.len() > TAG_WIDTH
    {
        return false;
    }
    let mut tag = [b' '; TAG_WIDTH * 2];
    tag[..TAG_WIDTH].copy_from_slice(header.hardware_version.as_bytes());
    tag[TAG_WIDTH..TAG_WIDTH + header.kernel_version.len()]
        .copy_from_slice(header.kernel_version.as_bytes());
    rom.windows(tag.len()).any(|window| window == tag)
}
