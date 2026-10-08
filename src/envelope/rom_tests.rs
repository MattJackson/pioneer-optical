use super::{DecodeError, Envelope, Layout, BANNER};

fn fixture(start: usize, banked: bool) -> Vec<u8> {
    let mut bytes = vec![0xff; 0x100000];
    let header = format!(
        "{}\r\nID : UNKNOWN OEM\r\nFile Type : Kernel\r\nHardware Version : XYZ 6789\r\nKernel Version : CUSTOM\r\n",
        String::from_utf8_lossy(BANNER)
    );
    bytes[..header.len()].copy_from_slice(header.as_bytes());
    bytes[start..start + 16].copy_from_slice(b"XYZ 6789CUSTOM  ");
    bytes[start + 16..start + 32].fill(0x42);
    if banked {
        bytes[0xfffc..0x10000].copy_from_slice(&(0xff0000 + start as u32 + 16).to_le_bytes());
    } else {
        for word in bytes[0xfff8..0x10000].chunks_exact_mut(2) {
            word.copy_from_slice(&((start + 16) as u16).to_le_bytes());
        }
    }
    bytes
}

#[test]
fn reset_vectors_locate_direct_rom_without_model_or_fixed_start() {
    for start in [0x4000, 0x8000, 0xc000] {
        for banked in [false, true] {
            let bytes = fixture(start, banked);
            let envelope = Envelope::load(&bytes).unwrap();
            assert_eq!(envelope.info().layout, Layout::KernelRom);
            assert_eq!(envelope.info().payload_offset, start);
            assert_eq!(envelope.image, bytes[start..0x10000]);
            assert_eq!(envelope.repack(&envelope.image).unwrap(), bytes);
            assert!(envelope.kernel_transfer_image().is_none());
            assert!(envelope.normal_transfer_image().is_none());
        }
    }
}

#[test]
fn repack_preserves_header_erased_padding_and_vector() {
    let bytes = fixture(0xc000, true);
    let envelope = Envelope::load(&bytes).unwrap();
    let mut image = envelope.image.clone();
    image[32] = 0x53;
    let rebuilt = envelope.repack(&image).unwrap();
    let differences: Vec<_> = rebuilt
        .iter()
        .zip(&bytes)
        .enumerate()
        .filter_map(|(i, (a, b))| (a != b).then_some(i))
        .collect();
    assert_eq!(differences, [0xc020]);
    assert_eq!(Envelope::load(&rebuilt).unwrap().image, image);
}

#[test]
fn tags_padding_size_and_vector_bounds_are_required() {
    for banked in [false, true] {
        let bytes = fixture(0xc000, banked);
        for offset in [0x201, 0xbfff, 0xc000, 0xc008, 0x10000, 0xfffff] {
            let mut corrupt = bytes.clone();
            corrupt[offset] ^= 1;
            assert_eq!(
                Envelope::load(&corrupt).unwrap_err(),
                DecodeError::UnsupportedLayout
            );
        }
        for entry in [0xbfff, 0xfffc, 0xffff] {
            let mut corrupt = bytes.clone();
            if banked {
                corrupt[0xfffc..0x10000].copy_from_slice(&(0xff0000u32 + entry).to_le_bytes());
            } else {
                corrupt[0xfffe..0x10000].copy_from_slice(&(entry as u16).to_le_bytes());
            }
            assert_eq!(
                Envelope::load(&corrupt).unwrap_err(),
                DecodeError::UnsupportedLayout
            );
        }
        assert!(Envelope::load(&bytes[..bytes.len() - 1]).is_err());
    }
}

#[test]
fn erased_entry_and_non_kernel_role_are_not_recognized() {
    let mut bytes = fixture(0xc000, true);
    bytes[0xc010..0xc012].fill(0xff);
    assert!(Envelope::load(&bytes).is_err());
    let mut bytes = fixture(0xc000, false);
    let offset = bytes.windows(6).position(|w| w == b"Kernel").unwrap();
    bytes[offset..offset + 6].copy_from_slice(b"Normal");
    assert!(Envelope::load(&bytes).is_err());
}
