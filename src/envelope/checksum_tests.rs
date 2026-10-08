use super::{DecodeError, Envelope, Layout, BANNER};

fn fixture(kind: &str, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0xff; 0x10000];
    let header = format!(
        "{}\r\nID : PIONEER TEST\r\nFile Type : {kind}\r\nHardware Version : TEST0001\r\nDestination : CUSTOM\r\nKernel Version : TEST\r\nKernel Version2 : 0001\r\n",
        String::from_utf8_lossy(BANNER)
    );
    bytes[..header.len()].copy_from_slice(header.as_bytes());
    let checksum = payload.chunks_exact(4).fold(0u32, |sum, word| {
        sum.wrapping_sub(u32::from_le_bytes(word.try_into().unwrap()))
    });
    bytes[0x8000..0x8004].copy_from_slice(&checksum.to_le_bytes());
    bytes.extend_from_slice(payload);
    bytes
}

#[test]
fn valid_sparse_pair_reports_missing_transfer_support_not_a_false_checksum_error() {
    let kernel = fixture("Kernel", &[1, 2, 3, 4]);
    let normal = fixture("Normal", &[5, 6, 7, 8]);
    assert_eq!(
        super::Update::load(&kernel, &normal).unwrap_err(),
        super::UpdateError::Representation {
            component: crate::ComponentKind::Kernel,
            layout: Layout::SparseChecksum,
        }
    );
    let mut corrupt = kernel;
    corrupt[0x10000] ^= 1;
    assert!(matches!(
        super::Update::load(&corrupt, &normal),
        Err(super::UpdateError::Decode {
            component: crate::ComponentKind::Kernel,
            source: DecodeError::ChecksumMismatch { .. }
        })
    ));
}

#[test]
fn both_component_roles_unwrap_and_roundtrip_without_model_lookup() {
    for kind in ["Kernel", "Normal"] {
        let bytes = fixture(kind, &[1, 2, 3, 4, 5, 6, 7, 8]);
        let envelope = Envelope::load(&bytes).unwrap();
        assert_eq!(envelope.info().layout, Layout::SparseChecksum);
        assert_eq!(envelope.info().payload_offset, 0x10000);
        assert_eq!(envelope.image, bytes[0x10000..]);
        assert_eq!(envelope.repack(&envelope.image).unwrap(), bytes);
        assert!(envelope.kernel_transfer_image().is_none());
    }
}

#[test]
fn checksum_wrapper_does_not_require_an_unrelated_xor_policy() {
    let kernel = Envelope::load(&fixture("Kernel", &[1, 2, 3, 4])).unwrap();
    let bytes = fixture("Normal", &[5, 6, 7, 8]);
    let normal = Envelope::load_with_kernel(&bytes, &kernel).unwrap();
    assert_eq!(normal.image, [5, 6, 7, 8]);
    assert_eq!(normal.receiver_xor_exceptions(), None);
    assert!(normal.normal_transfer_image().is_none());
}

#[test]
fn repacking_changes_checksum_and_preserves_wrapper() {
    let bytes = fixture("Normal", &[1, 0, 0, 0, 2, 0, 0, 0]);
    let envelope = Envelope::load(&bytes).unwrap();
    let changed = [7, 0, 0, 0, 4, 0, 0, 0];
    let repacked = envelope.repack(&changed).unwrap();
    assert_eq!(&repacked[..0x8000], &bytes[..0x8000]);
    assert_eq!(&repacked[0x8004..0x10000], &bytes[0x8004..0x10000]);
    assert_eq!(&repacked[0x8000..0x8004], &0xffff_fff5u32.to_le_bytes());
    assert_eq!(Envelope::load(&repacked).unwrap().image, changed);
    assert!(envelope.repack(&changed[..4]).is_none());
}

#[test]
fn corrupt_checksum_is_not_reported_as_unsupported() {
    let mut bytes = fixture("Kernel", &[1, 0, 0, 0]);
    bytes[0x10000] = 2;
    assert_eq!(
        Envelope::load(&bytes).unwrap_err(),
        DecodeError::ChecksumMismatch {
            layout: Layout::SparseChecksum,
            checksum_offset: 0x8000,
            stored: 0xffff_ffff,
            calculated: 0xffff_fffe,
        }
    );
}

#[test]
fn partial_word_has_a_distinct_error() {
    let mut bytes = fixture("Normal", &[1, 0, 0, 0]);
    bytes.pop();
    assert_eq!(
        Envelope::load(&bytes).unwrap_err(),
        DecodeError::PayloadAlignment {
            layout: Layout::SparseChecksum,
            alignment: 4,
            actual: 3,
        }
    );
}

#[test]
fn padding_and_role_are_part_of_recognition() {
    for offset in [0x200, 0x7fff, 0x8004, 0xffff] {
        let mut bytes = fixture("Kernel", &[1, 0, 0, 0]);
        bytes[offset] = 0;
        assert_eq!(
            Envelope::load(&bytes).unwrap_err(),
            DecodeError::UnsupportedLayout
        );
    }
    assert!(Envelope::load(&fixture("Plane", &[1, 0, 0, 0])).is_err());
}

#[test]
fn truncation_at_wrapper_boundaries_never_panics_or_loads() {
    let bytes = fixture("Kernel", &[1, 0, 0, 0]);
    for end in [0, 1, 0x160, 0x200, 0x8000, 0x8003, 0x8004, 0xffff, 0x10000] {
        assert!(Envelope::load(&bytes[..end]).is_err(), "end={end:#x}");
    }
}
