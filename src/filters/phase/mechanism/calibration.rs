/// How the running firmware interprets this unit's existing calibration words.
/// This is a format contract, separate from original hardware identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Calibration {
    WholeWord,
    PackedBytes,
}

pub(super) fn calibration(normal: &[u8]) -> Option<Calibration> {
    const WHOLE: &[u8] = &[
        0x0c, 0x88, 0x47, 0x16, 0xa8, 1, 0x47, 0x12, 0xa8, 2, 0x47, 8, 0xa8, 3, 0x47, 4, 0xf8,
        0xff, 0x40, 0x0e, 0x79, 0, 1, 0x13, 0x40, 4, 0x79, 0, 1, 0x12, 0x5e,
    ];
    const PACKED: &[u8] = &[
        0x6d, 0xf3, 0x0c, 0x89, 0x79, 3, 0, 0xff, 0x0d, 0x30, 0x0c, 0x99, 0x47, 0x22, 0xa9, 1,
        0x47, 0x14, 0xa9, 2, 0x47, 0x0a, 0xa9, 3, 0x46, 0x24, 0x79, 0, 1, 0x13, 0x40, 0x0a, 0x79,
        0, 1, 0x13, 0x40, 0x0e, 0x79, 0, 1, 0x12, 0x5e,
    ];
    let regions = crate::image::regions(normal)?;
    let mut found = Vec::new();
    for region in regions.slices() {
        for b in region.windows(36).step_by(2) {
            if b.starts_with(WHOLE) && b[34..] == [0x54, 0x70] {
                found.push(Calibration::WholeWord);
            }
        }
        for b in region.windows(66).step_by(2) {
            if !b.starts_with(PACKED)
                || b[46..53] != [0x40, 0x0c, 0x79, 0, 1, 0x12, 0x5e]
                || b[58..] != [0x18, 0, 0x66, 0x30, 0x6d, 0x73, 0x54, 0x70]
            {
                continue;
            }
            match &b[56..58] {
                [0x0c, 0x08] => found.push(Calibration::PackedBytes),
                [0, 0] => found.push(Calibration::WholeWord),
                _ => {}
            }
        }
    }
    found.sort_unstable();
    found.dedup();
    match found.as_slice() {
        [format] => Some(*format),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn calibration_formats_follow_reader_code_and_refuse_conflicting_evidence() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("mechanism-fixture.json")).unwrap();
        let decode = |field: &str| {
            let h = fixture[field].as_str().unwrap();
            (0..h.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap())
                .collect::<Vec<_>>()
        };
        let packed = decode("calibration_native");
        let whole = decode("calibration_old");
        assert_eq!(calibration(&packed), Some(Calibration::PackedBytes));
        assert_eq!(calibration(&whole), Some(Calibration::WholeWord));
        let mut shim = packed.clone();
        shim[56..58].fill(0);
        assert_eq!(calibration(&shim), Some(Calibration::WholeWord));
        for (bytes, format) in [
            (&packed, Calibration::PackedBytes),
            (&whole, Calibration::WholeWord),
            (&shim, Calibration::WholeWord),
        ] {
            let mut relocated = vec![0; 128];
            relocated.extend(bytes);
            assert_eq!(calibration(&relocated), Some(format));
            for length in 0..bytes.len() {
                assert_eq!(calibration(&bytes[..length]), None);
            }
        }
        let mut mixed = packed.clone();
        mixed.extend(&whole);
        assert_eq!(calibration(&mixed), None);
        let mut duplicate = packed.clone();
        duplicate.extend(&packed);
        assert_eq!(calibration(&duplicate), Some(Calibration::PackedBytes));
        let mut corrupt = packed;
        corrupt[58] ^= 1;
        assert_eq!(calibration(&corrupt), None);
    }
}
