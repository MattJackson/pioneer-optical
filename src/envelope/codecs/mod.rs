//! Internal format implementations. Selection uses file structure, never drive names.

use super::{DecodeError, HeaderInfo, Layout, SelectedLayout};
mod boot_key;
mod boot_key_m7900;
mod checksum {
    //! Sparse checksum wrapper; the enclosed bytes retain their stored representation.

    use super::{DecodeError, EnvelopeCodec, HeaderInfo, Layout, SelectedLayout};
    use crate::ComponentKind;

    const HEADER_END: usize = 0x200;
    const CHECKSUM: usize = 0x8000;
    const PAYLOAD: usize = 0x10000;
    const WORD: usize = 4;
    const ERASED: u8 = 0xff;

    pub(super) struct Sparse;

    impl EnvelopeCodec for Sparse {
        fn layout(&self) -> Layout {
            Layout::SparseChecksum
        }

        fn detect(&self, data: &[u8], header: &HeaderInfo) -> Option<SelectedLayout> {
            if !matches!(
                header.kind,
                Some(ComponentKind::Kernel | ComponentKind::Normal)
            ) || data.len() <= PAYLOAD
                || !data[HEADER_END..CHECKSUM].iter().all(|&b| b == ERASED)
                || !data[CHECKSUM + WORD..PAYLOAD].iter().all(|&b| b == ERASED)
            {
                return None;
            }
            Some((self.layout(), PAYLOAD, data.len(), Vec::new(), Vec::new()))
        }

        fn validate(&self, data: &[u8]) -> Result<(), DecodeError> {
            let payload = data.get(PAYLOAD..).ok_or(DecodeError::InvalidPayload)?;
            if payload.len() % WORD != 0 {
                return Err(DecodeError::PayloadAlignment {
                    layout: self.layout(),
                    alignment: WORD,
                    actual: payload.len(),
                });
            }
            let stored = data
                .get(CHECKSUM..CHECKSUM + WORD)
                .and_then(|word| word.try_into().ok())
                .map(u32::from_le_bytes)
                .ok_or(DecodeError::InvalidPayload)?;
            let calculated = checksum(payload);
            if stored != calculated {
                return Err(DecodeError::ChecksumMismatch {
                    layout: self.layout(),
                    checksum_offset: CHECKSUM,
                    stored,
                    calculated,
                });
            }
            Ok(())
        }

        fn transform(&self, bytes: &[u8], _: &[u8], _: bool, _: &[u32]) -> Option<Vec<u8>> {
            (bytes.len() % WORD == 0).then(|| bytes.to_vec())
        }

        fn finish_repack(&self, data: &mut [u8]) -> Option<()> {
            let value = checksum(data.get(PAYLOAD..)?);
            data.get_mut(CHECKSUM..CHECKSUM + WORD)?
                .copy_from_slice(&value.to_le_bytes());
            Some(())
        }
    }

    fn checksum(payload: &[u8]) -> u32 {
        payload.chunks_exact(WORD).fold(0u32, |sum, word| {
            sum.wrapping_sub(u32::from_le_bytes([word[0], word[1], word[2], word[3]]))
        })
    }
}
mod kernel {
    use super::super::{
        jump_seed, legacy_le_kernel, make_key, recover_seed, transform, HeaderInfo, Layout,
        SelectedLayout,
    };
    use super::EnvelopeCodec;
    use crate::ComponentKind;

    const HEADER: usize = 0x200;
    const KEY: usize = 0x1000;
    const BODY: usize = 0x10000;
    const FRONT_BODY: usize = HEADER + KEY;
    const END: usize = FRONT_BODY + BODY;
    const ID_SAMPLE_END: usize = KEY + 0x40;
    const SEED_SAMPLE: usize = 16;

    pub(super) struct Front;
    impl EnvelopeCodec for Front {
        fn decoded_checksum(&self, image: &[u8]) -> Option<u32> {
            Some(super::super::be32_sum(image))
        }
        fn kernel_transfer(&self, envelope: &super::super::DecodedEnvelope) -> Option<Vec<u8>> {
            front_key_transfer(envelope)
        }
        fn layout(&self) -> Layout {
            Layout::KernelFront
        }
        fn detect(&self, data: &[u8], header: &HeaderInfo) -> Option<SelectedLayout> {
            if header.kind != Some(ComponentKind::Kernel) || data.len() < END {
                return None;
            }
            let key = &data[HEADER..FRONT_BODY];
            let sample = transform(&data[FRONT_BODY..FRONT_BODY + ID_SAMPLE_END], key, false)?;
            crate::protocol::valid_hardware_field(&sample[KEY..KEY + 8]).then(|| {
                (
                    self.layout(),
                    FRONT_BODY,
                    END,
                    key.to_vec(),
                    data[END..].to_vec(),
                )
            })
        }
    }

    pub(super) struct Derived;
    impl EnvelopeCodec for Derived {
        fn decoded_checksum(&self, image: &[u8]) -> Option<u32> {
            Some(super::super::be32_sum(image))
        }
        fn kernel_transfer(&self, envelope: &super::super::DecodedEnvelope) -> Option<Vec<u8>> {
            front_key_transfer(envelope)
        }
        fn layout(&self) -> Layout {
            Layout::KernelDerived
        }
        fn detect(&self, data: &[u8], header: &HeaderInfo) -> Option<SelectedLayout> {
            if header.kind != Some(ComponentKind::Kernel) || data.len() < END {
                return None;
            }
            let state = recover_seed(&data[data.len() - SEED_SAMPLE..])?;
            let seed = jump_seed(state, data.len() - HEADER - SEED_SAMPLE + KEY, true);
            let key = make_key(seed, KEY);
            let sample = transform(&data[HEADER..HEADER + ID_SAMPLE_END], &key, false)?;
            crate::protocol::valid_hardware_field(&sample[KEY..KEY + 8]).then(|| {
                (
                    self.layout(),
                    HEADER,
                    HEADER + BODY,
                    key,
                    data[HEADER + BODY..].to_vec(),
                )
            })
        }
    }

    pub(super) struct Legacy;
    impl EnvelopeCodec for Legacy {
        fn layout(&self) -> Layout {
            Layout::KernelLegacyLe
        }
        fn detect(&self, data: &[u8], header: &HeaderInfo) -> Option<SelectedLayout> {
            if header.kind != Some(ComponentKind::Kernel) {
                return None;
            }
            legacy_le_kernel(data)
        }
    }

    // File framing and receiver framing are different representations. Both modern
    // file codecs provide the same front-key receiver image without an OEM profile.
    fn front_key_transfer(envelope: &super::super::DecodedEnvelope) -> Option<Vec<u8>> {
        if envelope.image.len() != BODY
            || envelope.key.len() != KEY
            || !super::super::be32_sum_zero(&envelope.image)
        {
            return None;
        }
        let file = envelope.repack(&envelope.image)?;
        if file.len() != END {
            return None;
        }
        let mut wire = Vec::with_capacity(END);
        wire.extend_from_slice(&file[..HEADER]);
        wire.extend_from_slice(&envelope.key);
        wire.extend(transform(&envelope.image, &envelope.key, true)?);
        Some(wire)
    }
}
mod normal;
mod plain {
    use super::super::{
        has_plain_image_layout, plane_lcg_xor, transformed_plane_layout, HeaderInfo, Layout,
        SelectedLayout, HEADER_LEN, PLANE_XOR_OFFSET,
    };
    use super::EnvelopeCodec;
    use crate::ComponentKind;

    pub(super) struct Plain;
    impl EnvelopeCodec for Plain {
        fn layout(&self) -> Layout {
            Layout::Plain
        }
        fn detect(&self, data: &[u8], header: &HeaderInfo) -> Option<SelectedLayout> {
            if !matches!(
                header.kind,
                Some(ComponentKind::Normal | ComponentKind::Plane)
            ) || !has_plain_image_layout(data)
            {
                return None;
            }
            Some((
                self.layout(),
                HEADER_LEN,
                data.len(),
                Vec::new(),
                Vec::new(),
            ))
        }
        fn transform(&self, bytes: &[u8], _: &[u8], _: bool, _: &[u32]) -> Option<Vec<u8>> {
            Some(bytes.to_vec())
        }
    }
    pub(super) struct Whitened;
    impl EnvelopeCodec for Whitened {
        fn layout(&self) -> Layout {
            Layout::TransformedPlane
        }
        fn detect(&self, data: &[u8], header: &HeaderInfo) -> Option<SelectedLayout> {
            transformed_plane_layout(data, header.kind?)
        }
        fn transform(&self, bytes: &[u8], _: &[u8], _: bool, _: &[u32]) -> Option<Vec<u8>> {
            let split = PLANE_XOR_OFFSET - HEADER_LEN;
            let mut output = bytes.get(..split)?.to_vec();
            output.extend(plane_lcg_xor(bytes.get(split..)?));
            Some(output)
        }
    }
}
mod rom {
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
}
mod tail_key;

pub(super) trait EnvelopeCodec: Sync {
    fn layout(&self) -> Layout;
    fn detect(&self, data: &[u8], header: &HeaderInfo) -> Option<SelectedLayout>;
    fn candidates(&self, data: &[u8], header: &HeaderInfo) -> Vec<SelectedLayout> {
        self.detect(data, header).into_iter().collect()
    }
    fn candidates_with_kernel(
        &self,
        data: &[u8],
        header: &HeaderInfo,
        _kernel: &super::Envelope,
    ) -> Vec<SelectedLayout> {
        self.candidates(data, header)
    }
    fn validate_decoded(&self, _image: &[u8]) -> Result<(), DecodeError> {
        Ok(())
    }
    fn kernel_transfer(&self, _envelope: &super::DecodedEnvelope) -> Option<Vec<u8>> {
        None
    }
    fn normal_transfer(&self, _envelope: &super::DecodedEnvelope) -> Option<Vec<u8>> {
        None
    }
    fn validate(&self, _data: &[u8]) -> Result<(), DecodeError> {
        Ok(())
    }
    /// A format-defined decoded whole-image zero-sum checksum, when one exists.
    /// Stored-wrapper checksums are validated separately by `validate`.
    fn decoded_checksum(&self, _image: &[u8]) -> Option<u32> {
        None
    }
    /// Repair a proven decoded checksum for same-length edits. Unsupported
    /// formats fail closed; this does not establish image semantics or admission.
    fn repair_decoded(&self, _original: &[u8], _image: &[u8]) -> Option<Vec<u8>> {
        None
    }
    fn finish_repack(&self, _data: &mut [u8]) -> Option<()> {
        Some(())
    }
    fn reverse_rotation(&self) -> bool {
        false
    }
    fn transform(
        &self,
        bytes: &[u8],
        key: &[u8],
        encode: bool,
        exceptions: &[u32],
    ) -> Option<Vec<u8>> {
        super::transform_with_policy(bytes, key, encode, self.reverse_rotation(), exceptions)
    }
}

const CODECS: &[&dyn EnvelopeCodec] = &[
    &boot_key::BootKey,
    &boot_key_m7900::BootKeyM7900,
    &kernel::Legacy,
    &rom::KernelRom,
    &checksum::Sparse,
    &tail_key::TailKey,
    &normal::Keyed,
    &normal::Reverse,
    &normal::Scaled,
    &kernel::Front,
    &kernel::Derived,
    &plain::Plain,
    &plain::Whitened,
];

pub(super) fn detect(
    data: &[u8],
    header: &HeaderInfo,
    kernel: Option<&super::Envelope>,
) -> Result<SelectedLayout, DecodeError> {
    let mut candidates = CODECS.iter().flat_map(|codec| match kernel {
        Some(kernel) => codec.candidates_with_kernel(data, header, kernel),
        None => codec.candidates(data, header),
    });
    let selected = candidates.next().ok_or(DecodeError::UnsupportedLayout)?;
    // Equal Normal geometry may have equivalent codecs: rotations by zero or
    // sixteen bits are their own inverses. Canonicalize only proven equivalence.
    for candidate in candidates {
        if !equivalent(&selected, &candidate) {
            return Err(DecodeError::AmbiguousLayout);
        }
    }
    Ok(selected)
}

pub(super) fn for_layout(layout: Layout) -> &'static dyn EnvelopeCodec {
    // Layout is a closed internal format identifier, not a model/profile lookup.
    match layout {
        Layout::NormalBootKeyM7900 => &boot_key_m7900::BootKeyM7900,
        Layout::NormalBootKey => &boot_key::BootKey,
        Layout::SparseChecksum => &checksum::Sparse,
        Layout::Plain => &plain::Plain,
        Layout::TransformedPlane => &plain::Whitened,
        Layout::Normal => &normal::Keyed,
        Layout::NormalReverse => &normal::Reverse,
        Layout::NormalScaledKey => &normal::Scaled,
        Layout::KernelFront => &kernel::Front,
        Layout::KernelDerived => &kernel::Derived,
        Layout::KernelLegacyLe => &kernel::Legacy,
        Layout::KernelRom => &rom::KernelRom,
        Layout::NormalTailKey => &tail_key::TailKey,
    }
}

fn equivalent(a: &SelectedLayout, b: &SelectedLayout) -> bool {
    let normal = |layout| {
        matches!(
            layout,
            Layout::Normal | Layout::NormalReverse | Layout::NormalScaledKey
        )
    };
    if !normal(a.0) || !normal(b.0) || a.1 != b.1 || a.2 != b.2 || a.3 != b.3 || a.4 != b.4 {
        return false;
    }
    let same_rotation = for_layout(a.0).reverse_rotation() == for_layout(b.0).reverse_rotation();
    same_rotation || rotations_equivalent(&a.3)
}

/// Every word rotates by zero or sixteen bits, so both directions agree.
pub(super) fn rotations_equivalent(key: &[u8]) -> bool {
    !key.is_empty() && key.len() % 4 == 0 && key.chunks_exact(4).all(|word| word[0] & 15 == 0)
}
