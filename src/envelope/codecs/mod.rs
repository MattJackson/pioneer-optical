//! Internal format implementations. Selection uses file structure, never drive names.

use super::{DecodeError, HeaderInfo, Layout, SelectedLayout};
mod checksum;
mod kernel;
mod normal;
mod plain;
mod rom;

pub(super) trait EnvelopeCodec: Sync {
    fn layout(&self) -> Layout;
    fn detect(&self, data: &[u8], header: &HeaderInfo) -> Option<SelectedLayout>;
    fn candidates(&self, data: &[u8], header: &HeaderInfo) -> Vec<SelectedLayout> {
        self.detect(data, header).into_iter().collect()
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
    &kernel::Legacy,
    &rom::KernelRom,
    &checksum::Sparse,
    &normal::Keyed,
    &normal::Reverse,
    &normal::Scaled,
    &kernel::Front,
    &kernel::Derived,
    &plain::Plain,
    &plain::Whitened,
];

pub(super) fn detect(data: &[u8], header: &HeaderInfo) -> Result<SelectedLayout, DecodeError> {
    let mut candidates = CODECS
        .iter()
        .flat_map(|codec| codec.candidates(data, header));
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
    same_rotation || a.3.chunks_exact(4).all(|word| word[0] & 15 == 0)
}
