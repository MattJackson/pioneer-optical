//! Envelope facts and recognizable reconstruction placeholders, not OEM provenance.
use super::{
    builder::NORMAL_SIGNATURE_RANGE, header_info, signature, ComponentKind, Envelope, HeaderInfo,
    Layout,
};

/// A combination of fields emitted by reconstruction without original metadata.
/// Matching does not prove who produced a file; non-matching does not prove OEM origin.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReconstructionPlaceholder {
    /// Zero encoding seed and an entirely zero Normal signature block.
    Normal,
    /// Zero encoding seed, revision `0000`, and date `00/00/00`.
    Kernel,
}

/// Signature presence and mathematical verification, without a trust assertion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SignatureStatus {
    /// The recognized signature slot contains only zero bytes.
    Absent,
    /// Verification result for a nonzero signature slot.
    Present(signature::SignatureCheck),
    /// This layout has no supported signature interpretation.
    Unsupported,
}

impl Envelope {
    /// Parsed envelope header fields, including revision, date and destination.
    pub fn header(&self) -> Option<HeaderInfo> {
        header_info(&self.header)
    }

    /// Original encoding key bytes. Empty for layouts without a key.
    /// A raw OEM key need not have a recoverable LCG seed.
    pub fn encoding_key(&self) -> &[u8] {
        &self.key
    }

    /// Recognized Normal ECDSA slot; other layouts return `None`.
    pub fn signature_bytes(&self) -> Option<&[u8]> {
        if matches!(self.info.layout, Layout::Normal | Layout::NormalReverse) {
            self.prefix.get(
                NORMAL_SIGNATURE_RANGE.start - super::HEADER_LEN
                    ..NORMAL_SIGNATURE_RANGE.end - super::HEADER_LEN,
            )
        } else {
            None
        }
    }

    /// Check the signature against the current decoded image, including caller edits.
    /// Verification reconstructs the encrypted envelope and may allocate its full size.
    /// A valid signature does not establish OEM provenance or receiver acceptance.
    pub fn signature_status(&self) -> SignatureStatus {
        let Some(bytes) = self.signature_bytes() else {
            return SignatureStatus::Unsupported;
        };
        if bytes.iter().all(|&byte| byte == 0) {
            return SignatureStatus::Absent;
        }
        SignatureStatus::Present(
            self.repack(&self.image)
                .map_or(signature::SignatureCheck::Unsupported, |data| {
                    signature::verify_normal_signature(&data)
                }),
        )
    }

    /// Recognize reconstruction placeholder combinations, without classifying OEM origin.
    /// Seed zero alone is not a placeholder. A missing seed is not seed zero.
    pub fn reconstruction_placeholder(&self) -> Option<ReconstructionPlaceholder> {
        if self.encoding_seed() != Some(0) {
            return None;
        }
        match self.info.kind {
            ComponentKind::Normal if self.signature_bytes()?.iter().all(|&byte| byte == 0) => {
                Some(ReconstructionPlaceholder::Normal)
            }
            ComponentKind::Kernel => {
                let header = self.header()?;
                (header.revision == "0000" && header.generated_date == "00/00/00")
                    .then_some(ReconstructionPlaceholder::Kernel)
            }
            _ => None,
        }
    }
}
