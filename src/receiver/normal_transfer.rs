//! Prepare a Normal transfer for the Kernel that will actually receive it. A
//! paired update hands off to its incoming Kernel first; a Normal-only update
//! keeps the installed Kernel. Moved here from the flasher so the decision of
//! when to keep, sign or re-encode a transfer lives with the codec.
use crate::envelope::{
    builder::{
        encode_normal_for_kernel, normal_authentication_from_kernel, normal_authentication_valid,
        NormalAuthentication, NormalKeySource, NormalSignature,
    },
    signature::{verify_normal_signature, SignatureCheck, SigningKey},
    Envelope,
};
use alloc::vec::Vec;

/// Envelope header length; a Normal shorter than this has no header.
const HEADER_LEN: usize = 0x200;

/// Why a Normal transfer could not be prepared for its receiving Kernel.
#[derive(Debug)]
#[non_exhaustive]
pub enum NormalTransferError {
    /// The source is not a decoded Normal component.
    NotNormal,
    /// The source image has missing bytes or a nonzero checksum.
    IncompleteSource,
    /// An unsigned backup does not rebuild exactly or has missing bytes.
    UnsignedNotExact,
    /// Signing an unsigned backup changed its firmware body.
    SigningChangedBody,
    /// A nonzero Normal signature does not verify: not an unsigned backup.
    InvalidSignature,
    /// The receiving Kernel's backup authentication format is unsupported.
    UnsupportedAuthentication,
    /// A transfer signing key could not be created.
    SigningKey(crate::envelope::Error),
    /// A signing key for the re-encoded Normal could not be created.
    EncodeSigningKey(crate::envelope::Error),
    /// The unsigned backup's transfer format could not be signed.
    Signing(crate::envelope::Error),
    /// The fresh transfer signature did not satisfy the receiving Kernel.
    SignatureRejected,
    /// The source lacks its original Kernel's decoding policy.
    NoDecodingPolicy,
    /// The source has no recoverable encoding seed.
    NoEncodingSeed,
    /// The transfer has no complete header.
    NoHeader,
    /// Re-encoding for the receiving Kernel failed.
    Encode(crate::envelope::Error),
    /// The re-encoded Normal does not decode under its receiving Kernel.
    ReencodedUndecodable(crate::envelope::DecodeError),
    /// The re-encoded Normal differs from the source firmware.
    ReencodedDiffers,
    /// Decoding the transfer under its receiving Kernel failed.
    Decode(crate::envelope::DecodeError),
}

impl core::fmt::Display for NormalTransferError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotNormal => f.write_str("Normal preparation requires a decoded Normal component"),
            Self::IncompleteSource => {
                f.write_str("Normal preparation requires a complete zero-checksum source image")
            }
            Self::UnsignedNotExact => f.write_str("the unsigned backup does not rebuild exactly or has missing firmware bytes"),
            Self::SigningChangedBody => f.write_str("signing changed the backup firmware body"),
            Self::InvalidSignature => f.write_str("the Normal signature is invalid; it is not an unsigned backup"),
            Self::UnsupportedAuthentication => f.write_str("the receiving Kernel's backup authentication format is not supported"),
            Self::SigningKey(e) => write!(f, "cannot create a transfer signing key: {e}"),
            Self::EncodeSigningKey(e) => write!(f, "cannot create Normal signing key: {e}"),
            Self::Signing(e) => write!(f, "the unsigned backup could not be signed for its Kernel: {e}"),
            Self::SignatureRejected => f.write_str("the transfer signature did not satisfy its receiving Kernel"),
            Self::NoDecodingPolicy => f.write_str("cannot re-encode Normal without its original Kernel's decoding policy"),
            Self::NoEncodingSeed => f.write_str("Normal has no recoverable encoding seed"),
            Self::NoHeader => f.write_str("Normal has no complete header"),
            Self::Encode(e) => write!(f, "cannot encode Normal for its receiving Kernel: {e:?}"),
            Self::ReencodedUndecodable(e) => write!(f, "re-encoded Normal does not decode under its receiving Kernel: {e}"),
            Self::ReencodedDiffers => f.write_str("re-encoded Normal differs from the source firmware"),
            Self::Decode(e) => write!(f, "{e}"),
        }
    }
}
impl std::error::Error for NormalTransferError {}

/// True when the Normal's signature field is all zero (an unsigned capture).
pub fn is_unsigned(bytes: &[u8]) -> bool {
    bytes
        .get(0x170..0x1c0)
        .is_some_and(|sig| sig.iter().all(|b| *b == 0))
}

/// Sign an owned transfer copy for `receiver`, retaining the original key
/// table and ciphertext; captures need not have a recoverable encoding seed.
pub fn sign_for_receiver(receiver: &Envelope, bytes: &[u8]) -> Result<Vec<u8>, NormalTransferError> {
    let signer = SigningKey::random().map_err(NormalTransferError::SigningKey)?;
    let mut signed = bytes.to_vec();
    match normal_authentication_from_kernel(&receiver.image) {
        Some(NormalAuthentication::KeyAndCiphertext) => signer.sign_normal(&mut signed),
        Some(NormalAuthentication::CiphertextOnly) => signer.sign_normal_ciphertext_only(&mut signed),
        _ => return Err(NormalTransferError::UnsupportedAuthentication),
    }
    .map_err(NormalTransferError::Signing)?;
    if !normal_authentication_valid(&signed, &receiver.image) {
        return Err(NormalTransferError::SignatureRejected);
    }
    Ok(signed)
}

/// The transfer bytes `receiver` accepts for `source`: the original bytes
/// (OEM signature kept) when they already decode and authenticate, a signed
/// copy of an exact unsigned capture, or a re-encoding under `receiver`.
pub fn for_receiver(
    receiver: &Envelope,
    source: &Envelope,
    bytes: &[u8],
) -> Result<Vec<u8>, NormalTransferError> {
    if source.info().kind != crate::ComponentKind::Normal {
        return Err(NormalTransferError::NotNormal);
    }
    if source.unrecovered_tail().is_some() || !crate::checksum::be32_sum_zero(&source.image) {
        return Err(NormalTransferError::IncompleteSource);
    }
    let decodes =
        Envelope::load_with_kernel(bytes, receiver).is_ok_and(|decoded| decoded.image == source.image);
    if decodes && normal_authentication_valid(bytes, &receiver.image) {
        // Preserve the OEM signature and file representation whenever possible.
        return Ok(bytes.to_vec());
    }
    if decodes && is_unsigned(bytes) {
        let original =
            Envelope::load_with_kernel(bytes, receiver).map_err(NormalTransferError::Decode)?;
        if original.unrecovered_tail().is_some()
            || original.repack(&original.image).as_deref() != Some(bytes)
        {
            return Err(NormalTransferError::UnsignedNotExact);
        }
        let signed = sign_for_receiver(receiver, bytes)?;
        let proof =
            Envelope::load_with_kernel(&signed, receiver).map_err(NormalTransferError::Decode)?;
        if proof.image != source.image {
            return Err(NormalTransferError::SigningChangedBody);
        }
        return Ok(signed);
    }
    if !is_unsigned(bytes)
        && !matches!(
            verify_normal_signature(bytes),
            SignatureCheck::ValidKeyAndCiphertext | SignatureCheck::ValidCiphertextOnly
        )
    {
        return Err(NormalTransferError::InvalidSignature);
    }
    if source.receiver_xor_exceptions().is_none() {
        return Err(NormalTransferError::NoDecodingPolicy);
    }
    let seed = source
        .encoding_seed()
        .ok_or(NormalTransferError::NoEncodingSeed)?;
    let signer = SigningKey::random().map_err(NormalTransferError::EncodeSigningKey)?;
    let encoded = encode_normal_for_kernel(
        &receiver.image,
        &source.image,
        bytes.get(..HEADER_LEN).ok_or(NormalTransferError::NoHeader)?,
        NormalKeySource::Seed(seed),
        NormalSignature::Sign(&signer),
    )
    .map_err(NormalTransferError::Encode)?;
    let proof = Envelope::load_with_kernel(&encoded, receiver)
        .map_err(NormalTransferError::ReencodedUndecodable)?;
    if proof.image != source.image || !crate::checksum::be32_sum_zero(&proof.image) {
        return Err(NormalTransferError::ReencodedDiffers);
    }
    Ok(encoded)
}
