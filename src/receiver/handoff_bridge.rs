//! Source-Kernel bridge, derived from the two recognized handoff contracts.
use super::{PreparationError, Receiver};
use crate::envelope::{Envelope, Update, KERNEL_CHECKSUM_WORD_OFFSET};
use crate::image::{kernel_handoff_contract, kernel_startup_entry, KernelHandoffError};

pub(super) fn prepare(receiver: &Receiver, target: &Envelope) -> Result<Update, PreparationError> {
    let source = receiver
        .installed_kernel()
        .ok_or(PreparationError::MissingInstalledKernel)?;
    let normal = receiver
        .installed_normal
        .as_ref()
        .ok_or(PreparationError::PatchedRepresentation)?;
    let refused = |error| PreparationError::KernelHandoff(error);
    let contract = kernel_handoff_contract(&source.image)
        .ok_or_else(|| refused(KernelHandoffError::UnknownInstalled))?;
    let startup = kernel_startup_entry(&source.image)
        .ok_or_else(|| refused(KernelHandoffError::UnknownInstalled))?;
    let destination = kernel_startup_entry(&target.image)
        .ok_or_else(|| refused(KernelHandoffError::UnknownTarget))?;
    // The installed updater must be able to start the bridge, whose startup
    // code stays untouched. Already-adapted or inconsistent sources refuse.
    if contract.entry != startup || startup == destination {
        return Err(refused(KernelHandoffError::Mismatch {
            installed: contract.entry,
            target: destination,
        }));
    }
    let mut image = source.image.clone();
    let sum = |bytes: &[u8]| {
        bytes.chunks_exact(4).fold(0u32, |sum, word| {
            sum.wrapping_add(u32::from_be_bytes(word.try_into().expect("word")))
        })
    };
    if image.len() % 4 != 0 || sum(&image) != 0 {
        return Err(PreparationError::PatchedRepresentation);
    }
    for at in &contract.operands {
        // No programmer operand may overlap the fixed Kernel checksum field.
        if *at < KERNEL_CHECKSUM_WORD_OFFSET + 4 && at + 3 > KERNEL_CHECKSUM_WORD_OFFSET {
            return Err(PreparationError::PatchedRepresentation);
        }
        image[*at..*at + 3].copy_from_slice(&destination.to_be_bytes()[1..]);
    }
    let checksum = KERNEL_CHECKSUM_WORD_OFFSET;
    let before = u32::from_be_bytes(image[checksum..checksum + 4].try_into().expect("checksum"));
    let adjusted = before.wrapping_sub(sum(&image));
    image[checksum..checksum + 4].copy_from_slice(&adjusted.to_be_bytes());
    let patched = kernel_handoff_contract(&image).ok_or(PreparationError::PatchedRepresentation)?;
    if patched.entry != destination
        || patched.operands != contract.operands
        || kernel_startup_entry(&image) != Some(startup)
        || sum(&image) != 0
    {
        return Err(PreparationError::PatchedRepresentation);
    }
    let kernel = source
        .repack(&image)
        .ok_or(PreparationError::PatchedRepresentation)?;
    let mut normal_bytes = normal
        .repack(&normal.image)
        .ok_or(PreparationError::PatchedRepresentation)?;
    let mut loaded = Update::load(&kernel, &normal_bytes);
    // A live capture may carry an empty signature. Authenticate an owned
    // transfer copy only after every other Update gate accepted that pair.
    // A nonzero invalid signature is never repaired or treated as unsigned.
    if matches!(loaded, Err(crate::envelope::UpdateError::Authentication))
        && normal_bytes
            .get(0x170..0x1c0)
            .is_some_and(|signature| signature.iter().all(|byte| *byte == 0))
    {
        use crate::envelope::{
            builder::{normal_authentication_from_kernel, NormalAuthentication},
            signature::SigningKey,
        };
        let signer = SigningKey::random().map_err(|_| PreparationError::PatchedRepresentation)?;
        match normal_authentication_from_kernel(&image) {
            Some(NormalAuthentication::KeyAndCiphertext) => signer.sign_normal(&mut normal_bytes),
            Some(NormalAuthentication::CiphertextOnly) => {
                signer.sign_normal_ciphertext_only(&mut normal_bytes)
            }
            _ => return Err(PreparationError::PatchedRepresentation),
        }
        .map_err(|_| PreparationError::PatchedRepresentation)?;
        loaded = Update::load(&kernel, &normal_bytes);
    }
    let bridge = loaded.map_err(PreparationError::Target)?;
    if bridge.kernel().image != image || bridge.normal().image != normal.image {
        return Err(PreparationError::PatchedRepresentation);
    }
    Ok(bridge)
}
