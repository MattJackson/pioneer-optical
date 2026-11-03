//! Rebuild corrected Normal files under their established codec and Kernel.
use super::Error;
use crate::envelope::{builder, signature::SigningKey, Envelope, Layout};

pub(super) fn matching_components(normal: &Envelope, kernel: Option<&Envelope>) -> bool {
    if normal.info().kind != crate::ComponentKind::Normal {
        return false;
    }
    let Some(kernel) = kernel else {
        return true;
    };
    if kernel.info().kind != crate::ComponentKind::Kernel {
        return false;
    }
    let n = normal.header_info();
    let k = kernel.header_info();
    for (n, k) in [
        (&n.hardware_version, &k.hardware_version),
        (&n.destination, &k.destination),
        (&n.kernel_version, &k.kernel_version),
        (&n.kernel_version2, &k.kernel_version2),
    ] {
        if n.is_empty() || n != k {
            return false;
        }
    }
    true
}

pub(crate) fn rebuild_normal(
    normal: &Envelope,
    kernel: Option<&Envelope>,
    image: &[u8],
    preserve_authentication: bool,
) -> Result<Vec<u8>, Error> {
    if !matching_components(normal, kernel) || normal.image.len() != image.len() {
        return Err(Error::ComponentMismatch);
    }
    let mut bytes = normal.repack(image).ok_or(Error::Representation)?;
    match normal.info().layout {
        // These codecs validate their native sums on reload below. BootKey
        // additionally requires the exact Kernel-derived transform.
        Layout::NormalTailKey => {}
        Layout::NormalBootKey if kernel.is_some() => {}
        Layout::NormalBootKey => return Err(Error::UnresolvedIdentity),
        Layout::SparseChecksum
            if kernel.map(|k| k.info().layout) == Some(Layout::SparseChecksum) => {}
        Layout::SparseChecksum => return Err(Error::Unsupported),
        _ => {
            let kernel = kernel.ok_or(Error::UnresolvedIdentity)?;
            use builder::NormalAuthentication;
            let authentication = builder::normal_authentication_from_kernel(&kernel.image)
                .ok_or(Error::Authentication)?;
            if !preserve_authentication {
                match authentication {
                    NormalAuthentication::KeyAndCiphertext => {
                        SigningKey::random()
                            .map_err(|_| Error::Authentication)?
                            .sign_normal(&mut bytes)
                            .map_err(|_| Error::Authentication)?;
                    }
                    NormalAuthentication::CiphertextOnly => {
                        SigningKey::random()
                            .map_err(|_| Error::Authentication)?
                            .sign_normal_ciphertext_only(&mut bytes)
                            .map_err(|_| Error::Authentication)?;
                    }
                    NormalAuthentication::Unsigned | NormalAuthentication::ScaledChecksumOnly => {}
                }
            }
            if !builder::normal_authentication_valid(&bytes, &kernel.image) {
                return Err(Error::Authentication);
            }
        }
    }
    let decoded = match kernel {
        Some(kernel) => Envelope::load_with_kernel(&bytes, kernel),
        None => Envelope::load(&bytes),
    }
    .map_err(|_| Error::Representation)?;
    if decoded.image != image {
        return Err(Error::VerificationFailed);
    }
    Ok(bytes)
}
