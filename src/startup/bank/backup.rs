//! Immutable full-bank backup binding. No device commands or mutation authority.
use super::conversion::{self, LayoutPair};
use sha2::{Digest, Sha256};
const PREFIX: &[u8] = b"PIONEER-BANK-BACKUP\0\x01";
const CURRENT_OFFSET: usize = PREFIX.len() + 64;

/// A source capture could not be bound to the audited transition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The decoded firmware or bank records were not recognized.
    Conversion(conversion::Error),
    /// The live base is not one of the audited capacity branches.
    Geometry,
    /// The native active pointer disagrees with captured header selection.
    ActiveBank,
    /// Current firmware is neither the source schema nor its exact bridge.
    CurrentImage,
}

/// Owned canonical backup, including both complete source banks and identities.
/// This is not a flash plan and exposes no mutable records or writer methods.
#[derive(Clone, Debug)]
pub struct BankBackup {
    source_digest: [u8; 32],
    base: u32,
    bytes: Vec<u8>,
    digest: [u8; 32],
    conversion_digest: [u8; 32],
}
/// Evidence that the host supplied a byte-exact persisted readback.
/// Durability requires the host to sync the file and its containing directory
/// before calling `confirm_persisted`; this library cannot prove filesystem I/O.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackupReceipt {
    digest: [u8; 32],
    conversion_digest: [u8; 32],
}
impl BackupReceipt {
    /// SHA-256 of the complete canonical backup.
    pub fn backup_digest(&self) -> [u8; 32] {
        self.digest
    }
    /// SHA-256 of the complete proposed target bank, including its footer.
    pub fn conversion_digest(&self) -> [u8; 32] {
        self.conversion_digest
    }
}
impl BankBackup {
    /// Bind the exact decoded source/destination and both A/B source banks.
    /// `base` and `active` must be live native RAM base/active-pointer values.
    /// No source record is modified; the backup includes the omitted 16KiB.
    pub fn capture(
        source: &[u8],
        target: &[u8],
        banks: [&[u8]; 2],
        base: u32,
        active: u32,
    ) -> Result<Self, Error> {
        let pair = LayoutPair::discover(source, target).map_err(Error::Conversion)?;
        Self::from_pair(&pair, banks, base, active)
    }
    fn from_pair(
        pair: &LayoutPair,
        banks: [&[u8]; 2],
        base: u32,
        active: u32,
    ) -> Result<Self, Error> {
        let target_base: u32 = match base {
            0x5e0000 => 0x5e8000,
            0x7d0000 => 0x7d0000,
            _ => return Err(Error::Geometry),
        };
        let converted = pair.convert(banks).map_err(Error::Conversion)?;
        let receipt = converted.receipt();
        if active != base + receipt.authoritative_bank() as u32 * 0x10000 {
            return Err(Error::ActiveBank);
        }
        let mut hash = Sha256::new();
        hash.update(converted.body_before_commit());
        hash.update(converted.footer_to_commit_last());
        let conversion_digest: [u8; 32] = hash.finalize().into();
        let mut bytes = PREFIX.to_vec();
        bytes.extend_from_slice(&receipt.source_image_sha256());
        bytes.extend_from_slice(&receipt.target_image_sha256());
        bytes.extend_from_slice(&receipt.source_image_sha256());
        // Fixed big-endian geometry preserves both capacity selection and the
        // original physical bank intervals independently of model labels.
        for value in [
            base,
            base + 0x10000,
            0x10000,
            target_base,
            target_base + 0xc000,
            0xc000,
            active,
        ] {
            bytes.extend_from_slice(&value.to_be_bytes());
        }
        bytes.push(receipt.authoritative_bank() as u8);
        bytes.extend_from_slice(&receipt.source_sequence().to_be_bytes());
        for hash in receipt.source_bank_sha256() {
            bytes.extend_from_slice(&hash);
        }
        bytes.extend_from_slice(&conversion_digest);
        bytes.extend_from_slice(banks[0]);
        bytes.extend_from_slice(banks[1]);
        let digest = Sha256::digest(&bytes).into();
        Ok(Self {
            source_digest: receipt.source_image_sha256(),
            base,
            bytes,
            digest,
            conversion_digest,
        })
    }
    /// Bind the actual running image separately from the original record
    /// schema. Only the exact OEM source or its canonical bridge is accepted.
    /// The returned backup needs its own persisted readback receipt.
    pub fn bind_current_image(mut self, current: &[u8]) -> Result<Self, Error> {
        let current_digest: [u8; 32] = Sha256::digest(current).into();
        if current_digest != self.source_digest {
            let bridge = super::bridge::recognize(current).ok_or(Error::CurrentImage)?;
            if bridge.base() != self.base
                || <[u8; 32]>::from(Sha256::digest(bridge.source_image())) != self.source_digest
            {
                return Err(Error::CurrentImage);
            }
        }
        self.bytes[CURRENT_OFFSET..CURRENT_OFFSET + 32].copy_from_slice(&current_digest);
        self.digest = Sha256::digest(&self.bytes).into();
        Ok(self)
    }
    /// Exact bytes to atomically write, sync and read back before any mutation.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// SHA-256 suitable for the host's durable filename and audit record.
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }
    /// Acknowledge only a byte-exact readback after host durability operations.
    pub fn confirm_persisted(&self, readback: &[u8]) -> Option<BackupReceipt> {
        (readback == self.bytes).then_some(BackupReceipt {
            digest: self.digest,
            conversion_digest: self.conversion_digest,
        })
    }
    /// Match a receipt to this immutable backup and its proposed conversion.
    pub fn accepts(&self, receipt: &BackupReceipt) -> bool {
        receipt.digest == self.digest && receipt.conversion_digest == self.conversion_digest
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn receipt_requires_exact_readback_and_cannot_cross_backups() {
        let bytes = b"test canonical backup".to_vec();
        let backup = BankBackup {
            source_digest: [0; 32],
            base: 0x5e0000,
            digest: Sha256::digest(&bytes).into(),
            bytes,
            conversion_digest: [3; 32],
        };
        let receipt = backup.confirm_persisted(backup.bytes()).unwrap();
        assert!(backup.accepts(&receipt));
        assert_eq!(receipt.backup_digest(), backup.digest());
        assert_eq!(receipt.conversion_digest(), [3; 32]);
        for i in 0..backup.bytes().len() {
            let mut changed = backup.bytes().to_vec();
            changed[i] ^= 1;
            assert!(backup.confirm_persisted(&changed).is_none());
        }
        assert!(backup.confirm_persisted(&backup.bytes()[1..]).is_none());
        let mut other = backup.clone();
        other.conversion_digest[0] ^= 1;
        assert!(!other.accepts(&receipt));
        other = backup.clone();
        other.digest[0] ^= 1;
        assert!(!other.accepts(&receipt));
    }
}
