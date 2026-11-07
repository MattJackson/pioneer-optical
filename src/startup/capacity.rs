//! Relational evidence for the discriminator selecting persistent bank addresses.
//!
//! Matching address cases does not establish matching discriminator results.
//! This owner requires either an unchanged complete pair, an address expression
//! independent of the result, or a complete recognized native transaction.
use super::bank::{Addresses, Storage};
use sha2::{Digest, Sha256};

mod native;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PairIdentity {
    normal: [u8; 32],
    kernel: [u8; 32],
}

/// Only constructors in this module can attach positive pairing evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Evidence {
    independent: bool,
    identity: Option<PairIdentity>,
    native: Option<native::Transaction>,
}

impl Evidence {
    #[cfg(test)]
    pub(super) const UNKNOWN: Self = Self {
        independent: false,
        identity: None,
        native: None,
    };

    pub(super) fn discover(normal: &[u8], kernel: Option<&[u8]>) -> Self {
        // Re-run native bank discovery here: a caller-created descriptive enum
        // must never manufacture an address-independent execution witness.
        let storage = super::bank::analyze_pair(normal, kernel);
        let independent = match storage {
            Some(Storage::Versioned(contract)) => match contract.addresses {
                Addresses::Fixed(_) => true,
                Addresses::Capacity {
                    when_one,
                    otherwise,
                } => when_one == otherwise,
            },
            Some(Storage::StateHeaders { .. } | Storage::KernelSequences { .. }) => true,
            None => false,
        };
        let kernel = kernel.filter(|bytes| bytes.len() == 0x10000);
        Self {
            independent,
            identity: kernel.map(|kernel| PairIdentity {
                normal: Sha256::digest(normal).into(),
                kernel: Sha256::digest(kernel).into(),
            }),
            native: if independent {
                None
            } else {
                kernel.and_then(|kernel| native::discover(normal, kernel))
            },
        }
    }

    /// The bank owner separately checks format, case addresses and validation.
    pub(super) fn relates(self, target: Self) -> bool {
        (self.independent && target.independent)
            || self
                .identity
                .is_some_and(|identity| target.identity == Some(identity))
            || self
                .native
                .is_some_and(|native| target.native == Some(native))
    }
}

#[cfg(all(test, feature = "envelope"))]
mod tests;
