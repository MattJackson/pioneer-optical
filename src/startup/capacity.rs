//! Relational evidence for the discriminator selecting persistent bank addresses.
//!
//! Matching address cases does not establish matching discriminator results.
//! Two firmwares relate only with an unchanged complete pair, an address
//! expression independent of the discriminator, or a proof that both run the
//! identical discriminator program over the identical address cases. The
//! program proof is derived from the two images with `h8-asm` (no hand-rolled
//! decoding, no live query), so an offline comparison equals the online one and
//! can only under-accept: a differing program never relates.
use super::bank::{Addresses, Storage};
use sha2::{Digest, Sha256};

mod program;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PairIdentity {
    normal: [u8; 32],
    kernel: [u8; 32],
}

/// Proof that two firmwares select persistent-bank addresses identically: the
/// same discriminator program (an `h8-asm`-bounded, relocation-normalized
/// digest) over the same two address cases. Equality of all three is required.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Discriminator {
    program: [u8; 32],
    when_one: [u32; 2],
    otherwise: [u32; 2],
}

/// Only constructors in this module can attach positive pairing evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Evidence {
    independent: bool,
    identity: Option<PairIdentity>,
    discriminator: Option<Discriminator>,
}

impl Evidence {
    #[cfg(test)]
    pub(super) const UNKNOWN: Self = Self {
        independent: false,
        identity: None,
        discriminator: None,
    };

    pub(super) fn discover(normal: &[u8], kernel: Option<&[u8]>) -> Self {
        // Re-run native bank discovery here: a caller-created descriptive enum
        // must never manufacture an address-independent execution witness.
        let storage = super::bank::analyze_pair(normal, kernel);
        let (independent, cases) = match storage {
            Some(Storage::Versioned(contract)) => match contract.addresses {
                Addresses::Fixed(_) => (true, None),
                Addresses::Capacity {
                    when_one,
                    otherwise,
                } => (when_one == otherwise, Some((when_one, otherwise))),
            },
            Some(Storage::StateHeaders { .. } | Storage::KernelSequences { .. }) => (true, None),
            None => (false, None),
        };
        let kernel = kernel.filter(|bytes| bytes.len() == 0x10000);
        // A capacity-selected contract needs its discriminator program proved;
        // an independent or non-capacity contract does not.
        let discriminator = if independent {
            None
        } else {
            cases.and_then(|(when_one, otherwise)| {
                let entry = super::bank::discriminator_entry(normal)?;
                let program = program::digest(normal, entry)?;
                Some(Discriminator {
                    program,
                    when_one,
                    otherwise,
                })
            })
        };
        Self {
            independent,
            identity: kernel.map(|kernel| PairIdentity {
                normal: Sha256::digest(normal).into(),
                kernel: Sha256::digest(kernel).into(),
            }),
            discriminator,
        }
    }

    /// Self-contained: proves the relation from the two images' own evidence,
    /// independent of the order other startup checks run in.
    pub(super) fn relates(self, target: Self) -> bool {
        (self.independent && target.independent)
            || self
                .identity
                .is_some_and(|identity| target.identity == Some(identity))
            || self
                .discriminator
                .is_some_and(|discriminator| target.discriminator == Some(discriminator))
    }
}

#[cfg(all(test, feature = "envelope"))]
mod tests;
