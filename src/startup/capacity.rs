//! Relational evidence for the discriminator selecting persistent bank addresses.
//!
//! Matching address cases does not establish matching discriminator results.
//! Two firmwares relate only with an unchanged complete pair, an address
//! expression independent of the discriminator, or a proof that both run the
//! same discriminator over the identical address cases: the same query and the
//! same decision, differing only in link layout and verified side calls. The
//! proof is derived from the two images with `h8-asm` (no hand-rolled decoding,
//! no live query), so an offline comparison equals the online one and can only
//! under-accept: a differing query or decision never relates.
use super::bank::{Addresses, Storage};
use sha2::{Digest, Sha256};

mod program;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PairIdentity {
    normal: [u8; 32],
    kernel: [u8; 32],
}

/// Proof that two firmwares select persistent-bank addresses identically: the
/// same discriminator (an `h8-asm`-bounded, link-layout-independent
/// fingerprint) over the same two address cases. Equality of all three is required.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Discriminator {
    program: [u8; 32],
    when_one: [u32; 2],
    otherwise: [u32; 2],
}

/// Only constructors in this module can attach positive pairing evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Evidence {
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

    pub(crate) fn discover(normal: &[u8], kernel: Option<&[u8]>) -> Self {
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
    pub(crate) fn relates(self, target: Self) -> bool {
        (self.independent && target.independent)
            || self
                .identity
                .is_some_and(|identity| target.identity == Some(identity))
            || self
                .discriminator
                .is_some_and(|discriminator| target.discriminator == Some(discriminator))
    }

    /// Canonical byte encoding so the pair-aware capacity filter can carry this
    /// evidence in its per-image assessment and reconstruct it in `compare`.
    /// Keeps `relates` the single source of truth for every surface.
    pub(crate) fn encode(self) -> alloc::vec::Vec<u8> {
        let mut bytes = alloc::vec::Vec::new();
        bytes.push(u8::from(self.independent));
        match self.identity {
            Some(id) => {
                bytes.push(1);
                bytes.extend_from_slice(&id.normal);
                bytes.extend_from_slice(&id.kernel);
            }
            None => bytes.push(0),
        }
        match self.discriminator {
            Some(d) => {
                bytes.push(1);
                bytes.extend_from_slice(&d.program);
                for w in d.when_one.iter().chain(d.otherwise.iter()) {
                    bytes.extend_from_slice(&w.to_be_bytes());
                }
            }
            None => bytes.push(0),
        }
        bytes
    }

    /// Reconstruct evidence from [`Evidence::encode`]. `None` on any malformed
    /// input, so a bad assessment can never manufacture a positive relation.
    pub(crate) fn decode(bytes: &[u8]) -> Option<Self> {
        let mut at = 0;
        let mut take = |n: usize| -> Option<&[u8]> {
            let slice = bytes.get(at..at + n)?;
            at += n;
            Some(slice)
        };
        let independent = match take(1)?[0] {
            0 => false,
            1 => true,
            _ => return None,
        };
        let identity = match take(1)?[0] {
            0 => None,
            1 => Some(PairIdentity {
                normal: take(32)?.try_into().ok()?,
                kernel: take(32)?.try_into().ok()?,
            }),
            _ => return None,
        };
        let discriminator = match take(1)?[0] {
            0 => None,
            1 => {
                let program = take(32)?.try_into().ok()?;
                let word = |b: &[u8]| u32::from_be_bytes(b.try_into().unwrap());
                let when_one = [word(take(4)?), word(take(4)?)];
                let otherwise = [word(take(4)?), word(take(4)?)];
                Some(Discriminator {
                    program,
                    when_one,
                    otherwise,
                })
            }
            _ => return None,
        };
        (at == bytes.len()).then_some(Self {
            independent,
            identity,
            discriminator,
        })
    }
}

#[cfg(all(test, feature = "envelope"))]
mod tests;
