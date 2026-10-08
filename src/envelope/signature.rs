//! Offline verification and experimental signing of Pioneer Normal envelopes
//! in the observed BDR/SAT generation. A valid signature under a caller-owned
//! key does not prove that the drive accepts a transfer.

use super::{Error, Result};
use num_bigint::BigUint;
use num_traits::{One, Zero};
use sha1::{Digest, Sha1};
use std::sync::OnceLock;

/// Result of [`verify_normal_signature`]. `Unsupported` covers every input
/// that cannot be classified: data too short, not an envelope, not a Normal,
/// or a public point off the established curve.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SignatureCheck {
    /// Not classifiable; see the type documentation.
    Unsupported,
    /// The public point is recognized, but neither observed signed range verifies.
    Invalid,
    /// The signature covers the key table and encrypted payload, from 0x200.
    ValidKeyAndCiphertext,
    /// The signature covers only the encrypted payload, from 0x10200.
    ValidCiphertextOnly,
}

/// Signing key for experimental Normal envelopes. A valid mathematical
/// signature does not establish that a drive trusts this public key.
pub struct SigningKey {
    scalar: BigUint,
}

impl core::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SigningKey").finish_non_exhaustive()
    }
}

impl SigningKey {
    /// Accept a 160-bit private scalar for a caller-owned signing key.
    pub fn from_bytes(bytes: [u8; 20]) -> Option<Self> {
        let scalar = BigUint::from_bytes_be(&bytes);
        (!scalar.is_zero() && scalar < curve().n).then_some(Self { scalar })
    }

    /// Generate a fresh caller-owned signing key from operating-system entropy.
    pub fn random() -> Result<Self> {
        for _ in 0..128 {
            let mut bytes = [0u8; 20];
            getrandom::fill(&mut bytes).map_err(|_| Error::EntropyUnavailable)?;
            if let Some(key) = Self::from_bytes(bytes) {
                return Ok(key);
            }
        }
        Err(Error::Randomness)
    }

    /// Replace the Normal header's signature and public point for the body
    /// beginning at 0x200. This proves format mathematics only.
    pub fn sign_normal(&self, envelope: &mut [u8]) -> Result<()> {
        self.sign_normal_from(envelope, 0x200)
    }

    /// Sign the encrypted payload beginning at 0x10200, as observed in the
    /// derived-key Kernel generation. This proves format mathematics only.
    pub fn sign_normal_ciphertext_only(&self, envelope: &mut [u8]) -> Result<()> {
        self.sign_normal_from(envelope, 0x10200)
    }

    fn sign_normal_from(&self, envelope: &mut [u8], start: usize) -> Result<()> {
        let saved = envelope.get(0x170..0x1c0).map(<[u8]>::to_vec);
        let result = self.sign_normal_in_place(envelope, start);
        if result.is_err() {
            if let Some(saved) = saved {
                envelope[0x170..0x1c0].copy_from_slice(&saved);
            }
        }
        result
    }

    fn sign_normal_in_place(&self, envelope: &mut [u8], start: usize) -> Result<()> {
        if envelope.len() < 0x10200 + 20
            || !super::header_info(envelope)
                .is_some_and(|h| h.kind == Some(crate::ComponentKind::Normal))
        {
            return Err(Error::NotSignableNormal);
        }
        let c = curve();
        let public = multiply(self.scalar.clone(), &c.g, c).ok_or(Error::InvalidPoint)?;
        let z = BigUint::from_bytes_be(&Sha1::digest(&envelope[start..]));
        for _ in 0..128 {
            let mut bytes = [0u8; 20];
            getrandom::fill(&mut bytes).map_err(|_| Error::EntropyUnavailable)?;
            let nonce = BigUint::from_bytes_be(&bytes);
            if nonce.is_zero() || nonce >= c.n {
                continue;
            }
            let ephemeral = multiply(nonce.clone(), &c.g, c).ok_or(Error::InvalidPoint)?;
            let r = ephemeral.0 % &c.n;
            let s = ((&z + &r * &self.scalar) * inverse(&nonce, &c.n)) % &c.n;
            if r.is_zero() || s.is_zero() {
                continue;
            }
            for (offset, value) in [
                (0x170, &r),
                (0x184, &s),
                (0x198, &public.0),
                (0x1ac, &public.1),
            ] {
                let word = value.to_bytes_be();
                if word.len() > 20 {
                    return Err(Error::OperandTooLarge);
                }
                envelope[offset..offset + 20].fill(0);
                envelope[offset + 20 - word.len()..offset + 20].copy_from_slice(&word);
            }
            let expected = if start == 0x200 {
                SignatureCheck::ValidKeyAndCiphertext
            } else {
                SignatureCheck::ValidCiphertextOnly
            };
            return (verify_normal_signature(envelope) == expected)
                .then_some(())
                .ok_or(Error::SelfVerification);
        }
        Err(Error::Randomness)
    }
}

#[derive(Clone)]
struct Point(BigUint, BigUint);

struct Curve {
    p: BigUint,
    a: BigUint,
    b: BigUint,
    n: BigUint,
    g: Point,
}

fn hex(s: &str) -> BigUint {
    BigUint::parse_bytes(s.as_bytes(), 16).expect("fixed curve parameter")
}

fn curve() -> &'static Curve {
    static CURVE: OnceLock<Curve> = OnceLock::new();
    CURVE.get_or_init(|| Curve {
        p: hex("e14639330258ef519cfe5fc1ad99284502874d2b"),
        a: hex("48fa0f23b610f399a80fbc0abe9cecd73c5d1e12"),
        b: hex("2794e57cf726ec2b17ff8ef71016038776faac60"),
        n: hex("e14639330258ef519cfc7f76cbc2926029906bb5"),
        g: Point(
            hex("75a35b281dee9b185654896f6d60b18d9ff954dc"),
            hex("b2c7fbc50a2e8b4b1a8a38577058ba4a005b6208"),
        ),
    })
}

fn sub(a: &BigUint, b: &BigUint, p: &BigUint) -> BigUint {
    if a >= b {
        (a - b) % p
    } else {
        let delta = (b - a) % p;
        if delta.is_zero() {
            BigUint::zero()
        } else {
            p - delta
        }
    }
}

fn inverse(a: &BigUint, p: &BigUint) -> BigUint {
    a.modpow(&(p - BigUint::from(2u8)), p)
}

fn add(left: Option<Point>, right: Option<Point>, c: &Curve) -> Option<Point> {
    let (Point(x1, y1), Point(x2, y2)) = match (left, right) {
        (Some(a), Some(b)) => (a, b),
        (Some(a), None) | (None, Some(a)) => return Some(a),
        (None, None) => return None,
    };
    let p = &c.p;
    if x1 == x2 && (&y1 + &y2) % p == BigUint::zero() {
        return None;
    }
    let slope = if x1 == x2 && y1 == y2 {
        let numerator = (BigUint::from(3u8) * &x1 * &x1 + &c.a) % p;
        let denominator = (BigUint::from(2u8) * &y1) % p;
        if denominator.is_zero() {
            return None;
        }
        numerator * inverse(&denominator, p) % p
    } else {
        let numerator = sub(&y2, &y1, p);
        let denominator = sub(&x2, &x1, p);
        numerator * inverse(&denominator, p) % p
    };
    let x3 = sub(&sub(&(&slope * &slope % p), &x1, p), &x2, p);
    let y3 = sub(&(&slope * sub(&x1, &x3, p) % p), &y1, p);
    Some(Point(x3, y3))
}

fn multiply(mut scalar: BigUint, point: &Point, c: &Curve) -> Option<Point> {
    let mut result = None;
    let mut current = Some(point.clone());
    while !scalar.is_zero() {
        if (&scalar & BigUint::one()) == BigUint::one() {
            result = add(result, current.clone(), c);
        }
        current = add(current.clone(), current, c);
        scalar >>= 1;
    }
    result
}

fn on_curve(q: &Point, c: &Curve) -> bool {
    q.0 < c.p
        && q.1 < c.p
        && (&q.1 * &q.1) % &c.p == ((&q.0 * &q.0 * &q.0) + (&c.a * &q.0) + &c.b) % &c.p
}

fn verifies(digest: &[u8], r: &BigUint, s: &BigUint, q: &Point, c: &Curve) -> bool {
    let z = BigUint::from_bytes_be(digest);
    let w = inverse(s, &c.n);
    let u1 = (&z * &w) % &c.n;
    let u2 = (r * &w) % &c.n;
    let x = add(multiply(u1, &c.g, c), multiply(u2, q, c), c);
    x.is_some_and(|point| point.0 % &c.n == *r)
}

/// Check the two signed ranges used by OEM Normal envelopes. `Invalid` means
/// this curve is recognized but the signature is wrong for both ranges.
pub fn verify_normal_signature(data: &[u8]) -> SignatureCheck {
    if data.len() < 0x10200 + 20
        || !super::is_envelope(data)
        || !super::header_info(data).is_some_and(|h| h.kind == Some(crate::ComponentKind::Normal))
    {
        return SignatureCheck::Unsupported;
    }
    let c = curve();
    let q = Point(
        BigUint::from_bytes_be(&data[0x198..0x1ac]),
        BigUint::from_bytes_be(&data[0x1ac..0x1c0]),
    );
    if !on_curve(&q, c) {
        return SignatureCheck::Unsupported;
    }
    let r = BigUint::from_bytes_be(&data[0x170..0x184]);
    let s = BigUint::from_bytes_be(&data[0x184..0x198]);
    if r.is_zero() || s.is_zero() || r >= c.n || s >= c.n {
        return SignatureCheck::Invalid;
    }
    for (offset, valid) in [
        (0x200, SignatureCheck::ValidKeyAndCiphertext),
        (0x10200, SignatureCheck::ValidCiphertextOnly),
    ] {
        let digest = Sha1::digest(&data[offset..]);
        if verifies(&digest, &r, &s, &q, c) {
            return valid;
        }
    }
    SignatureCheck::Invalid
}

#[cfg(test)]
#[path = "signature_tests.rs"]
mod tests;
