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
mod tests {
    use super::*;

    #[test]
    fn self_signed_envelope_passes_mathematical_verification_only() {
        // This deliberately exercises the host verifier, not the drive's
        // unproved public-key trust policy.
        let c = curve();
        let info = super::super::HeaderInfo {
            id: "PIONEER BDR-US04".into(),
            model: "BDR-US04".into(),
            revision: "1.14".into(),
            hardware_version: "SAT 8A10".into(),
            kernel_version: "GENERAL".into(),
            destination: "GENERAL".into(),
            generated_date: "20/06/15".into(),
            kernel_version2: "0000".into(),
            kind: Some(crate::ComponentKind::Normal),
        };
        let opaque = super::super::HeaderOpaque {
            id_left_padding: 0,
            prevalidation: [0; 0x10],
            validation: [0; 0x50],
            extension: [0; 0x30],
            filename: *b"S8A10001.114\0\0\0\0",
        };
        let mut envelope = super::super::build_header(&info, &opaque).unwrap().to_vec();
        envelope.extend(vec![0x5au8; 0x10000 + 0x100]);
        let private = BigUint::from(5u8);
        let nonce = BigUint::from(7u8);
        let public = multiply(private.clone(), &c.g, c).unwrap();
        let ephemeral = multiply(nonce.clone(), &c.g, c).unwrap();
        let r = ephemeral.0 % &c.n;
        let z = BigUint::from_bytes_be(&Sha1::digest(&envelope[0x200..]));
        let s = ((z + &r * &private) * inverse(&nonce, &c.n)) % &c.n;
        assert!(!r.is_zero() && !s.is_zero());
        for (offset, value) in [
            (0x170, &r),
            (0x184, &s),
            (0x198, &public.0),
            (0x1ac, &public.1),
        ] {
            let bytes = value.to_bytes_be();
            envelope[offset + 20 - bytes.len()..offset + 20].copy_from_slice(&bytes);
        }
        assert_eq!(
            verify_normal_signature(&envelope),
            SignatureCheck::ValidKeyAndCiphertext
        );
        envelope[0x10200] ^= 1;
        assert_eq!(verify_normal_signature(&envelope), SignatureCheck::Invalid);
    }

    #[test]
    fn ud04_oem_signatures_verify_against_fixed_known_answers() {
        let c = curve();
        let q = Point(
            hex("972e1cb6549e0599e69cb83a1f4718d97eb84a7b"),
            hex("2f289bdef9f429a15b2bfdf883a4d46795abce57"),
        );
        assert!(on_curve(&c.g, c));
        assert!(on_curve(&q, c));
        assert!(multiply(c.n.clone(), &c.g, c).is_none());
        for (digest, r, s) in [
            (
                "b0dcf6ae726aa7d600cb800d4e90cfea21d3747a",
                "40b72ab969671c73a89b532fe0f74892f7e76bc9",
                "0b73531c03558a22d68057d48976ac4eee0c5c9e",
            ),
            (
                "75a814fe90ec7fb07ba97f03889483c50134f9f9",
                "2b8852d0f4d76dd506ddee0ef222a184709e7afd",
                "02a13820b887e8ee9df62fc8bdbfddb0dc2abdbc",
            ),
        ] {
            let digest = hex(digest).to_bytes_be();
            assert!(verifies(&digest, &hex(r), &hex(s), &q, c));
            let mut changed = digest.clone();
            changed[0] ^= 1;
            assert!(!verifies(&changed, &hex(r), &hex(s), &q, c));
        }
    }

    fn normal_envelope() -> Vec<u8> {
        let info = super::super::HeaderInfo {
            id: "PIONEER BDR-US04".into(),
            model: "BDR-US04".into(),
            revision: "1.14".into(),
            hardware_version: "SAT 8A10".into(),
            kernel_version: "GENERAL".into(),
            destination: "GENERAL".into(),
            generated_date: "20/06/15".into(),
            kernel_version2: "0000".into(),
            kind: Some(crate::ComponentKind::Normal),
        };
        let opaque = super::super::HeaderOpaque {
            id_left_padding: 0,
            prevalidation: [0; 0x10],
            validation: [0; 0x50],
            extension: [0; 0x30],
            filename: [0; 0x10],
        };
        let mut envelope = super::super::build_header(&info, &opaque).unwrap().to_vec();
        envelope.extend(vec![0x5au8; 0x10000 + 0x100]);
        envelope
    }

    #[test]
    fn from_bytes_rejects_zero_and_out_of_range_scalars() {
        assert!(SigningKey::from_bytes([0u8; 20]).is_none());
        let mut n = [0u8; 20];
        let order = curve().n.to_bytes_be();
        n[20 - order.len()..].copy_from_slice(&order); // scalar == n, must be rejected
        assert!(SigningKey::from_bytes(n).is_none());
        let mut small = [0u8; 20];
        small[19] = 7;
        assert!(SigningKey::from_bytes(small).is_some());
    }

    #[test]
    fn on_curve_rejects_points_off_the_curve() {
        let c = curve();
        assert!(on_curve(&c.g, c));
        let off = Point(c.g.0.clone(), &c.g.1 + BigUint::one());
        assert!(!on_curve(&off, c));
        // Coordinates at or beyond the field modulus are rejected.
        let too_big = Point(c.p.clone(), c.g.1.clone());
        assert!(!on_curve(&too_big, c));
    }

    #[test]
    fn verify_classifies_unsupported_and_invalid_inputs() {
        let c = curve();
        // Too short.
        assert_eq!(
            verify_normal_signature(&[0u8; 16]),
            SignatureCheck::Unsupported
        );
        // Long enough but not a Pioneer envelope.
        assert_eq!(
            verify_normal_signature(&vec![0u8; 0x10300]),
            SignatureCheck::Unsupported
        );
        // Valid Normal envelope, but the public point is not on the curve.
        let mut env = normal_envelope();
        env[0x198] = 0xff; // corrupt the public X coordinate region
        assert_eq!(verify_normal_signature(&env), SignatureCheck::Unsupported);
        // Point on curve (the generator) but r == 0 -> Invalid.
        let mut env = normal_envelope();
        for (offset, value) in [(0x198, &c.g.0), (0x1ac, &c.g.1)] {
            let word = value.to_bytes_be();
            env[offset + 20 - word.len()..offset + 20].copy_from_slice(&word);
        }
        // r and s left as zero -> Invalid (point recognized, signature wrong).
        assert_eq!(verify_normal_signature(&env), SignatureCheck::Invalid);
    }

    #[test]
    fn random_key_signs_both_ranges_and_short_envelope_is_rejected() {
        let key = SigningKey::random().unwrap();
        let mut env = normal_envelope();
        key.sign_normal(&mut env).unwrap();
        assert_eq!(
            verify_normal_signature(&env),
            SignatureCheck::ValidKeyAndCiphertext
        );
        let mut env2 = normal_envelope();
        key.sign_normal_ciphertext_only(&mut env2).unwrap();
        assert_eq!(
            verify_normal_signature(&env2),
            SignatureCheck::ValidCiphertextOnly
        );
        // An envelope shorter than 0x10200 + 20 cannot be signed.
        let mut short = normal_envelope();
        short.truncate(0x10200 + 10);
        assert!(key.sign_normal(&mut short).is_err());
    }

    fn envelope_of(file_type: crate::ComponentKind, len: usize) -> Vec<u8> {
        let info = super::super::HeaderInfo {
            id: "PIONEER BDR-US04".into(),
            model: "BDR-US04".into(),
            revision: "1.14".into(),
            hardware_version: "SAT 8A10".into(),
            kernel_version: "GENERAL".into(),
            destination: "GENERAL".into(),
            generated_date: "20/06/15".into(),
            kernel_version2: "0000".into(),
            kind: Some(file_type),
        };
        let opaque = super::super::HeaderOpaque {
            id_left_padding: 0,
            prevalidation: [0; 0x10],
            validation: [0; 0x50],
            extension: [0; 0x30],
            filename: [0; 0x10],
        };
        let mut env = super::super::build_header(&info, &opaque).unwrap().to_vec();
        env.resize(len, 0x5a);
        env
    }

    #[test]
    fn sign_boundary_length_and_exact_error_messages() {
        let key = SigningKey::random().unwrap();
        // Exactly the minimum length (0x10200 + 20) must sign and verify.
        let mut min = envelope_of(crate::ComponentKind::Normal, 0x10200 + 20);
        key.sign_normal(&mut min).unwrap();
        assert_eq!(
            verify_normal_signature(&min),
            SignatureCheck::ValidKeyAndCiphertext
        );
        // One byte shorter is rejected with the length error, not a signing error:
        // distinguishes the `< 0x10200 + 20` boundary (==,<=) and `+ 20 -> - 20`.
        let mut too_short = envelope_of(crate::ComponentKind::Normal, 0x10200 + 19);
        assert_eq!(
            key.sign_normal(&mut too_short),
            Err(Error::NotSignableNormal)
        );
        let mut just_header = envelope_of(crate::ComponentKind::Normal, 0x10200);
        assert_eq!(
            key.sign_normal(&mut just_header),
            Err(Error::NotSignableNormal)
        );
        // A non-Normal envelope is rejected with the same length/identity error
        // (isolates the file-type `||` branch).
        let mut kernel = envelope_of(crate::ComponentKind::Kernel, 0x10200 + 40);
        assert_eq!(key.sign_normal(&mut kernel), Err(Error::NotSignableNormal));
    }

    #[test]
    fn verify_length_and_filetype_guards_are_exact() {
        let c = curve();
        // A fully valid signature in an envelope of exactly the minimum length
        // verifies -> isolates the `len < 0x10200 + 20` boundary (==, <=).
        let key = SigningKey::random().unwrap();
        let mut min = envelope_of(crate::ComponentKind::Normal, 0x10200 + 20);
        key.sign_normal(&mut min).unwrap();
        assert_eq!(
            verify_normal_signature(&min),
            SignatureCheck::ValidKeyAndCiphertext
        );

        // An envelope of length 0x10200 (below the window) with an on-curve point
        // must report Unsupported, not fall through to Invalid. This distinguishes
        // the `+ 20 -> - 20` mutant (which would proceed and return Invalid).
        let mut shortish = envelope_of(crate::ComponentKind::Normal, 0x10200);
        for (offset, value) in [(0x198, &c.g.0), (0x1ac, &c.g.1)] {
            let word = value.to_bytes_be();
            shortish[offset + 20 - word.len()..offset + 20].copy_from_slice(&word);
        }
        assert_eq!(
            verify_normal_signature(&shortish),
            SignatureCheck::Unsupported
        );

        // A long-enough Kernel-type envelope with an on-curve point must be
        // Unsupported (not Normal); isolates the file-type `||` branch.
        let mut kernel = envelope_of(crate::ComponentKind::Kernel, 0x10200 + 40);
        for (offset, value) in [(0x198, &c.g.0), (0x1ac, &c.g.1)] {
            let word = value.to_bytes_be();
            kernel[offset + 20 - word.len()..offset + 20].copy_from_slice(&word);
        }
        assert_eq!(
            verify_normal_signature(&kernel),
            SignatureCheck::Unsupported
        );
    }

    fn put(env: &mut [u8], offset: usize, value: &BigUint) {
        let bytes = value.to_bytes_be();
        assert!(bytes.len() <= 20);
        env[offset..offset + 20].fill(0);
        env[offset + 20 - bytes.len()..offset + 20].copy_from_slice(&bytes);
    }

    #[test]
    fn scalar_s_not_reduced_below_n_is_invalid() {
        // s + n verifies mathematically (inverse is mod n), so only the range
        // guard rejects it.
        let c = curve();
        let private = BigUint::from(5u8);
        let public = multiply(private.clone(), &c.g, c).unwrap();
        let mut env = normal_envelope();
        let z = BigUint::from_bytes_be(&Sha1::digest(&env[0x200..]));
        let mut found = None;
        for k in 1u32..400 {
            let nonce = BigUint::from(k);
            let r = multiply(nonce.clone(), &c.g, c).unwrap().0 % &c.n;
            let s = ((&z + &r * &private) * inverse(&nonce, &c.n)) % &c.n;
            if (&s + &c.n).bits() <= 160 {
                found = Some((r, s));
                break;
            }
        }
        let (r, s) = found.expect("a small s exists");
        put(&mut env, 0x170, &r);
        put(&mut env, 0x184, &s);
        put(&mut env, 0x198, &public.0);
        put(&mut env, 0x1ac, &public.1);
        assert_eq!(
            verify_normal_signature(&env),
            SignatureCheck::ValidKeyAndCiphertext
        );
        put(&mut env, 0x184, &(&s + &c.n));
        assert_eq!(verify_normal_signature(&env), SignatureCheck::Invalid);
    }

    #[test]
    fn add_distinguishes_doubling_negation_and_distinct_points() {
        let c = curve();
        let g = c.g.clone();
        // P + (-P) is the point at infinity.
        let neg = Point(g.0.clone(), &c.p - &g.1);
        assert!(add(Some(g.clone()), Some(neg), c).is_none());
        // Doubling matches repeated multiplication.
        let two = multiply(BigUint::from(2u8), &g, c).unwrap();
        let dbl = add(Some(g.clone()), Some(g.clone()), c).unwrap();
        assert_eq!((dbl.0, dbl.1), (two.0, two.1));
        // Distinct x with equal y is NOT a doubling: slope is zero.
        let u = |v: u32| BigUint::from(v);
        let r = add(Some(Point(u(1), u(5))), Some(Point(u(2), u(5))), c).unwrap();
        assert_eq!(r.0, &c.p - u(3));
        assert_eq!(r.1, &c.p - u(5));
        // Equal x with different y (not negations) is not a doubling either.
        let r = add(Some(Point(u(1), u(5))), Some(Point(u(1), u(6))), c).unwrap();
        assert_eq!(r.0, &c.p - u(2));
        assert_eq!(r.1, &c.p - u(5));
        // Different x whose y values sum to p is not infinity.
        let r = add(Some(Point(u(1), u(5))), Some(Point(u(2), &c.p - u(5))), c);
        assert!(r.is_some());
    }

    #[test]
    fn on_curve_rejects_x_equal_to_p() {
        let c = curve();
        // x = p reduces to 0 and y^2 = b has a root (p = 3 mod 4), so only the
        // range check rejects it.
        let y = hex("a514f3b012021ba8ff9777b3d922c4d63501a4de");
        assert_eq!((&y * &y) % &c.p, c.b);
        assert!(!on_curve(&Point(c.p.clone(), y.clone()), c));
        assert!(on_curve(&Point(BigUint::zero(), y), c));
    }

    #[test]
    fn signing_keys_with_short_public_coordinates_work() {
        // Scalar 50 gives a 19-byte public X: padded, not an error.
        let mut d = [0u8; 20];
        d[19] = 50;
        let key = SigningKey::from_bytes(d).unwrap();
        let mut env = normal_envelope();
        key.sign_normal(&mut env).unwrap();
        assert_eq!(
            verify_normal_signature(&env),
            SignatureCheck::ValidKeyAndCiphertext
        );
        assert_eq!(env[0x198], 0);
        assert_eq!(env[0x199], 0xc5);
    }

    #[test]
    fn signing_key_debug_hides_the_scalar() {
        let key = SigningKey::from_bytes([1; 20]).unwrap();
        assert_eq!(std::format!("{key:?}"), "SigningKey { .. }");
    }
}
