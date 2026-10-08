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
