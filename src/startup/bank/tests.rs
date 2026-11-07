//! CI fixtures for every recognized persistent-bank form, built from the
//! audited instruction shapes. Each asserts the exact recovered contract.
use super::legacy::shapes;
use super::*;
use alloc::{vec, vec::Vec};

fn put(b: &mut [u8], at: usize, bytes: &[u8]) {
    b[at..at + bytes.len()].copy_from_slice(bytes);
}
fn put32(b: &mut [u8], at: usize, value: u32) {
    put(b, at, &value.to_be_bytes());
}
fn put_call(b: &mut [u8], at: usize, target: u32) {
    put(b, at, &[0x5e]);
    put(b, at + 1, &target.to_be_bytes()[1..]);
}

const VALIDATOR: usize = 0x1000;
const LOADER_HELPER: usize = 0x1200;
const CALCULATION: usize = 0x1400;
const MAGIC: u32 = 0x1234_5678;
const SLOT: u32 = 0x00ff_e000;
const MARKERS: [u32; 2] = [0x10, 0x8010];

/// Versioned validator, its loader-flag helper, the capacity base calculation
/// and the adjacent startup calls binding the two.
fn versioned() -> Vec<u8> {
    versioned_with(MAGIC, MARKERS)
}

/// [`versioned`] with another header magic and marker offsets.
pub(super) fn versioned_with(magic: u32, markers: [u32; 2]) -> Vec<u8> {
    let mut b = vec![0; 0x4000];
    let v = VALIDATOR;
    put(
        &mut b,
        v,
        &[
            1, 0, 0x6d, 0xf3, 1, 0x20, 0x6d, 0xf4, 0x79, 0x37, 0, 6, 0x7a, 5,
        ],
    );
    put32(&mut b, v + 0xe, magic);
    put(&mut b, v + 0x12, &[1, 0, 0x6f, 0xf5, 0, 2, 0x7a, 6]);
    put32(&mut b, v + 0x1a, SLOT);
    put(
        &mut b,
        v + 0x1e,
        &[1, 0, 0x69, 0x63, 0x0f, 0xb4, 0x7a, 0x14],
    );
    put32(&mut b, v + 0x26, markers[0] + 4);
    put(
        &mut b,
        v + 0x2a,
        &[0x69, 0x41, 0x69, 0xf1, 1, 0, 0x78, 0x30, 0x6b, 0x22],
    );
    put32(&mut b, v + 0x34, markers[0]);
    put(
        &mut b,
        v + 0x38,
        &[
            0x7a, 0x22, 0xff, 0xff, 0xff, 0xff, 0x46, 0x38, 1, 0, 0x78, 0x30, 0x6b, 0x20,
        ],
    );
    put32(&mut b, v + 0x46, markers[1]);
    put(&mut b, v + 0x4a, &[0x0b, 0x70, 0x46, 0x2a]);
    put(
        &mut b,
        v + 0x4e,
        &[
            0x79, 1, 0, 1, 0x69, 0xf1, 0x0f, 0xf1, 0x79, 2, 0, 1, 0x0f, 0xc0,
        ],
    );
    put_call(&mut b, v + 0x5c, 0x41_3800);
    put(&mut b, v + 0x60, &[1, 0, 0x69, 0x60, 0x7a, 0x10]);
    put32(&mut b, v + 0x66, markers[0]);
    put(&mut b, v + 0x6a, &[0x0f, 0xf1, 0x0b, 0xf1, 0x79, 2, 0, 2]);
    put_call(&mut b, v + 0x72, 0x41_3800);
    put(&mut b, v + 0x76, &[0x40, 0x16]);
    put(
        &mut b,
        v + 0x78,
        &[0x1f, 0xd2, 0x47, 0x12, 1, 0, 0x78, 0x30, 0x6b, 0x20],
    );
    put32(&mut b, v + 0x82, markers[1]);
    put(&mut b, v + 0x86, &[0x1f, 0xd0, 0x47, 4]);
    put_call(&mut b, v + 0x8a, BASE + LOADER_HELPER as u32);
    put(&mut b, v + 0x8e, &[0x79, 0x17, 0, 6]);
    // Loader-flag helper: two wrappers of Kernel services 14 and 1A.
    let h = LOADER_HELPER;
    put(&mut b, h, &[0xf8, 1]);
    put_call(&mut b, h + 2, BASE + 0x1300);
    put(&mut b, h + 6, &[0xf8, 1]);
    put_call(&mut b, h + 8, BASE + 0x1310);
    put(&mut b, h + 12, &[0x18, 0x88]);
    put(&mut b, 0x1300, &[0x5e, 0x40, 0x0a, 0x14, 0x54, 0x70]);
    put(&mut b, 0x1310, &[0x5e, 0x40, 0x0a, 0x1a, 0x54, 0x70]);
    // Capacity calculation storing the runtime base into the validator slot.
    let c = CALCULATION;
    put_call(&mut b, c, 0x41_3900);
    put(&mut b, c + 4, &[0x7a, 1]);
    put32(&mut b, c + 6, 0x0020_0000);
    put(&mut b, c + 10, &[0xa8, 1, 0x46, 4, 0x79, 9, 0, 0x10]);
    put(&mut b, c + 18, &[0x0f, 0x90, 0x0b, 0x70, 0x7a, 0x21]);
    put32(&mut b, c + 24, 0x0020_0000);
    put(&mut b, c + 28, &[0x46, 8, 0x7a, 0x30]);
    put32(&mut b, c + 32, 0x0001_0001);
    put(&mut b, c + 36, &[0x40, 6, 0x7a, 0x30]);
    put32(&mut b, c + 40, 0x0000_8001);
    put(&mut b, c + 44, &[1, 0, 0x6b, 0xa0]);
    put32(&mut b, c + 48, SLOT);
    put(&mut b, c + 52, &[0x54, 0x70]);
    // Startup calls the calculation immediately before the validator.
    put_call(&mut b, 0x1600, BASE + CALCULATION as u32);
    put_call(&mut b, 0x1604, BASE + VALIDATOR as u32);
    b
}

fn versioned_contract() -> Contract {
    Contract {
        magic: MAGIC,
        addresses: Addresses::Capacity {
            when_one: [0xf_8010, 0x10_0010],
            otherwise: [0x1f_0010, 0x1f_8010],
        },
        validation: Validation::RejectMismatch,
    }
}

#[test]
fn versioned_validator_recovers_its_exact_capacity_contract() {
    let b = versioned();
    let guard = discover(&b).unwrap();
    assert_eq!(
        guard,
        Requirement {
            validator: 0x41_1000,
            base_slot: SLOT,
            magic: MAGIC,
            marker_offsets: MARKERS,
            reject_helper: 0x41_1200,
        }
    );
    assert_eq!(guard.stride(), Some(0x8000));
    let layout = guard.layout(&b).unwrap();
    assert_eq!(
        (layout.calculation, layout.capacity_query),
        (0x41_1400, 0x41_3900)
    );
    assert_eq!(layout.when_one.base, 0xf_8000);
    assert_eq!(layout.otherwise.base, 0x1f_0000);
    assert_eq!(analyze(&b), Some(versioned_contract()));
    assert_eq!(
        analyze_pair(&b, None),
        Some(Storage::Versioned(versioned_contract()))
    );
}

#[test]
fn versioned_operands_and_bindings_change_or_refuse_the_contract() {
    // Capacity immediate: a different, still valid, compact base.
    let mut b = versioned();
    put32(&mut b, CALCULATION + 40, 0x0000_4001);
    let Some(Contract {
        addresses: Addresses::Capacity {
            when_one,
            otherwise,
        },
        ..
    }) = analyze(&b)
    else {
        panic!("capacity form not recognized");
    };
    assert_eq!(when_one, [0xf_c010, 0x10_4010]);
    assert_eq!(otherwise, [0x1f_0010, 0x1f_8010]);
    // The register-1 form has no increment and a different compare offset.
    let mut b = versioned();
    let c = CALCULATION;
    put(&mut b, c + 18, &[0x7a, 0x21]);
    put32(&mut b, c + 20, 0x0020_0000);
    put(&mut b, c + 24, &[0x46, 8, 0x7a, 0x31]);
    put32(&mut b, c + 28, 0x0001_0000);
    put(&mut b, c + 32, &[0x40, 6, 0x7a, 0x31]);
    put32(&mut b, c + 36, 0x0000_8000);
    put(&mut b, c + 40, &[1, 0, 0x6b, 0xa1]);
    put32(&mut b, c + 44, SLOT);
    put(&mut b, c + 48, &[0x54, 0x70]);
    b[c + 50..c + 54].fill(0);
    assert_eq!(analyze(&b), Some(versioned_contract()));
    for (what, edit) in [
        ("equal markers", (VALIDATOR + 0x46, MARKERS[0])),
        ("second read differs", (VALIDATOR + 0x82, MARKERS[1] + 2)),
        ("erased magic", (VALIDATOR + 0xe, u32::MAX)),
        ("other slot", (CALCULATION + 48, SLOT + 4)),
    ] {
        let mut b = versioned();
        put32(&mut b, edit.0, edit.1);
        if what == "equal markers" {
            put32(&mut b, VALIDATOR + 0x82, MARKERS[0]);
        }
        assert_eq!(analyze(&b), None, "{what}");
    }
    // The rejection helper must set both loader flags through real wrappers.
    let mut b = versioned();
    b[0x1313] = 0x14;
    assert_eq!(discover(&b), None);
    // The calculation must be the call immediately preceding the validator.
    let mut b = versioned();
    put_call(&mut b, 0x1604, 0x41_3a00);
    assert_eq!(analyze(&b), None);
    // Two validators are never resolved to one of them.
    let mut b = versioned();
    let copy = b[VALIDATOR..VALIDATOR + 0x92].to_vec();
    put(&mut b, 0x2000, &copy);
    assert_eq!(discover(&b), None);
}

/// legacy::fixture with its initializer replaced by a rejecting form whose
/// operands carry the same magic and markers.
fn rejecting(code: &[u8]) -> Vec<u8> {
    let mut b = vec![0; 0x2000];
    super::legacy::fixture(&mut b);
    b[0x1800..0x18f0].fill(0);
    let long = code[1] == 0x20;
    let at = if long { 0x1804 } else { 0x1800 };
    if long {
        put(&mut b, 0x1800, &[1, 0, 0x6d, 0xf3]);
    }
    put(&mut b, at, code);
    put32(&mut b, at + 10, 0xfedc_4321);
    put32(&mut b, at + if long { 0x26 } else { 0x20 }, 0x7d_fffa);
    let tail = at
        + if long {
            0x96
        } else if code[0x5a] == 0x1f {
            0x5a
        } else {
            0x5e
        };
    put32(&mut b, tail + 8, 0x7e_fffa);
    put_call(&mut b, tail + 16, BASE + 0x1a00);
    // Older restart helper: set both loader flags before its restart.
    put(
        &mut b,
        0x1a00,
        &[
            0xf8, 1, 0x6a, 0xa8, 0, 0, 1, 0x42, 0x6a, 0xa8, 0, 0, 1, 0x40, 0x5a, 0x40, 0, 0x10,
        ],
    );
    b
}

#[test]
fn legacy_initializer_and_rejecting_forms_recover_fixed_contracts() {
    let mut b = vec![0; 0x2000];
    super::legacy::fixture(&mut b);
    let initialize = Storage::Versioned(Contract {
        magic: 0xfedc_4321,
        addresses: Addresses::Fixed([0x7d_fffa, 0x7e_fffa]),
        validation: Validation::InitializeAndSelect,
    });
    assert_eq!(analyze_pair(&b, None), Some(initialize));
    let reject = Storage::Versioned(Contract {
        validation: Validation::RejectMismatch,
        ..match initialize {
            Storage::Versioned(c) => c,
            _ => unreachable!(),
        }
    });
    for pattern in [
        shapes::REJECT_SHORT,
        shapes::REJECT_SHORT_ALT,
        shapes::REJECT_LONG,
    ] {
        let b = rejecting(pattern);
        assert_eq!(analyze_pair(&b, None), Some(reject));
        // The restart helper must set the second loader flag.
        let mut helper = b.clone();
        helper[0x1a0d] = 0x41;
        assert_eq!(analyze_pair(&helper, None), None);
        // A changed marker no longer binds to the selector.
        let mut marker = b;
        marker[0x1907] ^= 4;
        assert_eq!(analyze_pair(&marker, None), None);
    }
    assert_eq!(
        check(Some(initialize), Some(reject)),
        Err(Error::ConversionRequired {
            installed: initialize,
            target: reject
        })
    );
}

const HEADERS: [[u32; 2]; 2] = [[0x7d_0000, 0x7d_0004], [0x7e_0000, 0x7e_0004]];
const SEQUENCES: [u32; 2] = [0x7d_0008, 0x7e_0008];
const STATUS: [u32; 2] = [0x7d_000c, 0x7e_000c];

fn state_selector_at(b: &mut [u8], at: usize) {
    put(b, at, shapes::STATE_SELECTOR);
    for (offset, value) in [
        (2, SEQUENCES[0]),
        (8, SEQUENCES[1]),
        (16, HEADERS[0][0]),
        (46, HEADERS[0][1]),
        (34, HEADERS[1][0]),
        (58, HEADERS[1][1]),
        (88, STATUS[0]),
        (112, STATUS[1]),
    ] {
        put32(b, at + offset, value);
    }
}

/// Earlier Normal: the erased-state validator, its restart helper, and the
/// state selector it must agree with.
fn state_normal() -> Vec<u8> {
    let mut b = vec![0; 0x2000];
    let at = 0x400;
    put(&mut b, at, shapes::STATE_NORMAL);
    for (offset, value) in [
        (8, SEQUENCES[0]),
        (18, SEQUENCES[1]),
        (26, HEADERS[0][0]),
        (42, HEADERS[0][1]),
        (54, HEADERS[1][0]),
        (68, HEADERS[1][1]),
        (92, HEADERS[0][1]),
        (106, HEADERS[1][0]),
        (120, HEADERS[1][1]),
    ] {
        put32(&mut b, at + offset, value);
    }
    put_call(&mut b, at + 0x116, BASE + 0x1000);
    put_call(&mut b, at + 0xa0, BASE + at as u32 + 0x11a);
    b[at + 0xa0] = 0x5a;
    put(
        &mut b,
        0x1000,
        &[
            0xf8, 1, 0x6a, 0xa8, 0, 0, 1, 0x42, 0x6a, 0xa8, 0, 0, 1, 0x41, 0xf9, 0x80, 3, 9, 0x5a,
            0x40, 0, 0x10,
        ],
    );
    state_selector_at(&mut b, 0x800);
    put_call(&mut b, 0x100, BASE + 0x400);
    put_call(&mut b, 0x104, BASE + 0x800);
    b
}

#[test]
fn state_banks_recover_headers_sequences_and_status() {
    let state = Storage::StateHeaders {
        headers: HEADERS,
        sequences: SEQUENCES,
        status: STATUS,
    };
    let b = state_normal();
    assert_eq!(analyze_pair(&b, None), Some(state));
    for (what, at) in [
        ("uncalled validator", 0x101),
        ("uncalled selector", 0x105),
        ("restart helper", 0x100d),
        ("early exit target", 0x4a3),
        ("second sequence word", 0x400 + 18 + 3),
        ("bound header reread", 0x400 + 92 + 3),
        ("selector header", 0x800 + 16 + 3),
    ] {
        let mut changed = b.clone();
        changed[at] ^= 2;
        assert_eq!(analyze_pair(&changed, None), None, "{what}");
    }
    // Moving bank 1 consistently in both routines keeps every header and
    // sequence relation, but a non power-of-two spacing is refused.
    let mut spacing = b.clone();
    for at in [18, 54, 68, 106, 120] {
        let at = 0x400 + at;
        let moved = word(&spacing, at).unwrap() + 0x8000;
        put32(&mut spacing, at, moved);
    }
    for at in [8, 34, 58] {
        let at = 0x800 + at;
        let moved = word(&spacing, at).unwrap() + 0x8000;
        put32(&mut spacing, at, moved);
    }
    assert!(super::legacy::state_selector(&spacing, BASE).is_some());
    assert_eq!(analyze_pair(&spacing, None), None);
    assert_eq!(check(Some(state), Some(state)), Ok(()));
    let mut fixed = vec![0; 0x2000];
    super::legacy::fixture(&mut fixed);
    let fixed = analyze_pair(&fixed, None);
    assert!(matches!(
        check(fixed, Some(state)),
        Err(Error::ConversionRequired { .. })
    ));
    assert_eq!(check(None, Some(state)), Err(Error::UnknownInstalled));
    assert_eq!(check(Some(state), None), Err(Error::UnknownTarget));
}

#[test]
fn kernel_owned_banks_recover_selector_and_sequence_contracts() {
    let mut kernel = vec![0; 0x10000];
    state_selector_at(&mut kernel, 0x800);
    put_call(&mut kernel, 0x100, 0x40_0800);
    assert_eq!(
        super::legacy::state_selector(&kernel, 0x40_0000),
        Some(Storage::StateHeaders {
            headers: HEADERS,
            sequences: SEQUENCES,
            status: STATUS,
        })
    );
    // Without a call into the selector there is no contract.
    kernel[0x100] = 0;
    assert_eq!(super::legacy::state_selector(&kernel, 0x40_0000), None);

    let mut kernel = vec![0; 0x10000];
    let at = 0x2000;
    put(&mut kernel, at, &[0x6b, 0x28]);
    put32(&mut kernel, at + 2, 0x7c_fffe);
    put(&mut kernel, at + 6, &[0x6b, 0x20]);
    put32(&mut kernel, at + 8, 0x7d_fffe);
    put(
        &mut kernel,
        at + 12,
        &[
            0x79, 0x28, 0xff, 0xff, 0x47, 0x12, 0x79, 0x20, 0xff, 0xff, 0x47, 4, 0x1d, 8, 0x43, 8,
            0x7a, 0,
        ],
    );
    put32(&mut kernel, at + 30, 0x7c_0000);
    put(&mut kernel, at + 34, &[0x40, 6, 0x7a, 0]);
    put32(&mut kernel, at + 38, 0x7d_0000);
    put(&mut kernel, at + 42, &[0x54, 0x70]);
    put_call(&mut kernel, 0x100, 0x40_2000);
    let sequences = Storage::KernelSequences {
        sequences: [0x7c_fffe, 0x7d_fffe],
        bases: [0x7c_0000, 0x7d_0000],
    };
    assert_eq!(super::legacy::kernel_sequences(&kernel), Some(sequences));
    let mut spacing = kernel.clone();
    // A consistent but non power-of-two bank spacing.
    put32(&mut spacing, at + 2, 0x7d_7ffe);
    put32(&mut spacing, at + 8, 0x7e_fffe);
    put32(&mut spacing, at + 38, 0x7d_8000);
    assert_eq!(super::legacy::kernel_sequences(&spacing), None);
    let mut uncalled = kernel.clone();
    uncalled[0x103] = 2;
    assert_eq!(super::legacy::kernel_sequences(&uncalled), None);
    // Kernel-owned storage needs a recognized receiver and a complete Kernel.
    assert_eq!(analyze_pair(&[0; 0x100], Some(&kernel)), None);
    assert_eq!(analyze_pair(&[0; 0x100], Some(&kernel[..0x8000])), None);
}

/// BDR-212U-style storage (magic FEDC4321, 0x10000-byte banks) and
/// BDR-213U-style storage (magic FEDC4322, 0xC000-byte banks) recovered from
/// native validators. No conversion exists, so the bank gate refuses the pair
/// in both directions under the strict policy and under the Recovery family
/// override (`ExplicitCrossflash`).
#[test]
fn bdr_212u_and_213u_style_banks_never_convert_under_any_policy() {
    use crate::startup::checks::{Checks, Error as StartupError, Policy};
    let u212 = versioned_with(0xfedc_4321, [0xfffa, 0x1_fffa]);
    let u213 = versioned_with(0xfedc_4322, [0xbffa, 0x1_7ffa]);
    assert_eq!(discover(&u212).unwrap().stride(), Some(0x1_0000));
    assert_eq!(discover(&u213).unwrap().stride(), Some(0xc000));
    for (installed, target) in [(&u212, &u213), (&u213, &u212)] {
        let (from, to) = (analyze_pair(installed, None), analyze_pair(target, None));
        assert!(from.is_some() && to.is_some() && from != to);
        let refused = Error::ConversionRequired {
            installed: from.unwrap(),
            target: to.unwrap(),
        };
        assert_eq!(check(from, to), Err(refused));
        let (installed, target) = (
            Checks::discover(installed, None),
            Checks::discover(target, None),
        );
        assert_eq!(installed.plan_to(target), Err(StartupError::Banks(refused)));
        for policy in [Policy::CompatibleBanks, Policy::ExplicitCrossflash] {
            assert_eq!(
                installed.plan_to_with_policy(target, policy),
                Err(StartupError::Banks(refused))
            );
        }
    }
    for same in [&u212, &u213] {
        let kernel = vec![0; 0x10000];
        let checks = Checks::discover(same, Some(&kernel));
        for policy in [Policy::CompatibleBanks, Policy::ExplicitCrossflash] {
            assert!(checks.plan_to_with_policy(checks, policy).is_ok());
        }
    }
}
