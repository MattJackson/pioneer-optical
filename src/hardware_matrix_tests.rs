//! Conformance of code decisions with the owner's hardware matrix.
//!
//! `tests/fixtures/hardware-matrix.json` is extracted verbatim from the matrix
//! HTML by `tests/support/extract_hardware_matrix.py` (source SHA-256 recorded
//! in the fixture). These CI checks pin every policy the matrix states that can
//! be exercised without held firmware; the per-image family hashes are checked
//! against the private hoard by the ignored `hardware_matrix_corpus` test.
use crate::compatibility::{Error, Firmware};
use crate::filters::phase::{bundle, native, FILTER as PHASE};
use crate::filters::{Context, Filter, Transition};
use serde_json::Value;

fn matrix() -> Value {
    serde_json::from_str(include_str!("../tests/fixtures/hardware-matrix.json")).unwrap()
}

fn hex(value: &Value, len: usize) -> bool {
    value
        .as_str()
        .is_some_and(|s| s.len() == len && s.bytes().all(|b| b.is_ascii_hexdigit()))
}

#[test]
fn fixture_names_the_registered_scheme_owners_and_every_image_once() {
    let m = matrix();
    assert!(hex(&m["source"]["sha256"], 64));
    assert_eq!(m["scheme"], crate::image::MATRIX_FAMILY_SCHEME);
    let mut owners: Vec<_> = crate::filters::filters().iter().map(|f| f.id()).collect();
    owners.sort_unstable();
    let listed: Vec<_> = m["owner_ids"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(owners, listed);
    let rows = m["rows"].as_array().unwrap();
    assert_eq!(rows.len() as u64, m["counts"]["images"].as_u64().unwrap());
    let mut components = std::collections::BTreeSet::new();
    let mut known = 0;
    for row in rows {
        assert!(hex(&row["component"], 64));
        assert!(components.insert(row["component"].as_str().unwrap()));
        // A family identifier exists only when every required value is known.
        match (&row["as_is"], &row["candidate"]) {
            (Value::Null, Value::Null) => {}
            (a, c) if hex(a, 16) && hex(c, 16) => known += 1,
            other => panic!("partial family identifier {other:?}"),
        }
    }
    assert_eq!(known, m["counts"]["known"].as_u64().unwrap());
}

fn split_word(bound: bool) -> (Vec<u8>, Vec<u8>) {
    let mut direct = crate::image::phase::tests::fixture(false);
    direct.resize(0x400, 0xff);
    if bound {
        bundle::tests::install(
            &mut direct,
            0x200,
            0x300,
            [32, 160],
            bundle::tests::Convention::Direct,
        );
    }
    let mirrored = if bound {
        let mut raw = crate::image::phase::tests::fixture(false);
        raw.resize(0x400, 0xff);
        bundle::tests::install(
            &mut raw,
            0x200,
            0x300,
            [32, 160],
            bundle::tests::Convention::Mirrored,
        );
        native::correct_pair(&raw, native::Assignment::Swapped).unwrap()
    } else {
        native::correct_pair(&direct, native::Assignment::Swapped).unwrap()
    };
    (direct, mirrored)
}

fn phase_plan(hardware: &'static str, installed: &[u8], target: &[u8]) -> Result<bool, Error> {
    let context = |normal| {
        Context::new(Firmware {
            hardware,
            normal,
            kernel: None,
        })
    };
    let (installed, target) = (context(installed), context(target));
    PHASE
        .plan(
            &Transition {
                installed: &installed,
                target: &target,
            },
            &PHASE.inspect(&installed),
            &PHASE.inspect(&target),
        )
        .map(|operation| operation.is_some())
}

#[test]
fn sat1_phase_correction_is_suspended() {
    let m = matrix();
    assert!(m["phase_correction_policy"]
        .as_str()
        .unwrap()
        .starts_with("SAT1 correction claims are suspended"));
    // Held SAT1 phase programs bind no sled mechanism bundle.
    let (direct, swapped) = split_word(false);
    for (a, b) in [(&direct, &swapped), (&swapped, &direct)] {
        assert_eq!(phase_plan("SAT 1050", a, b), Err(Error::Unsupported));
    }
}

#[test]
fn phase_order_is_not_changed_on_assignment_evidence_alone() {
    let m = matrix();
    assert!(m["phase_assignment_limits"]
        .as_array()
        .unwrap()
        .iter()
        .any(|l| l == "Changing order is not approved by assignment evidence alone."));
    for hardware in ["SAT 8A10", "SAT 9621"] {
        // Assignment-only evidence (no bound mechanism bundle) refuses.
        let (direct, swapped) = split_word(false);
        assert_eq!(
            phase_plan(hardware, &direct, &swapped),
            Err(Error::Unsupported)
        );
        // A mirrored mechanism (XD08/XS08U, UD02D/UD04 shape) refuses too.
        let (direct, mirrored) = split_word(true);
        assert_eq!(
            phase_plan(hardware, &direct, &mirrored),
            Err(Error::Unsupported)
        );
        assert_eq!(
            phase_plan(hardware, &mirrored, &direct),
            Err(Error::Unsupported)
        );
    }
}

#[test]
fn layout_is_required_and_never_corrected() {
    let m = matrix();
    assert_eq!(m["layout"]["required"], Value::Bool(true));
    assert_eq!(m["layout"]["correctable"], Value::Bool(false));
    let layout = crate::filters::filters()
        .iter()
        .find(|f| f.id() == "persistent-parameter-layout")
        .unwrap();
    let mut a = alloc::vec![0xff; 0x2000];
    crate::image::matrix::install_test_contract(&mut a, 0x12);
    let mut b = a.clone();
    b[0x1000..].fill(0xff);
    crate::image::layout::install_test_layout_variant(&mut b, 0x1000, 5);
    crate::startup::bank::fixture(&mut b);
    let context = |normal| {
        Context::new(Firmware {
            hardware: "SAT 8600",
            normal,
            kernel: None,
        })
    };
    for (x, y) in [(&a, &b), (&b, &a)] {
        let (installed, target) = (context(x), context(y));
        let (i, t) = (layout.inspect(&installed), layout.inspect(&target));
        assert_ne!(i.finding, t.finding);
        assert!(layout
            .plan(
                &Transition {
                    installed: &installed,
                    target: &target,
                },
                &i,
                &t,
            )
            .is_err());
    }
}

#[test]
fn startup_kernel_getter_images_are_listed_unresolved() {
    let m = matrix();
    let needed: Vec<_> = m["sat1_kernel_getter_needed"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(needed.len(), 3);
    for component in &needed {
        assert_eq!(
            m["startup_009f"][component],
            "Kernel needed: 0x404622 getter"
        );
    }
    let flagged = m["startup_009f"]
        .as_object()
        .unwrap()
        .values()
        .filter(|v| v.as_str().is_some_and(|s| s.starts_with("Kernel needed")))
        .count();
    assert_eq!(flagged, needed.len());
}

#[test]
fn bank_conversion_and_212u_213u_are_not_sanctioned() {
    let m = matrix();
    assert_eq!(
        m["bank_conversion_status"],
        "not established as correctable"
    );
    let kat = m["compatibility_kats"]
        .as_array()
        .unwrap()
        .iter()
        .find(|k| k["name"] == "212U ≠ 213U without conversion")
        .unwrap();
    assert_eq!(kat["same"], Value::Bool(false));
}
