//! Code-declared hardware-matrix rules agree with the code that enforces them.
//!
//! Each registered owner declares its rules (`Filter::rules`); the generated
//! hardware matrix page renders them verbatim. These checks pin that every
//! statement there is backed by the owner's actual decisions. The per-image
//! families are checked against the private hoard by the ignored
//! `hardware_matrix_corpus` test.
use crate::compatibility::{Error, Firmware};
use crate::filters::identity::Domain;
use crate::filters::phase::{bundle, native, FILTER as PHASE};
use crate::filters::{Assessment, Context, Correctability, Filter, Role, Transition, Value};

fn rules(id: &str) -> &'static crate::filters::Rules {
    crate::filters::filters()
        .iter()
        .find(|f| f.id() == id)
        .and_then(|f| f.rules())
        .unwrap()
}

#[test]
fn every_registered_filter_declares_rules_matching_its_behaviour() {
    let empty = |hardware| {
        Context::new(Firmware {
            hardware,
            normal: &[],
            kernel: None,
        })
    };
    for filter in crate::filters::filters() {
        let rules = filter.rules().expect("registered filter declares rules");
        assert!(!rules.description.trim().is_empty(), "{}", filter.id());
        assert!(!rules.correction.trim().is_empty(), "{}", filter.id());
        assert!(rules.policies.iter().all(|p| !p.text.trim().is_empty()));
        if rules.correctability == Correctability::Operational {
            assert_eq!(rules.role, Role::Operational, "{}", filter.id());
        }
        for domain in Domain::ALL {
            let hardware = match domain {
                Domain::Sat1 => "SAT 1050",
                Domain::H8Sat => "SAT 8600",
                Domain::Ata => "ATA 0005",
                Domain::Scsi => "SCSI0001",
            };
            let context = empty(hardware);
            assert_eq!(filter.inspect(&context).role, rules.role, "{}", filter.id());
            if rules.correctability != Correctability::Never {
                continue;
            }
            // Declared never-correctable: a known difference refuses, a match passes.
            let at = |value| Assessment::known(filter.id(), rules.role, Value::U8(value), "test");
            let transition = Transition {
                installed: &context,
                target: &context,
            };
            assert!(filter.plan(&transition, &at(1), &at(2)).is_err());
            assert!(matches!(filter.plan(&transition, &at(1), &at(1)), Ok(None)));
        }
    }
    assert_eq!(
        rules("persistent-storage-geometry").correctability,
        Correctability::Never
    );
    assert_eq!(rules("phase").correctability, Correctability::Guarded);
    assert_eq!(
        rules("startup-prerequisite").correctability,
        Correctability::Guarded
    );
}

#[test]
fn identity_partitions_platforms_and_documents_it() {
    assert_eq!(Domain::ALL.len(), 4);
    for domain in Domain::ALL {
        assert!(crate::filters::identity::PARTITION.contains(domain.label()));
    }
    let mut body = alloc::vec![0xff; 0x2000];
    crate::image::matrix::install_test_contract(&mut body, 0x12);
    let family = |hardware| crate::image::family_with_context(&body, hardware, None);
    assert!(family("SAT 8600").is_some());
    assert_eq!(family("SAT 8600"), family("SAT 8801"));
    assert_eq!(family("SAT 8600"), family("SAT 9600"));
    assert_ne!(family("SAT 8600"), family("SAT 1046"));
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
fn sat1_phase_correction_binds_native_output_programs() {
    assert!(rules("phase")
        .policies_for(Domain::Sat1)
        .any(|p| p.domains == [Domain::Sat1] && p.text.contains("complete native output")));
    let (direct, swapped) = split_word(false);
    for (a, b) in [(&direct, &swapped), (&swapped, &direct)] {
        assert_eq!(phase_plan("SAT 1050", a, b), Ok(true));
    }
}

#[test]
fn phase_output_mapping_preserves_independent_mechanism_properties() {
    assert!(rules("phase")
        .policies_for(Domain::H8Sat)
        .any(|p| p.text.contains("No donor tables")));
    for hardware in ["SAT 8A10", "SAT 9621"] {
        for bound in [false, true] {
            let (direct, swapped) = split_word(bound);
            assert_eq!(phase_plan(hardware, &direct, &swapped), Ok(true));
            assert_eq!(phase_plan(hardware, &swapped, &direct), Ok(true));
            assert_eq!(phase_plan(hardware, &direct, &direct), Ok(false));
        }
    }
}

#[test]
fn layout_is_required_and_never_corrected() {
    let declared = rules("persistent-parameter-layout");
    assert_eq!(declared.role, Role::Hardware);
    assert_eq!(declared.correctability, Correctability::Never);
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
fn startup_rules_state_the_kernel_getter_refusal() {
    for domain in [Domain::Sat1, Domain::H8Sat] {
        assert!(rules("startup-prerequisite")
            .policies_for(domain)
            .any(|p| p.text.contains("Kernel-resident getter")));
    }
}

#[test]
fn matching_family_normalizes_supported_phase_mapping() {
    // Family = registered candidate key: built only from facts no owner
    // corrects. A phase-only difference shares the family; the phase owner
    // preserves the target mechanism while mapping its native output channels.
    let contract = |convention| {
        let mut body = alloc::vec![0xff; 0x2000];
        crate::image::matrix::install_test_contract(&mut body, 0x12);
        body[0x680..0x694].copy_from_slice(&[
            0x79, 0, 0, 0x9f, 0x5e, 0x41, 0x10, 0, 0x79, 0x20, 0xfe, 0x24, 0x47, 6, 0xf8, 1, 0x5e,
            0x41, 0x06, 0xa0,
        ]);
        body[0x6a0..0x6a6].copy_from_slice(&[0x5e, 0x40, 0x0a, 0x1a, 0x54, 0x70]);
        body[0xc00..0xd00].fill(0xff);
        body[0xf00..0x1000].fill(0xff);
        bundle::tests::install(
            &mut body,
            0xc00,
            0xf00,
            [0xd00 + 32, 0xd00 + 160],
            convention,
        );
        body
    };
    let direct = contract(bundle::tests::Convention::Direct);
    let coil_only = native::correct_pair(&direct, native::Assignment::Swapped).unwrap();
    let mirrored = native::correct_pair(
        &contract(bundle::tests::Convention::Mirrored),
        native::Assignment::Swapped,
    )
    .unwrap();
    let family = |body: &[u8]| crate::image::family_with_context(body, "SAT 8600", None);
    let as_is = |body: &[u8]| {
        crate::image::matrix::discover("SAT 8600", body, None)
            .unwrap()
            .as_is
    };
    assert!(family(&direct).is_some());
    assert_eq!(family(&direct), family(&coil_only));
    assert_eq!(family(&direct), family(&mirrored));
    assert_ne!(as_is(&direct), as_is(&coil_only));
    let firmware = |normal| Firmware {
        hardware: "SAT 8600",
        normal,
        kernel: None,
    };
    for (a, b) in [(&direct, &mirrored), (&mirrored, &direct)] {
        assert!(crate::compatibility::plan(firmware(a), firmware(b)).is_ok());
    }
    assert!(crate::compatibility::plan(firmware(&direct), firmware(&coil_only)).is_ok());
}
