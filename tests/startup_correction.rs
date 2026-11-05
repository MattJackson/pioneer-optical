//! Native startup correction through the actual owner and original codecs.
#![cfg(feature = "envelope")]
use pioneer_optical::{
    compatibility::Firmware,
    envelope::Envelope,
    filters::{self, Context, Filter, Preparation, Transition},
    image::layout::Observation,
    startup,
};
#[path = "../examples/hardware_matrix/page.rs"]
mod page;

#[test]
#[ignore = "requires PIONEER_HOARD; native startup image and original-codec proof"]
fn held_native_startup_gates_correct_through_original_codecs() {
    let root = std::path::PathBuf::from(std::env::var("PIONEER_HOARD").unwrap());
    let (packages, _) = page::hoard_packages(&root).unwrap();
    let mut seen = std::collections::BTreeSet::new();
    let mut images = Vec::new();
    let mut unresolved = 0;
    for package in packages {
        if !package.hardware.starts_with("SAT ") || !seen.insert(package.component.clone()) {
            continue;
        }
        let Ok(decoded) = page::decode(&root, &package) else {
            continue;
        };
        match startup::bound_selection(&decoded.normal.image) {
            Observation::Known(bound) => images.push((package, decoded, bound)),
            _ => unresolved += 1,
        }
    }
    let owner = &filters::startup::FILTER;
    let mut changed_count = 0;
    let mut same_count = 0;
    let mut failures = Vec::new();
    let mut representation_unproved = Vec::new();
    let mut codec_count = 0;
    // Kept separate from package enumeration so each donor is a held OEM image.
    for (package, target, bound) in &images {
        let donor_entry = images
            .iter()
            .find(|(_, _, other)| {
                other.layout == bound.layout
                    && other.requirement.required != bound.requirement.required
            })
            .unwrap_or_else(|| {
                images
                    .iter()
                    .find(|(p, _, _)| p.component == package.component)
                    .unwrap()
            });
        let (donor_package, donor, donor_bound) = donor_entry;
        let installed = Context::new(Firmware {
            hardware: &donor_package.hardware,
            normal: &donor.normal.image,
            kernel: donor.kernel.as_ref().map(|k| k.image.as_slice()),
        });
        let requested = Context::new(Firmware {
            hardware: &package.hardware,
            normal: &target.normal.image,
            kernel: target.kernel.as_ref().map(|k| k.image.as_slice()),
        });
        let operation = match owner.plan(
            &Transition {
                installed: &installed,
                target: &requested,
            },
            &owner.inspect(&installed),
            &owner.inspect(&requested),
        ) {
            Ok(Some(operation)) => operation,
            other => {
                failures.push(format!(
                    "{} {}: {other:?}",
                    package.hardware, package.component
                ));
                continue;
            }
        };
        assert_eq!(
            operation.required_words(),
            [filters::prerequisites::Word {
                parameter: 0x9f,
                value: donor_bound.requirement.required
            }]
        );
        assert!(owner.parameters(&requested).unwrap().is_empty());
        let preparation = Preparation {
            target: requested.firmware,
            normal: Some(&target.normal),
            kernel: target.kernel.as_ref(),
        };
        let output = operation
            .prepare(&preparation)
            .unwrap_or_else(|e| panic!("{}: {e:?}", package.component));
        if let Some(raw) = output {
            changed_count += 1;
            // Independent whole-image expected answer: the sole changed native
            // operand, plus the original codec's independently repaired checksum.
            let mut expected = target.normal.image.clone();
            let at = (bound.requirement.check_address - 0x410000) as usize;
            let compare = if expected[at + 4] == 0x5e {
                at + 8
            } else if expected[at + 4] == 0x7a {
                at + 12
            } else {
                at + 6
            };
            assert_eq!(&expected[compare..compare + 2], &[0x79, 0x20]);
            expected[compare + 2..compare + 4]
                .copy_from_slice(&donor_bound.requirement.required.to_be_bytes());
            assert_eq!(raw, expected, "{}: whole image diff", package.component);
            let mut repaired = raw;
            let sum = repaired.chunks_exact(4).fold(0u32, |sum, word| {
                sum.wrapping_add(u32::from_be_bytes(word.try_into().unwrap()))
            });
            let old = u32::from_be_bytes(repaired[16..20].try_into().unwrap());
            repaired[16..20].copy_from_slice(&old.wrapping_sub(sum).to_be_bytes());
            let registry: &[&dyn Filter] = &[owner];
            let plan = filters::runner::plan_with(
                &installed,
                &requested,
                filters::runner::Policy::Strict,
                registry,
            );
            let plan = plan.unwrap();
            let result = plan.prepare_with(&preparation, registry);
            if target
                .normal
                .repack_with_checksum(&target.normal.image)
                .is_none()
            {
                assert!(
                    matches!(
                        result,
                        Err(pioneer_optical::compatibility::Error::Representation)
                    ),
                    "missing original codec integrity must refuse"
                );
                representation_unproved.push(format!(
                    "{} {:?} kernel={} declared={:?} bytes={} sum={:#x}",
                    package.component,
                    target.normal.info().layout,
                    target.kernel.is_some(),
                    target.normal.info().declared_size,
                    target.normal.image.len(),
                    target.normal.image.chunks_exact(4).fold(0u32, |s, w| s
                        .wrapping_add(u32::from_be_bytes(w.try_into().unwrap())))
                ));
                continue;
            }
            let actual = result.unwrap().unwrap();
            codec_count += 1;
            assert_eq!(actual, repaired, "shared plan/prepare/verify output");
            operation.verify(&preparation, &repaired).unwrap();
            let encoded = target.normal.repack(&repaired).unwrap();
            let decoded = match &target.kernel {
                Some(kernel) => Envelope::load_with_kernel(&encoded, kernel),
                None => Envelope::load(&encoded),
            }
            .unwrap();
            assert_eq!(decoded.image, repaired);
            assert_eq!(decoded.repack(&decoded.image).unwrap(), encoded);
        } else {
            same_count += 1;
        }
    }
    eprintln!("startup held native bindings={}, changed={changed_count}, same={same_count}, unresolved={unresolved}; codecs={codec_count}, representation_unproved={representation_unproved:?}; failures={failures:?}",images.len());
    assert!(!images.is_empty());
    assert!(changed_count > 0);
    assert!(failures.is_empty(), "{failures:?}");
}
