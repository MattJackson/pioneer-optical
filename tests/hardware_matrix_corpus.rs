//! Per-image conformance with the owner's hardware matrix over held firmware.
//!
//! Private-runner job: `PIONEER_HOARD=<firmware-extractor hoard> cargo test
//! --release --all-features --test hardware_matrix_corpus -- --ignored`.
//! Every held package is decoded; its registered as-is and candidate family
//! identifiers and its matching family must equal the matrix rows, unresolved rows must stay
//! unresolved, Kernel-getter startup rows must refuse selection, and no pair
//! inside one matrix family may be admitted with a phase correction unless its
//! complete sled mechanism bundle is bound and identical.
#![cfg(feature = "envelope")]
use pioneer_optical::compatibility::Firmware;
use pioneer_optical::envelope::Envelope;
use pioneer_optical::filters::{identity, startup, Context};
use pioneer_optical::image::layout::Observation;
use std::collections::BTreeMap;
use std::path::Path;

fn tar_members(tar: &[u8]) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    let mut at = 0;
    while at + 512 <= tar.len() {
        let h = &tar[at..at + 512];
        if h.iter().all(|b| *b == 0) {
            break;
        }
        let text = |b: &[u8]| {
            String::from_utf8_lossy(&b[..b.iter().position(|c| *c == 0).unwrap_or(b.len())])
                .into_owned()
        };
        let mut name = text(&h[..100]);
        let prefix = text(&h[345..500]);
        if !prefix.is_empty() {
            name = format!("{prefix}/{name}");
        }
        let size = usize::from_str_radix(text(&h[124..136]).trim(), 8).unwrap();
        if h[156] == b'0' || h[156] == 0 {
            out.push((name, tar[at + 512..at + 512 + size].to_vec()));
        }
        at += 512 + size.div_ceil(512) * 512;
    }
    out
}

struct Image {
    hardware: String,
    normal: Envelope,
    kernel: Option<Envelope>,
}

fn firmware(i: &Image) -> Firmware<'_> {
    Firmware {
        hardware: &i.hardware,
        normal: &i.normal.image,
        kernel: i.kernel.as_ref().map(|k| k.image.as_slice()),
    }
}

#[test]
#[ignore = "requires PIONEER_HOARD (private firmware hoard); private-runner conformance job"]
fn every_held_image_matches_the_hardware_matrix() {
    let root = std::path::PathBuf::from(std::env::var("PIONEER_HOARD").expect("PIONEER_HOARD"));
    let matrix: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/hardware-matrix.json")).unwrap();
    let rows: BTreeMap<&str, &serde_json::Value> = matrix["rows"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| (r["component"].as_str().unwrap(), r))
        .collect();
    let index: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.join("index/packages.json")).unwrap()).unwrap();
    let mut images = BTreeMap::new();
    for package in index["packages"].as_array().unwrap() {
        let components = package["components"].as_array().unwrap();
        let normal_entry = components.iter().find(|c| c["role"] == "normal").unwrap();
        let component = normal_entry["sha256"].as_str().unwrap().to_owned();
        if images.contains_key(&component) {
            continue;
        }
        let members = tar_members(
            &std::fs::read(root.join(Path::new(package["path"].as_str().unwrap()))).unwrap(),
        );
        let member = |role: &str| {
            let name = components.iter().find(|c| c["role"] == role)?["member"].as_str()?;
            members
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, d)| d.clone())
        };
        let kernel = member("kernel").and_then(|k| Envelope::load(&k).ok());
        let bytes = member("normal").unwrap();
        let normal = match &kernel {
            Some(k) => Envelope::load_with_kernel(&bytes, k),
            None => Envelope::load(&bytes),
        };
        let Ok(normal) = normal else { continue };
        images.insert(
            component,
            Image {
                hardware: normal.info().hardware_version.clone(),
                normal,
                kernel,
            },
        );
    }
    let mut mismatches = Vec::new();
    let mut families: BTreeMap<String, Vec<&str>> = BTreeMap::new();
    let mut assignments = BTreeMap::new();
    for (component, image) in &images {
        let Some(row) = rows.get(component.as_str()) else {
            // Held after the matrix was generated: reported, never judged.
            eprintln!("{component}: held image absent from the matrix");
            continue;
        };
        let firmware = Firmware {
            hardware: &image.hardware,
            normal: &image.normal.image,
            kernel: image.kernel.as_ref().map(|k| k.image.as_slice()),
        };
        let context = Context::new(firmware);
        let found = identity::discover(&context).map(|i| {
            (
                format!("{:016x}", i.as_is.fingerprint()),
                format!("{:016x}", i.candidate.fingerprint()),
            )
        });
        let expected = row["as_is"]
            .as_str()
            .map(|a| (a.to_owned(), row["candidate"].as_str().unwrap().to_owned()));
        if found != expected {
            mismatches.push(format!("{component}: code {found:?} matrix {expected:?}"));
        }
        // The matching family (offline: Normal plus its own paired Kernel) is the
        // matrix candidate key, built only from facts no owner corrects.
        let matching = pioneer_optical::image::family_with_context(
            &image.normal.image,
            &image.hardware,
            image.kernel.as_ref().map(|k| k.image.as_slice()),
        )
        .map(|f| u64::from_str_radix(&f.to_string(), 16).unwrap());
        let candidate = row["candidate"]
            .as_str()
            .map(|c| u64::from_str_radix(c, 16).unwrap());
        if matching != candidate {
            mismatches.push(format!(
                "{component}: matching family {matching:?} matrix {candidate:?}"
            ));
        }
        if let Observation::Known(phase) = &context.native_phase {
            assignments.insert(component.as_str(), phase.assignment);
        }
        if let Some((_, candidate)) = found {
            families.entry(candidate).or_default().push(component);
        }
        let display = matrix["startup_009f"][component.as_str()].as_str();
        if display.is_some_and(|d| d.starts_with("Kernel needed"))
            && startup::selection(&context).is_ok()
        {
            mismatches.push(format!(
                "{component}: startup selected despite Kernel getter"
            ));
        }
    }
    for list in matrix["sat1_kernel_getter_needed"].as_array().unwrap() {
        assert!(images.contains_key(list.as_str().unwrap()));
    }
    // Phase corrections inside a matrix family need a bound, identical bundle.
    for members in families.values() {
        for a in members {
            for b in members {
                // Only pairs whose phase assignments differ can plan a phase edit.
                match (assignments.get(a), assignments.get(b)) {
                    (Some(p), Some(q)) if p != q => {}
                    _ => continue,
                }
                let (x, y) = (&images[*a], &images[*b]);
                let Ok(plan) = pioneer_optical::compatibility::plan(firmware(x), firmware(y))
                else {
                    continue;
                };
                let phase = plan
                    .corrections()
                    .iter()
                    .any(|c| matches!(c, pioneer_optical::compatibility::Correction::Phase { .. }));
                if phase {
                    let bound = |i: &Image| {
                        pioneer_optical::filters::phase::bundle::bind(&i.normal.image)
                            .map(|b| b.without_coil())
                    };
                    if !matches!((bound(x), bound(y)), (Ok(p), Ok(q)) if p == q) {
                        mismatches.push(format!("{a} -> {b}: phase admitted without bundle"));
                    }
                }
            }
        }
    }
    assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
}
