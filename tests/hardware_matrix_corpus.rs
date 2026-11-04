//! Generate the hardware matrix from the private hoard and check its invariants.
//!
//! Private-runner job:
//! `PIONEER_HOARD=<firmware-extractor hoard> cargo test --release --all-features
//! --test hardware_matrix_corpus -- --ignored --nocapture`.
//! Optionally `PIONEER_MATRIX_OUT=<path>.html` keeps the generated page.
//!
//! The page model is built exactly as `examples/hardware_matrix` builds it.
//! Every held package must be listed; every distinct Normal must be analyzed or
//! reported as undecodable; family IDs must equal the update path's families;
//! no family may cross a platform; unresolved images must carry their reasons;
//! and no pair inside one matching family may be admitted with a phase
//! correction unless its complete sled mechanism bundle is bound and identical.
#![cfg(feature = "envelope")]
#[path = "../examples/hardware_matrix/page.rs"]
mod page;

use pioneer_optical::compatibility::{Correction, Firmware};
use pioneer_optical::filters::{phase::bundle, Finding, Role};
use std::collections::{BTreeMap, BTreeSet};

struct Held {
    as_is: String,
    hardware: String,
    normal: Vec<u8>,
    kernel: Option<Vec<u8>>,
}
impl Held {
    fn firmware(&self) -> Firmware<'_> {
        Firmware {
            hardware: &self.hardware,
            normal: &self.normal,
            kernel: self.kernel.as_deref(),
        }
    }
}

#[test]
#[ignore = "requires PIONEER_HOARD (private firmware hoard); private-runner job"]
fn generated_matrix_holds_its_invariants_over_the_hoard() {
    let root = std::path::PathBuf::from(std::env::var("PIONEER_HOARD").expect("PIONEER_HOARD"));
    let (packages, index) = page::hoard_packages(&root).unwrap();
    let mut mismatches = Vec::new();
    let mut normalized = BTreeMap::new();
    let (analyses, failures) = page::analyze_hoard(&root, &packages, |_, decoded, analysis| {
        let kernel = decoded.kernel.as_ref();
        // The page's family is the update path's matching family. `Family`
        // displays without leading zeros; the page pads to 16 digits.
        let page = analysis
            .candidate
            .as_deref()
            .map(|c| u64::from_str_radix(c, 16).unwrap());
        let number =
            |f: pioneer_optical::image::Family| u64::from_str_radix(&f.to_string(), 16).unwrap();
        let family = pioneer_optical::image::family_with_context(
            &decoded.normal.image,
            &analysis.hardware,
            kernel.map(|k| k.image.as_slice()),
        )
        .map(number);
        if family != page {
            mismatches.push(format!(
                "{}: page {:?} update path {family:?}",
                analysis.component, analysis.candidate
            ));
        }
        if let Some(k) = kernel {
            if let Some(f) = decoded.normal.family_with_kernel(k) {
                if Some(number(f)) != page {
                    mismatches.push(format!("{}: Envelope family {f}", analysis.component));
                }
            }
        }
        if analysis.as_is.is_some() && analysis.as_is != analysis.candidate {
            normalized.insert(
                analysis.component.clone(),
                Held {
                    as_is: analysis.as_is.clone().unwrap(),
                    hardware: analysis.hardware.clone(),
                    normal: decoded.normal.image.clone(),
                    kernel: kernel.map(|k| k.image.clone()),
                },
            );
        }
    });
    let source = page::Source {
        crate_version: env!("CARGO_PKG_VERSION").into(),
        revision: "corpus-test".into(),
        hoard: format!("sha256:{}", page::sha256(&index)),
    };
    let data = page::data(&packages, &analyses, &failures, &source, None).unwrap();
    let html = page::render(&data);
    if let Some(out) = std::env::var_os("PIONEER_MATRIX_OUT") {
        std::fs::write(out, &html).unwrap();
    }
    eprintln!(
        "{} packages, {} images, {} with family ID, {} undecodable",
        packages.len(),
        analyses.len(),
        data["summary"]["known"],
        failures.len()
    );

    // Every package is listed, every distinct Normal is analyzed or reported.
    assert_eq!(data["records"].as_array().unwrap().len(), packages.len());
    let components: BTreeSet<_> = packages.iter().map(|p| p.component.as_str()).collect();
    let covered: BTreeSet<_> = analyses
        .iter()
        .map(|a| a.component.as_str())
        .chain(failures.iter().map(|f| f.component.as_str()))
        .collect();
    assert_eq!(components, covered);
    for component in &components {
        assert!(
            html.contains(component),
            "{component} missing from the page"
        );
    }

    let mut platforms: BTreeMap<&str, BTreeSet<String>> = BTreeMap::new();
    for a in &analyses {
        // A family ID exists exactly when every hardware finding is established.
        let open: Vec<_> = a
            .filters
            .iter()
            .filter(|f| {
                f.role == Role::Hardware
                    && matches!(f.finding, Finding::Unresolved(_) | Finding::Conflicting(_))
            })
            .collect();
        let domain = pioneer_optical::filters::identity::Domain::from_hardware(&a.hardware);
        if a.as_is.is_some() != a.candidate.is_some()
            || (domain.is_some() && a.candidate.is_none() != !open.is_empty())
        {
            mismatches.push(format!("{}: identity/finding disagreement", a.component));
        }
        if open.iter().any(|f| f.evidence.trim().is_empty()) {
            mismatches.push(format!("{}: unresolved without a reason", a.component));
        }
        if let Some(c) = &a.candidate {
            platforms
                .entry(c)
                .or_default()
                .insert(page::platform(&a.hardware));
        }
    }
    for (family, set) in &platforms {
        if set.len() > 1 {
            mismatches.push(format!("{family}: crosses platforms {set:?}"));
        }
    }

    // Phase corrections inside a matching family need a bound, identical bundle.
    let family: BTreeMap<&str, &str> = analyses
        .iter()
        .filter_map(|a| Some((a.component.as_str(), a.candidate.as_deref()?)))
        .collect();
    // Only pairs whose as-is identities differ can plan a phase edit.
    let pairs: Vec<_> = normalized
        .iter()
        .flat_map(|(a, x)| normalized.iter().map(move |(b, y)| (a, x, b, y)))
        .filter(|(a, x, b, y)| x.as_is != y.as_is && family[a.as_str()] == family[b.as_str()])
        .collect();
    let next = std::sync::atomic::AtomicUsize::new(0);
    let found = std::sync::Mutex::new(Vec::new());
    std::thread::scope(|scope| {
        for _ in 0..std::thread::available_parallelism().map_or(4, |n| n.get()) {
            scope.spawn(|| loop {
                let i = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let Some((a, x, b, y)) = pairs.get(i) else {
                    break;
                };
                let Ok(plan) = pioneer_optical::compatibility::plan(x.firmware(), y.firmware())
                else {
                    continue;
                };
                if plan
                    .corrections()
                    .iter()
                    .any(|c| matches!(c, Correction::Phase { .. }))
                {
                    let bound = |h: &Held| bundle::bind(&h.normal).map(|b| b.without_coil());
                    if !matches!((bound(x), bound(y)), (Ok(p), Ok(q)) if p == q) {
                        found
                            .lock()
                            .unwrap()
                            .push(format!("{a} -> {b}: phase admitted without bundle"));
                    }
                }
            });
        }
    });
    let mut found = found.into_inner().unwrap();
    found.sort();
    eprintln!("{} same-family phase pairs planned", pairs.len());
    mismatches.extend(found);
    assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
}
