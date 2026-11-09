//! Score every registered filter independently on every directed same-domain
//! pair in a firmware-extractor hoard.
//!
//! Analysis only. Product admission stays `compatibility::plan`, which refuses
//! at the first failing owner; this reports every owner's own verdict so a
//! pair blocked by one filter still shows what every other filter would say.
//!
//! ```text
//! cargo run --release --all-features --example blocker_matrix -- <HOARD> --out <DIR>
//! ```
//! Writes `<DIR>/pairs.tsv` (one row per directed pair, one column per filter)
//! and `<DIR>/summary.json` (per-filter classes, sole-blocker counts, blocker
//! sets, top unresolved reasons, and any disagreement with the product plan).
#[path = "../hardware_matrix/page.rs"]
mod page;

use pioneer_optical::compatibility::{self, Error, Firmware};
use pioneer_optical::filters::{
    self, identity::Domain, Assessment, Comparison, Context, Finding, Transition,
};
use serde_json::{json, Value as Json};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

/// Per-filter tally: classes, blocking pairs, sole-blocker pairs, unresolved reasons.
type Tally = (BTreeMap<String, u64>, u64, u64, BTreeMap<String, u64>);

struct Held {
    component: String,
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

/// Verdict classes. Only `match`, `accepted` and `correctable` let a pair pass.
fn class(
    comparison: &Comparison,
    result: &Result<Option<Box<dyn filters::Operation>>, Error>,
) -> String {
    match result {
        Ok(Some(_)) => "correctable".into(),
        Ok(None) if matches!(comparison, Comparison::Match) => "match".into(),
        Ok(None) => "accepted".into(),
        Err(Error::Incompatible) => "incompatible".into(),
        Err(Error::UnresolvedIdentity) => "unresolved".into(),
        Err(error) => format!("refused:{error:?}"),
    }
}

fn passes(class: &str) -> bool {
    matches!(class, "match" | "accepted" | "correctable")
}

/// The finding that made an owner unresolved, for grouping reasons.
fn reason(installed: &Assessment, target: &Assessment) -> String {
    let side = |a: &Assessment| match &a.finding {
        Finding::Known(_) => None,
        other => Some(format!("{other:?}")),
    };
    let text = side(installed)
        .map(|r| format!("installed {r}"))
        .or_else(|| side(target).map(|r| format!("target {r}")))
        .unwrap_or_else(|| "both known, owner refused".into());
    text.chars().take(200).collect()
}

/// A final missing-input refusal: the owner needs resident/Kernel code and this
/// image's paired Kernel is not held, so the code cannot be read. Using another
/// revision's Kernel would be a guess; the pair is not correctable for this
/// release because that Kernel is missing.
fn missing_kernel(assessment: &Assessment, image: &Held) -> bool {
    image.kernel.is_none()
        && matches!(&assessment.finding, Finding::Unresolved(reason)
            if reason.contains("resident") || reason.contains("ResidentCodeRequired"))
}

fn main() {
    let mut args = std::env::args().skip(1);
    let (mut hoard, mut out) = (None, None);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--out" => out = args.next().map(PathBuf::from),
            _ if hoard.is_none() && !arg.starts_with("--") => hoard = Some(PathBuf::from(arg)),
            _ => {
                eprintln!("usage: blocker_matrix HOARD --out DIR");
                std::process::exit(2)
            }
        }
    }
    let (Some(hoard), Some(out)) = (hoard, out) else {
        eprintln!("usage: blocker_matrix HOARD --out DIR");
        std::process::exit(2)
    };
    std::fs::create_dir_all(&out).expect("create output dir");

    let (packages, _) = page::hoard_packages(&hoard).expect("hoard index");
    let mut held = Vec::new();
    let (_, failures) = page::analyze_hoard(&hoard, &packages, |_, decoded, analysis| {
        held.push(Held {
            component: analysis.component.clone(),
            hardware: analysis.hardware.clone(),
            normal: decoded.normal.image.clone(),
            kernel: decoded.kernel.as_ref().map(|k| k.image.clone()),
        });
    });
    held.sort_by(|a, b| a.component.cmp(&b.component));
    eprintln!(
        "{} images decoded, {} failed to decode",
        held.len(),
        failures.len()
    );

    let registry = filters::filters();
    let ids: Vec<&str> = registry.iter().map(|f| f.id()).collect();

    // Inspect each image once, in parallel, keeping input order.
    let threads = std::thread::available_parallelism().map_or(4, |n| n.get());
    let chunk = held.len().div_ceil(threads).max(1);
    let mut inspected: Vec<(Context<'_>, Vec<Assessment>)> = Vec::with_capacity(held.len());
    std::thread::scope(|scope| {
        let handles: Vec<_> = held
            .chunks(chunk)
            .map(|part| {
                scope.spawn(move || {
                    part.iter()
                        .map(|h| {
                            let context = Context::new(h.firmware());
                            let assessments =
                                registry.iter().map(|f| f.inspect(&context)).collect();
                            (context, assessments)
                        })
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        for handle in handles {
            inspected.extend(handle.join().expect("inspect worker"));
        }
    });
    eprintln!(
        "inspected {} images with {} filters",
        inspected.len(),
        ids.len()
    );

    let domains: Vec<Option<Domain>> = held
        .iter()
        .map(|h| Domain::from_hardware(&h.hardware))
        .collect();
    let mut pairs = Vec::new();
    for a in 0..held.len() {
        for b in 0..held.len() {
            if a != b && domains[a].is_some() && domains[a] == domains[b] {
                pairs.push((a, b));
            }
        }
    }
    eprintln!("{} directed same-domain pairs", pairs.len());

    struct Row {
        a: usize,
        b: usize,
        classes: Vec<String>,
        reasons: Vec<Option<String>>,
    }
    // One owner verdict for (installed a, target b). Exact.
    let verdict = |k: usize, a: usize, b: usize| -> String {
        let transition = Transition {
            installed: &inspected[a].0,
            target: &inspected[b].0,
        };
        let (x, y) = (&inspected[a].1[k], &inspected[b].1[k]);
        class(
            &registry[k].compare(x, y),
            &registry[k].plan(&transition, x, y),
        )
    };

    // Owners decide from the installed side's assessment and cached native
    // observation plus the exact target image, so cache on that key. A random
    // exact sample below checks the assumption per owner; any owner that
    // disagrees is recomputed exactly for every pair.
    let mut key_ids: Vec<BTreeMap<String, u32>> = vec![BTreeMap::new(); ids.len()];
    let installed_key: Vec<Vec<u32>> = (0..held.len())
        .map(|i| {
            (0..ids.len())
                .map(|k| {
                    let key = format!("{:?}|{:?}", inspected[i].1[k], inspected[i].0.native_phase);
                    let next = key_ids[k].len() as u32;
                    *key_ids[k].entry(key).or_insert(next)
                })
                .collect()
        })
        .collect();
    let mut work: BTreeMap<(usize, u32, usize), usize> = BTreeMap::new();
    for &(a, b) in &pairs {
        for (k, &key) in installed_key[a].iter().enumerate() {
            work.entry((k, key, b)).or_insert(a);
        }
    }
    let work: Vec<((usize, u32, usize), usize)> = work.into_iter().collect();
    eprintln!(
        "{} unique owner evaluations (vs {} uncached)",
        work.len(),
        pairs.len() * ids.len()
    );
    let solved = Mutex::new(std::collections::HashMap::with_capacity(work.len()));
    let next = AtomicUsize::new(0);
    std::thread::scope(|scope| {
        for _ in 0..threads {
            scope.spawn(|| {
                let mut local = Vec::new();
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some(&((k, key, b), a)) = work.get(i) else {
                        break;
                    };
                    local.push(((k, key, b), verdict(k, a, b)));
                }
                solved.lock().unwrap().extend(local);
            });
        }
    });
    let solved = solved.into_inner().unwrap();

    // Exact cross-check on a deterministic sample of pairs.
    let mut seed: u64 = 0x9e37_79b9_7f4a_7c15;
    let sample: Vec<(usize, usize)> = (0..pairs.len().min(4000))
        .map(|_| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            pairs[(seed % pairs.len() as u64) as usize]
        })
        .collect();
    let mismatch: Vec<AtomicUsize> = (0..ids.len()).map(|_| AtomicUsize::new(0)).collect();
    let next = AtomicUsize::new(0);
    std::thread::scope(|scope| {
        for _ in 0..threads {
            scope.spawn(|| loop {
                let i = next.fetch_add(1, Ordering::Relaxed);
                let Some(&(a, b)) = sample.get(i) else { break };
                for k in 0..ids.len() {
                    if solved[&(k, installed_key[a][k], b)] != verdict(k, a, b) {
                        mismatch[k].fetch_add(1, Ordering::Relaxed);
                    }
                }
            });
        }
    });
    let mismatch: Vec<usize> = mismatch.iter().map(|m| m.load(Ordering::Relaxed)).collect();
    let exact: Vec<bool> = mismatch.iter().map(|&m| m > 0).collect();
    for (k, &m) in mismatch.iter().enumerate() {
        if m > 0 {
            eprintln!(
                "cache disagreed for {} on {m} sampled pairs; recomputing exactly",
                ids[k]
            );
        }
    }

    let next = AtomicUsize::new(0);
    let rows = Mutex::new(Vec::with_capacity(pairs.len()));
    std::thread::scope(|scope| {
        for _ in 0..threads {
            scope.spawn(|| {
                let mut local = Vec::new();
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some(&(a, b)) = pairs.get(i) else { break };
                    let mut classes = Vec::with_capacity(ids.len());
                    let mut reasons = Vec::with_capacity(ids.len());
                    for k in 0..ids.len() {
                        let c = if exact[k] {
                            verdict(k, a, b)
                        } else {
                            solved[&(k, installed_key[a][k], b)].clone()
                        };
                        let (x, y) = (&inspected[a].1[k], &inspected[b].1[k]);
                        let c = if c == "unresolved"
                            && (missing_kernel(x, &held[a]) || missing_kernel(y, &held[b]))
                        {
                            "missing-input".to_owned()
                        } else {
                            c
                        };
                        reasons.push((!passes(&c)).then(|| reason(x, y)));
                        classes.push(c);
                    }
                    local.push(Row {
                        a,
                        b,
                        classes,
                        reasons,
                    });
                }
                rows.lock().unwrap().extend(local);
            });
        }
    });
    let mut rows = rows.into_inner().unwrap();
    rows.sort_by_key(|r| (r.a, r.b));

    // Cross-check: every pair with no blocker must also pass the product plan.
    let clear: Vec<&Row> = rows
        .iter()
        .filter(|r| r.classes.iter().all(|c| passes(c)))
        .collect();
    let disagreements = Mutex::new(Vec::new());
    let next = AtomicUsize::new(0);
    std::thread::scope(|scope| {
        for _ in 0..threads {
            scope.spawn(|| loop {
                let i = next.fetch_add(1, Ordering::Relaxed);
                let Some(r) = clear.get(i) else { break };
                if let Err(error) = compatibility::plan(held[r.a].firmware(), held[r.b].firmware())
                {
                    disagreements.lock().unwrap().push(json!({
                        "installed": held[r.a].component,
                        "target": held[r.b].component,
                        "product_error": format!("{error:?}"),
                    }));
                }
            });
        }
    });
    let disagreements = disagreements.into_inner().unwrap();

    let mut tsv =
        std::io::BufWriter::new(std::fs::File::create(out.join("pairs.tsv")).expect("pairs.tsv"));
    writeln!(tsv, "installed\ttarget\tdomain\t{}", ids.join("\t")).unwrap();
    let mut per: BTreeMap<&str, Tally> = ids.iter().map(|id| (*id, Default::default())).collect();
    let mut sets: BTreeMap<String, u64> = BTreeMap::new();
    let (mut correctable, mut definite, mut open) = (0u64, 0u64, 0u64);
    for r in &rows {
        writeln!(
            tsv,
            "{}\t{}\t{:?}\t{}",
            held[r.a].component,
            held[r.b].component,
            domains[r.a].unwrap(),
            r.classes.join("\t")
        )
        .unwrap();
        let blockers: Vec<usize> = (0..ids.len()).filter(|&k| !passes(&r.classes[k])).collect();
        for (k, id) in ids.iter().enumerate() {
            let entry = per.get_mut(id).unwrap();
            *entry.0.entry(r.classes[k].clone()).or_default() += 1;
            if blockers.contains(&k) {
                entry.1 += 1;
                if blockers.len() == 1 {
                    entry.2 += 1;
                }
                if r.classes[k] == "unresolved" {
                    if let Some(reason) = &r.reasons[k] {
                        *entry.3.entry(reason.clone()).or_default() += 1;
                    }
                }
            }
        }
        let key = if blockers.is_empty() {
            "none".to_owned()
        } else {
            blockers
                .iter()
                .map(|&k| ids[k])
                .collect::<Vec<_>>()
                .join("+")
        };
        *sets.entry(key).or_default() += 1;
        if blockers.is_empty() {
            correctable += 1;
        } else if blockers.iter().any(|&k| r.classes[k] != "unresolved") {
            definite += 1;
        } else {
            open += 1;
        }
    }
    tsv.flush().unwrap();

    let per_filter: serde_json::Map<String, Json> = per
        .into_iter()
        .map(|(id, (classes, blocking, sole, reasons))| {
            let mut top: Vec<_> = reasons.into_iter().collect();
            top.sort_by_key(|entry| std::cmp::Reverse(entry.1));
            top.truncate(25);
            (
                id.to_owned(),
                json!({
                    "classes": classes,
                    "blocking_pairs": blocking,
                    "sole_blocker_pairs": sole,
                    "top_unresolved_reasons": top,
                }),
            )
        })
        .collect();
    let mut sets: Vec<_> = sets.into_iter().collect();
    sets.sort_by_key(|entry| std::cmp::Reverse(entry.1));
    let summary = json!({
        "filters": ids,
        "images": held.len(),
        "decode_failures": failures.len(),
        "pairs": rows.len(),
        "pass_all_filters": correctable,
        "blocked_with_definite_refusal": definite,
        "blocked_only_by_unresolved": open,
        "per_filter": per_filter,
        "blocker_sets": sets,
        "product_plan_disagreements": disagreements,
        "cache_sample_mismatches": ids.iter().zip(&mismatch).map(|(i, m)| (i.to_string(), json!(m))).collect::<serde_json::Map<_, _>>(),
    });
    std::fs::write(
        out.join("summary.json"),
        serde_json::to_string_pretty(&summary).unwrap(),
    )
    .expect("summary.json");
    println!(
        "pairs {} | pass all filters {} | blocked (definite) {} | blocked (only unresolved) {} | product disagreements {}",
        rows.len(),
        correctable,
        definite,
        open,
        summary["product_plan_disagreements"].as_array().unwrap().len()
    );
}
