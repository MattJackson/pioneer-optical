//! Generate the Pioneer hardware matrix page from a firmware-extractor hoard.
//!
//! ```text
//! cargo run --release --all-features --example hardware_matrix -- \
//!     <HOARD> --out Pioneer-Hardware-Matrix.html [--routes routes.json] [--data model.json]
//! ```
//!
//! Every value and every rule statement comes from the registered filters and
//! their declared rules; see `docs/hardware-matrix.md`.
mod page;

use std::path::{Path, PathBuf};
use std::process::Command;

fn usage() -> ! {
    eprintln!(
        "usage: hardware_matrix HOARD --out PAGE.html [--routes ROUTES.json] [--data MODEL.json]"
    );
    std::process::exit(2)
}

fn revision() -> String {
    let dir = env!("CARGO_MANIFEST_DIR");
    let git = |args: &[&str]| {
        Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(args)
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
    };
    match git(&["rev-parse", "HEAD"]) {
        Some(rev) => {
            // A failed status cannot establish a clean tree.
            let dirty = git(&["status", "--porcelain", "--untracked-files=no"])
                .map_or(true, |s| !s.is_empty());
            if dirty {
                format!("{rev}-dirty")
            } else {
                rev
            }
        }
        None => "unknown".into(),
    }
}

fn main() {
    let mut args = std::env::args().skip(1);
    let (mut hoard, mut out, mut routes, mut model) = (None, None, None, None);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--out" => out = Some(PathBuf::from(args.next().unwrap_or_else(|| usage()))),
            "--routes" => routes = Some(PathBuf::from(args.next().unwrap_or_else(|| usage()))),
            "--data" => model = Some(PathBuf::from(args.next().unwrap_or_else(|| usage()))),
            _ if hoard.is_none() && !arg.starts_with("--") => hoard = Some(PathBuf::from(arg)),
            _ => usage(),
        }
    }
    let (Some(hoard), Some(out)) = (hoard, out) else {
        usage()
    };
    if let Err(error) = run(&hoard, &out, routes.as_deref(), model.as_deref()) {
        eprintln!("hardware_matrix: {error}");
        std::process::exit(1);
    }
}

fn run(
    hoard: &Path,
    out: &Path,
    routes: Option<&Path>,
    model: Option<&Path>,
) -> Result<(), String> {
    let routes = routes
        .map(|path| {
            let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
            serde_json::from_slice::<serde_json::Value>(&bytes)
                .map_err(|e| format!("{}: {e}", path.display()))
        })
        .transpose()?;
    let (packages, index) = page::hoard_packages(hoard)?;
    let (analyses, failures) = page::analyze_hoard(hoard, &packages, |_, _, _| {});
    for failure in &failures {
        eprintln!(
            "{} ({}): {}",
            failure.component, failure.path, failure.error
        );
    }
    let source = page::Source {
        crate_version: env!("CARGO_PKG_VERSION").into(),
        revision: revision(),
        hoard: format!("sha256:{} (index/packages.json)", page::sha256(&index)),
    };
    let data = page::data(&packages, &analyses, &failures, &source, routes.as_ref())?;
    if let Some(path) = model {
        let text = serde_json::to_string_pretty(&data).map_err(|e| e.to_string())?;
        std::fs::write(path, text + "\n").map_err(|e| format!("{}: {e}", path.display()))?;
    }
    std::fs::write(out, page::render(&data)).map_err(|e| format!("{}: {e}", out.display()))?;
    eprintln!(
        "{}: {} packages, {} images, {} with family ID, {} failed to decode",
        out.display(),
        packages.len(),
        analyses.len(),
        analyses.iter().filter(|a| a.candidate.is_some()).count(),
        failures.len()
    );
    Ok(())
}
