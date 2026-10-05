//! Validation harness: read envelope-decoded firmware body files and print
//! `path<TAB>family<TAB>uhd` for each. `family` is lowercase hex or `NONE`.
//!
//! Run: `cargo run --example fw_scan --features fw -- <body-file>...`

use std::io::{self, Write};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());
    for path in &args {
        let body = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) => {
                writeln!(out, "{}\tERR:{}\tfalse", path, e).ok();
                continue;
            }
        };
        let fam = match pioneer_optical::fw::get_family(&body) {
            Some(id) => format!("{}", id),
            None => "NONE".to_string(),
        };
        let uhd = pioneer_optical::fw::is_uhd(&body);
        writeln!(out, "{}\t{}\t{}", path, fam, uhd).ok();
    }
}
