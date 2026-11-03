//! Print `path<TAB>family<TAB>uhd` for each decoded firmware body given.
//!
//! `cargo run --example image_scan --features image -- "SAT 8A10" <body>...`
//!
//! The hardware tag must come from structured firmware metadata. Images that
//! require an associated Kernel remain unresolved in this Normal-only example.

use pioneer_optical::image;

fn main() {
    let mut args = std::env::args().skip(1);
    let hardware = args.next().expect("usage: image_scan HARDWARE_TAG BODY...");
    for path in args {
        match std::fs::read(&path) {
            Ok(body) => {
                let family = image::family_with_context(&body, &hardware, None)
                    .map_or("none".into(), |f| f.to_string());
                println!("{path}\t{family}\t{}", image::is_uhd(&body));
            }
            Err(e) => eprintln!("{path}: {e}"),
        }
    }
}
