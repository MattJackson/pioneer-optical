//! Print `path<TAB>family<TAB>uhd` for each decoded firmware body given.
//!
//! `cargo run --example image_scan --features image -- <body>...`

use pioneer_optical::image;

fn main() {
    for path in std::env::args().skip(1) {
        match std::fs::read(&path) {
            Ok(body) => {
                let family = image::family(&body).map_or("none".into(), |f| f.to_string());
                println!("{path}\t{family}\t{}", image::is_uhd(&body));
            }
            Err(e) => eprintln!("{path}: {e}"),
        }
    }
}
