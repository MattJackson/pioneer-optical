//! Inspect decoded firmware without accessing a drive.
use std::{env, fs};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    let base = usize::from_str_radix(
        &args.next().ok_or("usage: logging_scan HEX_BASE IMAGE...")?,
        16,
    )?;
    for path in args {
        let mut image = vec![0; base];
        image.extend(fs::read(&path)?);
        println!("{}\t{:?}", path, pioneer_optical::logging::discover(&image));
    }
    Ok(())
}
