//! Offline audit of F4 response literal stores in recognized H8 dispatch layouts.
//! This reports code evidence, not a substitute for querying the connected drive.
use pioneer_optical::envelope::Envelope;
use std::{
    env, fs,
    path::{Path, PathBuf},
};
fn collect(path: &Path, paths: &mut Vec<PathBuf>) -> std::io::Result<()> {
    if path.is_dir() {
        for entry in fs::read_dir(path)? {
            collect(&entry?.path(), paths)?;
        }
    } else if path.extension().is_some_and(|e| e == "enc" || e == "bin") {
        paths.push(path.to_owned());
    }
    Ok(())
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut paths = Vec::new();
    for path in env::args().skip(1) {
        collect(Path::new(&path), &mut paths)?;
    }
    paths.sort();
    paths.dedup();
    for file in paths {
        let path = file.display().to_string();
        let raw = fs::read(&file)?;
        let b = if file.extension().is_some_and(|e| e == "enc") {
            if file
                .parent()
                .and_then(Path::file_name)
                .is_some_and(|n| n == "kernel")
            {
                println!("{path}: kernel image (settings execute in normal firmware)");
                continue;
            }
            let mut decoded = Envelope::load(&raw);
            if let Some(group) = file.parent().and_then(Path::parent) {
                if let Ok(entries) = fs::read_dir(group.join("kernel")) {
                    let mut kernels: Vec<_> = entries
                        .flatten()
                        .map(|e| e.path())
                        .filter(|p| p.extension().is_some_and(|e| e == "enc"))
                        .collect();
                    kernels.sort();
                    for kernel in kernels {
                        if let Ok(k) = Envelope::load(&fs::read(kernel)?) {
                            if let Ok(normal) = Envelope::load_with_kernel(&raw, &k) {
                                decoded = Ok(normal);
                                break;
                            }
                        }
                    }
                }
            }
            match decoded {
                Ok(e) => e.image.to_vec(),
                Err(e) => {
                    println!("{path}: decode unavailable: {e}");
                    continue;
                }
            }
        } else {
            raw
        };
        let base = 0x410000;
        match pioneer_optical::firmware::settings::inspect(&b, base) {
            Ok(evidence) => {
                println!(
                    "{path}: READ BUFFER={:#x}, F4={:#x}, next handler={:#x}",
                    evidence.read_buffer, evidence.response_builder, evidence.next_handler
                );
                for store in evidence.literal_stores {
                    println!(
                        "  {:#x}: F4[{}] <- {:#04x}",
                        store.address, store.offset, store.value
                    );
                }
            }
            Err(error) => println!("{path}: {error}"),
        }
    }
    Ok(())
}
