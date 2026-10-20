//! Read-only, inventory-complete startup audit. No device commands are issued.
//! Pattern misses and unknown layouts are explicitly unresolved, not absent.
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

fn walk(path: &Path, files: &mut Vec<PathBuf>) -> std::io::Result<()> {
    for entry in fs::read_dir(path)? {
        let path = entry?.path();
        if path.is_dir() {
            walk(&path, files)?;
        } else if path.extension().is_some_and(|e| e == "enc" || e == "bin") {
            files.push(path);
        }
    }
    Ok(())
}
fn addr(b: &[u8]) -> u32 {
    u32::from_be_bytes([0, b[0], b[1], b[2]])
}

// A review-clustering fingerprint, NOT a proof of semantic equivalence:
// callees and address constants are erased, so their behavior needs its own
// audit. Instruction lengths, branches and scalar constants are preserved.
fn writer_shape(b: &[u8], getter: u32, setter: u32) -> Option<String> {
    use h8_asm::{isa::decode_insn, Mode, Target};
    let start = setter.checked_sub(0x410000)? as usize;
    let end = getter.checked_sub(0x410000)? as usize;
    let body = b.get(start..end)?;
    if body.is_empty() || body.len() > 0x2000 {
        return None;
    }
    let mut normalized = body.to_vec();
    let mut i = 0;
    while i < body.len() {
        let insn = decode_insn(&body[i..], Target::H8S2000, Mode::Advanced).ok()?;
        let n = insn.len;
        if n == 0 || i + n > body.len() {
            return None;
        }
        if n == 4 && matches!(body[i], 0x5a | 0x5e) {
            normalized[i + 1..i + 4].fill(0);
        } else if n == 6 && body[i] == 0x7a && body[i + 1] < 8 {
            let value = u32::from_be_bytes(body[i + 2..i + 6].try_into().ok()?);
            if (0x400000..0xc00000).contains(&value) {
                normalized[i + 2..i + 6].fill(0);
            }
        }
        i += n;
    }
    Some(format!("{:x}", Sha256::digest(normalized)))
}

// Audited R0-index generic read/write switch shape. Still only a candidate:
// dispatcher binding, write admission and writer semantics require proof.
fn pairs(b: &[u8], base: u32) -> Vec<(u32, u32)> {
    b.windows(32)
        .enumerate()
        .filter_map(|(i, w)| {
            if i % 2 != 0
                || w[..7] != [0x0c, 0x66, 0x46, 8, 0x0d, 0x30, 0x5e]
                || w[10..12] != [0x40, 0x2e]
                || w[18..21] != [0x0d, 0xb1, 0x5e]
                || w[24..28] != [0x0d, 8, 0x0d, 0x30]
                || w[28] != 0x5e
            {
                return None;
            }
            let getter = addr(&w[7..10]);
            let setter = addr(&w[29..32]);
            let inside = |a: u32| a.checked_sub(base).is_some_and(|n| (n as usize) < b.len());
            (inside(getter) && inside(setter)).then_some((getter, setter))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn clustering_keeps_parameter_constants_and_rejects_bad_extents() {
        let a = [0x5e, 0x41, 0, 0x10, 0x79, 0, 0, 0x9f, 0x54, 0x70];
        let mut b = a;
        b[3] = 0x20;
        assert_eq!(
            writer_shape(&a, 0x41000a, 0x410000),
            writer_shape(&b, 0x41000a, 0x410000)
        );
        assert!(writer_shape(&a, 0x41000a, 0x410000).is_some());
        b[7] = 0x9e;
        assert_ne!(
            writer_shape(&a, 0x41000a, 0x410000),
            writer_shape(&b, 0x41000a, 0x410000)
        );
        assert!(writer_shape(&a, 0x410020, 0x410000).is_none());
        assert!(writer_shape(&a, 0x410000, 0x410000).is_none());
    }
    #[test]
    fn native_switch_offsets_match_the_audited_instructions() {
        let mut b = vec![0; 0x200];
        b[0..32].copy_from_slice(&[
            0x0c, 0x66, 0x46, 8, 0x0d, 0x30, 0x5e, 0x41, 1, 0, 0x40, 0x2e, 1, 0, 0x6f, 0x70, 0, 4,
            0x0d, 0xb1, 0x5e, 0x41, 1, 0x40, 0x0d, 8, 0x0d, 0x30, 0x5e, 0x41, 1, 0x80,
        ]);
        assert_eq!(pairs(&b, 0x410000), vec![(0x410100, 0x410180)]);
        for end in 0..32 {
            assert!(pairs(&b[..end], 0x410000).is_empty());
        }
        b[28] = 0x5a;
        assert!(pairs(&b, 0x410000).is_empty());
    }
}
fn row(path: &Path) -> Result<(String, String), Box<dyn std::error::Error>> {
    let role = path
        .parent()
        .and_then(Path::file_name)
        .unwrap()
        .to_string_lossy();
    let raw = fs::read(path)?;
    let hash = format!("{:x}", Sha256::digest(&raw));
    if path.extension().is_some_and(|e| e == "bin") {
        return Ok((
            format!("{role}:raw-unresolved"),
            format!(
                "{}\t{role}\t{hash}\traw-layout-unresolved\t\t\t\t\tunresolved",
                path.display()
            ),
        ));
    }
    let image = match pioneer_optical::envelope::Envelope::load(&raw) {
        Ok(f) => f.image,
        Err(e) => {
            return Ok((
                format!("{role}:decode-error"),
                format!(
                    "{}\t{role}\t{hash}\tdecode-error:{e}\t\t\t\t\tunresolved",
                    path.display()
                ),
            ))
        }
    };
    if role != "normal" {
        return Ok((
            format!("{role}:decoded-unresolved"),
            format!(
                "{}\t{role}\t{hash}\tdecoded-role-analysis-unresolved\t\t\t\t\tunresolved",
                path.display()
            ),
        ));
    }
    let native = pairs(&image, 0x410000);
    let native = native
        .iter()
        .map(|(g, s)| {
            format!(
                "{g:06x}:{s:06x}:{}",
                writer_shape(&image, *g, *s).unwrap_or_else(|| "unresolved-decoding".into())
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let (status, parameter, value, check) = match pioneer_optical::startup::discover(&image) {
        Ok(Some(r)) => (
            "recognized-loader-flag-comparison",
            format!("{:04x}", r.parameter),
            format!("{:04x}", r.required),
            format!("{:06x}", r.check_address),
        ),
        Ok(None) => (
            "no-recognized-check-UNRESOLVED",
            String::new(),
            String::new(),
            String::new(),
        ),
        Err(_) => (
            "ambiguous-UNRESOLVED",
            String::new(),
            String::new(),
            String::new(),
        ),
    };
    Ok((
        format!("{role}:{status}"),
        format!(
            "{}\t{role}\t{hash}\t{status}\t{parameter}\t{value}\t{check}\t{native}\tunresolved",
            path.display()
        ),
    ))
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let root = std::env::args_os()
        .nth(1)
        .ok_or("usage: startup_corpus HOARD_IMAGES_ROOT")?;
    let mut files = Vec::new();
    if Path::new(&root).extension().is_some_and(|e| e == "tsv") {
        for line in fs::read_to_string(&root)?.lines().skip(1) {
            let fields: Vec<_> = line.split('\t').collect();
            if fields.get(7).is_some_and(|s| !s.is_empty()) {
                files.push(PathBuf::from(fields[0]));
            }
        }
        files.sort();
        files.dedup();
    } else {
        walk(Path::new(&root), &mut files)?;
    }
    files.sort();
    println!("path\trole\tfile_sha256\tstartup_status\tparameter\trequired\tcheck_cpu\tnative_pairs_CANDIDATE\tconsumer_and_write_safety_audit");
    let mut counts = BTreeMap::<String, usize>::new();
    // Independent decoding is CPU-heavy; workers only read immutable inputs.
    let rows = std::thread::scope(|scope| {
        let handles = (0..4)
            .map(|worker| {
                let files = &files;
                scope.spawn(move || {
                    files
                        .iter()
                        .enumerate()
                        .filter(|(i, _)| i % 4 == worker)
                        .map(|(i, p)| (i, row(p).map_err(|e| e.to_string())))
                        .collect::<Vec<_>>()
                })
            })
            .collect::<Vec<_>>();
        handles
            .into_iter()
            .flat_map(|h| h.join().expect("audit worker panicked"))
            .collect::<Vec<_>>()
    });
    let mut rows = rows;
    rows.sort_by_key(|r| r.0);
    for (_, result) in rows {
        let (key, line) = result.map_err(std::io::Error::other)?;
        *counts.entry(key).or_default() += 1;
        println!("{line}");
    }
    eprintln!(
        "inventoried={} reported={}",
        files.len(),
        counts.values().sum::<usize>()
    );
    for (key, count) in counts {
        eprintln!("{key}: {count}");
    }
    Ok(())
}
