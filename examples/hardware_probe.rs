//! Offline expanded-region evidence for a Kernel/Normal pair.
//! Args: KERNEL_ENVELOPE NORMAL_ENVELOPE OUTPUT_DIRECTORY
use pioneer_optical::{
    analysis::Options,
    envelope::{decode_envelope, decode_envelope_with_kernel},
    image,
};
use serde_json::json;
use std::{fs, path::PathBuf};
fn main() {
    let a: Vec<_> = std::env::args().collect();
    if a.get(1).map(String::as_str) == Some("disasm") {
        use h8_asm::{
            isa::{decode_insn, disassemble_insn},
            Mode, Target,
        };
        let bytes = fs::read(&a[2]).unwrap();
        let mut offset = usize::from_str_radix(a[3].trim_start_matches("0x"), 16).unwrap();
        let count: usize = a.get(4).map(|x| x.parse().unwrap()).unwrap_or(40);
        for _ in 0..count {
            match decode_insn(&bytes[offset..], Target::H8S2000, Mode::Advanced) {
                Ok(d) => {
                    println!(
                        "{offset:06x}: {:20} {}",
                        bytes[offset..offset + d.len]
                            .iter()
                            .map(|x| format!("{x:02x}"))
                            .collect::<String>(),
                        disassemble_insn(d.insn, Target::H8S2000, Mode::Advanced).unwrap()
                    );
                    offset += d.len;
                }
                Err(_) => {
                    println!(
                        "{offset:06x}: {:02x}{:02x} .word",
                        bytes[offset],
                        bytes[offset + 1]
                    );
                    offset += 2;
                }
            }
        }
        return;
    }
    assert_eq!(a.len(), 4, "hardware_probe KERNEL NORMAL OUTPUT_DIR");
    let out = PathBuf::from(&a[3]);
    fs::create_dir_all(&out).unwrap();
    let k = if a[1] == "-" {
        None
    } else {
        Some(decode_envelope(&fs::read(&a[1]).unwrap()).expect("Kernel decode"))
    };
    let bytes = fs::read(&a[2]).unwrap();
    let n = if let Some(k) = k.as_ref() {
        decode_envelope_with_kernel(&bytes, k)
    } else {
        decode_envelope(&bytes)
    }
    .expect("Normal decode");
    let mut analyses = Vec::new();
    for (role, e) in k
        .as_ref()
        .map(|k| ("kernel", k))
        .into_iter()
        .chain(std::iter::once(("normal", &n)))
    {
        fs::write(out.join(format!("{role}.bin")), &e.image).unwrap();
        let analysis = e.analyze(Options::default(), &mut ()).unwrap();
        for region in &analysis.regions {
            fs::write(
                out.join(format!("{role}-region-{}.bin", region.id)),
                region.bytes(),
            )
            .unwrap();
        }
        let mut value = serde_json::to_value(&analysis).unwrap();
        value["role"] = json!(role);
        value["required_abi"] = json!(image::required_abi(&e.image).map(|a| a.entries().to_vec()));
        value["provided_abi"] = json!(image::provided_abi(&e.image).map(|a| a.entries().to_vec()));
        analyses.push(value);
    }
    let facts = json!({"components":analyses,"kernel_startup_entry":k.as_ref().and_then(|k|image::kernel_startup_entry(&k.image)),"kernel_handoff_entry":k.as_ref().and_then(|k|image::kernel_handoff_entry(&k.image)),"receiver_control":format!("{:?}",image::receiver_control(&n.image)),"kernel_marker_policy":format!("{:?}",image::kernel_marker_policy(&n.image))});
    fs::write(
        out.join("analysis.json"),
        serde_json::to_vec_pretty(&facts).unwrap(),
    )
    .unwrap();
}
