//! Export hardware fingerprint evidence from a local hoard as JSON.
use pioneer_optical::{
    envelope::{decode_envelope, decode_envelope_with_kernel},
    image,
};
use serde_json::{json, Value};
use std::{collections::BTreeMap, path::Path};

fn members(bytes: &[u8]) -> BTreeMap<String, &[u8]> {
    let mut out = BTreeMap::new();
    let mut at = 0;
    let text = |v: &[u8]| {
        String::from_utf8_lossy(&v[..v.iter().position(|x| *x == 0).unwrap_or(v.len())])
            .into_owned()
    };
    while let Some(h) = bytes.get(at..at + 512) {
        if h.iter().all(|b| *b == 0) {
            break;
        }
        let size = usize::from_str_radix(text(&h[124..136]).trim(), 8).expect("tar size");
        let prefix = text(&h[345..500]);
        let name = if prefix.is_empty() {
            text(&h[..100])
        } else {
            format!("{prefix}/{}", text(&h[..100]))
        };
        let data = bytes.get(at + 512..at + 512 + size).expect("truncated tar");
        if h[156] == b'0' || h[156] == 0 {
            out.insert(name, data);
        }
        at += 512 + size.div_ceil(512) * 512;
    }
    out
}

fn main() {
    let root_arg = std::env::args()
        .nth(1)
        .expect("usage: hardware_report HOARD_ROOT");
    let root = Path::new(&root_arg);
    let body_dir = std::env::args().nth(2);
    if let Some(dir) = &body_dir {
        std::fs::create_dir_all(dir).unwrap();
    }
    let index: Value =
        serde_json::from_slice(&std::fs::read(root.join("index/packages.json")).unwrap()).unwrap();
    let mut rows = Vec::new();
    let mut cache = BTreeMap::new();
    for p in index["packages"].as_array().unwrap() {
        if p["family"] != "pioneer" {
            continue;
        }
        let mut row = p.clone();
        let key = format!("{}:{}", p["kernel_sha256"], p["normal_sha256"]);
        let evidence = cache.entry(key).or_insert_with(|| {
            let result = (|| -> Result<Value, String> {
                let tar = std::fs::read(root.join(p["path"].as_str().ok_or("missing path")?)).map_err(|e| e.to_string())?;
                let files = members(&tar);
                let get = |role| p["components"].as_array()?.iter().find(|c| c["role"] == role)?.get("member")?.as_str().and_then(|m| files.get(m).copied());
                let n = get("normal").ok_or("no Normal component")?;
                let k = get("kernel").and_then(decode_envelope);
                let decoded = if let Some(k) = k.as_ref() { decode_envelope_with_kernel(n, k) } else { decode_envelope(n) }.ok_or("Normal decode failed")?;
                if let Some(dir)=&body_dir {
                    let sha=p["normal_sha256"].as_str().ok_or("missing Normal SHA")?;
                    std::fs::write(Path::new(dir).join(format!("{sha}.bin")),&decoded.image).map_err(|e|e.to_string())?;
                }
                let f = image::family_fingerprint(&decoded.image).ok_or("no hardware fingerprint")?;
                assert_eq!(Some(f.family), image::family(&decoded.image));
                Ok(json!({"family":f.family.to_string(),"asic":f.asic,"board":f.board,"pins":f.pins,"servo":f.servo,"uhd":image::is_uhd(&decoded.image),"decode_basis":if k.is_some(){"paired Kernel"}else{"standalone Normal"}}))
            })();
            match result { Ok(v) => v, Err(e) => json!({"error":e}) }
        });
        row["evidence"] = evidence.clone();
        rows.push(row);
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({"packages":rows})).unwrap()
    );
}
