//! Optional corpus validation without distributing firmware fixtures.
#![cfg(feature = "analysis")]
use pioneer_optical::{analysis::Options, envelope::Envelope};
use std::path::Path;

#[test]
#[ignore = "set PIONEER_ANALYSIS_CORPUS to a newline-separated envelope list"]
fn analysis_preserves_family_and_partitions_every_decodable_image() {
    let list = std::env::var("PIONEER_ANALYSIS_CORPUS").expect("envelope list path");
    let paths = std::fs::read_to_string(list).expect("read envelope list");
    let mut analyzed = 0;
    for path in paths.lines().filter(|p| !p.is_empty()) {
        let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("{path}: {e}"));
        let mut decoded = Envelope::load(&bytes);
        let path_ref = Path::new(path);
        if path_ref
            .parent()
            .and_then(Path::file_name)
            .is_some_and(|p| p == "normal")
        {
            if let Some(group) = path_ref.parent().and_then(Path::parent) {
                if let Ok(entries) = std::fs::read_dir(group.join("kernel")) {
                    let mut kernels: Vec<_> = entries.flatten().map(|e| e.path()).collect();
                    kernels.sort();
                    for kernel in kernels {
                        let Ok(kernel_bytes) = std::fs::read(kernel) else {
                            continue;
                        };
                        let Ok(kernel) = Envelope::load(&kernel_bytes) else {
                            continue;
                        };
                        if let Ok(envelope) = Envelope::load_with_kernel(&bytes, &kernel) {
                            decoded = Ok(envelope);
                            break;
                        }
                    }
                }
            }
        }
        let Ok(envelope) = decoded else { continue };
        let analysis = envelope
            .analyze(Options::default(), &mut ())
            .unwrap_or_else(|e| panic!("{path}: {e}"));
        assert_eq!(
            analysis.identity.family,
            envelope.family().map(|f| f.to_string()),
            "{path}"
        );
        let mut cursor = 0;
        for region in &analysis.regions {
            assert_eq!(region.stored.start, cursor, "{path}");
            assert!(region.stored.end <= envelope.image.len(), "{path}");
            assert_eq!(region.bytes().len(), region.size, "{path}");
            cursor = region.stored.end;
        }
        assert_eq!(cursor, envelope.image.len(), "{path}");
        analyzed += 1;
    }
    assert!(analyzed > 0, "no decodable images in corpus");
}
