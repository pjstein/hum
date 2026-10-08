//! Nothing outside `sim/` may depend on the simulator or on what its fakes
//! are allowed to use: `hum-sim` itself, the floating-point sampler crate
//! `rand_distr`, or the fake hash. W1-03 compares against the oracle by
//! running the simulator, never by linking it (ADR 0090).

use std::fs;
use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("sim/ has a parent")
        .to_path_buf()
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        let name = e.file_name().to_string_lossy().into_owned();
        if p.is_dir() {
            if matches!(
                name.as_str(),
                "sim"
                    | "target"
                    | ".git"
                    | "node_modules"
                    | ".venv"
                    | "docs"
                    | "prompts"
                    | "vectors"
            ) {
                continue;
            }
            walk(&p, out);
        } else {
            out.push(p);
        }
    }
}

#[test]
fn no_crate_outside_sim_depends_on_the_simulator_or_its_sampler() {
    let root = workspace_root();
    let mut files = vec![];
    walk(&root, &mut files);
    assert!(
        files.iter().any(|f| f.ends_with("Cargo.toml")),
        "the walk found no manifests; the check has no subjects"
    );
    let mut offenders = vec![];
    for f in &files {
        let name = f
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let ext = f
            .extension()
            .map(|e| e.to_string_lossy().into_owned())
            .unwrap_or_default();
        if name == "Cargo.toml" {
            let text = fs::read_to_string(f).unwrap_or_default();
            if text.contains("hum-sim") || text.contains("rand_distr") {
                offenders.push(format!("{}: depends on hum-sim or rand_distr", f.display()));
            }
        }
        if matches!(ext.as_str(), "rs" | "go" | "py" | "swift" | "kt") {
            let text = fs::read_to_string(f).unwrap_or_default();
            if text.contains("fake_hash") || text.contains("hum_sim::") {
                offenders.push(format!(
                    "{}: uses the simulator's fake hash or crate",
                    f.display()
                ));
            }
        }
    }
    assert!(offenders.is_empty(), "{offenders:#?}");
}
