//! The Hum simulator binary. `sim fast` is the per-commit gate, `sim full`
//! the nightly run. See `docs/specs/simulator.md` and `sim/README.md`.

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match hum_sim::cli::run(&args) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(2),
        Err(e) => {
            eprintln!("sim: {e:#}");
            ExitCode::from(1)
        }
    }
}
