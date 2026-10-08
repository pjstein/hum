//! Command line: `sim fast`, `sim full [--polis DIR]`, `sim replay …`,
//! `sim fixture --out DIR`. Returns `Ok(true)` when the run passed.

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use anyhow::{Context, bail};

use crate::data::polis;
use crate::data::synthetic::{SyntheticSpec, generate};
use crate::report::Report;
use crate::scenario::{self, Kind, Scenario, Source};

const HELP: &str = "\
hum sim — the Hum simulator (docs/specs/simulator.md)

usage:
  sim fast [--out DIR]                       per-commit suite, under a minute
  sim full [--polis DIR] [--out DIR]         nightly suite: all sizes, ε and seeds
  sim replay --size N [--eps E] [--seeds K] [--polis DIR --conversation NAME] [--out DIR]
  sim fixture --out DIR [--size N] [--seed S]   write the synthetic fixture in the Polis layout
  sim help

Polis open data (CC BY 4.0): git clone https://github.com/compdemocracy/openData DIR
and pass --polis DIR, or set HUM_POLIS_DATA. Reports go to target/sim/<mode>.json.
";

struct Args {
    cmd: String,
    flags: Vec<(String, String)>,
}

impl Args {
    fn parse(args: &[String]) -> anyhow::Result<Self> {
        let cmd = args.first().cloned().unwrap_or_else(|| "help".into());
        let mut flags = vec![];
        let mut i = 1;
        while i < args.len() {
            let a = &args[i];
            let Some(name) = a.strip_prefix("--") else {
                bail!("unexpected argument {a}")
            };
            let value = args
                .get(i + 1)
                .cloned()
                .with_context(|| format!("--{name} needs a value"))?;
            flags.push((name.to_string(), value));
            i += 2;
        }
        Ok(Self { cmd, flags })
    }

    fn get(&self, name: &str) -> Option<&str> {
        self.flags
            .iter()
            .rev()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }

    fn polis(&self) -> Option<PathBuf> {
        self.get("polis")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HUM_POLIS_DATA").map(PathBuf::from))
    }

    fn out(&self) -> PathBuf {
        self.get("out")
            .map_or_else(Report::default_dir, PathBuf::from)
    }
}

fn run_suite(mode: &str, scenarios: &[Scenario], out: &Path) -> anyhow::Result<bool> {
    let started = SystemTime::now();
    let mut results = Vec::with_capacity(scenarios.len());
    for s in scenarios {
        eprintln!("running {}", s.name);
        results.push(scenario::run(s));
    }
    let report = Report::new(mode, started, results);
    let path = report.write(out)?;
    print!("{}", report.text());
    println!("report: {}", path.display());
    Ok(report.passed)
}

/// Run the CLI.
pub fn run(args: &[String]) -> anyhow::Result<bool> {
    let a = Args::parse(args)?;
    match a.cmd.as_str() {
        "fast" => run_suite("fast", &scenario::fast_suite(), &a.out()),
        "full" => {
            let polis = a.polis();
            if polis.is_none() {
                eprintln!(
                    "no Polis checkout (--polis or HUM_POLIS_DATA): running the synthetic fixture only"
                );
            }
            run_suite("full", &scenario::full_suite(polis), &a.out())
        }
        "replay" => {
            let size: usize = a.get("size").context("--size is required")?.parse()?;
            let eps: f64 = a.get("eps").unwrap_or("4").parse()?;
            let seeds: u64 = a.get("seeds").unwrap_or("2").parse()?;
            let source = match (a.polis(), a.get("conversation")) {
                (Some(root), Some(conv)) => Source::Polis {
                    root,
                    conversation: conv.to_string(),
                },
                (None, Some(_)) => bail!("--conversation needs --polis"),
                _ => Source::Synthetic {
                    seed: a.get("seed").unwrap_or("1").parse()?,
                },
            };
            let s = Scenario {
                name: format!("replay-{size}-eps{eps}"),
                source,
                kind: Kind::PolisReplay {
                    size,
                    eps,
                    seeds: (0..seeds).collect(),
                },
            };
            run_suite("replay", &[s], &a.out())
        }
        "fixture" => {
            let out = PathBuf::from(a.get("out").context("--out is required")?);
            let size: usize = a.get("size").unwrap_or("1000").parse()?;
            let seed: u64 = a.get("seed").unwrap_or("1").parse()?;
            let m = generate(&SyntheticSpec::sized(size), seed);
            polis::write(&m, &out)?;
            println!(
                "wrote {} participants × {} statements to {}",
                m.n(),
                m.c(),
                out.display()
            );
            Ok(true)
        }
        "help" | "--help" | "-h" => {
            print!("{HELP}");
            Ok(true)
        }
        other => bail!("unknown command {other}\n{HELP}"),
    }
}
