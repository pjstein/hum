//! Loader for the Polis open data (<https://github.com/compdemocracy/openData>,
//! CC BY 4.0), a port of `load` in the research code. One directory per
//! conversation with `votes.csv`, `comments.csv` and `participants-votes.csv`.
//!
//! The data is not vendored. `just sim-full` reads it from `--polis <dir>` or
//! `$HUM_POLIS_DATA`; `just sim-fast` uses the synthetic fixture instead.

use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context, Result};

use super::{Vote, VoteMatrix};

/// Participants with fewer votes than this are dropped (research default).
pub const MIN_VOTES: usize = 7;

/// The four large conversations the research's size sweep (E2) drew from.
pub const E2_SOURCES: [&str; 4] = [
    "march-on.operation-marchin-orders",
    "austria-climate.9xnndurbfm.2022-07-07",
    "american-assembly.bowling-green",
    "vtaiwan.uberx",
];

/// Load one conversation directory into a vote matrix.
pub fn load(dir: &Path) -> Result<VoteMatrix> {
    load_with_min_votes(dir, MIN_VOTES)
}

/// `load` with an explicit participant minimum.
pub fn load_with_min_votes(dir: &Path, min_votes: usize) -> Result<VoteMatrix> {
    let name = dir
        .file_name()
        .map_or_else(|| "polis".to_string(), |s| s.to_string_lossy().into_owned());

    // comments.csv: keep moderated >= 0.
    let mut keep_comments: Vec<i64> = vec![];
    {
        let mut rdr = csv::ReaderBuilder::new()
            .flexible(true)
            .from_path(dir.join("comments.csv"))
            .with_context(|| format!("open {}", dir.join("comments.csv").display()))?;
        let headers = rdr.headers()?.clone();
        let col = |n: &str| {
            headers
                .iter()
                .position(|h| h == n)
                .with_context(|| format!("comments.csv lacks {n}"))
        };
        let (ci, mi) = (col("comment-id")?, col("moderated")?);
        for rec in rdr.records() {
            let rec = rec?;
            let id: i64 = rec
                .get(ci)
                .unwrap_or("")
                .trim()
                .parse()
                .context("comment-id")?;
            let moderated: f64 = rec.get(mi).unwrap_or("").trim().parse().unwrap_or(-1.0);
            if moderated >= 0.0 {
                keep_comments.push(id);
            }
        }
    }
    keep_comments.sort_unstable();
    keep_comments.dedup();
    let comment_index: HashMap<i64, usize> = keep_comments
        .iter()
        .enumerate()
        .map(|(j, &c)| (c, j))
        .collect();

    // votes.csv: last vote per (comment, voter) by timestamp.
    let mut latest: HashMap<(i64, i64), (i64, i64)> = HashMap::new();
    {
        let mut rdr = csv::ReaderBuilder::new()
            .flexible(true)
            .from_path(dir.join("votes.csv"))
            .with_context(|| format!("open {}", dir.join("votes.csv").display()))?;
        let headers = rdr.headers()?.clone();
        let col = |n: &str| {
            headers
                .iter()
                .position(|h| h == n)
                .with_context(|| format!("votes.csv lacks {n}"))
        };
        let (ti, ci, vi, vv) = (
            col("timestamp")?,
            col("comment-id")?,
            col("voter-id")?,
            col("vote")?,
        );
        for rec in rdr.records() {
            let rec = rec?;
            let ts: i64 = rec.get(ti).unwrap_or("0").trim().parse().unwrap_or(0);
            let cid: i64 = rec
                .get(ci)
                .unwrap_or("")
                .trim()
                .parse()
                .context("comment-id")?;
            let voter: i64 = rec
                .get(vi)
                .unwrap_or("")
                .trim()
                .parse()
                .context("voter-id")?;
            let vote: i64 = rec.get(vv).unwrap_or("").trim().parse().context("vote")?;
            if !comment_index.contains_key(&cid) {
                continue;
            }
            let e = latest.entry((cid, voter)).or_insert((ts, vote));
            if ts >= e.0 {
                *e = (ts, vote);
            }
        }
    }

    let mut per_voter: HashMap<i64, usize> = HashMap::new();
    for &(_, voter) in latest.keys() {
        *per_voter.entry(voter).or_default() += 1;
    }
    let mut voters: Vec<i64> = per_voter
        .iter()
        .filter(|(_, k)| **k >= min_votes)
        .map(|(v, _)| *v)
        .collect();
    voters.sort_unstable();
    let voter_index: HashMap<i64, usize> =
        voters.iter().enumerate().map(|(i, &v)| (v, i)).collect();

    let mut m = VoteMatrix::new(name, voters.len(), keep_comments.len());
    for (&(cid, voter), &(_, vote)) in &latest {
        if let (Some(&i), Some(&j)) = (voter_index.get(&voter), comment_index.get(&cid)) {
            m.set(i, j, Vote::from_polis(vote));
        }
    }

    // participants-votes.csv: Polis' own group per participant, when present.
    if let Ok(mut rdr) = csv::ReaderBuilder::new()
        .flexible(true)
        .from_path(dir.join("participants-votes.csv"))
        && let Ok(headers) = rdr.headers().cloned()
    {
        let pi = headers.iter().position(|h| h == "participant");
        let gi = headers.iter().position(|h| h == "group-id");
        if let (Some(pi), Some(gi)) = (pi, gi) {
            for rec in rdr.records().flatten() {
                let p: Option<i64> = rec.get(pi).and_then(|s| s.trim().parse().ok());
                let g: Option<usize> = rec
                    .get(gi)
                    .and_then(|s| s.trim().parse::<f64>().ok())
                    .map(|g| g as usize);
                if let Some(&i) = p.and_then(|p| voter_index.get(&p)) {
                    m.source_groups[i] = g;
                }
            }
        }
    }

    Ok(m.drop_empty_columns())
}

/// Write a matrix in the Polis layout, so the loader can be tested offline and
/// so a synthetic fixture can be handed to the research code.
pub fn write(m: &VoteMatrix, dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir)?;
    let mut w = csv::Writer::from_path(dir.join("comments.csv"))?;
    w.write_record([
        "timestamp",
        "datetime",
        "comment-id",
        "author-id",
        "agrees",
        "disagrees",
        "moderated",
        "comment-body",
    ])?;
    for j in 0..m.c() {
        w.write_record([
            "0",
            "",
            &j.to_string(),
            "",
            "0",
            "0",
            "1",
            &format!("synthetic statement {j}, \"quoted\", with a comma"),
        ])?;
    }
    w.flush()?;
    let mut w = csv::Writer::from_path(dir.join("votes.csv"))?;
    w.write_record(["timestamp", "datetime", "comment-id", "voter-id", "vote"])?;
    for i in 0..m.n() {
        for j in 0..m.c() {
            if let Some(v) = m.get(i, j) {
                w.write_record([
                    &(i * m.c() + j).to_string(),
                    "",
                    &j.to_string(),
                    &i.to_string(),
                    &(v.value() as i64).to_string(),
                ])?;
            }
        }
    }
    w.flush()?;
    let mut w = csv::Writer::from_path(dir.join("participants-votes.csv"))?;
    w.write_record([
        "participant",
        "group-id",
        "n-comments",
        "n-votes",
        "n-agree",
        "n-disagree",
    ])?;
    for i in 0..m.n() {
        let g = m.source_groups[i].map_or(String::new(), |g| g.to_string());
        w.write_record([
            &i.to_string(),
            &g,
            "0",
            &m.votes_in_row(i).to_string(),
            "0",
            "0",
        ])?;
    }
    w.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::synthetic::{SyntheticSpec, generate};

    #[test]
    fn round_trips_through_the_polis_layout() {
        let m = generate(&SyntheticSpec::sized(60), 7);
        let dir = std::env::temp_dir().join(format!("hum-sim-polis-{}", std::process::id()));
        write(&m, &dir).unwrap();
        let back = load_with_min_votes(&dir, 1).unwrap();
        std::fs::remove_dir_all(&dir).ok();
        assert_eq!(back.n(), m.n());
        assert_eq!(back.c(), m.c());
        assert_eq!(back.total_votes(), m.total_votes());
        assert_eq!(back.get(3, 2), m.get(3, 2));
        assert_eq!(back.source_groups, m.source_groups);
    }
}
