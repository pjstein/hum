//! A participants × statements vote matrix with missing entries.

use rand::Rng;
use rand::seq::index::sample;

/// One vote on one statement.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum Vote {
    /// Swipe right.
    Agree,
    /// Swipe left.
    Disagree,
    /// Swipe up (unsure).
    Pass,
}

impl Vote {
    /// Polis encoding: agree 1, disagree −1, pass 0.
    pub fn value(self) -> f64 {
        match self {
            Vote::Agree => 1.0,
            Vote::Disagree => -1.0,
            Vote::Pass => 0.0,
        }
    }

    /// From the Polis encoding; anything else is `None`.
    pub fn from_polis(v: i64) -> Option<Self> {
        match v {
            1 => Some(Vote::Agree),
            -1 => Some(Vote::Disagree),
            0 => Some(Vote::Pass),
            _ => None,
        }
    }
}

/// A dense vote matrix. Rows are participants, columns statements.
#[derive(Clone, Debug)]
pub struct VoteMatrix {
    n: usize,
    c: usize,
    cells: Vec<Option<Vote>>,
    /// Optional ground-truth group per participant (from the source data).
    pub source_groups: Vec<Option<usize>>,
    /// Where the conversation came from, for reports.
    pub name: String,
}

impl VoteMatrix {
    /// An empty matrix.
    pub fn new(name: impl Into<String>, n: usize, c: usize) -> Self {
        Self {
            n,
            c,
            cells: vec![None; n * c],
            source_groups: vec![None; n],
            name: name.into(),
        }
    }

    /// Participants.
    pub fn n(&self) -> usize {
        self.n
    }

    /// Statements.
    pub fn c(&self) -> usize {
        self.c
    }

    /// The vote of participant `i` on statement `j`.
    pub fn get(&self, i: usize, j: usize) -> Option<Vote> {
        self.cells[i * self.c + j]
    }

    /// Set a vote.
    pub fn set(&mut self, i: usize, j: usize, v: Option<Vote>) {
        self.cells[i * self.c + j] = v;
    }

    /// Row `i` as a slice.
    pub fn row(&self, i: usize) -> &[Option<Vote>] {
        &self.cells[i * self.c..(i + 1) * self.c]
    }

    /// Votes cast by participant `i`.
    pub fn votes_in_row(&self, i: usize) -> usize {
        self.row(i).iter().filter(|v| v.is_some()).count()
    }

    /// Votes on statement `j`.
    pub fn votes_in_col(&self, j: usize) -> usize {
        (0..self.n).filter(|&i| self.get(i, j).is_some()).count()
    }

    /// Total votes.
    pub fn total_votes(&self) -> usize {
        self.cells.iter().filter(|v| v.is_some()).count()
    }

    /// Keep only the given rows (in order) and drop statements nobody voted on.
    #[must_use]
    pub fn subset_rows(&self, rows: &[usize]) -> VoteMatrix {
        let mut m = VoteMatrix::new(self.name.clone(), rows.len(), self.c);
        for (ni, &i) in rows.iter().enumerate() {
            m.cells[ni * self.c..(ni + 1) * self.c].copy_from_slice(self.row(i));
            m.source_groups[ni] = self.source_groups[i];
        }
        m.drop_empty_columns()
    }

    /// Drop statements with no votes at all.
    #[must_use]
    pub fn drop_empty_columns(&self) -> VoteMatrix {
        let keep: Vec<usize> = (0..self.c).filter(|&j| self.votes_in_col(j) > 0).collect();
        if keep.len() == self.c {
            return self.clone();
        }
        let mut m = VoteMatrix::new(self.name.clone(), self.n, keep.len());
        for i in 0..self.n {
            for (nj, &j) in keep.iter().enumerate() {
                m.cells[i * keep.len() + nj] = self.get(i, j);
            }
            m.source_groups[i] = self.source_groups[i];
        }
        m
    }

    /// A uniformly random subsample of `n` participants (E2 in the research).
    #[must_use]
    pub fn subsample(&self, n: usize, rng: &mut impl Rng) -> VoteMatrix {
        if n >= self.n {
            return self.clone();
        }
        let mut idx = sample(rng, self.n, n).into_vec();
        idx.sort_unstable();
        self.subset_rows(&idx)
    }

    /// Keep at most `k` randomly chosen votes per participant (`bound`).
    #[must_use]
    pub fn bound(&self, k: usize, rng: &mut impl Rng) -> VoteMatrix {
        let mut m = self.clone();
        for i in 0..self.n {
            let idx: Vec<usize> = (0..self.c).filter(|&j| self.get(i, j).is_some()).collect();
            if idx.len() > k {
                let drop = sample(rng, idx.len(), idx.len() - k);
                for d in drop {
                    m.set(i, idx[d], None);
                }
            }
        }
        m
    }

    /// Per-statement mean of the cast votes (NaN where nobody voted).
    pub fn column_means(&self) -> Vec<f64> {
        (0..self.c)
            .map(|j| {
                let (mut s, mut k) = (0.0, 0usize);
                for i in 0..self.n {
                    if let Some(v) = self.get(i, j) {
                        s += v.value();
                        k += 1;
                    }
                }
                if k == 0 { f64::NAN } else { s / k as f64 }
            })
            .collect()
    }
}
