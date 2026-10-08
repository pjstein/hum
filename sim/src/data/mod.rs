//! Conversations the simulator replays: the vote matrix type, the Polis open
//! data loader and the seeded synthetic fixture.

pub mod polis;
pub mod synthetic;
pub mod votes;

pub use votes::{Vote, VoteMatrix};
