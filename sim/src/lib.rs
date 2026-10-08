//! The Hum simulator: a headless world of simulated phones that runs the
//! whole ratchet (chat → issue map → deck → release → chat) in-process.
//!
//! Wave 0 ships the skeleton described in `docs/specs/simulator.md`: scenario
//! loading, simulated phones as data structures, services behind ports with
//! fakes, a fake aggregator that is a port of the research pipeline in
//! `docs/research/dp-polis/polis_dp.py`, the Polis loader, a synthetic
//! fixture, the metrics, the leak checker and the report writer.
//!
//! Nothing in this crate is production code. The fakes use plain floating
//! point noise and a non-cryptographic hash; both are labelled and both are
//! replaced by wave 1 crates (see the spec).

#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::similar_names,
    clippy::many_single_char_names,
    clippy::too_many_lines,
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    clippy::missing_panics_doc,
    clippy::missing_errors_doc,
    clippy::struct_excessive_bools
)]

pub mod cli;
pub mod data;
pub mod fakes;
pub mod leak;
pub mod phone;
pub mod pipeline;
pub mod ports;
pub mod report;
pub mod scenario;
pub mod thresholds;
pub mod world;
