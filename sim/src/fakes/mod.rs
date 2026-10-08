//! Wave 0 fakes behind the ports. Each is replaced by a wave 1 workstream's
//! real component; each records everything it sees on the tape so the leak
//! checker can judge it the same way it will judge the real one.

pub mod aggregator;
pub mod delivery;
pub mod identity;
pub mod ledger;
pub mod store;

pub use aggregator::{FakeAggregator, Tiering};
pub use delivery::FakeDelivery;
pub use identity::{FakeIssuer, Scheme, SchemeVerifier, new_scheme};
pub use ledger::FakeLedger;
pub use store::FakeBlobStore;
