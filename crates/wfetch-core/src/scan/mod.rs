//! The scan engine.

pub mod rate;
pub mod result;

pub use rate::{RttEstimator, TokenBucket};
pub use result::{Confidence, Evidence, Host, ScanReport};
