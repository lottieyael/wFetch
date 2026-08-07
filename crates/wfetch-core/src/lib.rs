//! wFetch core: cross-platform network discovery, device identification and
//! host inventory.
//!
//! The crate is layered so that everything above the platform boundary is pure
//! and testable without a network:
//!
//! * [`addr`] — address arithmetic. No I/O.
//! * [`target`] — turns user-supplied target specs into a bounded scan plan.
//! * [`platform`] — the only place that touches OS network APIs.

pub mod addr;
pub mod mac;
pub mod platform;
pub mod target;

pub use addr::{AddrClass, AddrError, IpCidr, Ipv4Cidr, Ipv6Cidr};
pub use mac::MacAddr;
pub use platform::{Capabilities, HostPlatform, Interface, NeighborEntry, NeighborState};
pub use target::{TargetError, TargetPlan, TargetSpec};
