//! An in-memory [`HostPlatform`] for tests.
//!
//! Lets the engine's interface-selection and neighbour-merging logic be tested
//! against exact, reproducible topologies, including ones that are awkward to
//! build for real (a host with six NICs, a failed ARP entry, a VPN tunnel).

use super::{Capabilities, HostPlatform, Interface, NeighborEntry, PlatformError, Result};

/// A platform backend whose answers are supplied by the test.
#[derive(Debug, Clone)]
pub struct FakePlatform {
    interfaces: Vec<Interface>,
    neighbors: Vec<NeighborEntry>,
    capabilities: Capabilities,
    /// When set, `neighbors()` fails with this error instead of returning data,
    /// which is how the Android "no neighbour table" path is exercised.
    neighbors_error: Option<PlatformError>,
}

impl FakePlatform {
    pub fn new(interfaces: Vec<Interface>, neighbors: Vec<NeighborEntry>) -> Self {
        Self {
            interfaces,
            neighbors,
            capabilities: Capabilities::full(),
            neighbors_error: None,
        }
    }

    pub fn with_capabilities(mut self, c: Capabilities) -> Self {
        self.capabilities = c;
        self
    }

    /// Makes the neighbour table unreadable, as on unrooted Android.
    pub fn with_unreadable_neighbors(mut self) -> Self {
        self.neighbors_error = Some(PlatformError::Unsupported("neighbour table"));
        self.capabilities.neighbor_table = false;
        self
    }
}

impl HostPlatform for FakePlatform {
    fn name(&self) -> &'static str {
        "fake"
    }

    fn interfaces(&self) -> Result<Vec<Interface>> {
        Ok(self.interfaces.clone())
    }

    fn neighbors(&self) -> Result<Vec<NeighborEntry>> {
        match &self.neighbors_error {
            Some(e) => Err(e.clone()),
            None => Ok(self.neighbors.clone()),
        }
    }

    fn capabilities(&self) -> Capabilities {
        self.capabilities
    }
}
