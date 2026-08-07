//! Wire-format codecs for the discovery protocols.
//!
//! Every module here is pure: messages are built into and parsed out of byte
//! slices with no I/O. That keeps the formats testable without a network or
//! elevated privileges, and it is where the awkward details live — the RFC 1071
//! checksum, DNS name decompression, the NetBIOS level-1 name encoding — each
//! of which fails silently rather than loudly when it is wrong.

pub mod dns;
pub mod icmp;
pub mod mdns;
pub mod netbios;
pub mod ssdp;
