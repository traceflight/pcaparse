#![allow(clippy::unreadable_literal)]
#![deny(missing_docs)]

//! Provides parsers, readers and writers for Cap(Network Associates Sniffer 2.x),
//! Pcap and PcapNg files.
//!
//! For Pcap see the [`pcap`] module, especially [`PcapParser`](pcap::PcapParser),
//! [`PcapReader<R>`](pcap::PcapReader) and [`PcapWriter<W>`](pcap::PcapWriter).
//!
//! For PcapNg see the [`pcapng`] module, especially [`PcapNgParser`](pcapng::PcapNgParser),
//! [`PcapNgReader<R>`](pcapng::PcapNgReader) and [`PcapNgWriter<W>`](pcapng::PcapNgWriter)
//!
//! For Cap(NA Sniffer 2.x) see the [`cap`] module, especially [`CapParser`](cap::CapParser),
//! [`CapReader<R>`](cap::CapReader)

pub use common::*;
pub use errors::*;
pub use unified::*;

pub(crate) mod common;
pub(crate) mod errors;
pub(crate) mod read_buffer;

pub mod cap;
pub mod pcap;
pub mod pcapng;
pub mod unified;

#[cfg(feature = "tokio")]
#[allow(dead_code)]
#[doc = include_str!("../README.md")]
fn readme_compile_exemples() {}
