use byteorder::{BigEndian, LittleEndian};

use super::RawPcapPacket;
use crate::errors::*;
use crate::pcap::{PcapHeader, PcapPacket};
use crate::Endianness;

/// Parses a Pcap from a slice of bytes.
///
/// You can match on [`PcapError::IncompleteBuffer`](crate::errors::PcapError) to known if the parser need more data.
///
/// # Example
/// ```no_run
/// use pcaparse::pcap::PcapParser;
/// use pcaparse::PcapError;
///
/// let pcap = vec![0_u8; 0];
/// let mut src = &pcap[..];
///
/// // Creates a new parser and parse the pcap header
/// let (rem, pcap_parser) = PcapParser::new(&pcap[..]).unwrap();
/// src = rem;
///
/// loop {
///     match pcap_parser.next_packet(src) {
///         Ok((rem, packet)) => {
///             // Do something
///
///             // Don't forget to update src
///             src = rem;
///
///             // No more data, if no more incoming either then this is the end of the file
///             if rem.is_empty() {
///                 break;
///             }
///         },
///         Err(PcapError::IncompleteBuffer) => {}, // Load more data into src
///         Err(_) => {},                           // Parsing error
///     }
/// }
/// ```
#[derive(Debug)]
pub struct PcapParser {
    header: PcapHeader,
}

impl PcapParser {
    /// Creates a new [`PcapParser`].
    ///
    /// Returns the remainder and the parser.
    pub fn new(slice: &[u8]) -> PcapResult<(&[u8], PcapParser)> {
        let (slice, header) = PcapHeader::from_slice(slice)?;

        let parser = PcapParser { header };

        Ok((slice, parser))
    }

    /// Creates a new Asynchronously [`PcapParser`].
    ///
    /// Returns the remainder and the parser.
    #[cfg(feature = "tokio")]
    pub async fn async_new(slice: &[u8]) -> PcapResult<(&[u8], PcapParser)> {
        let (slice, header) = PcapHeader::async_from_slice(slice).await?;

        let parser = PcapParser { header };

        Ok((slice, parser))
    }

    /// Returns the remainder and the next [`PcapPacket`].
    pub fn next_packet<'a>(&self, slice: &'a [u8]) -> PcapResult<(&'a [u8], PcapPacket<'a>)> {
        match self.header.endianness {
            Endianness::Big => PcapPacket::from_slice::<BigEndian>(slice, self.header.ts_resolution, self.header.snaplen),
            Endianness::Little => PcapPacket::from_slice::<LittleEndian>(slice, self.header.ts_resolution, self.header.snaplen),
        }
    }

    /// Asynchronously returns the remainder and the next [`PcapPacket`].
    #[cfg(feature = "tokio")]
    pub async fn async_next_packet<'a>(&self, slice: &'a [u8]) -> PcapResult<(&'a [u8], PcapPacket<'a>)> {
        match self.header.endianness {
            Endianness::Big => PcapPacket::async_from_slice::<BigEndian>(slice, self.header.ts_resolution, self.header.snaplen).await,
            Endianness::Little => PcapPacket::async_from_slice::<LittleEndian>(slice, self.header.ts_resolution, self.header.snaplen).await,
        }
    }

    /// Returns the remainder and the next [`RawPcapPacket`].
    pub fn next_raw_packet<'a>(&self, slice: &'a [u8]) -> PcapResult<(&'a [u8], RawPcapPacket<'a>)> {
        match self.header.endianness {
            Endianness::Big => RawPcapPacket::from_slice::<BigEndian>(slice),
            Endianness::Little => RawPcapPacket::from_slice::<LittleEndian>(slice),
        }
    }

    /// Asynchronously returns the remainder and the next [`RawPcapPacket`].
    #[cfg(feature = "tokio")]
    pub async fn async_next_raw_packet<'a>(&self, slice: &'a [u8]) -> PcapResult<(&'a [u8], RawPcapPacket<'a>)> {
        match self.header.endianness {
            Endianness::Big => RawPcapPacket::async_from_slice::<BigEndian>(slice).await,
            Endianness::Little => RawPcapPacket::async_from_slice::<LittleEndian>(slice).await,
        }
    }

    /// Returns the header of the pcap file.
    pub fn header(&self) -> PcapHeader {
        self.header
    }
}
