use byteorder::{BigEndian, LittleEndian};

use super::RawCapPacket;
use crate::cap::{CapHeader, CapPacket};
use crate::errors::*;
use crate::Endianness;

/// Parses a Cap from a slice of bytes.
///
/// You can match on [`PcapError::IncompleteBuffer`](crate::errors::PcapError) to known if the parser need more data.
///
/// # Example
/// ```no_run
/// use pcaparse::cap::CapParser;
/// use pcaparse::PcapError;
///
/// let cap = vec![0_u8; 0];
/// let mut src = &cap[..];
///
/// // Creates a new parser and parse the cap header
/// let (rem, cap_parser) = CapParser::new(&cap[..]).unwrap();
/// src = rem;
///
/// loop {
///     match cap_parser.next_packet(src) {
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
pub struct CapParser {
    header: CapHeader,
}

impl CapParser {
    /// Creates a new [`CapParser`].
    ///
    /// Returns the remainder and the parser.
    pub fn new(slice: &[u8]) -> PcapResult<(&[u8], CapParser)> {
        let (slice, header) = CapHeader::from_slice(slice)?;

        let parser = CapParser { header };

        Ok((slice, parser))
    }

    /// Creates a new Asynchronously [`CapParser`].
    ///
    /// Returns the remainder and the parser.
    #[cfg(feature = "tokio")]
    pub async fn async_new(slice: &[u8]) -> PcapResult<(&[u8], CapParser)> {
        let (slice, header) = CapHeader::async_from_slice(slice).await?;

        let parser = CapParser { header };

        Ok((slice, parser))
    }

    /// Returns the remainder and the next [`CapPacket`].
    pub fn next_packet<'a>(&self, slice: &'a [u8]) -> PcapResult<(&'a [u8], CapPacket<'a>)> {
        match self.header.endianness {
            Endianness::Big => CapPacket::from_slice::<BigEndian>(slice, self.header.start_time),
            Endianness::Little => CapPacket::from_slice::<LittleEndian>(slice, self.header.start_time),
        }
    }

    /// Asynchronously returns the remainder and the next [`CapPacket`].
    #[cfg(feature = "tokio")]
    pub async fn async_next_packet<'a>(&self, slice: &'a [u8]) -> PcapResult<(&'a [u8], CapPacket<'a>)> {
        match self.header.endianness {
            Endianness::Big => CapPacket::async_from_slice::<BigEndian>(slice, self.header.start_time).await,
            Endianness::Little => CapPacket::async_from_slice::<LittleEndian>(slice, self.header.start_time).await,
        }
    }

    /// Returns the remainder and the next [`RawCapPacket`].
    pub fn next_raw_packet<'a>(&self, slice: &'a [u8]) -> PcapResult<(&'a [u8], RawCapPacket<'a>)> {
        match self.header.endianness {
            Endianness::Big => RawCapPacket::from_slice::<BigEndian>(slice),
            Endianness::Little => RawCapPacket::from_slice::<LittleEndian>(slice),
        }
    }

    /// Asynchronously returns the remainder and the next [`RawCapPacket`].
    #[cfg(feature = "tokio")]
    pub async fn async_next_raw_packet<'a>(&self, slice: &'a [u8]) -> PcapResult<(&'a [u8], RawCapPacket<'a>)> {
        match self.header.endianness {
            Endianness::Big => RawCapPacket::async_from_slice::<BigEndian>(slice).await,
            Endianness::Little => RawCapPacket::async_from_slice::<LittleEndian>(slice).await,
        }
    }

    /// Returns the header of the cap file.
    pub fn header(&self) -> CapHeader {
        self.header
    }
}
