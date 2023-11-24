use std::io::Read;

#[cfg(feature = "tokio")]
use tokio::io::AsyncRead;

use super::{PcapParser, RawPcapPacket};
use crate::errors::*;
use crate::pcap::{PcapHeader, PcapPacket};
use crate::read_buffer::ReadBuffer;

/// Reads a pcap from a reader.
///
/// # Example
///
/// ```rust,no_run
/// use std::fs::File;
///
/// use pcaparse::pcap::PcapReader;
///
/// let file_in = File::open("test.pcap").expect("Error opening file");
/// let mut pcap_reader = PcapReader::new(file_in).unwrap();
///
/// // Read test.pcap
/// while let Some(pkt) = pcap_reader.next_packet() {
///     //Check if there is no error
///     let pkt = pkt.unwrap();
///
///     //Do something
/// }
/// ```
#[derive(Debug)]
pub struct PcapReader<R> {
    parser: PcapParser,
    reader: ReadBuffer<R>,
}

impl<R> PcapReader<R> {
    /// Returns the global header of the pcap.
    pub fn header(&self) -> PcapHeader {
        self.parser.header()
    }
}

impl<R: Read> PcapReader<R> {
    /// Creates a new [`PcapReader`] from an existing reader.
    ///
    /// This function reads the global pcap header of the file to verify its integrity.
    ///
    /// The underlying reader must point to a valid pcap file/stream.
    ///
    /// # Errors
    /// The data stream is not in a valid pcap file format.
    ///
    /// The underlying data are not readable.
    pub fn new(reader: R) -> Result<PcapReader<R>, PcapError> {
        let mut reader = ReadBuffer::new(reader);
        let parser = reader.parse_with(PcapParser::new)?;

        Ok(PcapReader { parser, reader })
    }

    /// Consumes [`Self`], returning the wrapped reader.
    pub fn into_reader(self) -> R {
        self.reader.into_inner()
    }

    /// Returns the next [`PcapPacket`].
    pub fn next_packet(&mut self) -> Option<Result<PcapPacket, PcapError>> {
        match self.reader.has_data_left() {
            Ok(has_data) => {
                if has_data {
                    Some(self.reader.parse_with(|src| self.parser.next_packet(src)))
                } else {
                    None
                }
            },
            Err(e) => Some(Err(PcapError::IoError(e))),
        }
    }

    /// Returns the next [`RawPcapPacket`].
    pub fn next_raw_packet(&mut self) -> Option<Result<RawPcapPacket, PcapError>> {
        match self.reader.has_data_left() {
            Ok(has_data) => {
                if has_data {
                    Some(self.reader.parse_with(|src| self.parser.next_raw_packet(src)))
                } else {
                    None
                }
            },
            Err(e) => Some(Err(PcapError::IoError(e))),
        }
    }
}

impl<R> AsRef<R> for PcapReader<R> {
    fn as_ref(&self) -> &R {
        self.reader.as_ref()
    }
}

impl<R> AsMut<R> for PcapReader<R> {
    fn as_mut(&mut self) -> &mut R {
        self.reader.as_mut()
    }
}

#[cfg(feature = "tokio")]
impl<R: AsyncRead + Unpin> PcapReader<R> {
    /// Creates a new [`PcapReader`] from an existing reader.
    ///
    /// This function reads the global pcap header of the file to verify its integrity.
    ///
    /// The underlying reader must point to a valid pcap file/stream.
    ///
    /// # Errors
    /// The data stream is not in a valid pcap file format.
    ///
    /// The underlying data are not readable.
    pub async fn async_new(reader: R) -> Result<PcapReader<R>, PcapError> {
        let mut reader = ReadBuffer::new(reader);
        let parser = reader.async_parse_with(PcapParser::async_new).await?;

        Ok(PcapReader { parser, reader })
    }

    /// Consumes [`Self`], returning the wrapped reader.
    pub fn into_async_reader(self) -> R {
        self.reader.into_inner()
    }

    /// Returns the next [`PcapPacket`].
    pub async fn async_next_packet(&mut self) -> Option<Result<PcapPacket, PcapError>> {
        match self.reader.async_has_data_left().await {
            Ok(has_data) => {
                if has_data {
                    Some(self.reader.async_parse_with(|src| self.parser.async_next_packet(src)).await)
                } else {
                    None
                }
            },
            Err(e) => Some(Err(PcapError::IoError(e))),
        }
    }

    /// Returns the next [`RawPcapPacket`].
    pub async fn async_next_raw_packet(&mut self) -> Option<Result<RawPcapPacket, PcapError>> {
        match self.reader.async_has_data_left().await {
            Ok(has_data) => {
                if has_data {
                    Some(self.reader.async_parse_with(|src| self.parser.async_next_raw_packet(src)).await)
                } else {
                    None
                }
            },
            Err(e) => Some(Err(PcapError::IoError(e))),
        }
    }
}
