use std::io::Read;

#[cfg(feature = "tokio")]
use tokio::io::AsyncRead;

use super::{CapParser, RawCapPacket};
use crate::cap::{CapHeader, CapPacket};
use crate::errors::*;
use crate::read_buffer::ReadBuffer;

/// Reads a cap from a reader.
///
/// # Example
///
/// ```rust,no_run
/// use std::fs::File;
///
/// use pcaparse::cap::CapReader;
///
/// let file_in = File::open("test.cap").expect("Error opening file");
/// let mut cap_reader = CapReader::new(file_in).unwrap();
///
/// // Read test.cap
/// while let Some(pkt) = cap_reader.next_packet() {
///     //Check if there is no error
///     let pkt = pkt.unwrap();
///
///     //Do something
/// }
/// ```
#[derive(Debug)]
pub struct CapReader<R> {
    parser: CapParser,
    reader: ReadBuffer<R>,
}

impl<R> CapReader<R> {
    /// Returns the global header of the cap.
    pub fn header(&self) -> CapHeader {
        self.parser.header()
    }
}

impl<R: Read> CapReader<R> {
    /// Creates a new [`CapReader`] from an existing reader.
    ///
    /// This function reads the global cap header of the file to verify its integrity.
    ///
    /// The underlying reader must point to a valid cap file/stream.
    ///
    /// # Errors
    /// The data stream is not in a valid cap file format.
    ///
    /// The underlying data are not readable.
    pub fn new(reader: R) -> Result<CapReader<R>, PcapError> {
        let mut reader = ReadBuffer::new(reader);
        let parser = reader.parse_with(CapParser::new)?;

        Ok(CapReader { parser, reader })
    }

    /// Consumes [`Self`], returning the wrapped reader.
    pub fn into_reader(self) -> R {
        self.reader.into_inner()
    }

    /// Returns the next [`CapPacket`].
    pub fn next_packet(&mut self) -> Option<Result<CapPacket, PcapError>> {
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

    /// Returns the next [`RawCapPacket`].
    pub fn next_raw_packet(&mut self) -> Option<Result<RawCapPacket, PcapError>> {
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

impl<R> AsRef<R> for CapReader<R> {
    fn as_ref(&self) -> &R {
        self.reader.as_ref()
    }
}

impl<R> AsMut<R> for CapReader<R> {
    fn as_mut(&mut self) -> &mut R {
        self.reader.as_mut()
    }
}

#[cfg(feature = "tokio")]
impl<R: AsyncRead + Unpin> CapReader<R> {
    /// Creates a new [`CapReader`] from an existing reader.
    ///
    /// This function reads the global cap header of the file to verify its integrity.
    ///
    /// The underlying reader must point to a valid cap file/stream.
    ///
    /// # Errors
    /// The data stream is not in a valid cap file format.
    ///
    /// The underlying data are not readable.
    pub async fn async_new(reader: R) -> Result<CapReader<R>, PcapError> {
        let mut reader = ReadBuffer::new(reader);
        let parser = reader.async_parse_with(CapParser::async_new).await?;

        Ok(CapReader { parser, reader })
    }

    /// Consumes [`Self`], returning the wrapped reader.
    pub fn into_async_reader(self) -> R {
        self.reader.into_inner()
    }

    /// Returns the next [`CapPacket`].
    pub async fn async_next_packet(&mut self) -> Option<Result<CapPacket, PcapError>> {
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

    /// Returns the next [`RawCapPacket`].
    pub async fn async_next_raw_packet(&mut self) -> Option<Result<RawCapPacket, PcapError>> {
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
