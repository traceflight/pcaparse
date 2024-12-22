use std::{borrow::Cow, io::Read};

#[cfg(feature = "tokio")]
use tokio::io::AsyncRead;

use crate::{
    cap::{CapHeader, CapParser, CapReader},
    pcap::{PcapHeader, PcapParser, PcapReader},
    pcapng::{Block, PcapNgParser, PcapNgReader},
    read_buffer::ReadBuffer,
    DataLink, Format, Packet, PcapError,
};

/// Packet file reader
pub struct Reader<R> {
    /// Inner reader
    inner: InnerReader<R>,
    /// current datalink
    datalink: DataLink,
}

impl<R> Reader<R> {
    /// Get datalink
    pub fn datalink(&self) -> DataLink {
        self.datalink
    }

    /// Get file format
    pub fn format(&self) -> Format {
        self.inner.format()
    }

    /// Get header of packet file
    pub fn header(&self) -> Header {
        self.inner.header()
    }
}

impl<R: Read> Reader<R> {
    /// Try construct Reader by reader
    pub fn new(reader: R) -> Result<Self, PcapError> {
        let inner: InnerReader<R> = InnerReader::new(reader)?;
        let datalink = inner.datalink().unwrap_or(DataLink::ETHERNET);
        Ok(Self { inner, datalink })
    }

    /// Construct Reader by reader and file format
    pub fn new_with_format(reader: R, format: Format) -> Result<Self, PcapError> {
        let inner = InnerReader::new_with_format(reader, format)?;
        let datalink = inner.datalink().unwrap_or(DataLink::ETHERNET);
        Ok(Self { inner, datalink })
    }

    /// Get next packet
    pub fn next_packet<'a>(&'a mut self) -> Option<Result<Packet<'a>, PcapError>> {
        match &mut self.inner {
            InnerReader::Pcap(reader) => reader.next_packet().map(|result| result.map(|packet| (packet, self.datalink).into())),
            InnerReader::Cap(reader) => reader.next_packet().map(|result| result.map(|packet| (packet, self.datalink).into())),
            InnerReader::PcapNg(reader) => loop {
                match reader.next_block() {
                    None => return None,
                    Some(block) => match block {
                        Err(e) => return Some(Err(e)),
                        Ok(Block::InterfaceDescription(block)) => {
                            self.datalink = block.linktype;
                        },
                        Ok(Block::EnhancedPacket(block)) => {
                            // lifetime adjust
                            let data: Cow<'a, [u8]> = unsafe { std::mem::transmute(block.data) };
                            let packet = Packet {
                                timestamp: Some(block.timestamp),
                                orig_len: block.original_len,
                                data,
                                datalink: block.linktype,
                            };
                            return Some(Ok(packet));
                        },
                        Ok(Block::SimplePacket(block)) => {
                            let data: Cow<'a, [u8]> = unsafe { std::mem::transmute(block.data) };
                            let packet = Packet { orig_len: block.original_len, data, datalink: self.datalink, timestamp: None };
                            return Some(Ok(packet));
                        },
                        Ok(_) => {},
                    },
                }
            },
        }
    }
}

#[cfg(feature = "tokio")]
impl<R: AsyncRead + Unpin> Reader<R> {
    /// Try construct Reader by reader
    pub async fn async_new(reader: R) -> Result<Self, PcapError> {
        let inner: InnerReader<R> = InnerReader::async_new(reader).await?;
        let datalink = inner.datalink().unwrap_or(DataLink::ETHERNET);
        Ok(Self { inner, datalink })
    }

    /// Construct Reader by reader and file format
    pub async fn async_new_with_format(reader: R, format: Format) -> Result<Self, PcapError> {
        let inner = InnerReader::async_new_with_format(reader, format).await?;
        let datalink = inner.datalink().unwrap_or(DataLink::ETHERNET);
        Ok(Self { inner, datalink })
    }

    /// Get next packet
    pub async fn async_next_packet<'a>(&'a mut self) -> Option<Result<Packet<'a>, PcapError>> {
        match &mut self.inner {
            InnerReader::Pcap(reader) => reader.async_next_packet().await.map(|result| result.map(|packet| (packet, self.datalink).into())),
            InnerReader::Cap(reader) => reader.async_next_packet().await.map(|result| result.map(|packet| (packet, self.datalink).into())),
            InnerReader::PcapNg(reader) => loop {
                match reader.async_next_block().await {
                    None => return None,
                    Some(block) => match block {
                        Err(e) => return Some(Err(e)),
                        Ok(Block::InterfaceDescription(block)) => {
                            self.datalink = block.linktype;
                        },
                        Ok(Block::EnhancedPacket(block)) => {
                            // lifetime adjust
                            let data: Cow<'a, [u8]> = unsafe { std::mem::transmute(block.data) };
                            let packet = Packet {
                                timestamp: Some(block.timestamp),
                                orig_len: block.original_len,
                                data,
                                datalink: block.linktype,
                            };
                            return Some(Ok(packet));
                        },
                        Ok(Block::SimplePacket(block)) => {
                            let data: Cow<'a, [u8]> = unsafe { std::mem::transmute(block.data) };
                            let packet = Packet { orig_len: block.original_len, data, datalink: self.datalink, timestamp: None };
                            return Some(Ok(packet));
                        },
                        Ok(_) => {},
                    },
                }
            },
        }
    }
}

/// Inner reader of packet file
enum InnerReader<R> {
    /// Reader for pcap
    Pcap(PcapReader<R>),
    /// Reader for cap
    Cap(CapReader<R>),
    /// Reader for pcapng
    PcapNg(PcapNgReader<R>),
}

impl<R> InnerReader<R> {
    fn datalink(&self) -> Option<DataLink> {
        match &self {
            InnerReader::Pcap(pcap_reader) => Some(pcap_reader.datalink()),
            InnerReader::Cap(cap_reader) => Some(cap_reader.header().datalink),
            InnerReader::PcapNg(_) => None,
        }
    }

    fn format(&self) -> Format {
        match &self {
            InnerReader::Pcap(_) => Format::Pcap,
            InnerReader::Cap(_) => Format::Cap,
            InnerReader::PcapNg(_) => Format::PcapNg,
        }
    }

    pub fn header(&self) -> Header {
        match &self {
            InnerReader::Pcap(reader) => Header::Pcap(reader.header()),
            InnerReader::Cap(reader) => Header::Cap(reader.header()),
            InnerReader::PcapNg(_) => Header::PcapNg,
        }
    }
}

impl<R: Read> InnerReader<R> {
    fn new(reader: R) -> Result<Self, PcapError> {
        let mut reader = ReadBuffer::new(reader);
        match reader.parse_with(PcapParser::new) {
            Ok(parser) => {
                let reader: PcapReader<R> = (parser, reader).into();
                return Ok(Self::Pcap(reader));
            },
            Err(PcapError::IncompleteBuffer) => return Err(PcapError::IncompleteBuffer),
            _ => {},
        }

        reader.reset_pos();
        match reader.parse_with(PcapNgParser::new) {
            Ok(parser) => {
                let reader: PcapNgReader<R> = (parser, reader).into();
                return Ok(Self::PcapNg(reader));
            },
            Err(PcapError::IncompleteBuffer) => return Err(PcapError::IncompleteBuffer),
            _ => {},
        }

        reader.reset_pos();
        match reader.parse_with(CapParser::new) {
            Ok(parser) => {
                let reader: CapReader<R> = (parser, reader).into();
                return Ok(Self::Cap(reader));
            },
            Err(PcapError::IncompleteBuffer) => return Err(PcapError::IncompleteBuffer),
            _ => {},
        }

        Err(PcapError::UnsupportedFormat)
    }

    /// construct InnerReader by reader and file format
    fn new_with_format(reader: R, format: Format) -> Result<Self, PcapError> {
        match format {
            Format::Pcap => Ok(Self::Pcap(PcapReader::new(reader)?)),
            Format::Cap => Ok(Self::Cap(CapReader::new(reader)?)),
            Format::PcapNg => Ok(Self::PcapNg(PcapNgReader::new(reader)?)),
        }
    }
}

#[cfg(feature = "tokio")]
impl<R: AsyncRead + Unpin> InnerReader<R> {
    async fn async_new(reader: R) -> Result<Self, PcapError> {
        let mut reader = ReadBuffer::new(reader);
        match reader.async_parse_with(PcapParser::async_new).await {
            Ok(parser) => {
                let reader: PcapReader<R> = (parser, reader).into();
                return Ok(Self::Pcap(reader));
            },
            Err(PcapError::IncompleteBuffer) => return Err(PcapError::IncompleteBuffer),
            _ => {},
        }

        reader.reset_pos();
        match reader.async_parse_with(PcapNgParser::async_new).await {
            Ok(parser) => {
                let reader: PcapNgReader<R> = (parser, reader).into();
                return Ok(Self::PcapNg(reader));
            },
            Err(PcapError::IncompleteBuffer) => return Err(PcapError::IncompleteBuffer),
            _ => {},
        }

        reader.reset_pos();
        match reader.async_parse_with(CapParser::async_new).await {
            Ok(parser) => {
                let reader: CapReader<R> = (parser, reader).into();
                return Ok(Self::Cap(reader));
            },
            Err(PcapError::IncompleteBuffer) => return Err(PcapError::IncompleteBuffer),
            _ => {},
        }

        Err(PcapError::UnsupportedFormat)
    }

    /// construct InnerReader by reader and file format
    async fn async_new_with_format(reader: R, format: Format) -> Result<Self, PcapError> {
        match format {
            Format::Pcap => Ok(Self::Pcap(PcapReader::async_new(reader).await?)),
            Format::Cap => Ok(Self::Cap(CapReader::async_new(reader).await?)),
            Format::PcapNg => Ok(Self::PcapNg(PcapNgReader::async_new(reader).await?)),
        }
    }
}

/// Header for packet file
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Header {
    /// Header of pcap file
    Pcap(PcapHeader),
    /// Header of cap file
    Cap(CapHeader),
    /// No header field for PcapNg
    PcapNg,
}
