use std::io::Write;

use byteorder::{BigEndian, ByteOrder, LittleEndian};
#[cfg(feature = "tokio")]
use tokio::io::AsyncWrite;

#[cfg(feature = "tokio")]
use super::blocks::block_common::AsyncPcapNgBlock;
use super::blocks::block_common::{Block, PcapNgBlock};
use super::blocks::interface_description::InterfaceDescriptionBlock;
use super::blocks::section_header::SectionHeaderBlock;
use super::blocks::SECTION_HEADER_BLOCK;
use super::RawBlock;
use crate::{Endianness, PcapError, PcapResult};

/// Writes a PcapNg to a writer.
///
/// # Examples
/// ```rust,no_run
/// use std::fs::File;
///
/// use pcaparse::pcapng::{PcapNgReader, PcapNgWriter};
///
/// let file_in = File::open("test.pcapng").expect("Error opening file");
/// let mut pcapng_reader = PcapNgReader::new(file_in).unwrap();
///
/// let mut out = Vec::new();
/// let mut pcapng_writer = PcapNgWriter::new(out).unwrap();
///
/// // Read test.pcapng
/// while let Some(block) = pcapng_reader.next_block() {
///     // Check if there is no error
///     let block = block.unwrap();
///
///     // Write back parsed Block
///     pcapng_writer.write_block(&block).unwrap();
/// }
/// ```
pub struct PcapNgWriter<W> {
    section: SectionHeaderBlock<'static>,
    interfaces: Vec<InterfaceDescriptionBlock<'static>>,
    writer: W,
}

impl<W> PcapNgWriter<W> {
    /// Consumes [`Self`], returning the wrapped writer.
    pub fn into_inner(self) -> W {
        self.writer
    }

    /// Gets a reference to the underlying writer.
    pub fn get_ref(&self) -> &W {
        &self.writer
    }

    /// Gets a mutable reference to the underlying writer.
    ///
    /// You should not be used unless you really know what you're doing
    pub fn get_mut(&mut self) -> &mut W {
        &mut self.writer
    }

    /// Returns the current [`SectionHeaderBlock`].
    pub fn section(&self) -> &SectionHeaderBlock<'static> {
        &self.section
    }

    /// Returns all the current [`InterfaceDescriptionBlock`].
    pub fn interfaces(&self) -> &[InterfaceDescriptionBlock<'static>] {
        &self.interfaces
    }
}

impl<W: Write> PcapNgWriter<W> {
    /// Creates a new [`PcapNgWriter`] from an existing writer.
    ///
    /// Defaults to the native endianness of the CPU.
    ///
    /// Writes this global pcapng header to the file:
    /// ```rust, ignore
    /// Self {
    ///     endianness: Endianness::Native,
    ///     major_version: 1,
    ///     minor_version: 0,
    ///     section_length: -1,
    ///     options: vec![]
    /// }
    /// ```
    ///
    ///
    /// # Errors
    /// The writer can't be written to.
    pub fn new(writer: W) -> PcapResult<Self> {
        Self::with_endianness(writer, Endianness::native())
    }

    /// Creates a new [`PcapNgWriter`] from an existing writer with the given endianness.
    pub fn with_endianness(writer: W, endianness: Endianness) -> PcapResult<Self> {
        let section = SectionHeaderBlock { endianness, ..Default::default() };

        Self::with_section_header(writer, section)
    }

    /// Creates a new [`PcapNgWriter`] from an existing writer with the given section header.
    pub fn with_section_header(mut writer: W, section: SectionHeaderBlock<'static>) -> PcapResult<Self> {
        match section.endianness {
            Endianness::Big => section.clone().into_block().write_to::<BigEndian, _>(&mut writer).map_err(PcapError::IoError)?,
            Endianness::Little => section.clone().into_block().write_to::<LittleEndian, _>(&mut writer).map_err(PcapError::IoError)?,
        };

        Ok(Self { section, interfaces: vec![], writer })
    }

    /// Writes a [`Block`].
    ///
    /// # Example
    /// ```rust,no_run
    /// use std::borrow::Cow;
    /// use std::fs::File;
    /// use std::time::Duration;
    ///
    /// use pcaparse::pcapng::blocks::enhanced_packet::EnhancedPacketBlock;
    /// use pcaparse::pcapng::blocks::interface_description::InterfaceDescriptionBlock;
    /// use pcaparse::pcapng::{PcapNgBlock, PcapNgWriter};
    /// use pcaparse::DataLink;
    ///
    /// let data = [0u8; 10];
    ///
    /// let interface = InterfaceDescriptionBlock {
    ///     linktype: DataLink::ETHERNET,
    ///     snaplen: 0xFFFF,
    ///     options: vec![],
    ///     ts_offset: None,
    ///     ts_divide: None,
    /// };
    ///
    /// let packet = EnhancedPacketBlock {
    ///     interface_id: 0,
    ///     timestamp: Duration::from_secs(0),
    ///     original_len: data.len() as u32,
    ///     data: Cow::Borrowed(&data),
    ///     options: vec![],
    ///     timestamp_num: 0,
    ///     linktype: DataLink::ETHERNET,
    /// };
    ///
    /// let file = File::create("out.pcap").expect("Error creating file");
    /// let mut pcap_ng_writer = PcapNgWriter::new(file).unwrap();
    ///
    /// pcap_ng_writer.write_block(&interface.into_block()).unwrap();
    /// pcap_ng_writer.write_block(&packet.into_block()).unwrap();
    /// ```
    pub fn write_block(&mut self, block: &Block) -> PcapResult<usize> {
        match block {
            Block::SectionHeader(a) => {
                self.section = a.clone().into_owned();
                self.interfaces.clear();
            },
            Block::InterfaceDescription(a) => {
                self.interfaces.push(a.clone().into_owned());
            },
            Block::InterfaceStatistics(a) => {
                if a.interface_id as usize >= self.interfaces.len() {
                    return Err(PcapError::InvalidInterfaceId(a.interface_id));
                }
            },
            Block::EnhancedPacket(a) => {
                if a.interface_id as usize >= self.interfaces.len() {
                    return Err(PcapError::InvalidInterfaceId(a.interface_id));
                }
            },

            _ => (),
        }

        match self.section.endianness {
            Endianness::Big => block.write_to::<BigEndian, _>(&mut self.writer).map_err(PcapError::IoError),
            Endianness::Little => block.write_to::<LittleEndian, _>(&mut self.writer).map_err(PcapError::IoError),
        }
    }

    /// Writes a [`PcapNgBlock`].
    ///
    /// # Example
    /// ```rust,no_run
    /// use std::borrow::Cow;
    /// use std::fs::File;
    /// use std::time::Duration;
    ///
    /// use pcaparse::pcapng::blocks::enhanced_packet::EnhancedPacketBlock;
    /// use pcaparse::pcapng::blocks::interface_description::InterfaceDescriptionBlock;
    /// use pcaparse::pcapng::{PcapNgBlock, PcapNgWriter};
    /// use pcaparse::DataLink;
    ///
    /// let data = [0u8; 10];
    ///
    /// let interface = InterfaceDescriptionBlock {
    ///     linktype: DataLink::ETHERNET,
    ///     snaplen: 0xFFFF,
    ///     options: vec![],
    ///     ts_offset: None,
    ///     ts_divide: None,
    /// };
    ///
    /// let packet = EnhancedPacketBlock {
    ///     interface_id: 0,
    ///     timestamp: Duration::from_secs(0),
    ///     original_len: data.len() as u32,
    ///     data: Cow::Borrowed(&data),
    ///     options: vec![],
    ///     timestamp_num: 0,
    ///     linktype: DataLink::ETHERNET,
    /// };
    ///
    /// let file = File::create("out.pcap").expect("Error creating file");
    /// let mut pcap_ng_writer = PcapNgWriter::new(file).unwrap();
    ///
    /// pcap_ng_writer.write_pcapng_block(interface).unwrap();
    /// pcap_ng_writer.write_pcapng_block(packet).unwrap();
    /// ```
    pub fn write_pcapng_block<'a, B: PcapNgBlock<'a>>(&mut self, block: B) -> PcapResult<usize> {
        self.write_block(&block.into_block())
    }

    /// Writes a [`RawBlock`].
    ///
    /// Doesn't check the validity of the written blocks.
    pub fn write_raw_block(&mut self, block: &RawBlock) -> PcapResult<usize> {
        return match self.section.endianness {
            Endianness::Big => inner::<BigEndian, _>(&mut self.section, block, &mut self.writer),
            Endianness::Little => inner::<LittleEndian, _>(&mut self.section, block, &mut self.writer),
        };

        fn inner<B: ByteOrder, W: Write>(section: &mut SectionHeaderBlock, block: &RawBlock, writer: &mut W) -> PcapResult<usize> {
            if block.type_ == SECTION_HEADER_BLOCK {
                *section = block.clone().try_into_block::<B>()?.into_owned().into_section_header().unwrap();
            }

            block.write_to::<B, _>(writer).map_err(PcapError::IoError)
        }
    }
}

#[cfg(feature = "tokio")]
impl<W: AsyncWrite + Unpin + Send> PcapNgWriter<W> {
    /// Creates a new [`PcapNgWriter`] from an existing writer.
    ///
    /// Defaults to the native endianness of the CPU.
    ///
    /// Writes this global pcapng header to the file:
    /// ```rust, ignore
    /// Self {
    ///     endianness: Endianness::Native,
    ///     major_version: 1,
    ///     minor_version: 0,
    ///     section_length: -1,
    ///     options: vec![]
    /// }
    /// ```
    ///
    ///
    /// # Errors
    /// The writer can't be written to.
    pub async fn async_new(writer: W) -> PcapResult<Self> {
        Self::async_with_endianness(writer, Endianness::native()).await
    }

    /// Creates a new [`PcapNgWriter`] from an existing writer with the given endianness.
    pub async fn async_with_endianness(writer: W, endianness: Endianness) -> PcapResult<Self> {
        let section = SectionHeaderBlock { endianness, ..Default::default() };

        Self::async_with_section_header(writer, section).await
    }

    /// Creates a new [`PcapNgWriter`] from an existing writer with the given section header.
    pub async fn async_with_section_header(mut writer: W, section: SectionHeaderBlock<'static>) -> PcapResult<Self> {
        match section.endianness {
            Endianness::Big => section
                .clone()
                .into_block()
                .async_write_to::<BigEndian, _>(&mut writer)
                .await
                .map_err(PcapError::IoError)?,
            Endianness::Little => section
                .clone()
                .into_block()
                .async_write_to::<LittleEndian, _>(&mut writer)
                .await
                .map_err(PcapError::IoError)?,
        };

        Ok(Self { section, interfaces: vec![], writer })
    }

    /// Writes a [`Block`].
    ///
    /// # Example
    /// ```rust,no_run
    /// # tokio_test::block_on(async {
    /// use std::borrow::Cow;
    /// use std::time::Duration;
    /// use tokio::fs::File;
    ///
    /// use pcaparse::pcapng::blocks::enhanced_packet::EnhancedPacketBlock;
    /// use pcaparse::pcapng::blocks::interface_description::InterfaceDescriptionBlock;
    /// use pcaparse::pcapng::{PcapNgBlock, AsyncPcapNgBlock, PcapNgWriter};
    /// use pcaparse::DataLink;
    ///
    /// let data = [0u8; 10];
    ///
    /// let interface = InterfaceDescriptionBlock {
    ///     linktype: DataLink::ETHERNET,
    ///     snaplen: 0xFFFF,
    ///     options: vec![],
    ///     ts_offset: None,
    ///     ts_divide: None,
    /// };
    ///
    /// let packet = EnhancedPacketBlock {
    ///     interface_id: 0,
    ///     timestamp: Duration::from_secs(0),
    ///     original_len: data.len() as u32,
    ///     data: Cow::Borrowed(&data),
    ///     timestamp_num: 0,
    ///     linktype: DataLink::ETHERNET,
    ///     options: vec![],
    /// };
    ///
    /// let file = File::create("out.pcap").await.expect("Error creating file");
    /// let mut pcap_ng_writer = PcapNgWriter::async_new(file).await.unwrap();
    ///
    /// pcap_ng_writer.async_write_block(&interface.into_block()).await.unwrap();
    /// pcap_ng_writer.async_write_block(&packet.into_block()).await.unwrap();
    /// # });
    /// ```
    pub async fn async_write_block(&mut self, block: &Block<'_>) -> PcapResult<usize> {
        match block {
            Block::SectionHeader(a) => {
                self.section = a.clone().into_owned();
                self.interfaces.clear();
            },
            Block::InterfaceDescription(a) => {
                self.interfaces.push(a.clone().into_owned());
            },
            Block::InterfaceStatistics(a) => {
                if a.interface_id as usize >= self.interfaces.len() {
                    return Err(PcapError::InvalidInterfaceId(a.interface_id));
                }
            },
            Block::EnhancedPacket(a) => {
                if a.interface_id as usize >= self.interfaces.len() {
                    return Err(PcapError::InvalidInterfaceId(a.interface_id));
                }
            },

            _ => (),
        }

        match self.section.endianness {
            Endianness::Big => block.async_write_to::<BigEndian, _>(&mut self.writer).await.map_err(PcapError::IoError),
            Endianness::Little => block.async_write_to::<LittleEndian, _>(&mut self.writer).await.map_err(PcapError::IoError),
        }
    }

    /// Writes a [`PcapNgBlock`].
    ///
    /// # Example
    /// ```rust,no_run
    /// # tokio_test::block_on(async {
    /// use std::borrow::Cow;
    /// use std::time::Duration;
    /// use tokio::fs::File;
    ///
    /// use pcaparse::pcapng::blocks::enhanced_packet::EnhancedPacketBlock;
    /// use pcaparse::pcapng::blocks::interface_description::InterfaceDescriptionBlock;
    /// use pcaparse::pcapng::{PcapNgBlock, AsyncPcapNgBlock, PcapNgWriter};
    /// use pcaparse::DataLink;
    ///
    /// let data = [0u8; 10];
    ///
    /// let interface = InterfaceDescriptionBlock {
    ///     linktype: DataLink::ETHERNET,
    ///     snaplen: 0xFFFF,
    ///     options: vec![],
    ///     ts_offset: None,
    ///     ts_divide: None,
    /// };
    ///
    /// let packet = EnhancedPacketBlock {
    ///     interface_id: 0,
    ///     timestamp: Duration::from_secs(0),
    ///     original_len: data.len() as u32,
    ///     data: Cow::Borrowed(&data),
    ///     timestamp_num: 0,
    ///     linktype: DataLink::ETHERNET,
    ///     options: vec![],
    /// };
    ///
    /// let file = File::create("out.pcap").await.expect("Error creating file");
    /// let mut pcap_ng_writer = PcapNgWriter::async_new(file).await.unwrap();
    ///
    /// pcap_ng_writer.async_write_pcapng_block(interface).await.unwrap();
    /// pcap_ng_writer.async_write_pcapng_block(packet).await.unwrap();
    /// # });
    /// ```
    pub async fn async_write_pcapng_block<'a, B: AsyncPcapNgBlock<'a> + PcapNgBlock<'a>>(&mut self, block: B) -> PcapResult<usize> {
        self.async_write_block(&block.into_block()).await
    }

    /// Writes a [`RawBlock`].
    ///
    /// Doesn't check the validity of the written blocks.
    pub async fn async_write_raw_block(&mut self, block: &RawBlock<'_>) -> PcapResult<usize> {
        return match self.section.endianness {
            Endianness::Big => inner::<BigEndian, _>(&mut self.section, block, &mut self.writer).await,
            Endianness::Little => inner::<LittleEndian, _>(&mut self.section, block, &mut self.writer).await,
        };

        async fn inner<B: ByteOrder + Send, W: AsyncWrite + Unpin>(
            section: &mut SectionHeaderBlock<'_>,
            block: &RawBlock<'_>,
            writer: &mut W,
        ) -> PcapResult<usize> {
            if block.type_ == SECTION_HEADER_BLOCK {
                *section = block.clone().async_try_into_block::<B>().await?.into_owned().into_section_header().unwrap();
            }

            block.async_write_to::<B, _>(writer).await.map_err(PcapError::IoError)
        }
    }
}
