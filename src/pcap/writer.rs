use std::io::Write;

use byteorder::{BigEndian, LittleEndian};
#[cfg(feature = "tokio")]
use tokio::io::AsyncWrite;

use super::RawPcapPacket;
use crate::errors::*;
use crate::pcap::{PcapHeader, PcapPacket};
use crate::{Endianness, TsResolution};

/// Writes a pcap to a writer.
///
/// # Example
/// ```rust,no_run
/// use std::fs::File;
///
/// use pcaparse::pcap::{PcapReader, PcapWriter};
///
/// let file_in = File::open("test.pcap").expect("Error opening file");
/// let mut pcap_reader = PcapReader::new(file_in).unwrap();
///
/// let file_out = File::create("out.pcap").expect("Error creating file out");
/// let mut pcap_writer = PcapWriter::new(file_out).expect("Error writing file");
///
/// // Read test.pcap
/// while let Some(pkt) = pcap_reader.next_packet() {
///     //Check if there is no error
///     let pkt = pkt.unwrap();
///
///     //Write each packet of test.pcap in out.pcap
///     pcap_writer.write_packet(&pkt).unwrap();
/// }
/// ```
#[derive(Debug)]
pub struct PcapWriter<W> {
    endianness: Endianness,
    snaplen: u32,
    ts_resolution: TsResolution,
    writer: W,
}

impl<W: Write> PcapWriter<W> {
    /// Creates a new [`PcapWriter`] from an existing writer.
    ///
    /// Defaults to the native endianness of the CPU.
    ///
    /// Writes this default global pcap header to the file:
    /// ```rust, ignore
    /// PcapHeader {
    ///     version_major: 2,
    ///     version_minor: 4,
    ///     ts_correction: 0,
    ///     ts_accuracy: 0,
    ///     snaplen: MAXIMUM_SNAPLEN,
    ///     datalink: DataLink::ETHERNET,
    ///     ts_resolution: TsResolution::MicroSecond,
    ///     endianness: Endianness::Native
    /// };
    /// ```
    ///
    /// # Errors
    /// The writer can't be written to.
    pub fn new(writer: W) -> PcapResult<PcapWriter<W>> {
        let header = PcapHeader { endianness: Endianness::native(), ..Default::default() };

        PcapWriter::with_header(writer, header)
    }

    /// Creates a new [`PcapWriter`] from an existing writer with a user defined [`PcapHeader`].
    ///
    /// It also writes the pcap header to the file.
    ///
    /// # Errors
    /// The writer can't be written to.
    pub fn with_header(mut writer: W, header: PcapHeader) -> PcapResult<PcapWriter<W>> {
        header.write_to(&mut writer)?;

        Ok(PcapWriter {
            endianness: header.endianness,
            snaplen: header.snaplen,
            ts_resolution: header.ts_resolution,
            writer,
        })
    }

    /// Writes a [`PcapPacket`].
    pub fn write_packet(&mut self, packet: &PcapPacket) -> PcapResult<usize> {
        match self.endianness {
            Endianness::Big => packet.write_to::<_, BigEndian>(&mut self.writer, self.ts_resolution, self.snaplen),
            Endianness::Little => packet.write_to::<_, LittleEndian>(&mut self.writer, self.ts_resolution, self.snaplen),
        }
    }

    /// Writes a [`RawPcapPacket`].
    pub fn write_raw_packet(&mut self, packet: &RawPcapPacket) -> PcapResult<usize> {
        match self.endianness {
            Endianness::Big => packet.write_to::<_, BigEndian>(&mut self.writer),
            Endianness::Little => packet.write_to::<_, LittleEndian>(&mut self.writer),
        }
    }
}

#[cfg(feature = "tokio")]
impl<W: AsyncWrite + Unpin> PcapWriter<W> {
    /// Creates a new [`PcapWriter`] from an existing writer.
    ///
    /// Defaults to the native endianness of the CPU.
    ///
    /// Writes this default global pcap header to the file:
    /// ```rust, ignore
    /// PcapHeader {
    ///     version_major: 2,
    ///     version_minor: 4,
    ///     ts_correction: 0,
    ///     ts_accuracy: 0,
    ///     snaplen: MAXIMUM_SNAPLEN,
    ///     datalink: DataLink::ETHERNET,
    ///     ts_resolution: TsResolution::MicroSecond,
    ///     endianness: Endianness::Native
    /// };
    /// ```
    ///
    /// # Errors
    /// The writer can't be written to.
    pub async fn async_new(writer: W) -> PcapResult<PcapWriter<W>> {
        let header = PcapHeader { endianness: Endianness::native(), ..Default::default() };

        PcapWriter::async_with_header(writer, header).await
    }

    /// Creates a new [`PcapWriter`] from an existing writer with a user defined [`PcapHeader`].
    ///
    /// It also writes the pcap header to the file.
    ///
    /// # Errors
    /// The writer can't be written to.
    pub async fn async_with_header(mut writer: W, header: PcapHeader) -> PcapResult<PcapWriter<W>> {
        header.async_write_to(&mut writer).await?;

        Ok(PcapWriter {
            endianness: header.endianness,
            snaplen: header.snaplen,
            ts_resolution: header.ts_resolution,
            writer,
        })
    }

    /// Writes a [`PcapPacket`].
    pub async fn async_write_packet(&mut self, packet: &PcapPacket<'_>) -> PcapResult<usize> {
        match self.endianness {
            Endianness::Big => packet.async_write_to::<_, BigEndian>(&mut self.writer, self.ts_resolution, self.snaplen).await,
            Endianness::Little => packet.async_write_to::<_, LittleEndian>(&mut self.writer, self.ts_resolution, self.snaplen).await,
        }
    }

    /// Writes a [`RawPcapPacket`].
    pub async fn async_write_raw_packet(&mut self, packet: &RawPcapPacket<'_>) -> PcapResult<usize> {
        match self.endianness {
            Endianness::Big => packet.async_write_to::<_, BigEndian>(&mut self.writer).await,
            Endianness::Little => packet.async_write_to::<_, LittleEndian>(&mut self.writer).await,
        }
    }
}

impl<W> PcapWriter<W> {
    /// Returns the endianess used by the writer.
    pub fn endianness(&self) -> Endianness {
        self.endianness
    }

    /// Returns the snaplen used by the writer, i.e. an unsigned value indicating the maximum number of octets captured
    /// from each packet.
    pub fn snaplen(&self) -> u32 {
        self.snaplen
    }

    /// Returns the timestamp resolution of the writer.
    pub fn ts_resolution(&self) -> TsResolution {
        self.ts_resolution
    }

    /// Consumes [`Self`], returning the wrapped writer.
    pub fn into_writer(self) -> W {
        self.writer
    }
}
