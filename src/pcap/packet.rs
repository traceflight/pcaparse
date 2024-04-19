use std::borrow::Cow;
use std::io::Write;
use std::time::Duration;

use byteorder::ByteOrder;
use byteorder::{ReadBytesExt, WriteBytesExt};
use derive_into_owned::IntoOwned;
use tracing::warn;

#[cfg(feature = "tokio")]
use tokio::io::AsyncWrite;
#[cfg(feature = "tokio")]
use tokio_byteorder::{AsyncReadBytesExt, AsyncWriteBytesExt};

use crate::errors::*;
use crate::TsResolution;

/// Pcap packet.
///
/// The payload can be owned or borrowed.
#[derive(Clone, Debug, IntoOwned)]
pub struct PcapPacket<'a> {
    /// Timestamp EPOCH of the packet with a nanosecond resolution
    pub timestamp: Duration,
    /// Original length of the packet when captured on the wire
    pub orig_len: u32,
    /// Payload, owned or borrowed, of the packet
    pub data: Cow<'a, [u8]>,
}

impl<'a> PcapPacket<'a> {
    /// Creates a new borrowed [`PcapPacket`] with the given parameters.
    pub fn new(timestamp: Duration, orig_len: u32, data: &'a [u8]) -> PcapPacket<'a> {
        PcapPacket { timestamp, orig_len, data: Cow::Borrowed(data) }
    }

    /// Creates a new owned [`PcapPacket`] with the given parameters.
    pub fn new_owned(timestamp: Duration, orig_len: u32, data: Vec<u8>) -> PcapPacket<'static> {
        PcapPacket { timestamp, orig_len, data: Cow::Owned(data) }
    }

    /// Parses a new borrowed [`PcapPacket`] from a slice.
    pub fn from_slice<B: ByteOrder>(slice: &'a [u8], ts_resolution: TsResolution, snap_len: u32) -> PcapResult<(&'a [u8], PcapPacket<'a>)> {
        let (rem, raw_packet) = RawPcapPacket::from_slice::<B>(slice)?;
        let s = Self::try_from_raw_packet(raw_packet, ts_resolution, snap_len)?;

        Ok((rem, s))
    }

    /// Asynchronously parses a new borrowed [`PcapPacket`] from a slice.
    #[cfg(feature = "tokio")]
    pub async fn async_from_slice<B: ByteOrder>(
        slice: &'a [u8],
        ts_resolution: TsResolution,
        snap_len: u32,
    ) -> PcapResult<(&'a [u8], PcapPacket<'a>)> {
        let (rem, raw_packet) = RawPcapPacket::async_from_slice::<B>(slice).await?;
        let s = Self::try_from_raw_packet(raw_packet, ts_resolution, snap_len)?;

        Ok((rem, s))
    }

    /// Writes a [`PcapPacket`] to a writer.
    pub fn write_to<W: Write, B: ByteOrder>(&self, writer: &mut W, ts_resolution: TsResolution, snap_len: u32) -> PcapResult<usize> {
        // Transforms PcapPacket::ts into ts_sec and ts_frac //
        let ts_sec = self
            .timestamp
            .as_secs()
            .try_into()
            .map_err(|_| PcapError::InvalidField("PcapPacket: timestamp_secs > u32::MAX"))?;

        let mut ts_frac = self.timestamp.subsec_nanos();
        if ts_resolution == TsResolution::MicroSecond {
            ts_frac /= 1000;
        }

        // Validate the packet length //
        let incl_len = self.data.len().try_into().map_err(|_| PcapError::InvalidField("PcapPacket: incl_len > u32::MAX"))?;
        let orig_len = self.orig_len;

        if incl_len > snap_len {
            warn!("PcapPacket: incl_len > snap_len");
        }

        if incl_len > orig_len {
            warn!("PcapPacket: incl_len > orig_len");
        }

        let raw_packet = RawPcapPacket { ts_sec, ts_frac, incl_len, orig_len, data: Cow::Borrowed(&self.data[..]) };

        raw_packet.write_to::<_, B>(writer)
    }

    /// Asynchronously writes a [`PcapPacket`] to a writer.
    #[cfg(feature = "tokio")]
    pub async fn async_write_to<W: AsyncWrite + Unpin, B: ByteOrder>(
        &self,
        writer: &mut W,
        ts_resolution: TsResolution,
        snap_len: u32,
    ) -> PcapResult<usize> {
        // Transforms PcapPacket::ts into ts_sec and ts_frac //
        let ts_sec = self
            .timestamp
            .as_secs()
            .try_into()
            .map_err(|_| PcapError::InvalidField("PcapPacket: timestamp_secs > u32::MAX"))?;

        let mut ts_frac = self.timestamp.subsec_nanos();
        if ts_resolution == TsResolution::MicroSecond {
            ts_frac /= 1000;
        }

        // Validate the packet length //
        let incl_len = self.data.len().try_into().map_err(|_| PcapError::InvalidField("PcapPacket: incl_len > u32::MAX"))?;
        let orig_len = self.orig_len;

        if incl_len > snap_len {
            warn!("PcapPacket: incl_len > snap_len");
        }

        if incl_len > orig_len {
            warn!("PcapPacket: incl_len > orig_len");
        }

        let raw_packet = RawPcapPacket { ts_sec, ts_frac, incl_len, orig_len, data: Cow::Borrowed(&self.data[..]) };

        raw_packet.async_write_to::<_, B>(writer).await
    }

    /// Tries to create a [`PcapPacket`] from a [`RawPcapPacket`].
    pub fn try_from_raw_packet(raw: RawPcapPacket<'a>, ts_resolution: TsResolution, snap_len: u32) -> PcapResult<Self> {
        // Validate timestamps //
        let ts_sec = raw.ts_sec;
        let mut ts_nsec = raw.ts_frac;
        if ts_resolution == TsResolution::MicroSecond {
            ts_nsec = ts_nsec.checked_mul(1000).ok_or(PcapError::InvalidField("PacketHeader ts_nanosecond is invalid"))?;
        }
        if ts_nsec >= 1_000_000_000 {
            return Err(PcapError::InvalidField("PacketHeader ts_nanosecond >= 1_000_000_000"));
        }

        // Validate lengths //
        let incl_len = raw.incl_len;
        let orig_len = raw.orig_len;

        if incl_len > snap_len {
            warn!("PacketHeader incl_len > snap_len");
        }

        if orig_len > snap_len {
            warn!("PacketHeader orig_len > snap_len");
        }

        if incl_len > orig_len {
            warn!("PacketHeader incl_len > orig_len");
        }

        Ok(PcapPacket { timestamp: Duration::new(ts_sec as u64, ts_nsec), orig_len, data: raw.data })
    }
}

/// Raw Pcap packet with its header and data.
/// The fields of the packet are not validated.
/// The payload can be owned or borrowed.
#[derive(Clone, Debug, IntoOwned)]
pub struct RawPcapPacket<'a> {
    /// Timestamp in seconds
    pub ts_sec: u32,
    /// Nanosecond or microsecond part of the timestamp
    pub ts_frac: u32,
    /// Number of octets of the packet saved in file
    pub incl_len: u32,
    /// Original length of the packet on the wire
    pub orig_len: u32,
    /// Payload, owned or borrowed, of the packet
    pub data: Cow<'a, [u8]>,
}

impl<'a> RawPcapPacket<'a> {
    /// Parses a new borrowed [`RawPcapPacket`] from a slice.
    pub fn from_slice<B: ByteOrder>(mut slice: &'a [u8]) -> PcapResult<(&'a [u8], Self)> {
        // Check header length
        if slice.len() < 16 {
            return Err(PcapError::IncompleteBuffer);
        }

        // Read packet header  //
        // Can unwrap because the length check is done before
        let ts_sec = ReadBytesExt::read_u32::<B>(&mut slice).unwrap();
        let ts_frac = ReadBytesExt::read_u32::<B>(&mut slice).unwrap();
        let incl_len = ReadBytesExt::read_u32::<B>(&mut slice).unwrap();
        let orig_len = ReadBytesExt::read_u32::<B>(&mut slice).unwrap();

        let pkt_len = incl_len as usize;
        if slice.len() < pkt_len {
            return Err(PcapError::IncompleteBuffer);
        }

        let packet = RawPcapPacket { ts_sec, ts_frac, incl_len, orig_len, data: Cow::Borrowed(&slice[..pkt_len]) };
        let rem = &slice[pkt_len..];

        Ok((rem, packet))
    }

    /// Asynchronously parses a new borrowed [`RawPcapPacket`] from a slice.
    #[cfg(feature = "tokio")]
    pub async fn async_from_slice<B: ByteOrder>(mut slice: &'a [u8]) -> PcapResult<(&'a [u8], RawPcapPacket<'a>)> {
        // Check header length
        if slice.len() < 16 {
            return Err(PcapError::IncompleteBuffer);
        }

        // Read packet header  //
        // Can unwrap because the length check is done before
        let ts_sec = AsyncReadBytesExt::read_u32::<B>(&mut slice).await.unwrap();
        let ts_frac = AsyncReadBytesExt::read_u32::<B>(&mut slice).await.unwrap();
        let incl_len = AsyncReadBytesExt::read_u32::<B>(&mut slice).await.unwrap();
        let orig_len = AsyncReadBytesExt::read_u32::<B>(&mut slice).await.unwrap();

        let pkt_len = incl_len as usize;
        if slice.len() < pkt_len {
            return Err(PcapError::IncompleteBuffer);
        }

        let packet = RawPcapPacket { ts_sec, ts_frac, incl_len, orig_len, data: Cow::Borrowed(&slice[..pkt_len]) };
        let rem = &slice[pkt_len..];

        Ok((rem, packet))
    }

    /// Writes a [`RawPcapPacket`] to a writer.
    /// The fields of the packet are not validated.
    pub fn write_to<W: Write, B: ByteOrder>(&self, writer: &mut W) -> PcapResult<usize> {
        writer.write_u32::<B>(self.ts_sec).map_err(PcapError::IoError)?;
        writer.write_u32::<B>(self.ts_frac).map_err(PcapError::IoError)?;
        writer.write_u32::<B>(self.incl_len).map_err(PcapError::IoError)?;
        writer.write_u32::<B>(self.orig_len).map_err(PcapError::IoError)?;
        writer.write_all(&self.data).map_err(PcapError::IoError)?;

        Ok(16 + self.data.len())
    }

    /// Asynchronously writes a [`RawPcapPacket`] to a writer.
    /// The fields of the packet are not validated.
    #[cfg(feature = "tokio")]
    pub async fn async_write_to<W: AsyncWrite + Unpin, B: ByteOrder>(&self, writer: &mut W) -> PcapResult<usize> {
        writer.write_u32::<B>(self.ts_sec).await.map_err(PcapError::IoError)?;
        writer.write_u32::<B>(self.ts_frac).await.map_err(PcapError::IoError)?;
        writer.write_u32::<B>(self.incl_len).await.map_err(PcapError::IoError)?;
        writer.write_u32::<B>(self.orig_len).await.map_err(PcapError::IoError)?;
        tokio::io::AsyncWriteExt::write_all(writer, &self.data).await.map_err(PcapError::IoError)?;

        Ok(16 + self.data.len())
    }

    /// Tries to convert a [`RawPcapPacket`] into a [`PcapPacket`].
    pub fn try_into_pcap_packet(self, ts_resolution: TsResolution, snap_len: u32) -> PcapResult<PcapPacket<'a>> {
        PcapPacket::try_from_raw_packet(self, ts_resolution, snap_len)
    }
}
