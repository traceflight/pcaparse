use std::borrow::Cow;
use std::time::Duration;

use byteorder::ByteOrder;
use byteorder::ReadBytesExt;
use derive_into_owned::IntoOwned;

#[cfg(feature = "tokio")]
use tokio_byteorder::AsyncReadBytesExt;
use tracing::warn;

use crate::errors::*;

/// Cap packet. Network Associates Sniffer 2.x
///
/// The payload can be owned or borrowed.
#[derive(Clone, Debug, IntoOwned)]
pub struct CapPacket<'a> {
    /// Timestamp EPOCH of the packet with a nanosecond resolution
    pub timestamp: Duration,
    /// Original length of the packet when captured on the wire
    pub orig_len: u16,
    /// Payload, owned or borrowed, of the packet
    pub data: Cow<'a, [u8]>,
}

impl<'a> CapPacket<'a> {
    /// Parses a new borrowed [`CapPacket`] from a slice.
    pub fn from_slice<B: ByteOrder>(slice: &'a [u8], start_time: u32) -> PcapResult<(&'a [u8], CapPacket<'a>)> {
        let (rem, raw_packet) = RawCapPacket::from_slice::<B>(slice)?;
        let s = Self::try_from_raw_packet(raw_packet, start_time)?;

        Ok((rem, s))
    }

    /// Asynchronously parses a new borrowed [`CapPacket`] from a slice.
    #[cfg(feature = "tokio")]
    pub async fn async_from_slice<B: ByteOrder>(slice: &'a [u8], start_time: u32) -> PcapResult<(&'a [u8], CapPacket<'a>)> {
        let (rem, raw_packet) = RawCapPacket::async_from_slice::<B>(slice).await?;
        let s = Self::try_from_raw_packet(raw_packet, start_time)?;

        Ok((rem, s))
    }

    /// Tries to create a [`CapPacket`] from a [`RawCapPacket`].
    pub fn try_from_raw_packet(raw: RawCapPacket<'a>, start_time: u32) -> PcapResult<Self> {
        // Validate timestamps //
        let mut t = (raw.timelo as u64 + raw.timehi as u64 * 4294967296) as f64;
        t /= 1000000.0;

        let ts_sec = start_time + t as u32;
        let ts_nsec = ((t - (t as u32) as f64) * 1.0e9) as u32;

        if ts_nsec >= 1_000_000_000 {
            return Err(PcapError::InvalidField("PacketHeader ts_nanosecond >= 1_000_000_000"));
        }

        // Validate lengths //
        let incl_len = raw.incl_len;
        let orig_len = raw.orig_len;

        if incl_len > orig_len {
            warn!("PacketHeader incl_len > orig_len");
        }

        Ok(CapPacket { timestamp: Duration::new(ts_sec as u64, ts_nsec), orig_len, data: raw.data })
    }
}

/// Raw cap packet with its header and data.
/// The fields of the packet are not validated.
/// The payload can be owned or borrowed.
#[derive(Clone, Debug, IntoOwned)]
pub struct RawCapPacket<'a> {
    /// lower 32 bits of time stamp
    pub timelo: u32,
    /// upper 32 bits of time stamp
    pub timehi: u32,
    /// packet length
    pub orig_len: u16,
    /// capture length
    pub incl_len: u16,
    /// Payload, owned or borrowed, of the packet
    pub data: Cow<'a, [u8]>,
}

impl<'a> RawCapPacket<'a> {
    /// Parses a new borrowed [`RawCapPacket`] from a slice.
    pub fn from_slice<B: ByteOrder>(mut slice: &'a [u8]) -> PcapResult<(&'a [u8], Self)> {
        // Check header length
        if slice.len() < 40 {
            return Err(PcapError::IncompleteBuffer);
        }

        // Read packet header  //
        // Can unwrap because the length check is done before
        let timelo = ReadBytesExt::read_u32::<B>(&mut slice).unwrap();
        let timehi = ReadBytesExt::read_u32::<B>(&mut slice).unwrap();
        let orig_len = ReadBytesExt::read_u16::<B>(&mut slice).unwrap();
        let incl_len = ReadBytesExt::read_u16::<B>(&mut slice).unwrap();
        // 28 bytes various data
        slice = &slice[28..];

        let pkt_len = incl_len as usize;
        if slice.len() < pkt_len {
            return Err(PcapError::IncompleteBuffer);
        }

        let packet = RawCapPacket { timelo, timehi, incl_len, orig_len, data: Cow::Borrowed(&slice[..pkt_len]) };
        let rem = &slice[pkt_len..];

        Ok((rem, packet))
    }

    /// Asynchronously parses a new borrowed [`RawCapPacket`] from a slice.
    #[cfg(feature = "tokio")]
    pub async fn async_from_slice<B: ByteOrder>(mut slice: &'a [u8]) -> PcapResult<(&'a [u8], RawCapPacket<'a>)> {
        // Check header length
        if slice.len() < 40 {
            return Err(PcapError::IncompleteBuffer);
        }

        // Read packet header  //
        // Can unwrap because the length check is done before
        let timelo = AsyncReadBytesExt::read_u32::<B>(&mut slice).await.unwrap();
        let timehi = AsyncReadBytesExt::read_u32::<B>(&mut slice).await.unwrap();
        let orig_len = AsyncReadBytesExt::read_u16::<B>(&mut slice).await.unwrap();
        let incl_len = AsyncReadBytesExt::read_u16::<B>(&mut slice).await.unwrap();
        // 28 bytes various data
        slice = &slice[28..];

        let pkt_len = incl_len as usize;
        if slice.len() < pkt_len {
            return Err(PcapError::IncompleteBuffer);
        }

        let packet = RawCapPacket { timelo, timehi, incl_len, orig_len, data: Cow::Borrowed(&slice[..pkt_len]) };
        let rem = &slice[pkt_len..];

        Ok((rem, packet))
    }

    /// Tries to convert a [`RawCapPacket`] into a [`CapPacket`].
    pub fn try_into_cap_packet(self, start_time: u32) -> PcapResult<CapPacket<'a>> {
        CapPacket::try_from_raw_packet(self, start_time)
    }
}
