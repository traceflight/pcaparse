//! Packet Block.

use std::borrow::Cow;
use std::io::Result as IoResult;
use std::io::Write;

use byteorder::{ReadBytesExt, WriteBytesExt};
use derive_into_owned::IntoOwned;

use byteorder::ByteOrder;
#[cfg(feature = "tokio")]
use tokio::io::AsyncWrite;
#[cfg(feature = "tokio")]
use tokio_byteorder::{AsyncReadBytesExt, AsyncWriteBytesExt};

#[cfg(feature = "tokio")]
use super::block_common::AsyncPcapNgBlock;
use super::block_common::{Block, PcapNgBlock};
#[cfg(feature = "tokio")]
use super::opt_common::{AsyncPcapNgOption, AsyncWriteOptTo};
use super::opt_common::{CustomBinaryOption, CustomUtf8Option, PcapNgOption, UnknownOption, WriteOptTo};
use crate::errors::PcapError;

/// The Packet Block is obsolete, and MUST NOT be used in new files.
/// Use the Enhanced Packet Block or Simple Packet Block instead.
#[derive(Clone, Debug, IntoOwned, Eq, PartialEq)]
pub struct PacketBlock<'a> {
    /// It specifies the interface this packet comes from.
    pub interface_id: u16,

    /// Local drop counter.
    ///
    /// It specifies the number of packets lost (by the interface and the operating system)
    /// between this packet and the preceding one.
    pub drop_count: u16,

    /// The timestamp is a single 64-bit unsigned integer that represents the number of units of time
    /// that have elapsed since 1970-01-01 00:00:00 UTC.
    pub timestamp: u64,

    /// Number of octets captured from the packet (i.e. the length of the Packet Data field).
    pub captured_len: u32,

    /// Actual length of the packet when it was transmitted on the network.
    pub original_len: u32,

    /// The data coming from the network, including link-layer headers.
    pub data: Cow<'a, [u8]>,

    /// Options
    pub options: Vec<PacketOption<'a>>,
}

impl<'a> PcapNgBlock<'a> for PacketBlock<'a> {
    fn from_slice<B: ByteOrder>(mut slice: &'a [u8]) -> Result<(&'a [u8], Self), PcapError> {
        if slice.len() < 20 {
            return Err(PcapError::InvalidField("EnhancedPacketBlock: block length length < 20"));
        }

        let interface_id = ReadBytesExt::read_u16::<B>(&mut slice).unwrap();
        let drop_count = ReadBytesExt::read_u16::<B>(&mut slice).unwrap();
        let timestamp = ReadBytesExt::read_u64::<B>(&mut slice).unwrap();
        let captured_len = ReadBytesExt::read_u32::<B>(&mut slice).unwrap();
        let original_len = ReadBytesExt::read_u32::<B>(&mut slice).unwrap();

        let pad_len = (4 - (captured_len as usize % 4)) % 4;
        let tot_len = captured_len as usize + pad_len;

        if slice.len() < tot_len {
            return Err(PcapError::InvalidField("EnhancedPacketBlock: captured_len + padding > block length"));
        }

        let data = &slice[..captured_len as usize];
        slice = &slice[tot_len..];

        let (slice, options) = PacketOption::opts_from_slice::<B>(slice)?;
        let block = PacketBlock {
            interface_id,
            drop_count,
            timestamp,
            captured_len,
            original_len,
            data: Cow::Borrowed(data),
            options,
        };

        Ok((slice, block))
    }

    fn write_to<B: ByteOrder, W: Write>(&self, writer: &mut W) -> IoResult<usize> {
        writer.write_u16::<B>(self.interface_id)?;
        writer.write_u16::<B>(self.drop_count)?;
        writer.write_u64::<B>(self.timestamp)?;
        writer.write_u32::<B>(self.captured_len)?;
        writer.write_u32::<B>(self.original_len)?;
        writer.write_all(&self.data)?;

        let pad_len = (4 - (self.captured_len as usize % 4)) % 4;
        writer.write_all(&[0_u8; 3][..pad_len])?;

        let opt_len = PacketOption::write_opts_to::<B, _>(&self.options, writer)?;

        Ok(20 + self.data.len() + pad_len + opt_len)
    }

    fn into_block(self) -> Block<'a> {
        Block::Packet(self)
    }
}

#[cfg(feature = "tokio")]
#[async_trait::async_trait]
impl<'a> AsyncPcapNgBlock<'a> for PacketBlock<'a> {
    async fn async_from_slice<B: ByteOrder + Send>(mut slice: &'a [u8]) -> Result<(&'a [u8], PacketBlock<'a>), PcapError> {
        if slice.len() < 20 {
            return Err(PcapError::InvalidField("EnhancedPacketBlock: block length length < 20"));
        }

        let interface_id = AsyncReadBytesExt::read_u16::<B>(&mut slice).await.unwrap();
        let drop_count = AsyncReadBytesExt::read_u16::<B>(&mut slice).await.unwrap();
        let timestamp = AsyncReadBytesExt::read_u64::<B>(&mut slice).await.unwrap();
        let captured_len = AsyncReadBytesExt::read_u32::<B>(&mut slice).await.unwrap();
        let original_len = AsyncReadBytesExt::read_u32::<B>(&mut slice).await.unwrap();

        let pad_len = (4 - (captured_len as usize % 4)) % 4;
        let tot_len = captured_len as usize + pad_len;

        if slice.len() < tot_len {
            return Err(PcapError::InvalidField("EnhancedPacketBlock: captured_len + padding > block length"));
        }

        let data = &slice[..captured_len as usize];
        slice = &slice[tot_len..];

        let (slice, options) = PacketOption::async_opts_from_slice::<B>(slice).await?;
        let block = PacketBlock {
            interface_id,
            drop_count,
            timestamp,
            captured_len,
            original_len,
            data: Cow::Borrowed(data),
            options,
        };

        Ok((slice, block))
    }

    async fn async_write_to<B: ByteOrder, W: AsyncWrite + Unpin + Send>(&self, writer: &mut W) -> IoResult<usize> {
        writer.write_u16::<B>(self.interface_id).await?;
        writer.write_u16::<B>(self.drop_count).await?;
        writer.write_u64::<B>(self.timestamp).await?;
        writer.write_u32::<B>(self.captured_len).await?;
        writer.write_u32::<B>(self.original_len).await?;
        tokio::io::AsyncWriteExt::write_all(writer, &self.data).await?;

        let pad_len = (4 - (self.captured_len as usize % 4)) % 4;
        tokio::io::AsyncWriteExt::write_all(writer, &[0_u8; 3][..pad_len]).await?;

        let opt_len = PacketOption::async_write_opts_to::<B, _>(&self.options, writer).await?;

        Ok(20 + self.data.len() + pad_len + opt_len)
    }
}

/// Packet Block option
#[derive(Clone, Debug, IntoOwned, Eq, PartialEq)]
pub enum PacketOption<'a> {
    /// Comment associated with the current block
    Comment(Cow<'a, str>),

    /// 32-bit flags word containing link-layer information.
    Flags(u32),

    /// Contains a hash of the packet.
    Hash(Cow<'a, [u8]>),

    /// Custom option containing binary octets in the Custom Data portion
    CustomBinary(CustomBinaryOption<'a>),

    /// Custom option containing a UTF-8 string in the Custom Data portion
    CustomUtf8(CustomUtf8Option<'a>),

    /// Unknown option
    Unknown(UnknownOption<'a>),
}

impl<'a> PcapNgOption<'a> for PacketOption<'a> {
    fn from_slice<B: ByteOrder>(code: u16, length: u16, mut slice: &'a [u8]) -> Result<Self, PcapError> {
        let opt = match code {
            1 => PacketOption::Comment(Cow::Borrowed(std::str::from_utf8(slice)?)),
            2 => {
                if slice.len() != 4 {
                    return Err(PcapError::InvalidField("PacketOption: Flags length != 4"));
                }
                PacketOption::Flags(ReadBytesExt::read_u32::<B>(&mut slice).map_err(|_| PcapError::IncompleteBuffer)?)
            },
            3 => PacketOption::Hash(Cow::Borrowed(slice)),

            2988 | 19372 => PacketOption::CustomUtf8(CustomUtf8Option::from_slice::<B>(code, slice)?),
            2989 | 19373 => PacketOption::CustomBinary(CustomBinaryOption::from_slice::<B>(code, slice)?),

            _ => PacketOption::Unknown(UnknownOption::new(code, length, slice)),
        };

        Ok(opt)
    }

    fn write_to<B: ByteOrder, W: Write>(&self, writer: &mut W) -> IoResult<usize> {
        match self {
            PacketOption::Comment(a) => a.write_opt_to::<B, W>(1, writer),
            PacketOption::Flags(a) => a.write_opt_to::<B, W>(2, writer),
            PacketOption::Hash(a) => a.write_opt_to::<B, W>(3, writer),
            PacketOption::CustomBinary(a) => a.write_opt_to::<B, W>(a.code, writer),
            PacketOption::CustomUtf8(a) => a.write_opt_to::<B, W>(a.code, writer),
            PacketOption::Unknown(a) => a.write_opt_to::<B, W>(a.code, writer),
        }
    }
}

#[cfg(feature = "tokio")]
#[async_trait::async_trait]
impl<'a> AsyncPcapNgOption<'a> for PacketOption<'a> {
    async fn async_from_slice<B: ByteOrder + Send>(code: u16, length: u16, mut slice: &'a [u8]) -> Result<PacketOption<'a>, PcapError> {
        let opt = match code {
            1 => PacketOption::Comment(Cow::Borrowed(std::str::from_utf8(slice)?)),
            2 => {
                if slice.len() != 4 {
                    return Err(PcapError::InvalidField("PacketOption: Flags length != 4"));
                }
                PacketOption::Flags(AsyncReadBytesExt::read_u32::<B>(&mut slice).await.map_err(|_| PcapError::IncompleteBuffer)?)
            },
            3 => PacketOption::Hash(Cow::Borrowed(slice)),

            2988 | 19372 => PacketOption::CustomUtf8(CustomUtf8Option::async_from_slice::<B>(code, slice).await?),
            2989 | 19373 => PacketOption::CustomBinary(CustomBinaryOption::async_from_slice::<B>(code, slice).await?),

            _ => PacketOption::Unknown(UnknownOption::new(code, length, slice)),
        };

        Ok(opt)
    }

    async fn async_write_to<B: ByteOrder, W: AsyncWrite + Unpin + Send>(&self, writer: &mut W) -> IoResult<usize> {
        match self {
            PacketOption::Comment(a) => a.async_write_opt_to::<B, W>(1, writer).await,
            PacketOption::Flags(a) => a.async_write_opt_to::<B, W>(2, writer).await,
            PacketOption::Hash(a) => a.async_write_opt_to::<B, W>(3, writer).await,
            PacketOption::CustomBinary(a) => a.async_write_opt_to::<B, W>(a.code, writer).await,
            PacketOption::CustomUtf8(a) => a.async_write_opt_to::<B, W>(a.code, writer).await,
            PacketOption::Unknown(a) => a.async_write_opt_to::<B, W>(a.code, writer).await,
        }
    }
}
