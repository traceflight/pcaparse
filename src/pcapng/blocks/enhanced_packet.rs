//! Enhanced Packet Block (EPB).

use std::borrow::Cow;
use std::io::Result as IoResult;
use std::io::Write;
use std::time::Duration;

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
use crate::DataLink;

/// An Enhanced Packet Block (EPB) is the standard container for storing the packets coming from the network.
#[derive(Clone, Debug, IntoOwned, Eq, PartialEq)]
pub struct EnhancedPacketBlock<'a> {
    /// It specifies the interface this packet comes from.
    ///
    /// The correct interface will be the one whose Interface Description Block
    /// (within the current Section of the file) is identified by the same number of this field.
    pub interface_id: u32,

    /// Timestamp number stored in data
    pub timestamp_num: u64,

    /// Number of units of time that have elapsed since 1970-01-01 00:00:00 UTC.
    /// Temporarily, the timestamp is calculated in macroseconds as the timeunit.
    pub timestamp: Duration,

    /// Linktype update from IDB, use ethernet as default.
    pub linktype: DataLink,

    /// Actual length of the packet when it was transmitted on the network.
    pub original_len: u32,

    /// The data coming from the network, including link-layer headers.
    pub data: Cow<'a, [u8]>,

    /// Options
    pub options: Vec<EnhancedPacketOption<'a>>,
}

impl<'a> PcapNgBlock<'a> for EnhancedPacketBlock<'a> {
    fn from_slice<B: ByteOrder>(mut slice: &'a [u8]) -> Result<(&'a [u8], Self), PcapError> {
        if slice.len() < 20 {
            return Err(PcapError::InvalidField("EnhancedPacketBlock: block length length < 20"));
        }

        let interface_id = ReadBytesExt::read_u32::<B>(&mut slice).unwrap();
        let timestamp_high = ReadBytesExt::read_u32::<B>(&mut slice).unwrap() as u64;
        let timestamp_low = ReadBytesExt::read_u32::<B>(&mut slice).unwrap() as u64;
        let timestamp_num = (timestamp_high << 32) + timestamp_low;
        let captured_len = ReadBytesExt::read_u32::<B>(&mut slice).unwrap();
        let original_len = ReadBytesExt::read_u32::<B>(&mut slice).unwrap();

        let pad_len = (4 - (captured_len as usize % 4)) % 4;
        let tot_len = captured_len as usize + pad_len;

        if slice.len() < tot_len {
            return Err(PcapError::InvalidField("EnhancedPacketBlock: captured_len + padding > block length"));
        }

        let data = &slice[..captured_len as usize];
        slice = &slice[tot_len..];

        let (slice, options) = EnhancedPacketOption::opts_from_slice::<B>(slice)?;
        let block = EnhancedPacketBlock {
            interface_id,
            timestamp_num,
            timestamp: Duration::from_micros(timestamp_num),
            linktype: DataLink::ETHERNET,
            original_len,
            data: Cow::Borrowed(data),
            options,
        };

        Ok((slice, block))
    }

    fn write_to<B: ByteOrder, W: Write>(&self, writer: &mut W) -> IoResult<usize> {
        let pad_len = (4 - (&self.data.len() % 4)) % 4;

        writer.write_u32::<B>(self.interface_id)?;

        let timestamp = self.timestamp_num;
        let timestamp_high = (timestamp >> 32) as u32;
        writer.write_u32::<B>(timestamp_high)?;
        let timestamp_low = (timestamp & 0xFFFFFFFF) as u32;
        writer.write_u32::<B>(timestamp_low)?;

        writer.write_u32::<B>(self.data.len() as u32)?;
        writer.write_u32::<B>(self.original_len)?;
        writer.write_all(&self.data)?;
        writer.write_all(&[0_u8; 3][..pad_len])?;

        let opt_len = EnhancedPacketOption::write_opts_to::<B, W>(&self.options, writer)?;

        Ok(20 + &self.data.len() + pad_len + opt_len)
    }

    fn into_block(self) -> Block<'a> {
        Block::EnhancedPacket(self)
    }
}

#[cfg(feature = "tokio")]
#[async_trait::async_trait]
impl<'a> AsyncPcapNgBlock<'a> for EnhancedPacketBlock<'a> {
    async fn async_from_slice<B: ByteOrder + Send>(mut slice: &'a [u8]) -> Result<(&'a [u8], EnhancedPacketBlock<'a>), PcapError> {
        if slice.len() < 20 {
            return Err(PcapError::InvalidField("EnhancedPacketBlock: block length length < 20"));
        }

        let interface_id = AsyncReadBytesExt::read_u32::<B>(&mut slice).await.unwrap();
        let timestamp_high = AsyncReadBytesExt::read_u32::<B>(&mut slice).await.unwrap() as u64;
        let timestamp_low = AsyncReadBytesExt::read_u32::<B>(&mut slice).await.unwrap() as u64;
        let timestamp_num = (timestamp_high << 32) + timestamp_low;
        let captured_len = AsyncReadBytesExt::read_u32::<B>(&mut slice).await.unwrap();
        let original_len = AsyncReadBytesExt::read_u32::<B>(&mut slice).await.unwrap();

        let pad_len = (4 - (captured_len as usize % 4)) % 4;
        let tot_len = captured_len as usize + pad_len;

        if slice.len() < tot_len {
            return Err(PcapError::InvalidField("EnhancedPacketBlock: captured_len + padding > block length"));
        }

        let data = &slice[..captured_len as usize];
        slice = &slice[tot_len..];

        let (slice, options) = EnhancedPacketOption::async_opts_from_slice::<B>(slice).await?;
        let block = EnhancedPacketBlock {
            interface_id,
            timestamp_num,
            timestamp: Duration::from_micros(timestamp_num),
            linktype: DataLink::ETHERNET,
            original_len,
            data: Cow::Borrowed(data),
            options,
        };

        Ok((slice, block))
    }

    async fn async_write_to<B: ByteOrder, W: AsyncWrite + Unpin + Send>(&self, writer: &mut W) -> IoResult<usize> {
        let pad_len = (4 - (&self.data.len() % 4)) % 4;

        writer.write_u32::<B>(self.interface_id).await?;

        let timestamp = self.timestamp_num;
        let timestamp_high = (timestamp >> 32) as u32;
        writer.write_u32::<B>(timestamp_high).await?;
        let timestamp_low = (timestamp & 0xFFFFFFFF) as u32;
        writer.write_u32::<B>(timestamp_low).await?;

        writer.write_u32::<B>(self.data.len() as u32).await?;
        writer.write_u32::<B>(self.original_len).await?;
        tokio::io::AsyncWriteExt::write_all(writer, &self.data).await?;
        tokio::io::AsyncWriteExt::write_all(writer, &[0_u8; 3][..pad_len]).await?;

        let opt_len = EnhancedPacketOption::async_write_opts_to::<B, W>(&self.options, writer).await?;

        Ok(20 + &self.data.len() + pad_len + opt_len)
    }
}

/// The Enhanced Packet Block (EPB) options
#[derive(Clone, Debug, IntoOwned, Eq, PartialEq)]
pub enum EnhancedPacketOption<'a> {
    /// Comment associated with the current block
    Comment(Cow<'a, str>),

    /// 32-bit flags word containing link-layer information.
    Flags(u32),

    /// Contains a hash of the packet.
    Hash(Cow<'a, [u8]>),

    /// 64-bit integer value specifying the number of packets lost
    /// (by the interface and the operating system) between this packet and the preceding one for
    /// the same interface or, for the first packet for an interface, between this packet
    /// and the start of the capture process.
    DropCount(u64),

    /// Custom option containing binary octets in the Custom Data portion
    CustomBinary(CustomBinaryOption<'a>),

    /// Custom option containing a UTF-8 string in the Custom Data portion
    CustomUtf8(CustomUtf8Option<'a>),

    /// Unknown option
    Unknown(UnknownOption<'a>),
}

impl<'a> PcapNgOption<'a> for EnhancedPacketOption<'a> {
    fn from_slice<B: ByteOrder>(code: u16, length: u16, mut slice: &'a [u8]) -> Result<Self, PcapError> {
        let opt = match code {
            1 => EnhancedPacketOption::Comment(Cow::Borrowed(std::str::from_utf8(slice)?)),
            2 => {
                if slice.len() != 4 {
                    return Err(PcapError::InvalidField("EnhancedPacketOption: Flags length != 4"));
                }
                EnhancedPacketOption::Flags(ReadBytesExt::read_u32::<B>(&mut slice).map_err(|_| PcapError::IncompleteBuffer)?)
            },
            3 => EnhancedPacketOption::Hash(Cow::Borrowed(slice)),
            4 => {
                if slice.len() != 8 {
                    return Err(PcapError::InvalidField("EnhancedPacketOption: DropCount length != 8"));
                }
                EnhancedPacketOption::DropCount(ReadBytesExt::read_u64::<B>(&mut slice).map_err(|_| PcapError::IncompleteBuffer)?)
            },

            2988 | 19372 => EnhancedPacketOption::CustomUtf8(CustomUtf8Option::from_slice::<B>(code, slice)?),
            2989 | 19373 => EnhancedPacketOption::CustomBinary(CustomBinaryOption::from_slice::<B>(code, slice)?),

            _ => EnhancedPacketOption::Unknown(UnknownOption::new(code, length, slice)),
        };

        Ok(opt)
    }

    fn write_to<B: ByteOrder, W: Write>(&self, writer: &mut W) -> IoResult<usize> {
        match self {
            EnhancedPacketOption::Comment(a) => a.write_opt_to::<B, W>(1, writer),
            EnhancedPacketOption::Flags(a) => a.write_opt_to::<B, W>(2, writer),
            EnhancedPacketOption::Hash(a) => a.write_opt_to::<B, W>(3, writer),
            EnhancedPacketOption::DropCount(a) => a.write_opt_to::<B, W>(4, writer),
            EnhancedPacketOption::CustomBinary(a) => a.write_opt_to::<B, W>(a.code, writer),
            EnhancedPacketOption::CustomUtf8(a) => a.write_opt_to::<B, W>(a.code, writer),
            EnhancedPacketOption::Unknown(a) => a.write_opt_to::<B, W>(a.code, writer),
        }
    }
}

#[cfg(feature = "tokio")]
#[async_trait::async_trait]
impl<'a> AsyncPcapNgOption<'a> for EnhancedPacketOption<'a> {
    async fn async_from_slice<B: ByteOrder + Send>(code: u16, length: u16, mut slice: &'a [u8]) -> Result<Self, PcapError> {
        let opt = match code {
            1 => EnhancedPacketOption::Comment(Cow::Borrowed(std::str::from_utf8(slice)?)),
            2 => {
                if slice.len() != 4 {
                    return Err(PcapError::InvalidField("EnhancedPacketOption: Flags length != 4"));
                }
                EnhancedPacketOption::Flags(AsyncReadBytesExt::read_u32::<B>(&mut slice).await.map_err(|_| PcapError::IncompleteBuffer)?)
            },
            3 => EnhancedPacketOption::Hash(Cow::Borrowed(slice)),
            4 => {
                if slice.len() != 8 {
                    return Err(PcapError::InvalidField("EnhancedPacketOption: DropCount length != 8"));
                }
                EnhancedPacketOption::DropCount(
                    AsyncReadBytesExt::read_u64::<B>(&mut slice).await.map_err(|_| PcapError::IncompleteBuffer)?,
                )
            },

            2988 | 19372 => EnhancedPacketOption::CustomUtf8(CustomUtf8Option::async_from_slice::<B>(code, slice).await?),
            2989 | 19373 => EnhancedPacketOption::CustomBinary(CustomBinaryOption::async_from_slice::<B>(code, slice).await?),

            _ => EnhancedPacketOption::Unknown(UnknownOption::new(code, length, slice)),
        };

        Ok(opt)
    }

    async fn async_write_to<B: ByteOrder, W: AsyncWrite + Unpin + Send>(&self, writer: &mut W) -> IoResult<usize> {
        match self {
            EnhancedPacketOption::Comment(a) => a.async_write_opt_to::<B, W>(1, writer).await,
            EnhancedPacketOption::Flags(a) => a.async_write_opt_to::<B, W>(2, writer).await,
            EnhancedPacketOption::Hash(a) => a.async_write_opt_to::<B, W>(3, writer).await,
            EnhancedPacketOption::DropCount(a) => a.async_write_opt_to::<B, W>(4, writer).await,
            EnhancedPacketOption::CustomBinary(a) => a.async_write_opt_to::<B, W>(a.code, writer).await,
            EnhancedPacketOption::CustomUtf8(a) => a.async_write_opt_to::<B, W>(a.code, writer).await,
            EnhancedPacketOption::Unknown(a) => a.async_write_opt_to::<B, W>(a.code, writer).await,
        }
    }
}
