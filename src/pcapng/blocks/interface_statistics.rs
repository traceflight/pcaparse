//! Interface Statistics Block.

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

/// The Interface Statistics Block contains the capture statistics for a given interface and it is optional.
#[derive(Clone, Debug, IntoOwned, Eq, PartialEq)]
pub struct InterfaceStatisticsBlock<'a> {
    /// Specifies the interface these statistics refers to.
    ///
    /// The correct interface will be the one whose Interface Description Block (within the current Section of the file)
    /// is identified by same number of this field.
    pub interface_id: u32,

    /// Time this statistics refers to.
    ///
    /// The format of the timestamp is the same already defined in the Enhanced Packet Block.
    /// The length of a unit of time is specified by the 'if_tsresol' option of the Interface Description Block referenced by this packet.
    pub timestamp: u64,

    /// Options
    pub options: Vec<InterfaceStatisticsOption<'a>>,
}

impl<'a> PcapNgBlock<'a> for InterfaceStatisticsBlock<'a> {
    fn from_slice<B: ByteOrder>(mut slice: &'a [u8]) -> Result<(&[u8], Self), PcapError> {
        if slice.len() < 12 {
            return Err(PcapError::InvalidField("InterfaceStatisticsBlock: block length < 12"));
        }

        let interface_id = ReadBytesExt::read_u32::<B>(&mut slice).unwrap();
        let timestamp = ReadBytesExt::read_u64::<B>(&mut slice).unwrap();
        let (slice, options) = InterfaceStatisticsOption::opts_from_slice::<B>(slice)?;

        let block = InterfaceStatisticsBlock { interface_id, timestamp, options };

        Ok((slice, block))
    }

    fn write_to<B: ByteOrder, W: Write>(&self, writer: &mut W) -> IoResult<usize> {
        writer.write_u32::<B>(self.interface_id)?;
        writer.write_u64::<B>(self.timestamp)?;

        let opt_len = InterfaceStatisticsOption::write_opts_to::<B, _>(&self.options, writer)?;
        Ok(12 + opt_len)
    }

    fn into_block(self) -> Block<'a> {
        Block::InterfaceStatistics(self)
    }
}

#[cfg(feature = "tokio")]
#[async_trait::async_trait]
impl<'a> AsyncPcapNgBlock<'a> for InterfaceStatisticsBlock<'a> {
    async fn async_from_slice<B: ByteOrder + Send>(mut slice: &'a [u8]) -> Result<(&[u8], Self), PcapError> {
        if slice.len() < 12 {
            return Err(PcapError::InvalidField("InterfaceStatisticsBlock: block length < 12"));
        }

        let interface_id = AsyncReadBytesExt::read_u32::<B>(&mut slice).await.unwrap();
        let timestamp = AsyncReadBytesExt::read_u64::<B>(&mut slice).await.unwrap();
        let (slice, options) = InterfaceStatisticsOption::async_opts_from_slice::<B>(slice).await?;

        let block = InterfaceStatisticsBlock { interface_id, timestamp, options };

        Ok((slice, block))
    }

    async fn async_write_to<B: ByteOrder, W: AsyncWrite + Unpin + Send>(&self, writer: &mut W) -> IoResult<usize> {
        writer.write_u32::<B>(self.interface_id).await?;
        writer.write_u64::<B>(self.timestamp).await?;

        let opt_len = InterfaceStatisticsOption::async_write_opts_to::<B, _>(&self.options, writer).await?;
        Ok(12 + opt_len)
    }
}

/// The Interface Statistics Block options
#[derive(Clone, Debug, IntoOwned, Eq, PartialEq)]
pub enum InterfaceStatisticsOption<'a> {
    /// The opt_comment option is a UTF-8 string containing human-readable comment text
    /// that is associated to the current block.
    Comment(Cow<'a, str>),

    /// The isb_starttime option specifies the time the capture started.
    IsbStartTime(u64),

    /// The isb_endtime option specifies the time the capture ended.
    IsbEndTime(u64),

    /// The isb_ifrecv option specifies the 64-bit unsigned integer number of packets received from the physical interface
    /// starting from the beginning of the capture.
    IsbIfRecv(u64),

    /// The isb_ifdrop option specifies the 64-bit unsigned integer number of packets dropped by the interface
    /// due to lack of resources starting from the beginning of the capture.
    IsbIfDrop(u64),

    /// The isb_filteraccept option specifies the 64-bit unsigned integer number of packets accepted
    /// by filter starting from the beginning of the capture.
    IsbFilterAccept(u64),

    /// The isb_osdrop option specifies the 64-bit unsigned integer number of packets dropped
    /// by the operating system starting from the beginning of the capture.
    IsbOsDrop(u64),

    /// The isb_usrdeliv option specifies the 64-bit unsigned integer number of packets delivered
    /// to the user starting from the beginning of the capture.
    IsbUsrDeliv(u64),

    /// Custom option containing binary octets in the Custom Data portion
    CustomBinary(CustomBinaryOption<'a>),

    /// Custom option containing a UTF-8 string in the Custom Data portion
    CustomUtf8(CustomUtf8Option<'a>),

    /// Unknown option
    Unknown(UnknownOption<'a>),
}

impl<'a> PcapNgOption<'a> for InterfaceStatisticsOption<'a> {
    fn from_slice<B: ByteOrder>(code: u16, length: u16, mut slice: &'a [u8]) -> Result<Self, PcapError> {
        let opt = match code {
            1 => InterfaceStatisticsOption::Comment(Cow::Borrowed(std::str::from_utf8(slice)?)),
            2 => InterfaceStatisticsOption::IsbStartTime(ReadBytesExt::read_u64::<B>(&mut slice).map_err(|_| PcapError::IncompleteBuffer)?),
            3 => InterfaceStatisticsOption::IsbEndTime(ReadBytesExt::read_u64::<B>(&mut slice).map_err(|_| PcapError::IncompleteBuffer)?),
            4 => InterfaceStatisticsOption::IsbIfRecv(ReadBytesExt::read_u64::<B>(&mut slice).map_err(|_| PcapError::IncompleteBuffer)?),
            5 => InterfaceStatisticsOption::IsbIfDrop(ReadBytesExt::read_u64::<B>(&mut slice).map_err(|_| PcapError::IncompleteBuffer)?),
            6 => InterfaceStatisticsOption::IsbFilterAccept(
                ReadBytesExt::read_u64::<B>(&mut slice).map_err(|_| PcapError::IncompleteBuffer)?,
            ),
            7 => InterfaceStatisticsOption::IsbOsDrop(ReadBytesExt::read_u64::<B>(&mut slice).map_err(|_| PcapError::IncompleteBuffer)?),
            8 => InterfaceStatisticsOption::IsbUsrDeliv(ReadBytesExt::read_u64::<B>(&mut slice).map_err(|_| PcapError::IncompleteBuffer)?),

            2988 | 19372 => InterfaceStatisticsOption::CustomUtf8(CustomUtf8Option::from_slice::<B>(code, slice)?),
            2989 | 19373 => InterfaceStatisticsOption::CustomBinary(CustomBinaryOption::from_slice::<B>(code, slice)?),

            _ => InterfaceStatisticsOption::Unknown(UnknownOption::new(code, length, slice)),
        };

        Ok(opt)
    }

    fn write_to<B: ByteOrder, W: Write>(&self, writer: &mut W) -> IoResult<usize> {
        match self {
            InterfaceStatisticsOption::Comment(a) => a.write_opt_to::<B, W>(1, writer),
            InterfaceStatisticsOption::IsbStartTime(a) => a.write_opt_to::<B, W>(2, writer),
            InterfaceStatisticsOption::IsbEndTime(a) => a.write_opt_to::<B, W>(3, writer),
            InterfaceStatisticsOption::IsbIfRecv(a) => a.write_opt_to::<B, W>(4, writer),
            InterfaceStatisticsOption::IsbIfDrop(a) => a.write_opt_to::<B, W>(5, writer),
            InterfaceStatisticsOption::IsbFilterAccept(a) => a.write_opt_to::<B, W>(6, writer),
            InterfaceStatisticsOption::IsbOsDrop(a) => a.write_opt_to::<B, W>(7, writer),
            InterfaceStatisticsOption::IsbUsrDeliv(a) => a.write_opt_to::<B, W>(8, writer),
            InterfaceStatisticsOption::CustomBinary(a) => a.write_opt_to::<B, W>(a.code, writer),
            InterfaceStatisticsOption::CustomUtf8(a) => a.write_opt_to::<B, W>(a.code, writer),
            InterfaceStatisticsOption::Unknown(a) => a.write_opt_to::<B, W>(a.code, writer),
        }
    }
}

#[cfg(feature = "tokio")]
#[async_trait::async_trait]
impl<'a> AsyncPcapNgOption<'a> for InterfaceStatisticsOption<'a> {
    async fn async_from_slice<B: ByteOrder + Send>(code: u16, length: u16, mut slice: &'a [u8]) -> Result<Self, PcapError> {
        let opt = match code {
            1 => InterfaceStatisticsOption::Comment(Cow::Borrowed(std::str::from_utf8(slice)?)),
            2 => InterfaceStatisticsOption::IsbStartTime(
                AsyncReadBytesExt::read_u64::<B>(&mut slice).await.map_err(|_| PcapError::IncompleteBuffer)?,
            ),
            3 => InterfaceStatisticsOption::IsbEndTime(
                AsyncReadBytesExt::read_u64::<B>(&mut slice).await.map_err(|_| PcapError::IncompleteBuffer)?,
            ),
            4 => InterfaceStatisticsOption::IsbIfRecv(
                AsyncReadBytesExt::read_u64::<B>(&mut slice).await.map_err(|_| PcapError::IncompleteBuffer)?,
            ),
            5 => InterfaceStatisticsOption::IsbIfDrop(
                AsyncReadBytesExt::read_u64::<B>(&mut slice).await.map_err(|_| PcapError::IncompleteBuffer)?,
            ),
            6 => InterfaceStatisticsOption::IsbFilterAccept(
                AsyncReadBytesExt::read_u64::<B>(&mut slice).await.map_err(|_| PcapError::IncompleteBuffer)?,
            ),
            7 => InterfaceStatisticsOption::IsbOsDrop(
                AsyncReadBytesExt::read_u64::<B>(&mut slice).await.map_err(|_| PcapError::IncompleteBuffer)?,
            ),
            8 => InterfaceStatisticsOption::IsbUsrDeliv(
                AsyncReadBytesExt::read_u64::<B>(&mut slice).await.map_err(|_| PcapError::IncompleteBuffer)?,
            ),

            2988 | 19372 => InterfaceStatisticsOption::CustomUtf8(CustomUtf8Option::async_from_slice::<B>(code, slice).await?),
            2989 | 19373 => InterfaceStatisticsOption::CustomBinary(CustomBinaryOption::async_from_slice::<B>(code, slice).await?),

            _ => InterfaceStatisticsOption::Unknown(UnknownOption::new(code, length, slice)),
        };

        Ok(opt)
    }

    async fn async_write_to<B: ByteOrder, W: AsyncWrite + Unpin + Send>(&self, writer: &mut W) -> IoResult<usize> {
        match self {
            InterfaceStatisticsOption::Comment(a) => a.async_write_opt_to::<B, W>(1, writer).await,
            InterfaceStatisticsOption::IsbStartTime(a) => a.async_write_opt_to::<B, W>(2, writer).await,
            InterfaceStatisticsOption::IsbEndTime(a) => a.async_write_opt_to::<B, W>(3, writer).await,
            InterfaceStatisticsOption::IsbIfRecv(a) => a.async_write_opt_to::<B, W>(4, writer).await,
            InterfaceStatisticsOption::IsbIfDrop(a) => a.async_write_opt_to::<B, W>(5, writer).await,
            InterfaceStatisticsOption::IsbFilterAccept(a) => a.async_write_opt_to::<B, W>(6, writer).await,
            InterfaceStatisticsOption::IsbOsDrop(a) => a.async_write_opt_to::<B, W>(7, writer).await,
            InterfaceStatisticsOption::IsbUsrDeliv(a) => a.async_write_opt_to::<B, W>(8, writer).await,
            InterfaceStatisticsOption::CustomBinary(a) => a.async_write_opt_to::<B, W>(a.code, writer).await,
            InterfaceStatisticsOption::CustomUtf8(a) => a.async_write_opt_to::<B, W>(a.code, writer).await,
            InterfaceStatisticsOption::Unknown(a) => a.async_write_opt_to::<B, W>(a.code, writer).await,
        }
    }
}
