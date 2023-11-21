//! Unknown Block.

use std::borrow::Cow;
use std::io::Result as IoResult;
use std::io::Write;

use byteorder::ByteOrder;
use derive_into_owned::IntoOwned;
#[cfg(feature = "tokio")]
use tokio::io::AsyncWrite;

#[cfg(feature = "tokio")]
use super::block_common::AsyncPcapNgBlock;
use super::block_common::{Block, PcapNgBlock};
use crate::PcapError;

/// Unknown block
#[derive(Clone, Debug, IntoOwned, Eq, PartialEq)]
pub struct UnknownBlock<'a> {
    /// Block type
    pub type_: u32,
    /// Block length
    pub length: u32,
    /// Block value
    pub value: Cow<'a, [u8]>,
}

impl<'a> UnknownBlock<'a> {
    /// Creates a new [`UnknownBlock`]
    pub fn new(type_: u32, length: u32, value: &'a [u8]) -> Self {
        UnknownBlock { type_, length, value: Cow::Borrowed(value) }
    }
}

impl<'a> PcapNgBlock<'a> for UnknownBlock<'a> {
    fn from_slice<B: ByteOrder>(_slice: &'a [u8]) -> Result<(&[u8], Self), PcapError>
    where
        Self: Sized,
    {
        unimplemented!("UnkknownBlock::<as PcapNgBlock>::From_slice shouldn't be called")
    }

    fn write_to<B: ByteOrder, W: Write>(&self, writer: &mut W) -> IoResult<usize> {
        writer.write_all(&self.value)?;
        Ok(self.value.len())
    }

    fn into_block(self) -> Block<'a> {
        Block::Unknown(self)
    }
}

#[cfg(feature = "tokio")]
#[async_trait::async_trait]
impl<'a> AsyncPcapNgBlock<'a> for UnknownBlock<'a> {
    async fn async_from_slice<B: ByteOrder>(_slice: &'a [u8]) -> Result<(&[u8], UnknownBlock<'a>), PcapError>
    where
        Self: Sized,
    {
        unimplemented!("UnkknownBlock::<as PcapNgBlock>::From_slice shouldn't be called")
    }

    async fn async_write_to<B: ByteOrder, W: AsyncWrite + Unpin + Send>(&self, writer: &mut W) -> IoResult<usize> {
        tokio::io::AsyncWriteExt::write_all(writer, &self.value).await?;
        Ok(self.value.len())
    }
}
