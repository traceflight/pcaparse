//! Systemd Journal Export Block.

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
use crate::errors::PcapError;

/// The Systemd Journal Export Block is a lightweight containter for systemd Journal Export Format entry data.
#[derive(Clone, Debug, IntoOwned, Eq, PartialEq)]
pub struct SystemdJournalExportBlock<'a> {
    /// A journal entry as described in the Journal Export Format documentation.
    pub journal_entry: Cow<'a, [u8]>,
}

impl<'a> PcapNgBlock<'a> for SystemdJournalExportBlock<'a> {
    fn from_slice<B: ByteOrder>(slice: &'a [u8]) -> Result<(&'a [u8], Self), PcapError> {
        let packet = SystemdJournalExportBlock { journal_entry: Cow::Borrowed(slice) };
        Ok((&[], packet))
    }

    fn write_to<B: ByteOrder, W: Write>(&self, writer: &mut W) -> IoResult<usize> {
        writer.write_all(&self.journal_entry)?;

        let pad_len = (4 - (self.journal_entry.len() % 4)) % 4;
        writer.write_all(&[0_u8; 3][..pad_len])?;

        Ok(self.journal_entry.len() + pad_len)
    }

    fn into_block(self) -> Block<'a> {
        Block::SystemdJournalExport(self)
    }
}

#[cfg(feature = "tokio")]
#[async_trait::async_trait]
impl<'a> AsyncPcapNgBlock<'a> for SystemdJournalExportBlock<'a> {
    async fn async_from_slice<B: ByteOrder>(slice: &'a [u8]) -> Result<(&'a [u8], SystemdJournalExportBlock<'a>), PcapError> {
        let packet = SystemdJournalExportBlock { journal_entry: Cow::Borrowed(slice) };
        Ok((&[], packet))
    }

    async fn async_write_to<B: ByteOrder, W: AsyncWrite + Unpin + Send>(&self, writer: &mut W) -> IoResult<usize> {
        tokio::io::AsyncWriteExt::write_all(writer, &self.journal_entry).await?;

        let pad_len = (4 - (self.journal_entry.len() % 4)) % 4;
        tokio::io::AsyncWriteExt::write_all(writer, &[0_u8; 3][..pad_len]).await?;

        Ok(self.journal_entry.len() + pad_len)
    }
}
