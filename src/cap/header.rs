use byteorder::ReadBytesExt;
use byteorder::{BigEndian, ByteOrder, LittleEndian};
#[cfg(feature = "tokio")]
use tokio_byteorder::AsyncReadBytesExt;

use crate::DataLink;
use crate::{errors::*, Endianness};

/* Capture file header, *including* magic number, is padded to 128 bytes. */
const CAPTUREFILE_HEADER_SIZE: usize = 128;

/// Magic number in NetXRay 1.x files.
/// ['V', 'L', '\0', '\0']
const OLD_NETXRAY_MAGIC: u32 = 0x564C0000;

//// Magic number in NetXRay 2.0 and later, and Windows Sniffer, files.
/// ['X', 'C', 'P', '\0']
const NETXRAY_MAGIC: u32 = 0x58435000;

/// NetXRay file header (minus magic number).
///
/// As field usages are identified, please revise as needed
/// Please do *not* use netxray_hdr xxx... names in the code
/// (Placeholder names for all 'unknown' fields are
///   of form xxx_x<hex_hdr_offset>
///   where <hex_hdr_offset> *includes* the magic number)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct CapHeader {
    /// Major version number
    pub version_major: u32,
    /// Minor version number
    pub version_minor: u32,
    /// UNIX \[UTC\] time when capture started
    pub start_time: u32,
    /// number of packets
    pub nframes: u32,
    /// start offset
    pub start_offset: u32,
    /// end offset
    pub end_offset: u32,
    /// datalink type u8
    pub datalink: DataLink,
    /// [See code]
    pub network_plus: u8,
    /// capture type
    pub captype: u8,
    /// Endianness of the cap (excluding the packet data)
    pub endianness: Endianness,
}

impl CapHeader {
    /// Creates a new [`CapHeader`] from a slice of bytes.
    ///
    /// Returns an error if the reader doesn't contain a valid pcap
    /// or if there is a reading error.
    ///
    /// [`PcapError::IncompleteBuffer`] indicates that there is not enough data in the buffer.
    pub fn from_slice(mut slice: &[u8]) -> PcapResult<(&[u8], CapHeader)> {
        // Check that slice.len() > CapHeader length
        if slice.len() < CAPTUREFILE_HEADER_SIZE {
            return Err(PcapError::IncompleteBuffer);
        }

        let magic_number = ReadBytesExt::read_u32::<BigEndian>(&mut slice).unwrap();

        match magic_number {
            NETXRAY_MAGIC => return init_cap_header::<LittleEndian>(slice, Endianness::Little),
            OLD_NETXRAY_MAGIC => return Err(PcapError::UnsupportedVersion(magic_number.to_string())),
            _ => return Err(PcapError::InvalidField("CapHeader: wrong magic number")),
        };

        // Inner function used for the initialisation of the CapHeader.
        // Must check the srcclength before calling it.
        fn init_cap_header<B: ByteOrder>(mut src: &[u8], endianness: Endianness) -> PcapResult<(&[u8], CapHeader)> {
            let version_major = match src[0..3] {
                [0x30, 0x30, 0x32] => 2,
                _ => return Err(PcapError::UnsupportedVersion(String::from_utf8_lossy(&src[0..3]).to_string())),
            };
            src = &src[4..];
            let version_minor = match String::from_utf8_lossy(&src[0..3]).parse::<u32>() {
                Ok(v) => v,
                Err(_e) => return Err(PcapError::InvalidField("CapHeader: invalid minor version")),
            };
            src = &src[4..];
            let start_time = ReadBytesExt::read_u32::<B>(&mut src).unwrap();

            let nframes = ReadBytesExt::read_u32::<B>(&mut src).unwrap();
            src = &src[4..];
            let start_offset = ReadBytesExt::read_u32::<B>(&mut src).unwrap();
            let end_offset = ReadBytesExt::read_u32::<B>(&mut src).unwrap();

            src = &src[12..];
            let network = ReadBytesExt::read_u8(&mut src).unwrap();
            let network_plus = ReadBytesExt::read_u8(&mut src).unwrap();
            src = &src[2..];

            src = &src[32..];

            src = &src[4..];
            let captype = ReadBytesExt::read_u8(&mut src).unwrap();
            src = &src[11..];

            src = &src[32..];

            let mut _network_type;
            match network_plus {
                0 => _network_type = network + 1,
                2 => _network_type = network,
                _ => return Err(PcapError::InvalidField("CapHeader: invalid network plus code")),
            }

            let header = CapHeader {
                version_major,
                version_minor,
                start_time,
                nframes,
                datalink: DataLink::ETHERNET,
                network_plus,
                captype,
                start_offset,
                end_offset,
                endianness,
            };

            Ok((src, header))
        }
    }

    /// Asynchronously creates a new [`CapHeader`] from a slice of bytes.
    ///
    /// Returns an error if the reader doesn't contain a valid pcap
    /// or if there is a reading error.
    ///
    /// [`PcapError::IncompleteBuffer`] indicates that there is not enough data in the buffer.
    #[cfg(feature = "tokio")]
    pub async fn async_from_slice(mut slice: &[u8]) -> PcapResult<(&[u8], CapHeader)> {
        // Check that slice.len() > CapHeader length
        if slice.len() < CAPTUREFILE_HEADER_SIZE {
            return Err(PcapError::IncompleteBuffer);
        }

        let magic_number = AsyncReadBytesExt::read_u32::<BigEndian>(&mut slice).await.unwrap();

        match magic_number {
            NETXRAY_MAGIC => return init_cap_header::<LittleEndian>(slice, Endianness::Little).await,
            OLD_NETXRAY_MAGIC => return Err(PcapError::UnsupportedVersion(magic_number.to_string())),
            _ => return Err(PcapError::InvalidField("CapHeader: wrong magic number")),
        };

        // Inner function used for the initialisation of the CapHeader.
        // Must check the srcclength before calling it.
        async fn init_cap_header<B: ByteOrder>(mut src: &[u8], endianness: Endianness) -> PcapResult<(&[u8], CapHeader)> {
            let version_major = match src[0..3] {
                [0x30, 0x30, 0x32] => 2,
                _ => return Err(PcapError::UnsupportedVersion(String::from_utf8_lossy(&src[0..3]).to_string())),
            };
            src = &src[4..];
            let version_minor = match String::from_utf8_lossy(&src[0..3]).parse::<u32>() {
                Ok(v) => v,
                Err(_e) => return Err(PcapError::InvalidField("CapHeader: invalid minor version")),
            };
            src = &src[4..];
            let start_time = AsyncReadBytesExt::read_u32::<B>(&mut src).await.unwrap();

            let nframes = AsyncReadBytesExt::read_u32::<B>(&mut src).await.unwrap();
            src = &src[4..];
            let start_offset = AsyncReadBytesExt::read_u32::<B>(&mut src).await.unwrap();
            let end_offset = AsyncReadBytesExt::read_u32::<B>(&mut src).await.unwrap();

            src = &src[12..];
            let network = AsyncReadBytesExt::read_u8(&mut src).await.unwrap();
            let network_plus = AsyncReadBytesExt::read_u8(&mut src).await.unwrap();
            src = &src[2..];

            src = &src[32..];

            src = &src[4..];
            let captype = AsyncReadBytesExt::read_u8(&mut src).await.unwrap();
            src = &src[11..];

            src = &src[32..];

            let mut _network_type;
            match network_plus {
                0 => _network_type = network + 1,
                2 => _network_type = network,
                _ => return Err(PcapError::InvalidField("CapHeader: invalid network plus code")),
            }

            let header = CapHeader {
                version_major,
                version_minor,
                start_time,
                nframes,
                datalink: DataLink::ETHERNET,
                network_plus,
                captype,
                start_offset,
                end_offset,
                endianness,
            };

            Ok((src, header))
        }
    }
}
