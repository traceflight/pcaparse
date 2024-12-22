use std::io::Read;
use std::{fs::File, path::PathBuf};

use glob::glob;
use pcaparse::{
    pcapng::{PcapNgParser, PcapNgReader, PcapNgWriter},
    Format, Reader,
};

#[cfg(feature = "tokio")]
#[tokio::test]
async fn async_reader() {
    for entry in glob("tests/pcapng/**/**/*.pcapng").expect("Failed to read glob pattern") {
        let entry = entry.unwrap();

        let file = tokio::fs::File::open(&entry).await.unwrap();
        let mut pcapng_reader = PcapNgReader::async_new(file).await.unwrap();

        let mut i = 0;
        while let Some(block) = pcapng_reader.async_next_block().await {
            let _block = block.unwrap_or_else(|_| panic!("Error on block {i} on file: {entry:?}"));
            i += 1;
        }
    }
}
#[test]
fn reader() {
    for entry in glob("tests/pcapng/**/**/*.pcapng").expect("Failed to read glob pattern") {
        let entry = entry.unwrap();

        let file = File::open(&entry).unwrap();
        let mut pcapng_reader = PcapNgReader::new(file).unwrap();

        let mut i = 0;
        while let Some(block) = pcapng_reader.next_block() {
            let _block = block.unwrap_or_else(|_| panic!("Error on block {i} on file: {entry:?}"));
            i += 1;
        }
    }
}

#[test]
fn unified_reader() {
    for entry in glob("tests/pcapng/**/**/*.pcapng").expect("Failed to read glob pattern") {
        let entry = entry.unwrap();

        let file = File::open(&entry).unwrap();
        let mut pcapng_reader = Reader::new(file).unwrap();

        assert_eq!(pcapng_reader.format(), Format::PcapNg);

        let mut i = 0;
        while let Some(_) = pcapng_reader.next_packet() {
            i += 1;
        }
        println!("{i}");
    }
}

#[test]
fn read_le_difficult() {
    let file = File::open(PathBuf::from("tests/pcapng/little_endian/difficult/test202.pcapng")).unwrap();
    let mut pcapng_reader = PcapNgReader::new(file).unwrap();

    let mut i = 0;
    while let Some(_block) = pcapng_reader.next_block() {
        i += 1;
    }
    println!("{i}");
}

#[test]
fn unified_reader_le_difficult() {
    let file = File::open(PathBuf::from("tests/pcapng/little_endian/difficult/test202.pcapng")).unwrap();
    let mut pcapng_reader = Reader::new(file).unwrap();

    assert_eq!(pcapng_reader.format(), Format::PcapNg);

    let mut i = 0;
    while let Some(Ok(packet)) = pcapng_reader.next_packet() {
        match i {
            0 => assert_eq!(packet.orig_len, 314),
            1 => assert_eq!(packet.orig_len, 342),
            2 => assert_eq!(packet.orig_len, 168),
            3 => assert_eq!(packet.orig_len, 314),
            4 => assert_eq!(packet.orig_len, 342),
            5 => assert_eq!(packet.orig_len, 314),
            6 => assert_eq!(packet.orig_len, 342),
            7 => assert_eq!(packet.orig_len, 168),
            _ => {},
        }
        i += 1;
    }
    assert_eq!(i, 8);
}

#[cfg(feature = "tokio")]
#[tokio::test]
async fn async_unified_reader_le_difficult() {
    let file = tokio::fs::File::open(PathBuf::from("tests/pcapng/little_endian/difficult/test202.pcapng"))
        .await
        .unwrap();
    let mut pcapng_reader = Reader::async_new(file).await.unwrap();

    assert_eq!(pcapng_reader.format(), Format::PcapNg);

    let mut i = 0;
    while let Some(Ok(packet)) = pcapng_reader.async_next_packet().await {
        match i {
            0 => assert_eq!(packet.orig_len, 314),
            1 => assert_eq!(packet.orig_len, 342),
            2 => assert_eq!(packet.orig_len, 168),
            3 => assert_eq!(packet.orig_len, 314),
            4 => assert_eq!(packet.orig_len, 342),
            5 => assert_eq!(packet.orig_len, 314),
            6 => assert_eq!(packet.orig_len, 342),
            7 => assert_eq!(packet.orig_len, 168),
            _ => {},
        }
        i += 1;
    }
    assert_eq!(i, 8);
}

#[cfg(feature = "tokio")]
#[tokio::test]
async fn async_parser() {
    use tokio::io::AsyncReadExt;

    for entry in glob("tests/pcapng/**/**/*.pcapng").expect("Failed to read glob pattern") {
        let entry = entry.unwrap();

        let mut file = tokio::fs::File::open(&entry).await.unwrap();
        let mut data = Vec::new();
        file.read_to_end(&mut data).await.unwrap();

        let mut src = &data[..];
        let (rem, mut pcapng_parser) = PcapNgParser::async_new(src).await.unwrap();
        src = rem;

        let mut i = 0;
        loop {
            if src.is_empty() {
                break;
            }

            let (rem, _) = pcapng_parser
                .async_next_block(src)
                .await
                .unwrap_or_else(|e| panic!("Error on block {i} on file: {entry:?}, e: {e}"));
            src = rem;

            i += 1;
        }
    }
}

#[test]
fn parser() {
    for entry in glob("tests/pcapng/**/**/*.pcapng").expect("Failed to read glob pattern") {
        let entry = entry.unwrap();

        let mut file = File::open(&entry).unwrap();
        let mut data = Vec::new();
        file.read_to_end(&mut data).unwrap();

        let mut src = &data[..];
        let (rem, mut pcapng_parser) = PcapNgParser::new(src).unwrap();
        src = rem;

        let mut i = 0;
        loop {
            if src.is_empty() {
                break;
            }

            let (rem, _) = pcapng_parser
                .next_block(src)
                .unwrap_or_else(|e| panic!("Error on block {i} on file: {entry:?}, e: {e}"));
            src = rem;

            i += 1;
        }
    }
}

#[cfg(feature = "tokio")]
#[tokio::test]
async fn async_writer() {
    for entry in glob("tests/pcapng/**/**/*.pcapng").expect("Failed to read glob pattern") {
        let entry = entry.unwrap();

        let pcapng_in = std::fs::read(&entry).unwrap();
        let mut pcapng_reader = PcapNgReader::new(&pcapng_in[..]).unwrap();
        let mut pcapng_writer = PcapNgWriter::async_with_section_header(Vec::new(), pcapng_reader.section().clone()).await.unwrap();

        let mut idx = 0;
        while let Some(block) = pcapng_reader.next_block() {
            let block = block.unwrap();
            pcapng_writer
                .async_write_block(&block)
                .await
                .unwrap_or_else(|_| panic!("Error writing block, file: {entry:?}, block n°{idx}, block: {block:?}"));
            idx += 1;
        }

        let expected = &pcapng_in;
        let actual = pcapng_writer.get_ref();

        if expected != actual {
            let mut expected_reader = PcapNgReader::new(&expected[..]).unwrap();
            let mut actual_reader = PcapNgReader::async_new(&actual[..]).await.unwrap();

            let mut idx = 0;
            while let (Some(expected), Some(actual)) = (expected_reader.next_block(), actual_reader.async_next_block().await) {
                let expected = expected.unwrap();
                let actual = actual.unwrap();

                if expected != actual {
                    assert_eq!(expected, actual, "Pcap written != pcap read, file: {entry:?}, block n°{idx}")
                }

                idx += 1;
            }

            panic!("Pcap written != pcap read  but blocks are equal, file: {entry:?}");
        }
    }
}

#[test]
fn writer() {
    for entry in glob("tests/pcapng/**/**/*.pcapng").expect("Failed to read glob pattern") {
        let entry = entry.unwrap();

        let pcapng_in = std::fs::read(&entry).unwrap();
        let mut pcapng_reader = PcapNgReader::new(&pcapng_in[..]).unwrap();
        let mut pcapng_writer = PcapNgWriter::with_section_header(Vec::new(), pcapng_reader.section().clone()).unwrap();

        let mut idx = 0;
        while let Some(block) = pcapng_reader.next_block() {
            let block = block.unwrap();
            pcapng_writer
                .write_block(&block)
                .unwrap_or_else(|_| panic!("Error writing block, file: {entry:?}, block n°{idx}, block: {block:?}"));
            idx += 1;
        }

        let expected = &pcapng_in;
        let actual = pcapng_writer.get_ref();

        if expected != actual {
            let mut expected_reader = PcapNgReader::new(&expected[..]).unwrap();
            let mut actual_reader = PcapNgReader::new(&actual[..]).unwrap();

            let mut idx = 0;
            while let (Some(expected), Some(actual)) = (expected_reader.next_block(), actual_reader.next_block()) {
                let expected = expected.unwrap();
                let actual = actual.unwrap();

                if expected != actual {
                    assert_eq!(expected, actual, "Pcap written != pcap read, file: {entry:?}, block n°{idx}")
                }

                idx += 1;
            }

            panic!("Pcap written != pcap read  but blocks are equal, file: {entry:?}");
        }
    }
}
