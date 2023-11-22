use criterion::{criterion_group, criterion_main, Criterion};
use pcaparse::cap::{CapParser, CapReader};
use pcaparse::pcap::{PcapParser, PcapReader};
use pcaparse::pcapng::{PcapNgParser, PcapNgReader};
use pcaparse::PcapError;

/// Bench and compare Pcap readers and parsers
pub fn pcap(c: &mut Criterion) {
    let pcap = std::fs::read("benches/bench.pcap").unwrap();

    let mut group = c.benchmark_group("Pcap");
    group.throughput(criterion::Throughput::Bytes(pcap.len() as u64));

    group.bench_function("Parser", |b| {
        b.iter(|| {
            let (mut src, parser) = PcapParser::new(&pcap).unwrap();
            loop {
                match parser.next_packet(src) {
                    Ok((rem, _)) => src = rem,
                    Err(PcapError::IncompleteBuffer) => break,
                    Err(_) => panic!(),
                }
            }
        })
    });

    group.bench_function("ParserRaw", |b| {
        b.iter(|| {
            let (mut src, parser) = PcapParser::new(&pcap).unwrap();
            loop {
                match parser.next_raw_packet(src) {
                    Ok((rem, _)) => src = rem,
                    Err(PcapError::IncompleteBuffer) => break,
                    Err(_) => panic!(),
                }
            }
        })
    });

    group.bench_function("Reader", |b| {
        b.iter(|| {
            let mut src = &pcap[..];
            let mut reader = PcapReader::new(&mut src).unwrap();
            while let Some(pkt) = reader.next_packet() {
                pkt.unwrap();
            }
        })
    });

    group.bench_function("ReaderRaw", |b| {
        b.iter(|| {
            let mut src = &pcap[..];
            let mut reader = PcapReader::new(&mut src).unwrap();
            while let Some(pkt) = reader.next_raw_packet() {
                pkt.unwrap();
            }
        })
    });
}

/// Bench and compare PcapNg readers and parsers
pub fn pcapng(c: &mut Criterion) {
    let pcapng = std::fs::read("benches/bench.pcapng").unwrap();

    let mut group = c.benchmark_group("PcapNg");
    group.throughput(criterion::Throughput::Bytes(pcapng.len() as u64));

    group.bench_function("Parser", |b| {
        b.iter(|| {
            let (mut src, mut parser) = PcapNgParser::new(&pcapng).unwrap();
            loop {
                match parser.next_block(src) {
                    Ok((rem, _)) => src = rem,
                    Err(PcapError::IncompleteBuffer) => break,
                    Err(_) => panic!(),
                }
            }
        })
    });

    group.bench_function("ParserRaw", |b| {
        b.iter(|| {
            let (mut src, mut parser) = PcapNgParser::new(&pcapng).unwrap();
            loop {
                match parser.next_raw_block(src) {
                    Ok((rem, _)) => src = rem,
                    Err(PcapError::IncompleteBuffer) => break,
                    Err(_) => panic!(),
                }
            }
        })
    });

    group.bench_function("Reader", |b| {
        b.iter(|| {
            let mut src = &pcapng[..];
            let mut reader = PcapNgReader::new(&mut src).unwrap();
            while let Some(pkt) = reader.next_block() {
                pkt.unwrap();
            }
        })
    });

    group.bench_function("ReaderRaw", |b| {
        b.iter(|| {
            let mut src = &pcapng[..];
            let mut reader = PcapNgReader::new(&mut src).unwrap();
            while let Some(pkt) = reader.next_raw_block() {
                pkt.unwrap();
            }
        })
    });
}

/// Bench and compare Cap readers and parsers
pub fn cap(c: &mut Criterion) {
    let cap = std::fs::read("benches/bench.cap").unwrap();

    let mut group = c.benchmark_group("Cap");
    group.throughput(criterion::Throughput::Bytes(cap.len() as u64));

    group.bench_function("Parser", |b| {
        b.iter(|| {
            let (mut src, parser) = CapParser::new(&cap).unwrap();
            loop {
                match parser.next_packet(src) {
                    Ok((rem, _)) => src = rem,
                    Err(PcapError::IncompleteBuffer) => break,
                    Err(_) => panic!(),
                }
            }
        })
    });

    group.bench_function("ParserRaw", |b| {
        b.iter(|| {
            let (mut src, parser) = CapParser::new(&cap).unwrap();
            loop {
                match parser.next_raw_packet(src) {
                    Ok((rem, _)) => src = rem,
                    Err(PcapError::IncompleteBuffer) => break,
                    Err(_) => panic!(),
                }
            }
        })
    });

    group.bench_function("Reader", |b| {
        b.iter(|| {
            let mut src = &cap[..];
            let mut reader = CapReader::new(&mut src).unwrap();
            while let Some(pkt) = reader.next_packet() {
                pkt.unwrap();
            }
        })
    });

    group.bench_function("ReaderRaw", |b| {
        b.iter(|| {
            let mut src = &cap[..];
            let mut reader = CapReader::new(&mut src).unwrap();
            while let Some(pkt) = reader.next_raw_packet() {
                pkt.unwrap();
            }
        })
    });
}

criterion_group!(benches, pcap, pcapng, cap);
criterion_main!(benches);
