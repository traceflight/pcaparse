# pcaparse

This is a combination of awesome [pcap-file](https://github.com/courvoif/pcap-file) crate and [pcap-file-tokio](https://github.com/mauricelam/pcap-file-tokio) crate with some issues fixed and new features added.


Provides parsers, readers and writers for Cap(Network Associates Sniffer 2.x), Pcap and PcapNg files.

[![Crates.io](https://img.shields.io/crates/v/pcaparse.svg)](https://crates.io/crates/pcaparse)
[![rustdoc](https://img.shields.io/badge/Doc-pcaparse-green.svg)](https://docs.rs/pcaparse/)
[![Crates.io](https://img.shields.io/crates/l/pcaparse.svg)](https://github.com/traceflight/pcaparse/blob/main/LICENSE)


## Why this crate

* I previously made a [PR](https://github.com/courvoif/pcap-file/pull/34) to [pcap-file](https://github.com/courvoif/pcap-file) repo to handle a snaplen issue, but the author seems has no time to maintain it.
* The sync and async processing share similar logic but divided into two crates, which will increase the difficulty of fixing problems.


## To do

- [ ] Fix timestamp of pcapng
- [x] Add parser and reader for cap(Network Associates Sniffer 2.x) file
- [ ] Add writer for cap(Network Associates Sniffer 2.x) file

## Crate Features

`tokio` enables async reading and writing via `tokio` crate.

## Installation
This crate is on [crates.io](https://crates.io/crates/pcaparse).
Add it to your `Cargo.toml`:

```toml
[dependencies]
pcaparse = "0.1"
```

## Examples

### PcapReader
```rust,no_run
use std::fs::File;
use pcaparse::pcap::PcapReader;

let file_in = File::open("test.pcap").expect("Error opening file");
let mut pcap_reader = PcapReader::new(file_in).unwrap();

// Read test.pcap
while let Some(pkt) = pcap_reader.next_packet() {
    //Check if there is no error
    let pkt = pkt.unwrap();

    //Do something
 }
```


### Async PcapReader

enable `tokio` feature first

```rust,no_run
use tokio::fs::File;
use pcaparse::pcap::PcapReader;

#[tokio::main]
async fn main() {
    let file_in = File::open("test.pcap").await.expect("Error opening file");
    let mut pcap_reader = PcapReader::async_new(file_in).await.unwrap();

    // Read test.pcap
    while let Some(pkt) = pcap_reader.async_next_packet().await {
        //Check if there is no error
        let pkt = pkt.unwrap();

        //Do something
    }
}
```

### Async PcapReader from tokio's TcpStream (AKA pcap-over-ip)

enable `tokio` feature first

```rust,no_run
use tokio::net::{TcpListener, TcpStream};
use pcaparse::pcap::PcapReader;

#[tokio::main]
async fn main() {
    let listener = TcpListener::bind("0.0.0.0:12345").await.unwrap();
    println!("start listen 12345");
    loop {
        let (stream, _) = listener.accept().await.unwrap();
        tokio::spawn(async move {
            process(stream).await;
        });
    }
}

async fn process(stream: TcpStream) {
    let mut pcap_reader = PcapReader::async_new(stream).await.unwrap();
    // Read test.pcap
    while let Some(pkt) = pcap_reader.async_next_packet().await {
        //Check if there is no error
        let pkt = pkt.unwrap();
        //Do something
    }
}
```

### PcapNgReader
```rust,no_run
use std::fs::File;
use pcaparse::pcapng::PcapNgReader;

let file_in = File::open("test.pcapng").expect("Error opening file");
let mut pcapng_reader = PcapNgReader::new(file_in).unwrap();

// Read test.pcapng
while let Some(block) = pcapng_reader.next_block() {
    // Check if there is no error
    let block = block.unwrap();

    //  Do something
}
```

### Async PcapNgReader from tokio's File

enable `tokio` feature first

```rust,no_run
use tokio::fs::File;
use pcaparse::pcapng::PcapNgReader;

#[tokio::main]
async fn main() {
    let file_in = File::open("test.pcapng").await.expect("Error opening file");
    let mut pcapng_reader = PcapNgReader::async_new(file_in).await.unwrap();

    // Read test.pcapng
    while let Some(block) = pcapng_reader.async_next_block().await {
        // Check if there is no error
        let block = block.unwrap();

        //  Do something
    }
}
```


### CapReader
```rust,no_run
use std::fs::File;
use pcaparse::cap::CapReader;

let file_in = File::open("test.cap").expect("Error opening file");
let mut cap_reader = CapReader::new(file_in).unwrap();

// Read test.cap
while let Some(pkt) = cap_reader.next_packet() {
    //Check if there is no error
    let pkt = pkt.unwrap();

    //Do something
 }
```

### Async CapReader

enable `tokio` feature first

```rust,no_run
use tokio::fs::File;
use pcaparse::cap::CapReader;

#[tokio::main]
async fn main() {
    let file_in = File::open("test.cap").await.expect("Error opening file");
    let mut cap_reader = CapReader::async_new(file_in).await.unwrap();

    // Read test.cap
    while let Some(pkt) = cap_reader.async_next_packet().await {
        //Check if there is no error
        let pkt = pkt.unwrap();

        //Do something
    }
}
```

## Fuzzing
Currently there are 4 crude harnesses to check that the parser won't panic in any situation. To start fuzzing you must install `cargo-fuzz` with the command:
```bash
$ cargo install cargo-fuzz
```

And then, in the root of the repository, you can run the harnesses as:
```bash
$ cargo fuzz run pcap_reader
$ cargo fuzz run pcap_ng_reader
$ cargo fuzz run pcap_parser
$ cargo fuzz run pcap_ng_parser
```

Keep in mind that libfuzzer by default uses only one core, so you can either run all the harnesses in different terminals, or you can pass the `-jobs` and `-workers` attributes. More info can be found in its documentation [here](https://llvm.org/docs/LibFuzzer.html).
To get better crash reports add to you rust flags: `-Zsanitizer=address`. 
E.g.
```bash
RUSTFLAGS="-Zsanitizer=address" cargo fuzz run pcap_reader
```


## License
Licensed under MIT.


## Disclaimer
To test the library I used the excellent PcapNg testing suite provided by [hadrielk](https://github.com/hadrielk/pcapng-test-generator). 

