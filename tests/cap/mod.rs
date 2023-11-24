use pcaparse::{cap::CapReader, DataLink};

static DATA: &[u8; 1466] = include_bytes!("dns-only.cap");

#[cfg(feature = "tokio")]
#[tokio::test]
async fn async_read() {
    let mut cap_reader = CapReader::async_new(&DATA[..]).await.unwrap();
    let datalink = cap_reader.header().datalink;
    assert_eq!(datalink, DataLink::ETHERNET);

    //Global header len
    let mut data_len = 128;
    while let Some(pkt) = cap_reader.async_next_packet().await {
        let pkt = pkt.unwrap();

        //Packet header len
        data_len += 40;
        data_len += pkt.data.len();
    }

    assert_eq!(data_len, DATA.len());
}

#[cfg(feature = "tokio")]
#[tokio::test]
async fn async_read_tokio_file() {
    let reader = tokio::fs::File::open("tests/cap/dns-only.cap").await.unwrap();
    let mut cap_reader = CapReader::async_new(reader).await.unwrap();
    let datalink = cap_reader.header().datalink;
    assert_eq!(datalink, DataLink::ETHERNET);

    //Global header len
    let mut data_len = 128;
    while let Some(pkt) = cap_reader.async_next_packet().await {
        let pkt = pkt.unwrap();

        //Packet header len
        data_len += 40;
        data_len += pkt.data.len();
    }

    assert_eq!(data_len, DATA.len());
}

#[test]
fn read_cap() {
    let mut cap_reader = CapReader::new(&DATA[..]).unwrap();
    let datalink = cap_reader.header().datalink;
    assert_eq!(datalink, DataLink::ETHERNET);

    //Global header len
    let mut data_len = 128;
    while let Some(pkt) = cap_reader.next_packet() {
        let pkt = pkt.unwrap();

        //Packet header len
        data_len += 40;
        data_len += pkt.data.len();
    }

    assert_eq!(data_len, DATA.len());
}
