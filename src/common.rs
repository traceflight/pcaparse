use std::{borrow::Cow, time::Duration};

use byteorder::ByteOrder;
use derive_into_owned::IntoOwned;

/// Timestamp resolution of the pcap
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum TsResolution {
    /// Microsecond resolution
    MicroSecond,
    /// Nanosecond resolution
    NanoSecond,
}

/// Endianness of the pcap
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Endianness {
    /// Big endian
    Big,
    /// Little endian
    Little,
}

impl Endianness {
    /// True if LitlleEndian
    pub fn is_little(self) -> bool {
        match self {
            Endianness::Big => false,
            Endianness::Little => true,
        }
    }

    /// True if BigEndian
    pub fn is_big(self) -> bool {
        match self {
            Endianness::Big => true,
            Endianness::Little => false,
        }
    }

    /// Return the endianness of the given ByteOrder
    pub fn from_byteorder<B: ByteOrder>() -> Self {
        if B::read_u32(&[0, 0, 0, 1]) == 1 {
            Endianness::Big
        } else {
            Endianness::Little
        }
    }

    /// Return the native endianness of the system
    pub fn native() -> Self {
        #[cfg(target_endian = "big")]
        return Endianness::Big;

        #[cfg(target_endian = "little")]
        return Endianness::Little;
    }
}

/// Commen packet.
///
/// The payload can be owned or borrowed.
#[derive(Clone, Debug, IntoOwned)]
pub struct Packet<'a> {
    /// Timestamp EPOCH of the packet with a nanosecond resolution
    pub timestamp: Option<Duration>,
    /// Original length of the packet when captured on the wire
    pub orig_len: u32,
    /// Payload, owned or borrowed, of the packet
    pub data: Cow<'a, [u8]>,
    /// DataLink of current packet
    pub datalink: DataLink,
}

/// format of packet file
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub enum Format {
    /// pcap file
    Pcap,
    /// cap file
    Cap,
    /// pcapng file
    PcapNg,
}

/// Data link type
///
/// The link-layer header type specifies the first protocol of the packet.
///
/// See [http://www.tcpdump.org/linktypes.html](http://www.tcpdump.org/linktypes.html)
#[allow(non_camel_case_types)]
#[allow(missing_docs)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum DataLink {
    NULL,
    ETHERNET,
    EXP_ETHERNET,
    AX25,
    PRONET,
    CHAOS,
    IEEE802_5,
    ARCNET_BSD,
    SLIP,
    PPP,
    FDDI,
    PPP_HDLC,
    PPP_ETHER,
    SYMANTEC_FIREWALL,
    ATM_RFC1483,
    RAW,
    SLIP_BSDOS,
    PPP_BSDOS,
    MATCHING_MIN,
    C_HDLC,
    IEEE802_11,
    ATM_CLIP,
    FRELAY,
    LOOP,
    ENC,
    LANE8023,
    HIPPI,
    NETBSD_HDLC,
    LINUX_SLL,
    LTALK,
    ECONET,
    IPFILTER,
    PFLOG,
    CISCO_IOS,
    IEEE802_11_PRISM,
    IEEE802_11_AIRONET,
    HHDLC,
    IP_OVER_FC,
    SUNATM,
    RIO,
    PCI_EXP,
    AURORA,
    IEEE802_11_RADIOTAP,
    TZSP,
    ARCNET_LINUX,
    JUNIPER_MLPPP,
    JUNIPER_MLFR,
    JUNIPER_ES,
    JUNIPER_GGSN,
    JUNIPER_MFR,
    JUNIPER_ATM2,
    JUNIPER_SERVICES,
    JUNIPER_ATM1,
    APPLE_IP_OVER_IEEE1394,
    MTP2_WITH_PHDR,
    MTP2,
    MTP3,
    SCCP,
    DOCSIS,
    LINUX_IRDA,
    IBM_SP,
    IBM_SN,
    USER0,
    USER1,
    USER2,
    USER3,
    USER4,
    USER5,
    USER6,
    USER7,
    USER8,
    USER9,
    USER10,
    USER11,
    USER12,
    USER13,
    USER14,
    USER15,
    IEEE802_11_AVS,
    JUNIPER_MONITOR,
    BACNET_MS_TP,
    PPP_PPPD,
    JUNIPER_PPPOE,
    JUNIPER_PPPOE_ATM,
    GPRS_LLC,
    GPF_T,
    GPF_F,
    GCOM_T1E1,
    GCOM_SERIAL,
    JUNIPER_PIC_PEER,
    ERF_ETH,
    ERF_POS,
    LINUX_LAPD,
    JUNIPER_ETHER,
    JUNIPER_PPP,
    JUNIPER_FRELAY,
    JUNIPER_CHDLC,
    MFR,
    JUNIPER_VP,
    A429,
    A653_ICM,
    USB_FREEBSD,
    BLUETOOTH_HCI_H4,
    IEEE802_16_MAC_CPS,
    USB_LINUX,
    CAN20B,
    IEEE802_15_4_LINUX,
    PPI,
    IEEE802_16_MAC_CPS_RADIO,
    JUNIPER_ISM,
    IEEE802_15_4,
    SITA,
    ERF,
    RAIF1,
    IPMB_KONTRON,
    JUNIPER_ST,
    BLUETOOTH_HCI_H4_WITH_PHDR,
    AX25_KISS,
    LAPD,
    PPP_WITH_DIR,
    C_HDLC_WITH_DIR,
    FRELAY_WITH_DIR,
    LAPB_WITH_DIR,
    IPMB_LINUX,
    FLEXRAY,
    MOST,
    LIN,
    X2E_SERIAL,
    X2E_XORAYA,
    IEEE802_15_4_NONASK_PHY,
    LINUX_EVDEV,
    GSMTAP_UM,
    GSMTAP_ABIS,
    MPLS,
    USB_LINUX_MMAPPED,
    DECT,
    AOS,
    WIHART,
    FC_2,
    FC_2_WITH_FRAME_DELIMS,
    IPNET,
    CAN_SOCKETCAN,
    IPV4,
    IPV6,
    IEEE802_15_4_NOFCS,
    DBUS,
    JUNIPER_VS,
    JUNIPER_SRX_E2E,
    JUNIPER_FIBRECHANNEL,
    DVB_CI,
    MUX27010,
    STANAG_5066_D_PDU,
    JUNIPER_ATM_CEMIC,
    NFLOG,
    NETANALYZER,
    NETANALYZER_TRANSPARENT,
    IPOIB,
    MPEG_2_TS,
    NG40,
    NFC_LLCP,
    PFSYNC,
    INFINIBAND,
    SCTP,
    USBPCAP,
    RTAC_SERIAL,
    BLUETOOTH_LE_LL,
    WIRESHARK_UPPER_PDU,
    NETLINK,
    BLUETOOTH_LINUX_MONITOR,
    BLUETOOTH_BREDR_BB,
    BLUETOOTH_LE_LL_WITH_PHDR,
    PROFIBUS_DL,
    PKTAP,
    EPON,
    IPMI_HPM_2,
    ZWAVE_R1_R2,
    ZWAVE_R3,
    WATTSTOPPER_DLM,
    ISO_14443,
    RDS,
    USB_DARWIN,
    OPENFLOW,
    SDLC,
    TI_LLN_SNIFFER,
    LORATAP,
    VSOCK,
    NORDIC_BLE,
    DOCSIS31_XRA31,
    ETHERNET_MPACKET,
    DISPLAYPORT_AUX,
    LINUX_SLL2,
    SERCOS_MONITOR,
    OPENVIZSLA,
    EBHSCR,
    VPP_DISPATCH,
    DSA_TAG_BRCM,
    DSA_TAG_BRCM_PREPEND,
    IEEE802_15_4_TAP,
    DSA_TAG_DSA,
    DSA_TAG_EDSA,
    ELEE,
    Z_WAVE_SERIAL,
    USB_2_0,
    ATSC_ALP,
    ETW,
    NETANALYZER_NG,
    ZBOSS_NCP,
    USB_2_0_LOW_SPEED,
    USB_2_0_FULL_SPEED,
    USB_2_0_HIGH_SPEED,
    AUERSWALD_LOG,

    Unknown(u32),
}

impl From<u32> for DataLink {
    fn from(n: u32) -> DataLink {
        match n {
            0 => DataLink::NULL,
            1 => DataLink::ETHERNET,
            2 => DataLink::EXP_ETHERNET,
            3 => DataLink::AX25,
            4 => DataLink::PRONET,
            5 => DataLink::CHAOS,
            6 => DataLink::IEEE802_5,
            7 => DataLink::ARCNET_BSD,
            8 => DataLink::SLIP,
            9 => DataLink::PPP,
            10 => DataLink::FDDI,
            50 => DataLink::PPP_HDLC,
            51 => DataLink::PPP_ETHER,
            99 => DataLink::SYMANTEC_FIREWALL,
            100 => DataLink::ATM_RFC1483,
            101 => DataLink::RAW,
            102 => DataLink::SLIP_BSDOS,
            103 => DataLink::PPP_BSDOS,
            104 => DataLink::C_HDLC,
            105 => DataLink::IEEE802_11,
            106 => DataLink::ATM_CLIP,
            107 => DataLink::FRELAY,
            108 => DataLink::LOOP,
            109 => DataLink::ENC,
            110 => DataLink::LANE8023,
            111 => DataLink::HIPPI,
            112 => DataLink::NETBSD_HDLC,
            113 => DataLink::LINUX_SLL,
            114 => DataLink::LTALK,
            115 => DataLink::ECONET,
            116 => DataLink::IPFILTER,
            117 => DataLink::PFLOG,
            118 => DataLink::CISCO_IOS,
            119 => DataLink::IEEE802_11_PRISM,
            120 => DataLink::IEEE802_11_AIRONET,
            121 => DataLink::HHDLC,
            122 => DataLink::IP_OVER_FC,
            123 => DataLink::SUNATM,
            124 => DataLink::RIO,
            125 => DataLink::PCI_EXP,
            126 => DataLink::AURORA,
            127 => DataLink::IEEE802_11_RADIOTAP,
            128 => DataLink::TZSP,
            129 => DataLink::ARCNET_LINUX,
            130 => DataLink::JUNIPER_MLPPP,
            131 => DataLink::JUNIPER_MLFR,
            132 => DataLink::JUNIPER_ES,
            133 => DataLink::JUNIPER_GGSN,
            134 => DataLink::JUNIPER_MFR,
            135 => DataLink::JUNIPER_ATM2,
            136 => DataLink::JUNIPER_SERVICES,
            137 => DataLink::JUNIPER_ATM1,
            138 => DataLink::APPLE_IP_OVER_IEEE1394,
            139 => DataLink::MTP2_WITH_PHDR,
            140 => DataLink::MTP2,
            141 => DataLink::MTP3,
            142 => DataLink::SCCP,
            143 => DataLink::DOCSIS,
            144 => DataLink::LINUX_IRDA,
            145 => DataLink::IBM_SP,
            146 => DataLink::IBM_SN,
            147 => DataLink::USER0,
            148 => DataLink::USER1,
            149 => DataLink::USER2,
            150 => DataLink::USER3,
            151 => DataLink::USER4,
            152 => DataLink::USER5,
            153 => DataLink::USER6,
            154 => DataLink::USER7,
            155 => DataLink::USER8,
            156 => DataLink::USER9,
            157 => DataLink::USER10,
            158 => DataLink::USER11,
            159 => DataLink::USER12,
            160 => DataLink::USER13,
            161 => DataLink::USER14,
            162 => DataLink::USER15,
            163 => DataLink::IEEE802_11_AVS,
            164 => DataLink::JUNIPER_MONITOR,
            165 => DataLink::BACNET_MS_TP,
            166 => DataLink::PPP_PPPD,
            167 => DataLink::JUNIPER_PPPOE,
            168 => DataLink::JUNIPER_PPPOE_ATM,
            169 => DataLink::GPRS_LLC,
            170 => DataLink::GPF_T,
            171 => DataLink::GPF_F,
            172 => DataLink::GCOM_T1E1,
            173 => DataLink::GCOM_SERIAL,
            174 => DataLink::JUNIPER_PIC_PEER,
            175 => DataLink::ERF_ETH,
            176 => DataLink::ERF_POS,
            177 => DataLink::LINUX_LAPD,
            178 => DataLink::JUNIPER_ETHER,
            179 => DataLink::JUNIPER_PPP,
            180 => DataLink::JUNIPER_FRELAY,
            181 => DataLink::JUNIPER_CHDLC,
            182 => DataLink::MFR,
            183 => DataLink::JUNIPER_VP,
            184 => DataLink::A429,
            185 => DataLink::A653_ICM,
            186 => DataLink::USB_FREEBSD,
            187 => DataLink::BLUETOOTH_HCI_H4,
            188 => DataLink::IEEE802_16_MAC_CPS,
            189 => DataLink::USB_LINUX,
            190 => DataLink::CAN20B,
            191 => DataLink::IEEE802_15_4_LINUX,
            192 => DataLink::PPI,
            193 => DataLink::IEEE802_16_MAC_CPS_RADIO,
            194 => DataLink::JUNIPER_ISM,
            195 => DataLink::IEEE802_15_4,
            196 => DataLink::SITA,
            197 => DataLink::ERF,
            198 => DataLink::RAIF1,
            199 => DataLink::IPMB_KONTRON,
            200 => DataLink::JUNIPER_ST,
            201 => DataLink::BLUETOOTH_HCI_H4_WITH_PHDR,
            202 => DataLink::AX25_KISS,
            203 => DataLink::LAPD,
            204 => DataLink::PPP_WITH_DIR,
            205 => DataLink::C_HDLC_WITH_DIR,
            206 => DataLink::FRELAY_WITH_DIR,
            207 => DataLink::LAPB_WITH_DIR,
            209 => DataLink::IPMB_LINUX,
            210 => DataLink::FLEXRAY,
            211 => DataLink::MOST,
            212 => DataLink::LIN,
            213 => DataLink::X2E_SERIAL,
            214 => DataLink::X2E_XORAYA,
            215 => DataLink::IEEE802_15_4_NONASK_PHY,
            216 => DataLink::LINUX_EVDEV,
            217 => DataLink::GSMTAP_UM,
            218 => DataLink::GSMTAP_ABIS,
            219 => DataLink::MPLS,
            220 => DataLink::USB_LINUX_MMAPPED,
            221 => DataLink::DECT,
            222 => DataLink::AOS,
            223 => DataLink::WIHART,
            224 => DataLink::FC_2,
            225 => DataLink::FC_2_WITH_FRAME_DELIMS,
            226 => DataLink::IPNET,
            227 => DataLink::CAN_SOCKETCAN,
            228 => DataLink::IPV4,
            229 => DataLink::IPV6,
            230 => DataLink::IEEE802_15_4_NOFCS,
            231 => DataLink::DBUS,
            232 => DataLink::JUNIPER_VS,
            233 => DataLink::JUNIPER_SRX_E2E,
            234 => DataLink::JUNIPER_FIBRECHANNEL,
            235 => DataLink::DVB_CI,
            236 => DataLink::MUX27010,
            237 => DataLink::STANAG_5066_D_PDU,
            238 => DataLink::JUNIPER_ATM_CEMIC,
            239 => DataLink::NFLOG,
            240 => DataLink::NETANALYZER,
            241 => DataLink::NETANALYZER_TRANSPARENT,
            242 => DataLink::IPOIB,
            243 => DataLink::MPEG_2_TS,
            244 => DataLink::NG40,
            245 => DataLink::NFC_LLCP,
            246 => DataLink::PFSYNC,
            247 => DataLink::INFINIBAND,
            248 => DataLink::SCTP,
            249 => DataLink::USBPCAP,
            250 => DataLink::RTAC_SERIAL,
            251 => DataLink::BLUETOOTH_LE_LL,
            252 => DataLink::WIRESHARK_UPPER_PDU,
            253 => DataLink::NETLINK,
            254 => DataLink::BLUETOOTH_LINUX_MONITOR,
            255 => DataLink::BLUETOOTH_BREDR_BB,
            256 => DataLink::BLUETOOTH_LE_LL_WITH_PHDR,
            257 => DataLink::PROFIBUS_DL,
            258 => DataLink::PKTAP,
            259 => DataLink::EPON,
            260 => DataLink::IPMI_HPM_2,
            261 => DataLink::ZWAVE_R1_R2,
            262 => DataLink::ZWAVE_R3,
            263 => DataLink::WATTSTOPPER_DLM,
            264 => DataLink::ISO_14443,
            265 => DataLink::RDS,
            266 => DataLink::USB_DARWIN,
            267 => DataLink::OPENFLOW,
            268 => DataLink::SDLC,
            269 => DataLink::TI_LLN_SNIFFER,
            270 => DataLink::LORATAP,
            271 => DataLink::VSOCK,
            272 => DataLink::NORDIC_BLE,
            273 => DataLink::DOCSIS31_XRA31,
            274 => DataLink::ETHERNET_MPACKET,
            275 => DataLink::DISPLAYPORT_AUX,
            276 => DataLink::LINUX_SLL2,
            277 => DataLink::SERCOS_MONITOR,
            278 => DataLink::OPENVIZSLA,
            279 => DataLink::EBHSCR,
            280 => DataLink::VPP_DISPATCH,
            281 => DataLink::DSA_TAG_BRCM,
            282 => DataLink::DSA_TAG_BRCM_PREPEND,
            283 => DataLink::IEEE802_15_4_TAP,
            284 => DataLink::DSA_TAG_DSA,
            285 => DataLink::DSA_TAG_EDSA,
            286 => DataLink::ELEE,
            287 => DataLink::Z_WAVE_SERIAL,
            288 => DataLink::USB_2_0,
            289 => DataLink::ATSC_ALP,
            290 => DataLink::ETW,
            291 => DataLink::NETANALYZER_NG,
            292 => DataLink::ZBOSS_NCP,
            293 => DataLink::USB_2_0_LOW_SPEED,
            294 => DataLink::USB_2_0_FULL_SPEED,
            295 => DataLink::USB_2_0_HIGH_SPEED,
            296 => DataLink::AUERSWALD_LOG,

            _ => DataLink::Unknown(n),
        }
    }
}

impl From<DataLink> for u32 {
    fn from(link: DataLink) -> u32 {
        match link {
            DataLink::NULL => 0,
            DataLink::ETHERNET => 1,
            DataLink::EXP_ETHERNET => 2,
            DataLink::AX25 => 3,
            DataLink::PRONET => 4,
            DataLink::CHAOS => 5,
            DataLink::IEEE802_5 => 6,
            DataLink::ARCNET_BSD => 7,
            DataLink::SLIP => 8,
            DataLink::PPP => 9,
            DataLink::FDDI => 10,
            DataLink::PPP_HDLC => 50,
            DataLink::PPP_ETHER => 51,
            DataLink::SYMANTEC_FIREWALL => 99,
            DataLink::ATM_RFC1483 => 100,
            DataLink::RAW => 101,
            DataLink::SLIP_BSDOS => 102,
            DataLink::PPP_BSDOS => 103,
            DataLink::MATCHING_MIN => 104,
            DataLink::C_HDLC => 104,
            DataLink::IEEE802_11 => 105,
            DataLink::ATM_CLIP => 106,
            DataLink::FRELAY => 107,
            DataLink::LOOP => 108,
            DataLink::ENC => 109,
            DataLink::LANE8023 => 110,
            DataLink::HIPPI => 111,
            DataLink::NETBSD_HDLC => 112,
            DataLink::LINUX_SLL => 113,
            DataLink::LTALK => 114,
            DataLink::ECONET => 115,
            DataLink::IPFILTER => 116,
            DataLink::PFLOG => 117,
            DataLink::CISCO_IOS => 118,
            DataLink::IEEE802_11_PRISM => 119,
            DataLink::IEEE802_11_AIRONET => 120,
            DataLink::HHDLC => 121,
            DataLink::IP_OVER_FC => 122,
            DataLink::SUNATM => 123,
            DataLink::RIO => 124,
            DataLink::PCI_EXP => 125,
            DataLink::AURORA => 126,
            DataLink::IEEE802_11_RADIOTAP => 127,
            DataLink::TZSP => 128,
            DataLink::ARCNET_LINUX => 129,
            DataLink::JUNIPER_MLPPP => 130,
            DataLink::JUNIPER_MLFR => 131,
            DataLink::JUNIPER_ES => 132,
            DataLink::JUNIPER_GGSN => 133,
            DataLink::JUNIPER_MFR => 134,
            DataLink::JUNIPER_ATM2 => 135,
            DataLink::JUNIPER_SERVICES => 136,
            DataLink::JUNIPER_ATM1 => 137,
            DataLink::APPLE_IP_OVER_IEEE1394 => 138,
            DataLink::MTP2_WITH_PHDR => 139,
            DataLink::MTP2 => 140,
            DataLink::MTP3 => 141,
            DataLink::SCCP => 142,
            DataLink::DOCSIS => 143,
            DataLink::LINUX_IRDA => 144,
            DataLink::IBM_SP => 145,
            DataLink::IBM_SN => 146,
            DataLink::USER0 => 147,
            DataLink::USER1 => 148,
            DataLink::USER2 => 149,
            DataLink::USER3 => 150,
            DataLink::USER4 => 151,
            DataLink::USER5 => 152,
            DataLink::USER6 => 153,
            DataLink::USER7 => 154,
            DataLink::USER8 => 155,
            DataLink::USER9 => 156,
            DataLink::USER10 => 157,
            DataLink::USER11 => 158,
            DataLink::USER12 => 159,
            DataLink::USER13 => 160,
            DataLink::USER14 => 161,
            DataLink::USER15 => 162,
            DataLink::IEEE802_11_AVS => 163,
            DataLink::JUNIPER_MONITOR => 164,
            DataLink::BACNET_MS_TP => 165,
            DataLink::PPP_PPPD => 166,
            DataLink::JUNIPER_PPPOE => 167,
            DataLink::JUNIPER_PPPOE_ATM => 168,
            DataLink::GPRS_LLC => 169,
            DataLink::GPF_T => 170,
            DataLink::GPF_F => 171,
            DataLink::GCOM_T1E1 => 172,
            DataLink::GCOM_SERIAL => 173,
            DataLink::JUNIPER_PIC_PEER => 174,
            DataLink::ERF_ETH => 175,
            DataLink::ERF_POS => 176,
            DataLink::LINUX_LAPD => 177,
            DataLink::JUNIPER_ETHER => 178,
            DataLink::JUNIPER_PPP => 179,
            DataLink::JUNIPER_FRELAY => 180,
            DataLink::JUNIPER_CHDLC => 181,
            DataLink::MFR => 182,
            DataLink::JUNIPER_VP => 183,
            DataLink::A429 => 184,
            DataLink::A653_ICM => 185,
            DataLink::USB_FREEBSD => 186,
            DataLink::BLUETOOTH_HCI_H4 => 187,
            DataLink::IEEE802_16_MAC_CPS => 188,
            DataLink::USB_LINUX => 189,
            DataLink::CAN20B => 190,
            DataLink::IEEE802_15_4_LINUX => 191,
            DataLink::PPI => 192,
            DataLink::IEEE802_16_MAC_CPS_RADIO => 193,
            DataLink::JUNIPER_ISM => 194,
            DataLink::IEEE802_15_4 => 195,
            DataLink::SITA => 196,
            DataLink::ERF => 197,
            DataLink::RAIF1 => 198,
            DataLink::IPMB_KONTRON => 199,
            DataLink::JUNIPER_ST => 200,
            DataLink::BLUETOOTH_HCI_H4_WITH_PHDR => 201,
            DataLink::AX25_KISS => 202,
            DataLink::LAPD => 203,
            DataLink::PPP_WITH_DIR => 204,
            DataLink::C_HDLC_WITH_DIR => 205,
            DataLink::FRELAY_WITH_DIR => 206,
            DataLink::LAPB_WITH_DIR => 207,
            DataLink::IPMB_LINUX => 209,
            DataLink::FLEXRAY => 210,
            DataLink::MOST => 211,
            DataLink::LIN => 212,
            DataLink::X2E_SERIAL => 213,
            DataLink::X2E_XORAYA => 214,
            DataLink::IEEE802_15_4_NONASK_PHY => 215,
            DataLink::LINUX_EVDEV => 216,
            DataLink::GSMTAP_UM => 217,
            DataLink::GSMTAP_ABIS => 218,
            DataLink::MPLS => 219,
            DataLink::USB_LINUX_MMAPPED => 220,
            DataLink::DECT => 221,
            DataLink::AOS => 222,
            DataLink::WIHART => 223,
            DataLink::FC_2 => 224,
            DataLink::FC_2_WITH_FRAME_DELIMS => 225,
            DataLink::IPNET => 226,
            DataLink::CAN_SOCKETCAN => 227,
            DataLink::IPV4 => 228,
            DataLink::IPV6 => 229,
            DataLink::IEEE802_15_4_NOFCS => 230,
            DataLink::DBUS => 231,
            DataLink::JUNIPER_VS => 232,
            DataLink::JUNIPER_SRX_E2E => 233,
            DataLink::JUNIPER_FIBRECHANNEL => 234,
            DataLink::DVB_CI => 235,
            DataLink::MUX27010 => 236,
            DataLink::STANAG_5066_D_PDU => 237,
            DataLink::JUNIPER_ATM_CEMIC => 238,
            DataLink::NFLOG => 239,
            DataLink::NETANALYZER => 240,
            DataLink::NETANALYZER_TRANSPARENT => 241,
            DataLink::IPOIB => 242,
            DataLink::MPEG_2_TS => 243,
            DataLink::NG40 => 244,
            DataLink::NFC_LLCP => 245,
            DataLink::PFSYNC => 246,
            DataLink::INFINIBAND => 247,
            DataLink::SCTP => 248,
            DataLink::USBPCAP => 249,
            DataLink::RTAC_SERIAL => 250,
            DataLink::BLUETOOTH_LE_LL => 251,
            DataLink::WIRESHARK_UPPER_PDU => 252,
            DataLink::NETLINK => 253,
            DataLink::BLUETOOTH_LINUX_MONITOR => 254,
            DataLink::BLUETOOTH_BREDR_BB => 255,
            DataLink::BLUETOOTH_LE_LL_WITH_PHDR => 256,
            DataLink::PROFIBUS_DL => 257,
            DataLink::PKTAP => 258,
            DataLink::EPON => 259,
            DataLink::IPMI_HPM_2 => 260,
            DataLink::ZWAVE_R1_R2 => 261,
            DataLink::ZWAVE_R3 => 262,
            DataLink::WATTSTOPPER_DLM => 263,
            DataLink::ISO_14443 => 264,
            DataLink::RDS => 265,
            DataLink::USB_DARWIN => 266,
            DataLink::OPENFLOW => 267,
            DataLink::SDLC => 268,
            DataLink::TI_LLN_SNIFFER => 269,
            DataLink::LORATAP => 270,
            DataLink::VSOCK => 271,
            DataLink::NORDIC_BLE => 272,
            DataLink::DOCSIS31_XRA31 => 273,
            DataLink::ETHERNET_MPACKET => 274,
            DataLink::DISPLAYPORT_AUX => 275,
            DataLink::LINUX_SLL2 => 276,
            DataLink::SERCOS_MONITOR => 277,
            DataLink::OPENVIZSLA => 278,
            DataLink::EBHSCR => 279,
            DataLink::VPP_DISPATCH => 280,
            DataLink::DSA_TAG_BRCM => 281,
            DataLink::DSA_TAG_BRCM_PREPEND => 282,
            DataLink::IEEE802_15_4_TAP => 283,
            DataLink::DSA_TAG_DSA => 284,
            DataLink::DSA_TAG_EDSA => 285,
            DataLink::ELEE => 286,
            DataLink::Z_WAVE_SERIAL => 287,
            DataLink::USB_2_0 => 288,
            DataLink::ATSC_ALP => 289,
            DataLink::ETW => 290,
            DataLink::NETANALYZER_NG => 291,
            DataLink::ZBOSS_NCP => 292,
            DataLink::USB_2_0_LOW_SPEED => 293,
            DataLink::USB_2_0_FULL_SPEED => 294,
            DataLink::USB_2_0_HIGH_SPEED => 295,
            DataLink::AUERSWALD_LOG => 296,

            DataLink::Unknown(n) => n,
        }
    }
}
