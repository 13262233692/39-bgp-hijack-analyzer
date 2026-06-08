use byteorder::{BigEndian, ReadBytesExt};
use std::io::{Cursor, Read};

pub const MRT_HEADER_LEN: usize = 12;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum MrtType {
    TableDumpV2 = 13,
    Bgp4Mp = 16,
    Bgp4MpEt = 17,
    Unknown(u16),
}

impl From<u16> for MrtType {
    fn from(v: u16) -> Self {
        match v {
            13 => MrtType::TableDumpV2,
            16 => MrtType::Bgp4Mp,
            17 => MrtType::Bgp4MpEt,
            _ => MrtType::Unknown(v),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum TableDumpV2Subtype {
    PeerIndexTable = 1,
    RibIpv4Unicast = 2,
    RibIpv4Multicast = 3,
    RibIpv6Unicast = 4,
    RibIpv6Multicast = 5,
    RibGeneric = 6,
    Unknown(u16),
}

impl From<u16> for TableDumpV2Subtype {
    fn from(v: u16) -> Self {
        match v {
            1 => TableDumpV2Subtype::PeerIndexTable,
            2 => TableDumpV2Subtype::RibIpv4Unicast,
            3 => TableDumpV2Subtype::RibIpv4Multicast,
            4 => TableDumpV2Subtype::RibIpv6Unicast,
            5 => TableDumpV2Subtype::RibIpv6Multicast,
            6 => TableDumpV2Subtype::RibGeneric,
            _ => TableDumpV2Subtype::Unknown(v),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum Bgp4MpSubtype {
    StateChange = 0,
    StateChangeAs4 = 1,
    Message = 2,
    MessageAs4 = 4,
    MessageLocal = 3,
    MessageLocalAs4 = 5,
    Unknown(u16),
}

impl From<u16> for Bgp4MpSubtype {
    fn from(v: u16) -> Self {
        match v {
            0 => Bgp4MpSubtype::StateChange,
            1 => Bgp4MpSubtype::StateChangeAs4,
            2 => Bgp4MpSubtype::Message,
            3 => Bgp4MpSubtype::MessageLocal,
            4 => Bgp4MpSubtype::MessageAs4,
            5 => Bgp4MpSubtype::MessageLocalAs4,
            _ => Bgp4MpSubtype::Unknown(v),
        }
    }
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct MrtHeader {
    pub timestamp: u32,
    pub microsecond_timestamp: Option<u32>,
    pub mrt_type: MrtType,
    pub subtype: u16,
    pub length: u32,
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct MrtRecord {
    pub header: MrtHeader,
    pub data: Vec<u8>,
}

pub struct MrtParser;

impl MrtParser {
    pub fn parse_header(cursor: &mut Cursor<&[u8]>) -> anyhow::Result<MrtHeader> {
        let timestamp = cursor.read_u32::<BigEndian>()?;
        let mrt_type_raw = cursor.read_u16::<BigEndian>()?;
        let subtype = cursor.read_u16::<BigEndian>()?;
        let length = cursor.read_u32::<BigEndian>()?;

        let mrt_type = MrtType::from(mrt_type_raw);

        Ok(MrtHeader {
            timestamp,
            microsecond_timestamp: None,
            mrt_type,
            subtype,
            length,
        })
    }

    #[allow(dead_code)]
    pub fn parse_records(data: &[u8]) -> anyhow::Result<Vec<MrtRecord>> {
        let mut cursor = Cursor::new(data);
        let mut records = Vec::new();
        let data_len = data.len() as u64;

        while cursor.position() + MRT_HEADER_LEN as u64 <= data_len {
            let header = match Self::parse_header(&mut cursor) {
                Ok(h) => h,
                Err(_) => break,
            };

            let record_data_len = header.length as usize;
            if cursor.position() + record_data_len as u64 > data_len {
                break;
            }

            let mut record_data = vec![0u8; record_data_len];
            cursor.read_exact(&mut record_data)?;

            records.push(MrtRecord {
                header,
                data: record_data,
            });
        }

        Ok(records)
    }

    pub fn stream_records<F>(data: &[u8], mut callback: F) -> anyhow::Result<u64>
    where
        F: FnMut(&MrtHeader, &[u8]),
    {
        let mut cursor = Cursor::new(data);
        let data_len = data.len() as u64;
        let mut count = 0u64;

        while cursor.position() + MRT_HEADER_LEN as u64 <= data_len {
            let header = match Self::parse_header(&mut cursor) {
                Ok(h) => h,
                Err(_) => break,
            };

            let record_data_len = header.length as usize;
            if cursor.position() + record_data_len as u64 > data_len {
                break;
            }

            let start = cursor.position() as usize;
            callback(&header, &data[start..start + record_data_len]);
            cursor.set_position((start + record_data_len) as u64);
            count += 1;
        }

        Ok(count)
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct PeerEntry {
    pub peer_bgp_id: u32,
    pub peer_as: u32,
    pub peer_ip: std::net::IpAddr,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct PeerIndexTable {
    pub collector_bgp_id: u32,
    pub view_name: String,
    pub peers: Vec<PeerEntry>,
}

impl PeerIndexTable {
    #[allow(dead_code)]
    pub fn parse(data: &[u8]) -> anyhow::Result<Self> {
        let mut cursor = Cursor::new(data);
        let collector_bgp_id = cursor.read_u32::<BigEndian>()?;
        let view_name_len = cursor.read_u16::<BigEndian>()? as usize;
        let mut view_name_buf = vec![0u8; view_name_len];
        cursor.read_exact(&mut view_name_buf)?;
        let view_name = String::from_utf8_lossy(&view_name_buf).to_string();

        let peer_count = cursor.read_u16::<BigEndian>()? as usize;
        let mut peers = Vec::with_capacity(peer_count);

        for _ in 0..peer_count {
            let peer_type = cursor.read_u8()?;
            let afi = (peer_type >> 0) & 1;
            let _as4 = (peer_type >> 1) & 1;

            let peer_bgp_id = cursor.read_u32::<BigEndian>()?;

            let peer_ip = if afi == 1 {
                let mut ip_buf = [0u8; 16];
                cursor.read_exact(&mut ip_buf)?;
                std::net::IpAddr::from(ip_buf)
            } else {
                let mut ip_buf = [0u8; 4];
                cursor.read_exact(&mut ip_buf)?;
                std::net::IpAddr::from(ip_buf)
            };

            let peer_as = if _as4 == 1 {
                cursor.read_u32::<BigEndian>()?
            } else {
                cursor.read_u16::<BigEndian>()? as u32
            };

            peers.push(PeerEntry {
                peer_bgp_id,
                peer_as,
                peer_ip,
            });
        }

        Ok(PeerIndexTable {
            collector_bgp_id,
            view_name,
            peers,
        })
    }
}
