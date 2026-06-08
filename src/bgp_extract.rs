use byteorder::{BigEndian, ReadBytesExt};
use std::io::{Cursor, Read};
use std::net::Ipv4Addr;

use crate::mrt_parser::{Bgp4MpSubtype, MrtHeader, MrtType, TableDumpV2Subtype};

#[derive(Debug, Clone)]
pub struct BgpPrefix {
    pub prefix: String,
    pub prefix_len: u8,
}

impl BgpPrefix {
    pub fn new(prefix: String, prefix_len: u8) -> Self {
        Self { prefix, prefix_len }
    }

    pub fn cidr(&self) -> String {
        format!("{}/{}", self.prefix, self.prefix_len)
    }
}

#[derive(Debug, Clone)]
pub struct AsPathSegment {
    pub segment_type: u8,
    pub asns: Vec<u32>,
}

impl AsPathSegment {
    pub fn is_as_set(&self) -> bool {
        self.segment_type == 2
    }

    pub fn is_as_sequence(&self) -> bool {
        self.segment_type == 1
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct BgpUpdate {
    pub announced_prefixes: Vec<BgpPrefix>,
    pub withdrawn_prefixes: Vec<BgpPrefix>,
    pub as_path: Vec<AsPathSegment>,
    pub origin_as: Option<u32>,
    pub next_hop: Option<String>,
    pub source_as: Option<u32>,
    pub peer_as: Option<u32>,
    pub timestamp: u32,
}

pub struct BgpExtractor;

impl BgpExtractor {
    const BGP_MARKER: [u8; 16] = [0xFF; 16];
    const AS_PATH_ATTR: u8 = 2;
    const NEXT_HOP_ATTR: u8 = 3;
    const MP_REACH_NLRI_ATTR: u8 = 14;
    const MP_UNREACH_NLRI_ATTR: u8 = 15;

    pub fn extract_from_record(header: &MrtHeader, data: &[u8]) -> anyhow::Result<Option<BgpUpdate>> {
        match header.mrt_type {
            MrtType::TableDumpV2 => Self::extract_table_dump_v2(header, data),
            MrtType::Bgp4Mp | MrtType::Bgp4MpEt => Self::extract_bgp4mp(header, data),
            _ => Ok(None),
        }
    }

    fn extract_table_dump_v2(header: &MrtHeader, data: &[u8]) -> anyhow::Result<Option<BgpUpdate>> {
        let subtype = TableDumpV2Subtype::from(header.subtype);
        match subtype {
            TableDumpV2Subtype::RibIpv4Unicast
            | TableDumpV2Subtype::RibIpv4Multicast
            | TableDumpV2Subtype::RibIpv6Unicast
            | TableDumpV2Subtype::RibIpv6Multicast => {
                Self::parse_rib_entry(header, data, &subtype)
            }
            _ => Ok(None),
        }
    }

    fn parse_rib_entry(
        header: &MrtHeader,
        data: &[u8],
        subtype: &TableDumpV2Subtype,
    ) -> anyhow::Result<Option<BgpUpdate>> {
        let mut cursor = Cursor::new(data);

        let _sequence_number = cursor.read_u32::<BigEndian>()?;
        let prefix_len = cursor.read_u8()?;

        let is_ipv4 = matches!(
            subtype,
            TableDumpV2Subtype::RibIpv4Unicast | TableDumpV2Subtype::RibIpv4Multicast
        );

        let prefix = if is_ipv4 {
            let byte_count = ((prefix_len as usize) + 7) / 8;
            let mut prefix_bytes = [0u8; 4];
            cursor.read_exact(&mut prefix_bytes[..byte_count])?;
            let mut full_bytes = [0u8; 4];
            full_bytes[..byte_count].copy_from_slice(&prefix_bytes[..byte_count]);
            Ipv4Addr::from(full_bytes).to_string()
        } else {
            let byte_count = ((prefix_len as usize) + 7) / 8;
            let mut prefix_bytes = [0u8; 16];
            cursor.read_exact(&mut prefix_bytes[..byte_count])?;
            format!("{:?}", std::net::Ipv6Addr::from(prefix_bytes))
        };

        let entry_count = cursor.read_u16::<BigEndian>()?;

        for _ in 0..entry_count {
            let _peer_index = cursor.read_u16::<BigEndian>()?;
            let _originated_time = cursor.read_u32::<BigEndian>()?;
            let path_attr_len = cursor.read_u16::<BigEndian>()? as usize;
            let path_attr_start = cursor.position() as usize;
            let path_attr_data = &data[path_attr_start..path_attr_start + path_attr_len];

            let (as_path, next_hop, announced_v6) = Self::parse_bgp_path_attributes(path_attr_data)?;

            let mut announced = vec![BgpPrefix::new(prefix.clone(), prefix_len)];
            if let Some(v6_prefixes) = announced_v6 {
                announced = v6_prefixes;
            }

            let origin_as = Self::extract_origin_as(&as_path);

            return Ok(Some(BgpUpdate {
                announced_prefixes: announced,
                withdrawn_prefixes: Vec::new(),
                as_path,
                origin_as,
                next_hop,
                source_as: None,
                peer_as: None,
                timestamp: header.timestamp,
            }));
        }

        Ok(None)
    }

    fn extract_bgp4mp(header: &MrtHeader, data: &[u8]) -> anyhow::Result<Option<BgpUpdate>> {
        let subtype = Bgp4MpSubtype::from(header.subtype);

        let is_update = matches!(
            subtype,
            Bgp4MpSubtype::Message
                | Bgp4MpSubtype::MessageAs4
                | Bgp4MpSubtype::MessageLocal
                | Bgp4MpSubtype::MessageLocalAs4
        );

        if !is_update {
            return Ok(None);
        }

        let is_as4 = matches!(
            subtype,
            Bgp4MpSubtype::MessageAs4 | Bgp4MpSubtype::MessageLocalAs4
        );

        let mut cursor = Cursor::new(data);

        let peer_as = if is_as4 {
            cursor.read_u32::<BigEndian>()?
        } else {
            cursor.read_u16::<BigEndian>()? as u32
        };

        let local_as = if is_as4 {
            cursor.read_u32::<BigEndian>()?
        } else {
            cursor.read_u16::<BigEndian>()? as u32
        };

        let _iface_len = cursor.read_u16::<BigEndian>()? as usize;
        let afi = cursor.read_u16::<BigEndian>()?;

        let _peer_ip = if afi == 2 {
            let mut buf = [0u8; 16];
            cursor.read_exact(&mut buf)?;
            format!("{:?}", std::net::Ipv6Addr::from(buf))
        } else {
            let mut buf = [0u8; 4];
            cursor.read_exact(&mut buf)?;
            Ipv4Addr::from(buf).to_string()
        };

        let bgp_msg_start = cursor.position() as usize;
        let bgp_msg_data = &data[bgp_msg_start..];

        Self::parse_bgp_update_message(bgp_msg_data, header.timestamp, Some(peer_as), Some(local_as))
    }

    fn parse_bgp_update_message(
        data: &[u8],
        timestamp: u32,
        peer_as: Option<u32>,
        local_as: Option<u32>,
    ) -> anyhow::Result<Option<BgpUpdate>> {
        if data.len() < 19 {
            return Ok(None);
        }

        let mut cursor = Cursor::new(data);

        let mut marker = [0u8; 16];
        cursor.read_exact(&mut marker)?;
        if marker != Self::BGP_MARKER {
            return Ok(None);
        }

        let _msg_len = cursor.read_u16::<BigEndian>()?;
        let msg_type = cursor.read_u8()?;

        if msg_type != 2 {
            return Ok(None);
        }

        let withdrawn_len = cursor.read_u16::<BigEndian>()? as usize;
        let withdrawn_data_start = cursor.position() as usize;
        let withdrawn_prefixes = Self::parse_prefix_list(&data[withdrawn_data_start..withdrawn_data_start + withdrawn_len], true)?;
        cursor.set_position((withdrawn_data_start + withdrawn_len) as u64);

        let path_attr_len = cursor.read_u16::<BigEndian>()? as usize;
        let path_attr_start = cursor.position() as usize;
        let path_attr_data = &data[path_attr_start..path_attr_start + path_attr_len];

        let (as_path, next_hop, mp_reach_prefixes) = Self::parse_bgp_path_attributes(path_attr_data)?;

        let mp_unreach_prefixes = Self::extract_mp_unreach_prefixes(path_attr_data)?;

        let mut announced_prefixes = Self::parse_nlri_prefixes(
            &data[path_attr_start + path_attr_len..],
            true,
        )?;
        if let Some(v6_prefixes) = mp_reach_prefixes {
            announced_prefixes = v6_prefixes;
        }

        let mut withdrawn = withdrawn_prefixes;
        withdrawn.extend(mp_unreach_prefixes);

        let origin_as = Self::extract_origin_as(&as_path);

        Ok(Some(BgpUpdate {
            announced_prefixes,
            withdrawn_prefixes: withdrawn,
            as_path,
            origin_as,
            next_hop,
            source_as: local_as,
            peer_as,
            timestamp,
        }))
    }

    fn parse_bgp_path_attributes(
        data: &[u8],
    ) -> anyhow::Result<(Vec<AsPathSegment>, Option<String>, Option<Vec<BgpPrefix>>)> {
        let mut cursor = Cursor::new(data);
        let mut as_path = Vec::new();
        let mut next_hop = None;
        let mut mp_reach = None;
        let data_len = data.len() as u64;

        while cursor.position() < data_len {
            let flags = match cursor.read_u8() {
                Ok(b) => b,
                Err(_) => break,
            };
            let attr_type = match cursor.read_u8() {
                Ok(b) => b,
                Err(_) => break,
            };

            let extended_len = (flags & 0x10) != 0;
            let attr_len = if extended_len {
                cursor.read_u16::<BigEndian>()? as usize
            } else {
                cursor.read_u8()? as usize
            };

            let attr_start = cursor.position() as usize;
            let attr_data = if attr_start + attr_len <= data.len() {
                &data[attr_start..attr_start + attr_len]
            } else {
                break;
            };

            match attr_type {
                Self::AS_PATH_ATTR => {
                    as_path = Self::parse_as_path(attr_data)?;
                }
                Self::NEXT_HOP_ATTR => {
                    if attr_len >= 4 {
                        let nh = Ipv4Addr::new(
                            attr_data[0],
                            attr_data[1],
                            attr_data[2],
                            attr_data[3],
                        );
                        next_hop = Some(nh.to_string());
                    }
                }
                Self::MP_REACH_NLRI_ATTR => {
                    mp_reach = Self::parse_mp_reach_nlri(attr_data);
                }
                _ => {}
            }

            cursor.set_position((attr_start + attr_len) as u64);
        }

        Ok((as_path, next_hop, mp_reach))
    }

    fn parse_as_path(data: &[u8]) -> anyhow::Result<Vec<AsPathSegment>> {
        let mut cursor = Cursor::new(data);
        let mut segments = Vec::new();

        while cursor.position() < data.len() as u64 {
            let segment_type = cursor.read_u8()?;
            let asn_count = cursor.read_u8()?;

            let mut asns = Vec::with_capacity(asn_count as usize);
            let bytes_per_asn = if data.len() > 2 && (segment_type == 1 || segment_type == 2) {
                let remaining = data.len() - cursor.position() as usize;
                if remaining >= asn_count as usize * 4 {
                    4
                } else {
                    2
                }
            } else {
                2
            };

            for _ in 0..asn_count {
                if bytes_per_asn == 4 {
                    asns.push(cursor.read_u32::<BigEndian>()?);
                } else {
                    asns.push(cursor.read_u16::<BigEndian>()? as u32);
                }
            }

            segments.push(AsPathSegment {
                segment_type,
                asns,
            });
        }

        Ok(segments)
    }

    fn extract_origin_as(as_path: &[AsPathSegment]) -> Option<u32> {
        as_path.iter().rev().find_map(|seg| {
            if seg.is_as_sequence() && !seg.asns.is_empty() {
                Some(*seg.asns.last().unwrap())
            } else {
                None
            }
        })
    }

    pub fn flatten_as_path(as_path: &[AsPathSegment]) -> Vec<u32> {
        let mut result = Vec::new();
        for seg in as_path {
            if seg.is_as_sequence() {
                result.extend_from_slice(&seg.asns);
            } else if seg.is_as_set() {
                if let Some(&first) = seg.asns.first() {
                    result.push(first);
                }
            }
        }
        result
    }

    fn parse_prefix_list(data: &[u8], is_ipv4: bool) -> anyhow::Result<Vec<BgpPrefix>> {
        let mut prefixes = Vec::new();
        let mut cursor = Cursor::new(data);

        while cursor.position() < data.len() as u64 {
            let prefix_len = cursor.read_u8()?;
            let byte_count = ((prefix_len as usize) + 7) / 8;

            if is_ipv4 {
                let mut bytes = [0u8; 4];
                if byte_count > 0 {
                    cursor.read_exact(&mut bytes[..byte_count])?;
                }
                let mut full = [0u8; 4];
                full[..byte_count].copy_from_slice(&bytes[..byte_count]);
                prefixes.push(BgpPrefix::new(Ipv4Addr::from(full).to_string(), prefix_len));
            } else {
                let mut bytes = [0u8; 16];
                if byte_count > 0 {
                    cursor.read_exact(&mut bytes[..byte_count])?;
                }
                let mut full = [0u8; 16];
                full[..byte_count].copy_from_slice(&bytes[..byte_count]);
                prefixes.push(BgpPrefix::new(
                    format!("{:?}", std::net::Ipv6Addr::from(full)),
                    prefix_len,
                ));
            }
        }

        Ok(prefixes)
    }

    fn parse_nlri_prefixes(data: &[u8], is_ipv4: bool) -> anyhow::Result<Vec<BgpPrefix>> {
        Self::parse_prefix_list(data, is_ipv4)
    }

    fn parse_mp_reach_nlri(data: &[u8]) -> Option<Vec<BgpPrefix>> {
        if data.len() < 5 {
            return None;
        }

        let afi = u16::from_be_bytes([data[0], data[1]]);
        let _safi = data[2];
        let next_hop_len = data[3] as usize;

        let nlri_start = 4 + next_hop_len;
        if nlri_start >= data.len() {
            return None;
        }

        let is_ipv4 = afi == 1;
        let nlri_data = &data[nlri_start..];

        Self::parse_prefix_list(nlri_data, is_ipv4).ok()
    }

    fn extract_mp_unreach_prefixes(data: &[u8]) -> anyhow::Result<Vec<BgpPrefix>> {
        let mut cursor = Cursor::new(data);
        let mut prefixes = Vec::new();
        let data_len = data.len() as u64;

        while cursor.position() < data_len {
            let flags = match cursor.read_u8() {
                Ok(b) => b,
                Err(_) => break,
            };
            let attr_type = match cursor.read_u8() {
                Ok(b) => b,
                Err(_) => break,
            };

            let extended_len = (flags & 0x10) != 0;
            let attr_len = if extended_len {
                cursor.read_u16::<BigEndian>()? as usize
            } else {
                cursor.read_u8()? as usize
            };

            let attr_start = cursor.position() as usize;

            if attr_type == Self::MP_UNREACH_NLRI_ATTR && attr_len >= 3 {
                let attr_data = &data[attr_start..attr_start + attr_len];
                let afi = u16::from_be_bytes([attr_data[0], attr_data[1]]);
                let _safi = attr_data[2];
                let is_ipv4 = afi == 1;
                let nlri_data = &attr_data[3..];
                if let Ok(pfxs) = Self::parse_prefix_list(nlri_data, is_ipv4) {
                    prefixes = pfxs;
                }
            }

            cursor.set_position((attr_start + attr_len) as u64);
        }

        Ok(prefixes)
    }
}
