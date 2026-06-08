use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use dashmap::DashMap;
use rayon::prelude::*;

use crate::bgp_extract::{BgpExtractor, BgpUpdate};
use crate::mrt_parser::MrtParser;

pub struct ProcessingStats {
    pub total_records: u64,
    pub bgp_updates: u64,
    pub as_path_entries: u64,
    pub unique_prefixes: u64,
    pub unique_asns: u64,
    pub elapsed_ms: u64,
}

pub struct ParallelProcessor {
    pub prefix_as_map: DashMap<String, Vec<u32>>,
    pub as_link_counts: DashMap<(u32, u32), u64>,
    pub all_updates: DashMap<u32, Vec<BgpUpdate>>,
}

impl ParallelProcessor {
    pub fn new() -> Self {
        Self {
            prefix_as_map: DashMap::new(),
            as_link_counts: DashMap::new(),
            all_updates: DashMap::new(),
        }
    }

    pub fn process_files(&self, paths: &[PathBuf]) -> anyhow::Result<ProcessingStats> {
        let total_records = AtomicU64::new(0);
        let bgp_updates = AtomicU64::new(0);
        let as_path_entries = AtomicU64::new(0);
        let start = Instant::now();

        paths.par_iter().for_each(|path| {
            if let Ok(data) = Self::read_mrt_file(path) {
                let _ = MrtParser::stream_records(&data, |header, record_data| {
                    total_records.fetch_add(1, Ordering::Relaxed);

                    if let Ok(Some(update)) = BgpExtractor::extract_from_record(header, record_data) {
                        bgp_updates.fetch_add(1, Ordering::Relaxed);

                        let flat_path = BgpExtractor::flatten_as_path(&update.as_path);
                        if !flat_path.is_empty() {
                            as_path_entries.fetch_add(1, Ordering::Relaxed);
                        }

                        for prefix in &update.announced_prefixes {
                            let key = prefix.cidr();
                            self.prefix_as_map
                                .entry(key)
                                .or_insert_with(Vec::new)
                                .value_mut()
                                .extend_from_slice(&flat_path);
                        }

                        for window in flat_path.windows(2) {
                            let link = (window[0], window[1]);
                            *self
                                .as_link_counts
                                .entry(link)
                                .or_insert(0)
                                .value_mut() += 1;
                        }

                        if let Some(origin) = update.origin_as {
                            self.all_updates
                                .entry(origin)
                                .or_insert_with(Vec::new)
                                .value_mut()
                                .push(update);
                        }
                    }
                });
            }
        });

        let unique_prefixes = self.prefix_as_map.len() as u64;
        let unique_asns = self.all_updates.len() as u64;

        Ok(ProcessingStats {
            total_records: total_records.load(Ordering::Relaxed),
            bgp_updates: bgp_updates.load(Ordering::Relaxed),
            as_path_entries: as_path_entries.load(Ordering::Relaxed),
            unique_prefixes,
            unique_asns,
            elapsed_ms: start.elapsed().as_millis() as u64,
        })
    }

    fn read_mrt_file(path: &Path) -> anyhow::Result<Vec<u8>> {
        let raw = std::fs::read(path)?;

        if raw.len() >= 2 {
            let b0 = raw[0];
            let b1 = raw[1];

            if b0 == 0x1F && b1 == 0x8B {
                return Self::decompress_gzip(&raw);
            }

            if b0 == 0x42 && b1 == 0x5A {
                return Self::decompress_bz2(&raw);
            }
        }

        Ok(raw)
    }

    fn decompress_gzip(data: &[u8]) -> anyhow::Result<Vec<u8>> {
        use flate2::read::GzDecoder;
        use std::io::Read;

        let mut decoder = GzDecoder::new(data);
        let mut decompressed = Vec::with_capacity(data.len() * 4);
        decoder.read_to_end(&mut decompressed)?;
        Ok(decompressed)
    }

    fn decompress_bz2(data: &[u8]) -> anyhow::Result<Vec<u8>> {
        use bzip2::read::BzDecoder;
        use std::io::Read;

        let mut decoder = BzDecoder::new(data);
        let mut decompressed = Vec::with_capacity(data.len() * 4);
        decoder.read_to_end(&mut decompressed)?;
        Ok(decompressed)
    }

    pub fn get_asn_degree_map(&self) -> DashMap<u32, u64> {
        let degree_map: DashMap<u32, u64> = DashMap::new();

        for entry in self.as_link_counts.iter() {
            let (src, dst) = entry.key();
            let count = entry.value();
            *degree_map.entry(*src).or_insert(0).value_mut() += count;
            *degree_map.entry(*dst).or_insert(0).value_mut() += count;
        }

        degree_map
    }
}
