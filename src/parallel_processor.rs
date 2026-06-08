use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use crossbeam_channel::bounded;
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

enum ProcessingMessage {
    PrefixAsn {
        prefix: String,
        asns: Vec<u32>,
    },
    AsLink {
        from: u32,
        to: u32,
    },
    Update {
        origin_as: u32,
        update: BgpUpdate,
    },
}

pub struct ParallelProcessor {
    pub prefix_as_map: HashMap<String, Vec<u32>>,
    pub as_link_counts: HashMap<(u32, u32), u64>,
    pub all_updates: HashMap<u32, Vec<BgpUpdate>>,
}

impl ParallelProcessor {
    pub fn process_files(paths: &[PathBuf]) -> anyhow::Result<(Self, ProcessingStats)> {
        let total_records = AtomicU64::new(0);
        let bgp_updates = AtomicU64::new(0);
        let as_path_entries = AtomicU64::new(0);
        let start = Instant::now();

        let (tx, rx) = bounded::<ProcessingMessage>(65536);

        let aggregator_handle = std::thread::spawn(move || {
            let mut prefix_as_map: HashMap<String, Vec<u32>> = HashMap::new();
            let mut as_link_counts: HashMap<(u32, u32), u64> = HashMap::new();
            let mut all_updates: HashMap<u32, Vec<BgpUpdate>> = HashMap::new();

            while let Ok(msg) = rx.recv() {
                match msg {
                    ProcessingMessage::PrefixAsn { prefix, asns } => {
                        prefix_as_map
                            .entry(prefix)
                            .or_insert_with(Vec::new)
                            .extend(asns);
                    }
                    ProcessingMessage::AsLink { from, to } => {
                        *as_link_counts.entry((from, to)).or_insert(0) += 1;
                    }
                    ProcessingMessage::Update { origin_as, update } => {
                        all_updates
                            .entry(origin_as)
                            .or_insert_with(Vec::new)
                            .push(update);
                    }
                }
            }

            (prefix_as_map, as_link_counts, all_updates)
        });

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
                            let _ = tx.send(ProcessingMessage::PrefixAsn {
                                prefix: prefix.cidr(),
                                asns: flat_path.clone(),
                            });
                        }

                        for window in flat_path.windows(2) {
                            let _ = tx.send(ProcessingMessage::AsLink {
                                from: window[0],
                                to: window[1],
                            });
                        }

                        if let Some(origin) = update.origin_as {
                            let _ = tx.send(ProcessingMessage::Update {
                                origin_as: origin,
                                update,
                            });
                        }
                    }
                });
            }
        });

        drop(tx);

        let (prefix_as_map, as_link_counts, all_updates) = aggregator_handle
            .join()
            .map_err(|_| anyhow::anyhow!("Aggregator thread panicked"))?;

        let unique_prefixes = prefix_as_map.len() as u64;
        let unique_asns = all_updates.len() as u64;

        let processor = Self {
            prefix_as_map,
            as_link_counts,
            all_updates,
        };

        let stats = ProcessingStats {
            total_records: total_records.load(Ordering::Relaxed),
            bgp_updates: bgp_updates.load(Ordering::Relaxed),
            as_path_entries: as_path_entries.load(Ordering::Relaxed),
            unique_prefixes,
            unique_asns,
            elapsed_ms: start.elapsed().as_millis() as u64,
        };

        Ok((processor, stats))
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

    pub fn get_asn_degree_map(&self) -> HashMap<u32, u64> {
        let mut degree_map: HashMap<u32, u64> = HashMap::new();

        for (&(src, dst), &count) in &self.as_link_counts {
            *degree_map.entry(src).or_insert(0) += count;
            *degree_map.entry(dst).or_insert(0) += count;
        }

        degree_map
    }
}
