use std::collections::HashMap;

use crate::parallel_processor::ParallelProcessor;
use crate::topology::AsTopology;

#[derive(Debug, Clone)]
pub struct HijackAlert {
    pub prefix: String,
    pub origin_as: u32,
    pub hijack_as: u32,
    pub alert_type: AlertType,
    pub confidence: f64,
    pub evidence: String,
}

#[derive(Debug, Clone, PartialEq)]
#[allow(dead_code)]
pub enum AlertType {
    PrefixHijack,
    PathManipulation,
    ZombieNode,
    AsPathLoop,
    UnknownOrigin,
}

#[derive(Debug, Clone)]
pub struct ZombieNode {
    pub asn: u32,
    pub reason: String,
    pub affected_prefixes: Vec<String>,
    pub suspicious_paths: Vec<Vec<u32>>,
}

pub struct AnomalyDetector;

impl AnomalyDetector {
    pub fn detect_hijacks(
        processor: &ParallelProcessor,
        topology: &AsTopology,
    ) -> Vec<HijackAlert> {
        let mut alerts = Vec::new();

        let prefix_owners = Self::build_prefix_ownership(processor);

        for entry in processor.prefix_as_map.iter() {
            let prefix = entry.key();
            let asns = entry.value();

            let unique_asns: Vec<u32> = {
                let mut seen = std::collections::HashSet::new();
                asns.iter().filter(|a| seen.insert(**a)).copied().collect()
            };

            if unique_asns.len() > 1 {
                if let Some(owner_asn) = prefix_owners.get(prefix) {
                    for &asn in &unique_asns {
                        if asn != *owner_asn {
                            let hub_asns: Vec<u32> = topology
                                .get_top_hubs(20)
                                .iter()
                                .map(|(a, _)| *a)
                                .collect();

                            let confidence = Self::compute_confidence(
                                asn,
                                *owner_asn,
                                &hub_asns,
                                topology,
                            );

                            let alert_type = if Self::is_zombie_asn(asn, topology) {
                                AlertType::ZombieNode
                            } else {
                                AlertType::PrefixHijack
                            };

                            alerts.push(HijackAlert {
                                prefix: prefix.clone(),
                                origin_as: *owner_asn,
                                hijack_as: asn,
                                alert_type,
                                confidence,
                                evidence: format!(
                                    "AS{} claims ownership of {} (legitimate: AS{})",
                                    asn, prefix, owner_asn
                                ),
                            });
                        }
                    }
                }
            }
        }

        let loop_alerts = Self::detect_as_path_loops(processor);
        alerts.extend(loop_alerts);

        alerts.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap_or(std::cmp::Ordering::Equal));
        alerts
    }

    fn build_prefix_ownership(processor: &ParallelProcessor) -> HashMap<String, u32> {
        let mut ownership = HashMap::new();
        let mut prefix_asn_count: HashMap<String, HashMap<u32, usize>> = HashMap::new();

        for entry in processor.prefix_as_map.iter() {
            let prefix = entry.key();
            let asns = entry.value();

            let counter = prefix_asn_count.entry(prefix.clone()).or_insert_with(HashMap::new);
            for &asn in asns.iter() {
                *counter.entry(asn).or_insert(0) += 1;
            }
        }

        for (prefix, counter) in prefix_asn_count {
            if let Some((&best_asn, _)) = counter.iter().max_by_key(|(_, &count)| count) {
                ownership.insert(prefix, best_asn);
            }
        }

        ownership
    }

    fn compute_confidence(
        suspicious_asn: u32,
        legitimate_asn: u32,
        hub_asns: &[u32],
        topology: &AsTopology,
    ) -> f64 {
        let mut confidence: f64 = 0.5;

        if !hub_asns.contains(&suspicious_asn) {
            confidence += 0.2;
        }

        if let Some(&suspicious_idx) = topology.asn_to_idx.get(&suspicious_asn) {
            let degree = topology.graph[suspicious_idx].degree;
            if degree < 5 {
                confidence += 0.2;
            } else if degree < 20 {
                confidence += 0.1;
            }
        }

        if legitimate_asn != suspicious_asn {
            confidence += 0.1;
        }

        confidence.min(1.0)
    }

    fn is_zombie_asn(asn: u32, topology: &AsTopology) -> bool {
        if let Some(&idx) = topology.asn_to_idx.get(&asn) {
            let out_degree = topology.graph.neighbors_directed(idx, petgraph::Direction::Outgoing).count();
            let in_degree = topology.graph.neighbors_directed(idx, petgraph::Direction::Incoming).count();

            if in_degree == 0 && out_degree > 0 {
                return true;
            }

            if out_degree <= 1 && in_degree == 0 {
                return true;
            }
        }
        false
    }

    fn detect_as_path_loops(processor: &ParallelProcessor) -> Vec<HijackAlert> {
        let mut alerts = Vec::new();

        for entry in processor.all_updates.iter() {
            let _asn = *entry.key();
            let updates = entry.value();

            for update in updates {
                let flat_path = crate::bgp_extract::BgpExtractor::flatten_as_path(&update.as_path);
                let mut seen = std::collections::HashSet::new();
                for &path_asn in &flat_path {
                    if seen.contains(&path_asn) {
                        for prefix in &update.announced_prefixes {
                            alerts.push(HijackAlert {
                                prefix: prefix.cidr(),
                                origin_as: path_asn,
                                hijack_as: path_asn,
                                alert_type: AlertType::AsPathLoop,
                                confidence: 0.9,
                                evidence: format!(
                                    "AS-Path loop detected: AS{} appears multiple times in path to {}",
                                    path_asn,
                                    prefix.cidr()
                                ),
                            });
                        }
                        break;
                    }
                    seen.insert(path_asn);
                }
            }
        }

        alerts
    }

    pub fn detect_zombie_nodes(
        processor: &ParallelProcessor,
        topology: &AsTopology,
    ) -> Vec<ZombieNode> {
        let mut zombies = Vec::new();

        for entry in processor.all_updates.iter() {
            let asn = *entry.key();
            if Self::is_zombie_asn(asn, topology) {
                let updates = entry.value();
                let affected_prefixes: Vec<String> = updates
                    .iter()
                    .flat_map(|u| u.announced_prefixes.iter().map(|p| p.cidr()))
                    .collect();

                let suspicious_paths: Vec<Vec<u32>> = updates
                    .iter()
                    .filter_map(|u| {
                        let flat = crate::bgp_extract::BgpExtractor::flatten_as_path(&u.as_path);
                        if flat.len() > 1 {
                            Some(flat)
                        } else {
                            None
                        }
                    })
                    .take(5)
                    .collect();

                if !affected_prefixes.is_empty() {
                    zombies.push(ZombieNode {
                        asn,
                        reason: "Low connectivity with active route announcements".to_string(),
                        affected_prefixes,
                        suspicious_paths,
                    });
                }
            }
        }

        zombies.sort_by(|a, b| b.affected_prefixes.len().cmp(&a.affected_prefixes.len()));
        zombies
    }
}
