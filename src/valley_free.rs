use std::collections::HashMap;
use std::hash::Hash;

use crate::bgp_extract::BgpExtractor;
use crate::parallel_processor::ParallelProcessor;
use crate::topology::AsTopology;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AsRelationship {
    ProviderToCustomer,
    CustomerToProvider,
    PeerToPeer,
}

impl AsRelationship {
    #[allow(dead_code)]
    pub fn label(&self) -> &'static str {
        match self {
            AsRelationship::ProviderToCustomer => "Provider→Customer",
            AsRelationship::CustomerToProvider => "Customer→Provider",
            AsRelationship::PeerToPeer => "Peer↔Peer",
        }
    }

    #[allow(dead_code)]
    pub fn short_label(&self) -> &'static str {
        match self {
            AsRelationship::ProviderToCustomer => "p2c",
            AsRelationship::CustomerToProvider => "c2p",
            AsRelationship::PeerToPeer => "p2p",
        }
    }
}

#[derive(Debug, Clone)]
pub struct RouteLeakViolation {
    pub prefix: String,
    pub as_path: Vec<u32>,
    pub relationships: Vec<Option<AsRelationship>>,
    pub violation_index: usize,
    pub violation_desc: String,
    pub leak_type: LeakType,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum LeakType {
    ValleyDownUp,
    ValleyDownPeer,
    ValleyPeerUp,
    MultiPeer,
}

impl LeakType {
    pub fn label(&self) -> &'static str {
        match self {
            LeakType::ValleyDownUp => "Valley (Down→Up)",
            LeakType::ValleyDownPeer => "Valley (Down→Peer)",
            LeakType::ValleyPeerUp => "Valley (Peer→Up)",
            LeakType::MultiPeer => "Multi-Peer",
        }
    }
}

pub struct ValleyFreeChecker {
    relationships: HashMap<(u32, u32), AsRelationship>,
    #[allow(dead_code)]
    degree_map: HashMap<u32, u64>,
    #[allow(dead_code)]
    peer_degree_ratio: f64,
}

impl ValleyFreeChecker {
    pub fn new(_topology: &AsTopology, processor: &ParallelProcessor) -> Self {
        let degree_map = processor.get_asn_degree_map();
        let relationships = Self::infer_relationships(&degree_map, &processor.as_link_counts);

        Self {
            relationships,
            degree_map,
            peer_degree_ratio: 0.4,
        }
    }

    fn infer_relationships(
        degree_map: &HashMap<u32, u64>,
        as_link_counts: &HashMap<(u32, u32), u64>,
    ) -> HashMap<(u32, u32), AsRelationship> {
        let mut relationships = HashMap::new();

        for &(as_a, as_b) in as_link_counts.keys() {
            let deg_a = *degree_map.get(&as_a).unwrap_or(&0) as f64;
            let deg_b = *degree_map.get(&as_b).unwrap_or(&0) as f64;

            let max_deg = deg_a.max(deg_b);
            let min_deg = deg_a.min(deg_b);
            let ratio = if max_deg > 0.0 { min_deg / max_deg } else { 1.0 };

            let rel = if ratio >= 0.6 {
                AsRelationship::PeerToPeer
            } else if deg_a > deg_b {
                AsRelationship::ProviderToCustomer
            } else {
                AsRelationship::CustomerToProvider
            };

            relationships.insert((as_a, as_b), rel);
        }

        relationships
    }

    pub fn get_relationship(&self, from: u32, to: u32) -> Option<AsRelationship> {
        if let Some(rel) = self.relationships.get(&(from, to)) {
            Some(*rel)
        } else if let Some(rel) = self.relationships.get(&(to, from)) {
            Some(rel.mirror())
        } else {
            None
        }
    }

    pub fn check_as_path(&self, as_path: &[u32]) -> Vec<RouteLeakViolation> {
        if as_path.len() < 3 {
            return Vec::new();
        }

        let mut violations = Vec::new();

        let relationships: Vec<Option<AsRelationship>> = as_path
            .windows(2)
            .map(|w| self.get_relationship(w[0], w[1]))
            .collect();

        let mut seen_down = false;
        let mut seen_peer = false;

        for (i, rel_opt) in relationships.iter().enumerate() {
            let rel = match rel_opt {
                Some(r) => r,
                None => continue,
            };

            match rel {
                AsRelationship::CustomerToProvider => {
                    if seen_down {
                        violations.push(RouteLeakViolation {
                            prefix: String::new(),
                            as_path: as_path.to_vec(),
                            relationships: relationships.clone(),
                            violation_index: i,
                            violation_desc: format!(
                                "AS{} → AS{} (c2p) after descending path — Valley detected",
                                as_path[i], as_path[i + 1]
                            ),
                            leak_type: LeakType::ValleyDownUp,
                        });
                    } else if seen_peer {
                        violations.push(RouteLeakViolation {
                            prefix: String::new(),
                            as_path: as_path.to_vec(),
                            relationships: relationships.clone(),
                            violation_index: i,
                            violation_desc: format!(
                                "AS{} → AS{} (c2p) after peer link — Valley detected",
                                as_path[i], as_path[i + 1]
                            ),
                            leak_type: LeakType::ValleyPeerUp,
                        });
                    }
                }
                AsRelationship::ProviderToCustomer => {
                    seen_down = true;
                    if seen_peer {
                        violations.push(RouteLeakViolation {
                            prefix: String::new(),
                            as_path: as_path.to_vec(),
                            relationships: relationships.clone(),
                            violation_index: i,
                            violation_desc: format!(
                                "AS{} → AS{} (p2c) after peer link — Valley detected",
                                as_path[i], as_path[i + 1]
                            ),
                            leak_type: LeakType::ValleyDownPeer,
                        });
                    }
                }
                AsRelationship::PeerToPeer => {
                    if seen_peer {
                        violations.push(RouteLeakViolation {
                            prefix: String::new(),
                            as_path: as_path.to_vec(),
                            relationships: relationships.clone(),
                            violation_index: i,
                            violation_desc: format!(
                                "AS{} → AS{} (p2p) — Multiple peer links in path",
                                as_path[i], as_path[i + 1]
                            ),
                            leak_type: LeakType::MultiPeer,
                        });
                    } else if seen_down {
                        violations.push(RouteLeakViolation {
                            prefix: String::new(),
                            as_path: as_path.to_vec(),
                            relationships: relationships.clone(),
                            violation_index: i,
                            violation_desc: format!(
                                "AS{} → AS{} (p2p) after descending path — Valley detected",
                                as_path[i], as_path[i + 1]
                            ),
                            leak_type: LeakType::ValleyDownPeer,
                        });
                    }
                    seen_peer = true;
                }
            }
        }

        violations
    }

    pub fn detect_route_leaks(
        &self,
        processor: &ParallelProcessor,
    ) -> Vec<RouteLeakViolation> {
        let mut all_violations = Vec::new();

        for (_, updates) in &processor.all_updates {
            for update in updates {
                let flat_path = BgpExtractor::flatten_as_path(&update.as_path);
                let mut violations = self.check_as_path(&flat_path);

                for prefix in &update.announced_prefixes {
                    for v in &mut violations {
                        if v.prefix.is_empty() {
                            v.prefix = prefix.cidr();
                        }
                    }
                }

                all_violations.extend(violations);
            }
        }

        all_violations.sort_by(|a, b| {
            b.leak_type
                .label()
                .cmp(a.leak_type.label())
                .then_with(|| b.violation_index.cmp(&a.violation_index))
        });

        let mut seen = std::collections::HashSet::new();
        all_violations.retain(|v| {
            let key = (v.as_path.clone(), v.violation_index, v.leak_type.clone());
            seen.insert(key)
        });

        all_violations
    }

    pub fn relationship_stats(&self) -> HashMap<String, usize> {
        let mut stats = HashMap::new();
        let mut p2c = 0usize;
        let mut c2p = 0usize;
        let mut p2p = 0usize;

        for rel in self.relationships.values() {
            match rel {
                AsRelationship::ProviderToCustomer => p2c += 1,
                AsRelationship::CustomerToProvider => c2p += 1,
                AsRelationship::PeerToPeer => p2p += 1,
            }
        }

        stats.insert("Provider→Customer".to_string(), p2c);
        stats.insert("Customer→Provider".to_string(), c2p);
        stats.insert("Peer↔Peer".to_string(), p2p);

        stats
    }

    pub fn total_relationships(&self) -> usize {
        self.relationships.len()
    }
}

impl AsRelationship {
    pub fn mirror(&self) -> AsRelationship {
        match self {
            AsRelationship::ProviderToCustomer => AsRelationship::CustomerToProvider,
            AsRelationship::CustomerToProvider => AsRelationship::ProviderToCustomer,
            AsRelationship::PeerToPeer => AsRelationship::PeerToPeer,
        }
    }
}
