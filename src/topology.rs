use std::collections::HashMap;

use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::algo::dijkstra;
use petgraph::Direction;

use crate::parallel_processor::ParallelProcessor;

#[derive(Debug, Clone)]
pub struct AsNode {
    pub asn: u32,
    pub degree: u64,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct AsEdge {
    pub weight: u64,
}

pub struct AsTopology {
    pub graph: DiGraph<AsNode, AsEdge>,
    pub asn_to_idx: HashMap<u32, NodeIndex>,
}

impl AsTopology {
    pub fn build_from_processor(processor: &ParallelProcessor) -> Self {
        let mut graph = DiGraph::<AsNode, AsEdge>::new();
        let mut asn_to_idx = HashMap::new();

        let degree_map = processor.get_asn_degree_map();

        for entry in processor.as_link_counts.iter() {
            let (src_asn, dst_asn) = entry.key();

            for &asn in &[*src_asn, *dst_asn] {
                if !asn_to_idx.contains_key(&asn) {
                    let degree = degree_map.get(&asn).map(|r| *r.value()).unwrap_or(0);
                    let idx = graph.add_node(AsNode { asn, degree });
                    asn_to_idx.insert(asn, idx);
                }
            }
        }

        for entry in processor.as_link_counts.iter() {
            let (src_asn, dst_asn) = entry.key();
            let weight = *entry.value();

            if let (Some(&src_idx), Some(&dst_idx)) =
                (asn_to_idx.get(src_asn), asn_to_idx.get(dst_asn))
            {
                graph.add_edge(src_idx, dst_idx, AsEdge { weight });
            }
        }

        AsTopology {
            graph,
            asn_to_idx,
        }
    }

    pub fn get_top_hubs(&self, n: usize) -> Vec<(u32, u64)> {
        let mut nodes: Vec<_> = self
            .graph
            .node_indices()
            .filter_map(|idx| {
                let node = &self.graph[idx];
                Some((node.asn, node.degree))
            })
            .collect();

        nodes.sort_by(|a, b| b.1.cmp(&a.1));
        nodes.truncate(n);
        nodes
    }

    pub fn get_hub_paths(&self, hub_asn: u32, max_depth: usize) -> Vec<Vec<u32>> {
        let mut paths = Vec::new();

        if let Some(&start_idx) = self.asn_to_idx.get(&hub_asn) {
            let mut visited = vec![false; self.graph.node_count()];
            let mut current_path = vec![hub_asn];
            Self::dfs_paths(
                &self.graph,
                &self.asn_to_idx,
                start_idx,
                &mut visited,
                &mut current_path,
                &mut paths,
                max_depth,
            );
        }

        paths
    }

    fn dfs_paths(
        graph: &DiGraph<AsNode, AsEdge>,
        asn_to_idx: &HashMap<u32, NodeIndex>,
        current: NodeIndex,
        visited: &mut Vec<bool>,
        current_path: &mut Vec<u32>,
        paths: &mut Vec<Vec<u32>>,
        max_depth: usize,
    ) {
        if current_path.len() > max_depth {
            return;
        }

        if current_path.len() > 1 {
            paths.push(current_path.clone());
        }

        if current_path.len() == max_depth {
            return;
        }

        visited[current.index()] = true;

        let neighbors: Vec<_> = graph
            .neighbors_directed(current, Direction::Outgoing)
            .collect();

        for neighbor in neighbors {
            if !visited[neighbor.index()] {
                let asn = graph[neighbor].asn;
                current_path.push(asn);
                Self::dfs_paths(graph, asn_to_idx, neighbor, visited, current_path, paths, max_depth);
                current_path.pop();
            }
        }

        visited[current.index()] = false;
    }

    #[allow(dead_code)]
    pub fn compute_shortest_path(&self, from_asn: u32, to_asn: u32) -> Option<Vec<u32>> {
        let from_idx = self.asn_to_idx.get(&from_asn)?;
        let to_idx = self.asn_to_idx.get(&to_asn)?;

        let _paths = dijkstra(&self.graph, *from_idx, Some(*to_idx), |_| 1u64);
        None
    }

    pub fn node_count(&self) -> usize {
        self.graph.node_count()
    }

    pub fn edge_count(&self) -> usize {
        self.graph.edge_count()
    }
}
