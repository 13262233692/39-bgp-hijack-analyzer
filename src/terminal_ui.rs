use colored::*;
use crate::anomaly::{AlertType, HijackAlert, ZombieNode};
use crate::parallel_processor::ProcessingStats;
use crate::topology::AsTopology;
use crate::valley_free::{AsRelationship, LeakType, RouteLeakViolation, ValleyFreeChecker};

pub struct TerminalUi;

impl TerminalUi {
    pub fn print_banner() {
        println!();
        println!(
            "{}",
            r#"
  ╔══════════════════════════════════════════════════════════════╗
  ║                                                              ║
  ║   ██████╗ ██████╗  █████╗ ███╗   ██╗ ██████╗               ║
  ║   ██╔══██╗██╔══██╗██╔══██╗████╗  ██║██╔═══██╗              ║
  ║   ██████╔╝██████╔╝███████║██╔██╗ ██║██║   ██║              ║
  ║   ██╔══██╗██╔══██╗██╔══██║██║╚██╗██║██║   ██║              ║
  ║   ██████╔╝██║  ██║██║  ██║██║ ╚████║╚██████╔╝              ║
  ║   ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝               ║
  ║                                                              ║
  ║   HIJACK ANALYZER ── Internet Backbone Audit Terminal       ║
  ║   RouteViews MRT · AS Topology · Hijack Detection           ║
  ║                                                              ║
  ╚══════════════════════════════════════════════════════════════╝
"#
            .bright_cyan()
        );
    }

    pub fn print_stats(stats: &ProcessingStats) {
        println!("{}", "┌─────────────────────────────────────────────┐".bright_blue());
        println!(
            "{}{}{}",
            "│ ".bright_blue(),
            "PROCESSING STATISTICS".bold().bright_white(),
            "                             │".bright_blue()
        );
        println!("{}", "├─────────────────────────────────────────────┤".bright_blue());
        println!(
            "{} {}{}{}",
            "│".bright_blue(),
            "MRT Records Parsed:  ".dimmed(),
            format!("{}", stats.total_records).bright_green().bold(),
            "                     │".bright_blue()
        );
        println!(
            "{} {}{}{}",
            "│".bright_blue(),
            "BGP Updates Found:   ".dimmed(),
            format!("{}", stats.bgp_updates).bright_green().bold(),
            "                     │".bright_blue()
        );
        println!(
            "{} {}{}{}",
            "│".bright_blue(),
            "AS-Path Entries:     ".dimmed(),
            format!("{}", stats.as_path_entries).bright_yellow().bold(),
            "                     │".bright_blue()
        );
        println!(
            "{} {}{}{}",
            "│".bright_blue(),
            "Unique Prefixes:     ".dimmed(),
            format!("{}", stats.unique_prefixes).bright_cyan().bold(),
            "                     │".bright_blue()
        );
        println!(
            "{} {}{}{}",
            "│".bright_blue(),
            "Unique AS Numbers:   ".dimmed(),
            format!("{}", stats.unique_asns).bright_cyan().bold(),
            "                     │".bright_blue()
        );
        println!(
            "{} {}{}{}",
            "│".bright_blue(),
            "Processing Time:     ".dimmed(),
            format!("{}ms", stats.elapsed_ms).bright_magenta().bold(),
            "│".bright_blue()
        );
        println!("{}", "└─────────────────────────────────────────────┘".bright_blue());
        println!();
    }

    pub fn print_topology_info(topology: &AsTopology) {
        println!("{}", "╔═══════════════════════════════════════════════════════╗".bright_cyan());
        println!(
            "{}{}{}",
            "║ ".bright_cyan(),
            "AS TOPOLOGY GRAPH".bold().bright_white(),
            "                                     ║".bright_cyan()
        );
        println!("{}", "╠═══════════════════════════════════════════════════════╣".bright_cyan());
        println!(
            "{} {}{}{}",
            "║".bright_cyan(),
            "Total AS Nodes:     ".dimmed(),
            format!("{}", topology.node_count()).bright_green().bold(),
            "                              ║".bright_cyan()
        );
        println!(
            "{} {}{}{}",
            "║".bright_cyan(),
            "Total AS Links:     ".dimmed(),
            format!("{}", topology.edge_count()).bright_green().bold(),
            "                              ║".bright_cyan()
        );
        println!("{}", "╚═══════════════════════════════════════════════════════╝".bright_cyan());
        println!();
    }

    pub fn print_top_hubs(topology: &AsTopology, n: usize) {
        let hubs = topology.get_top_hubs(n);

        println!("{}", "╔══════════════════════════════════════════════════════════════════╗".bright_yellow());
        println!(
            "{}{}{}",
            "║ ".bright_yellow(),
            format!("TOP {} TRAFFIC CORE HUBS", n).bold().bright_white(),
            "                                                ║".bright_yellow()
        );
        println!("{}", "╠══════════════════════════════════════════════════════════════════╣".bright_yellow());
        println!(
            "{} {}{}{}{}",
            "║".bright_yellow(),
            "Rank".bold().dimmed(),
            "  AS Number    ".bold().dimmed(),
            "Link Degree".bold().dimmed(),
            "  Bar                      ║".bright_yellow()
        );
        println!("{}", "╠══════════════════════════════════════════════════════════════════╣".bright_yellow());

        let max_degree = hubs.first().map(|(_, d)| *d).unwrap_or(1);

        for (i, (asn, degree)) in hubs.iter().enumerate() {
            let bar_len = (*degree as f64 / max_degree as f64 * 20.0) as usize;
            let bar: String = "█".repeat(bar_len);

            let rank_str = format!("{:>3}", i + 1);
            let asn_str = format!("AS{:>8}", asn);
            let degree_str = format!("{:>10}", degree);

            let rank_colored = if i < 3 {
                rank_str.bright_red().bold()
            } else if i < 10 {
                rank_str.bright_yellow()
            } else {
                rank_str.dimmed()
            };

            let bar_colored = if i < 3 {
                bar.bright_red()
            } else if i < 10 {
                bar.bright_yellow()
            } else {
                bar.bright_cyan()
            };

            println!(
                "{} {}  {}  {}  {}{}",
                "║".bright_yellow(),
                rank_colored,
                asn_str.bright_green().bold(),
                degree_str.bright_white(),
                bar_colored,
                "║".bright_yellow()
            );
        }

        println!("{}", "╚══════════════════════════════════════════════════════════════════╝".bright_yellow());
        println!();
    }

    pub fn print_hub_paths(topology: &AsTopology, hubs: &[(u32, u64)], max_paths: usize) {
        println!("{}", "╔══════════════════════════════════════════════════════════════════╗".bright_magenta());
        println!(
            "{}{}{}",
            "║ ".bright_magenta(),
            "HUB GRAPH STRUCTURE PATHS".bold().bright_white(),
            "                                             ║".bright_magenta()
        );
        println!("{}", "╠══════════════════════════════════════════════════════════════════╣".bright_magenta());

        for (i, (asn, degree)) in hubs.iter().enumerate() {
            if i >= 5 {
                break;
            }

            let paths = topology.get_hub_paths(*asn, 4);
            let display_paths: Vec<_> = paths.into_iter().take(max_paths).collect();

            println!(
                "{} {} {}{}",
                "║".bright_magenta(),
                format!("AS{}", asn).bright_green().bold(),
                format!("(degree: {})", degree).dimmed(),
                "║".bright_magenta()
            );

            for path in &display_paths {
                let path_str: Vec<String> = path
                    .iter()
                    .map(|asn| format!("AS{}", asn))
                    .collect();
                let formatted = path_str.join(&format!(" {} ", "→".bright_cyan()));
                println!(
                    "{}   {} {}",
                    "║".bright_magenta(),
                    "├─".dimmed(),
                    formatted
                );
            }

            if i < 4 && i < hubs.len() - 1 {
                println!(
                    "{} {}",
                    "║".bright_magenta(),
                    "│".dimmed()
                );
            }
        }

        println!("{}", "╚══════════════════════════════════════════════════════════════════╝".bright_magenta());
        println!();
    }

    pub fn print_hijack_alerts(alerts: &[HijackAlert]) {
        println!("{}", "╔══════════════════════════════════════════════════════════════════╗".bright_red());
        println!(
            "{}{}{}",
            "║ ".bright_red(),
            "⚠  ROUTE HIJACK DETECTION  ⚠".bold().bright_white(),
            "                                            ║".bright_red()
        );
        println!("{}", "╠══════════════════════════════════════════════════════════════════╣".bright_red());

        if alerts.is_empty() {
            println!(
                "{} {} {}",
                "║".bright_red(),
                "No hijack alerts detected ✓".bright_green().bold(),
                "║".bright_red()
            );
        } else {
            let display_count = alerts.len().min(20);
            for (i, alert) in alerts[..display_count].iter().enumerate() {
                let alert_icon = match alert.alert_type {
                    AlertType::PrefixHijack => "🔴 PREFIX HIJACK".bright_red().bold(),
                    AlertType::PathManipulation => "🟠 PATH MANIPULATION".bright_yellow().bold(),
                    AlertType::ZombieNode => "🟣 ZOMBIE NODE".bright_magenta().bold(),
                    AlertType::AsPathLoop => "🔴 AS-PATH LOOP".bright_red().bold(),
                    AlertType::RouteLeak => "🚨 ROUTE LEAK".bright_red().bold(),
                    AlertType::UnknownOrigin => "🟡 UNKNOWN ORIGIN".bright_yellow().bold(),
                };

                println!(
                    "{} {} {}",
                    "║".bright_red(),
                    format!("[{:>2}]", i + 1).dimmed(),
                    alert_icon
                );
                println!(
                    "{}   {} {} {}",
                    "║".bright_red(),
                    "Prefix:".dimmed(),
                    alert.prefix.bright_cyan(),
                    format!("(legit: AS{})", alert.origin_as).dimmed()
                );
                println!(
                    "{}   {} {}",
                    "║".bright_red(),
                    "Suspicious AS:".dimmed(),
                    format!("AS{}", alert.hijack_as).bright_red().bold()
                );
                println!(
                    "{}   {} {:.0}%  {}",
                    "║".bright_red(),
                    "Confidence:".dimmed(),
                    alert.confidence * 100.0,
                    alert.evidence.dimmed()
                );

                if i < display_count - 1 {
                    println!(
                        "{} {}",
                        "║".bright_red(),
                        "├──────────────────────────────────────────────────".dimmed()
                    );
                }
            }

            if alerts.len() > 20 {
                println!(
                    "{} {}",
                    "║".bright_red(),
                    format!("... and {} more alerts", alerts.len() - 20).dimmed()
                );
            }
        }

        println!("{}", "╚══════════════════════════════════════════════════════════════════╝".bright_red());
        println!();
    }

    pub fn print_zombie_nodes(zombies: &[ZombieNode]) {
        println!("{}", "╔══════════════════════════════════════════════════════════════════╗".bright_magenta());
        println!(
            "{}{}{}",
            "║ ".bright_magenta(),
            "☠  ZOMBIE NODE DETECTION  ☠".bold().bright_white(),
            "                                            ║".bright_magenta()
        );
        println!("{}", "╠══════════════════════════════════════════════════════════════════╣".bright_magenta());

        if zombies.is_empty() {
            println!(
                "{} {} {}",
                "║".bright_magenta(),
                "No zombie nodes detected ✓".bright_green().bold(),
                "║".bright_magenta()
            );
        } else {
            let display_count = zombies.len().min(15);
            for (i, zombie) in zombies[..display_count].iter().enumerate() {
                println!(
                    "{} {} {}",
                    "║".bright_magenta(),
                    format!("[{:>2}]", i + 1).dimmed(),
                    format!("AS{}", zombie.asn).bright_magenta().bold()
                );
                println!(
                    "{}   {} {}",
                    "║".bright_magenta(),
                    "Reason:".dimmed(),
                    zombie.reason.bright_yellow()
                );
                println!(
                    "{}   {} {}",
                    "║".bright_magenta(),
                    "Affected Prefixes:".dimmed(),
                    format!("{} prefixes", zombie.affected_prefixes.len()).bright_cyan()
                );

                for prefix in zombie.affected_prefixes.iter().take(3) {
                    println!(
                        "{}     {} {}",
                        "║".bright_magenta(),
                        "•".dimmed(),
                        prefix.bright_white()
                    );
                }
                if zombie.affected_prefixes.len() > 3 {
                    println!(
                        "{}     {} {}",
                        "║".bright_magenta(),
                        "...".dimmed(),
                        format!("+{} more", zombie.affected_prefixes.len() - 3).dimmed()
                    );
                }

                if !zombie.suspicious_paths.is_empty() {
                    println!(
                        "{}   {}",
                        "║".bright_magenta(),
                        "Suspicious AS-Paths:".dimmed()
                    );
                    for path in zombie.suspicious_paths.iter().take(2) {
                        let path_str: Vec<String> = path.iter().map(|a| format!("AS{}", a)).collect();
                        let formatted = path_str.join(&format!(" {} ", "→".bright_red()));
                        println!(
                            "{}     {} {}",
                            "║".bright_magenta(),
                            "├─".dimmed(),
                            formatted
                        );
                    }
                }

                if i < display_count - 1 {
                    println!(
                        "{} {}",
                        "║".bright_magenta(),
                        "├──────────────────────────────────────────────────".dimmed()
                    );
                }
            }
        }

        println!("{}", "╚══════════════════════════════════════════════════════════════════╝".bright_magenta());
        println!();
    }

    pub fn print_valley_free_relationships(checker: &ValleyFreeChecker) {
        let stats = checker.relationship_stats();

        println!("{}", "╔══════════════════════════════════════════════════════════════════╗".bright_cyan());
        println!(
            "{}{}{}",
            "║ ".bright_cyan(),
            "AS BUSINESS RELATIONSHIPS (Gao-Rexford)".bold().bright_white(),
            "                    ║".bright_cyan()
        );
        println!("{}", "╠══════════════════════════════════════════════════════════════════╣".bright_cyan());
        println!(
            "{} {}{}{}",
            "║".bright_cyan(),
            "Total Inferred Links: ".dimmed(),
            format!("{}", checker.total_relationships()).bright_green().bold(),
            "                             ║".bright_cyan()
        );

        let p2c = stats.get("Provider→Customer").unwrap_or(&0);
        let c2p = stats.get("Customer→Provider").unwrap_or(&0);
        let p2p = stats.get("Peer↔Peer").unwrap_or(&0);

        println!(
            "{} {} {}{}",
            "║".bright_cyan(),
            "Provider→Customer:".dimmed(),
            format!("{}", p2c).bright_yellow().bold(),
            "                           ║".bright_cyan()
        );
        println!(
            "{} {} {}{}",
            "║".bright_cyan(),
            "Customer→Provider:".dimmed(),
            format!("{}", c2p).bright_yellow().bold(),
            "                           ║".bright_cyan()
        );
        println!(
            "{} {} {}{}",
            "║".bright_cyan(),
            "Peer↔Peer:        ".dimmed(),
            format!("{}", p2p).bright_green().bold(),
            "                           ║".bright_cyan()
        );
        println!(
            "{} {}",
            "║".bright_cyan(),
            "Inference: Degree-ratio heuristic (ratio ≥ 0.6 → Peer)".dimmed()
        );
        println!("{}", "╚══════════════════════════════════════════════════════════════════╝".bright_cyan());
        println!();
    }

    pub fn print_valley_free_violations(violations: &[RouteLeakViolation]) {
        println!("{}", "╔══════════════════════════════════════════════════════════════════════════════╗".bright_red());
        println!(
            "{}{}{}",
            "║ ".bright_red(),
            "🚨 VALLEY-FREE ROUTE LEAK VIOLATIONS  🚨".bold().bright_white(),
            "                                ║".bright_red()
        );
        println!("{}", "╠══════════════════════════════════════════════════════════════════════════════╣".bright_red());

        if violations.is_empty() {
            println!(
                "{} {} {}",
                "║".bright_red(),
                "All AS-Paths comply with Valley-Free policy ✓".bright_green().bold(),
                "                ║".bright_red()
            );
        } else {
            println!(
                "{} {} {}",
                "║".bright_red(),
                "Valley-Free violations detected:".bright_yellow().bold(),
                format!(" {} violation(s)", violations.len()).bright_red().bold()
            );
            println!(
                "{} {}",
                "║".bright_red(),
                "Path descending (p2c) then ascending (c2p) or crossing peer = LEAK".dimmed()
            );
            println!(
                "{} {}",
                "║".bright_red(),
                "├─────────────────────────────────────────────────────────────────".dimmed()
            );

            let display_count = violations.len().min(25);
            for (i, v) in violations[..display_count].iter().enumerate() {
                let leak_label = match v.leak_type {
                    LeakType::ValleyDownUp => "VALLEY (Down→Up)".bright_red().bold(),
                    LeakType::ValleyDownPeer => "VALLEY (Down→Peer)".bright_red().bold(),
                    LeakType::ValleyPeerUp => "VALLEY (Peer→Up)".bright_yellow().bold(),
                    LeakType::MultiPeer => "MULTI-PEER".bright_magenta().bold(),
                };

                println!(
                    "{} {} {} {}",
                    "║".bright_red(),
                    format!("[{:>2}]", i + 1).dimmed(),
                    leak_label,
                    format!("at hop {}", v.violation_index + 1).dimmed()
                );

                if !v.prefix.is_empty() {
                    println!(
                        "{}   {} {}",
                        "║".bright_red(),
                        "Prefix:".dimmed(),
                        v.prefix.bright_cyan()
                    );
                }

                let path_str = Self::format_valley_free_path(&v.as_path, &v.relationships);
                println!(
                    "{}   {} {}",
                    "║".bright_red(),
                    "AS-Path:".dimmed(),
                    path_str
                );

                println!(
                    "{}   {} {}",
                    "║".bright_red(),
                    "Violation:".dimmed(),
                    v.violation_desc.bright_red()
                );

                if i < display_count - 1 {
                    println!(
                        "{} {}",
                        "║".bright_red(),
                        "├─────────────────────────────────────────────────────────────────".dimmed()
                    );
                }
            }

            if violations.len() > 25 {
                println!(
                    "{} {}",
                    "║".bright_red(),
                    format!("... and {} more violations", violations.len() - 25).dimmed()
                );
            }
        }

        println!("{}", "╚══════════════════════════════════════════════════════════════════════════════╝".bright_red());
        println!();
    }

    fn format_valley_free_path(
        as_path: &[u32],
        relationships: &[Option<AsRelationship>],
    ) -> String {
        if as_path.is_empty() {
            return String::new();
        }

        let mut parts = Vec::new();
        parts.push(format!("AS{}", as_path[0]));

        for (i, rel_opt) in relationships.iter().enumerate() {
            let arrow = match rel_opt {
                Some(AsRelationship::ProviderToCustomer) => "↓".bright_yellow().to_string(),
                Some(AsRelationship::CustomerToProvider) => "↑".bright_cyan().to_string(),
                Some(AsRelationship::PeerToPeer) => "⇄".bright_magenta().to_string(),
                None => "→".dimmed().to_string(),
            };
            parts.push(arrow);
            parts.push(format!("AS{}", as_path[i + 1]));
        }

        parts.join(" ")
    }

    pub fn print_completion_banner() {
        println!();
        println!(
            "{}",
            "  ═══════════════════════════════════════════════════════════"
                .bright_green()
        );
        println!(
            "{}",
            "  ✓  Audit Complete ── Backbone integrity report generated"
                .bright_green()
                .bold()
        );
        println!(
            "{}",
            "  ═══════════════════════════════════════════════════════════"
                .bright_green()
        );
        println!();
    }
}
