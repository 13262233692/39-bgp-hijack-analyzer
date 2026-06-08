use std::path::PathBuf;

use clap::Parser;
use colored::*;

mod mrt_parser;
mod bgp_extract;
mod parallel_processor;
mod topology;
mod anomaly;
mod valley_free;
mod terminal_ui;

use parallel_processor::ParallelProcessor;
use terminal_ui::TerminalUi;
use topology::AsTopology;
use anomaly::AnomalyDetector;
use valley_free::ValleyFreeChecker;

#[derive(Parser, Debug)]
#[command(
    name = "BGP Hijack Analyzer",
    version = "0.1.0",
    about = "Internet backbone security audit terminal · RouteViews MRT parser · AS topology · Hijack detection"
)]
struct Args {
    #[arg(short, long, help = "MRT file or directory to analyze")]
    input: PathBuf,

    #[arg(short, long, default_value = "20", help = "Number of top hubs to display")]
    top: usize,

    #[arg(short, long, default_value = "5", help = "Max graph paths per hub")]
    paths: usize,

    #[arg(long, default_value_t = false, help = "Skip anomaly detection")]
    skip_anomaly: bool,
}

fn collect_mrt_files(path: &PathBuf) -> Vec<PathBuf> {
    if path.is_file() {
        vec![path.clone()]
    } else if path.is_dir() {
        let mut files = Vec::new();
        if let Ok(entries) = std::fs::read_dir(path) {
            for entry in entries.flatten() {
                let p = entry.path();
                if p.is_file() {
                    let ext = p
                        .extension()
                        .and_then(|e| e.to_str())
                        .unwrap_or("")
                        .to_lowercase();
                    let name = p
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("")
                        .to_lowercase();
                    if ext == "gz"
                        || ext == "bz2"
                        || ext == "mrt"
                        || ext == "rib"
                        || name.contains("rib")
                        || name.contains("updates")
                        || name.contains("mrt")
                    {
                        files.push(p);
                    }
                }
            }
        }
        files.sort();
        files
    } else {
        Vec::new()
    }
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    TerminalUi::print_banner();

    let mrt_files = collect_mrt_files(&args.input);

    if mrt_files.is_empty() {
        eprintln!(
            "{}: No MRT files found at {}",
            "ERROR".bright_red().bold(),
            args.input.display()
        );
        eprintln!(
            "  {} Download RouteViews data from:",
            "→".bright_cyan()
        );
        eprintln!(
            "    {} http://archive.routeviews.org/",
            "•".dimmed()
        );
        eprintln!(
            "    {} http://routeviews.org/bgpdata/",
            "•".dimmed()
        );
        std::process::exit(1);
    }

    println!(
        "{} {} MRT file(s) discovered",
        "◈".bright_cyan(),
        mrt_files.len().to_string().bright_green().bold()
    );
    for f in &mrt_files {
        println!(
            "  {} {}",
            "├─".dimmed(),
            f.display().to_string().bright_white()
        );
    }
    println!();

    println!(
        "{} {}",
        "◈".bright_yellow(),
        "Initializing parallel processor...".bright_white()
    );
    println!(
        "  {} Rayon thread pool: {} threads",
        "├─".dimmed(),
        rayon::current_num_threads().to_string().bright_green()
    );
    println!();

    let (processor, stats) = ParallelProcessor::process_files(&mrt_files)?;

    TerminalUi::print_stats(&stats);

    if stats.bgp_updates == 0 {
        eprintln!(
            "{}: No BGP updates extracted from MRT files",
            "WARNING".bright_yellow().bold()
        );
        eprintln!(
            "  {} Ensure files are valid RouteViews MRT dumps",
            "→".bright_cyan()
        );
        std::process::exit(1);
    }

    println!(
        "{} {}",
        "◈".bright_yellow(),
        "Building AS topology graph...".bright_white()
    );
    let topology = AsTopology::build_from_processor(&processor);
    TerminalUi::print_topology_info(&topology);

    let hubs = topology.get_top_hubs(args.top);
    TerminalUi::print_top_hubs(&topology, args.top);
    TerminalUi::print_hub_paths(&topology, &hubs, args.paths);

    if !args.skip_anomaly {
        println!(
            "{} {}",
            "◈".bright_cyan(),
            "Inferring AS business relationships (Gao-Rexford)...".bright_white()
        );
        println!();

        let checker = ValleyFreeChecker::new(&topology, &processor);
        TerminalUi::print_valley_free_relationships(&checker);

        println!(
            "{} {}",
            "◈".bright_red(),
            "Running Valley-Free route leak validation...".bright_white()
        );
        println!();

        let violations = checker.detect_route_leaks(&processor);
        TerminalUi::print_valley_free_violations(&violations);

        println!(
            "{} {}",
            "◈".bright_red(),
            "Running anomaly detection...".bright_white()
        );
        println!();

        let alerts = AnomalyDetector::detect_hijacks(&processor, &topology);
        TerminalUi::print_hijack_alerts(&alerts);

        let zombies = AnomalyDetector::detect_zombie_nodes(&processor, &topology);
        TerminalUi::print_zombie_nodes(&zombies);
    }

    TerminalUi::print_completion_banner();

    Ok(())
}
