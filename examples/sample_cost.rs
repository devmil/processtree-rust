//! Times the phases of a full sample: `cargo run --release --example sample_cost`.
use processtree::{EngineConfig, ProcessTreeEngine};
use std::time::{Duration, Instant};

fn main() {
    let engine = ProcessTreeEngine::new(EngineConfig {
        icon_cache_dir: Some(std::env::temp_dir().join("processtree-sample-cost-icons")),
        metric_history_len: 1,
        ..EngineConfig::default()
    });
    engine.start().unwrap();
    for _ in 0..3 {
        engine.snapshot_with_topology().unwrap();
        std::thread::sleep(Duration::from_millis(200));
    }
    let rounds = 20u32;
    let (mut total, mut sockets) = (Duration::ZERO, Duration::ZERO);
    let (mut enumerate, mut enrich, mut tree) = (0u64, 0u64, 0u64);
    for _ in 0..rounds {
        let started = Instant::now();
        engine.snapshot_with_topology().unwrap();
        total += started.elapsed();
        let timing = engine.last_poll_timing();
        enumerate += timing.enumerate_micros;
        enrich += timing.metric_enrich_micros;
        tree += timing.tree_micros;
        let started = Instant::now();
        let _ = processtree::introspection::network::query_network_snapshot();
        sockets += started.elapsed();
        std::thread::sleep(Duration::from_millis(200));
    }
    let r = u64::from(rounds);
    println!(
        "sample {:?}  enumerate+ports {}us  enrich {}us  tree {}us  | socket table alone {:?}",
        total / rounds,
        enumerate / r,
        enrich / r,
        tree / r,
        sockets / rounds
    );
    engine.stop();
}
