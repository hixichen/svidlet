//! A load generator that stands in for the kubelet.
//!
//! Dials a running svidlet's CSI socket and issues `NodePublishVolume` the way
//! the kubelet would, so the memory and latency numbers come from the real
//! process serving the real protocol rather than from a test harness.
//!
//!   svidlet-bench <csi-socket> <target-dir> <count> [--unpublish]

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Instant;

use svidlet::config::volume_context as vc;
use svidlet::csi::proto::csi::node_client::NodeClient;
use svidlet::csi::proto::csi::{NodePublishVolumeRequest, NodeUnpublishVolumeRequest};
use tonic::transport::Endpoint;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 {
        eprintln!(
            "usage: {} <csi-socket> <target-dir> <count> [--unpublish]",
            args[0]
        );
        std::process::exit(2);
    }
    let socket = args[1].clone();
    let target_dir = PathBuf::from(&args[2]);
    let count: usize = args[3].parse()?;
    let unpublish = args.iter().any(|a| a == "--unpublish");

    // tonic understands unix:// natively, so this is the same transport the
    // kubelet uses.
    let channel = Endpoint::from_shared(format!("unix://{socket}"))?
        .connect()
        .await?;
    let mut client = NodeClient::new(channel);

    std::fs::create_dir_all(&target_dir)?;

    let started = Instant::now();
    let mut latencies = Vec::with_capacity(count);
    for i in 0..count {
        let target = target_dir.join(format!("pod-{i}/mount"));
        let mut ctx = HashMap::new();
        ctx.insert(vc::EPHEMERAL.to_string(), "true".to_string());
        ctx.insert(vc::POD_NAME.to_string(), format!("workload-{i}"));
        // Spread across namespaces and service accounts, so the store is not
        // holding one identity repeated N times.
        ctx.insert(vc::POD_NAMESPACE.to_string(), format!("ns-{}", i % 20));
        ctx.insert(vc::POD_UID.to_string(), format!("uid-{i}"));
        ctx.insert(vc::SERVICE_ACCOUNT.to_string(), format!("sa-{}", i % 50));

        let at = Instant::now();
        client
            .node_publish_volume(NodePublishVolumeRequest {
                volume_id: format!("csi-bench-{i}"),
                target_path: target.display().to_string(),
                readonly: true,
                volume_context: ctx,
            })
            .await
            .map_err(|e| format!("publish {i} failed: {e}"))?;
        latencies.push(at.elapsed());

        if (i + 1) % 100 == 0 {
            eprintln!("  published {}/{count}", i + 1);
        }
    }
    let elapsed = started.elapsed();

    latencies.sort_unstable();
    let at =
        |q: f64| latencies[((latencies.len() as f64 - 1.0) * q) as usize].as_secs_f64() * 1000.0;
    println!(
        "published={count} in {:.1}s ({:.0}/s)  p50={:.1}ms p90={:.1}ms p99={:.1}ms",
        elapsed.as_secs_f64(),
        count as f64 / elapsed.as_secs_f64(),
        at(0.50),
        at(0.90),
        at(0.99),
    );

    if unpublish {
        for i in 0..count {
            let target = target_dir.join(format!("pod-{i}/mount"));
            client
                .node_unpublish_volume(NodeUnpublishVolumeRequest {
                    volume_id: format!("csi-bench-{i}"),
                    target_path: target.display().to_string(),
                })
                .await?;
        }
        println!("unpublished={count}");
    }
    Ok(())
}
