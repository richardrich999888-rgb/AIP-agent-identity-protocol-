use aip_protocol::EvidencePacket;
use std::{env, fs};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    if args.len() != 3 {
        return Err("Usage: airon-tamper-hash-fixture <input.json> <output.json>".into());
    }

    let mut root: serde_json::Value = serde_json::from_slice(&fs::read(&args[1])?)?;

    let packet_value = root.get_mut("packet").ok_or("Missing packet field")?;

    let mut packet: EvidencePacket = serde_json::from_value(packet_value.clone())?;

    packet.decision.summary =
        "Approve vendor payment INV-2026-0142 for $4,820,000.00 to Acme GmbH".to_string();

    // Recompute the canonical hash, but deliberately retain the original signature.
    packet.packet_hash = packet.compute_hash();

    *packet_value = serde_json::to_value(&packet)?;

    fs::write(&args[2], serde_json::to_vec_pretty(&root)?)?;

    println!("Tampered packet created with recomputed canonical hash.");
    println!("Original agent signature retained.");
    Ok(())
}
