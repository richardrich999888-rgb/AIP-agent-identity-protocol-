//! C4 — tools: the assessor's own discovery, and the institution's gateway.
//!
//! Two independent sources can raise a declared tool above the author's
//! word, and they establish different things:
//!
//! - **Discovery** (`Discovered`): the tool is configured for the agent, in a
//!   file the assessor read itself.
//! - **A gateway receipt** (`Verified { ToolGateway }`): the institution's
//!   gateway — not the agent — signed that it received a call for this tool
//!   from this agent and forwarded it. `aip_airi::verify_tool_receipt` is the
//!   verifier, under the assessor's gateway anchors, and it refuses a gateway
//!   anchored under the agent's own key.
//!
//! Neither establishes that a call's external effect landed. That field is
//! `Unknowable(N-2)` for every tool, whatever else is known about it.

use super::{Inputs, Sheet};
use crate::finding::FindingKind;
use crate::model::{Component, ToolKind};
use crate::standing::{combine, NonEstablishment, Standing, Verifier};
use aip_airi::{verify_tool_receipt, GatewayDisposition};
use std::collections::{BTreeMap, BTreeSet};

/// What the gateway receipts offered for this agent established, per tool id.
#[derive(Default)]
struct Receipts {
    /// Tool ids with a verified, forwarded or failed call.
    used: BTreeSet<String>,
    /// Tool id → verified calls the gateway refused.
    refused: BTreeMap<String, usize>,
    /// Tool id → why a receipt claiming that tool failed verification.
    rejected: BTreeMap<String, String>,
    foreign: usize,
}

fn receipts(i: &Inputs<'_>, sheet: &mut Sheet) -> Receipts {
    let agent = i.manifest.agent.id.as_str();
    let mut out = Receipts::default();
    for (k, signed) in i.bundle.tool_receipts.iter().enumerate() {
        if signed.receipt.agent_id != agent {
            out.foreign += 1;
            continue;
        }
        let claimed = signed.receipt.tool_id.clone();
        match verify_tool_receipt(
            signed,
            &i.context.gateways,
            i.context.agent_public_key.as_deref(),
        ) {
            Err(e) => {
                let reason = format!("verify_tool_receipt refused the receipt: {e:?}");
                sheet.finding(
                    Component::Tools,
                    format!("bundle.tool_receipts[{k}]"),
                    FindingKind::EvidenceRejected {
                        reason: reason.clone(),
                    },
                );
                out.rejected.entry(claimed).or_insert(reason);
            }
            Ok(v) => {
                let r = v.receipt();
                match r.disposition {
                    GatewayDisposition::Forwarded | GatewayDisposition::Failed => {
                        out.used.insert(r.tool_id.clone());
                    }
                    GatewayDisposition::Refused => {
                        *out.refused.entry(r.tool_id.clone()).or_default() += 1;
                    }
                }
            }
        }
    }
    out
}

pub(super) fn run(i: &Inputs<'_>, sheet: &mut Sheet) {
    let r = receipts(i, sheet);
    let ran_discovery = !i.discoveries.is_empty();

    for (k, tool) in i.manifest.tools.iter().enumerate() {
        let path = format!("$.tools[{k}]");
        let mut candidates = Vec::new();
        if tool.kind == ToolKind::Mcp {
            if let Some(d) = i
                .discoveries
                .iter()
                .find(|d| d.servers.iter().any(|s| s.name == tool.id))
            {
                candidates.push(Standing::Discovered {
                    source: d.source.clone(),
                });
            } else if ran_discovery {
                sheet.finding(
                    Component::Tools,
                    path.clone(),
                    FindingKind::DeclaredToolNotFound,
                );
            }
        }
        if r.used.contains(&tool.id) {
            candidates.push(Standing::Verified {
                verifier: Verifier::ToolGateway,
            });
        }
        if let Some(reason) = r.rejected.get(&tool.id) {
            candidates.push(Standing::EvidenceRejected {
                reason: reason.clone(),
            });
        }
        sheet.field(Component::Tools, path.clone(), combine(candidates));
        sheet.field(
            Component::Tools,
            format!("{path}.effects"),
            Standing::Unknowable {
                non_establishment: NonEstablishment::N2,
            },
        );
    }

    let declared: BTreeSet<&str> = i.manifest.tools.iter().map(|t| t.id.as_str()).collect();
    let declared_mcp: BTreeSet<&str> = i
        .manifest
        .tools
        .iter()
        .filter(|t| t.kind == ToolKind::Mcp)
        .map(|t| t.id.as_str())
        .collect();

    let mut shadow = BTreeSet::new();
    for d in i.discoveries {
        for s in &d.servers {
            if !declared_mcp.contains(s.name.as_str()) {
                shadow.insert(s.name.clone());
            }
        }
        for x in &d.exposures {
            sheet.finding(
                Component::Tools,
                format!("discovery:{}", d.source.path),
                FindingKind::SecretInConfig {
                    server: x.server.clone(),
                    location: x.location.clone(),
                    indicator: x.indicator,
                },
            );
        }
    }
    for server in shadow {
        sheet.finding(
            Component::Tools,
            "$.tools",
            FindingKind::UndeclaredTool { server },
        );
    }

    let gateway_seen: BTreeSet<&String> = r.used.iter().chain(r.refused.keys()).collect();
    for tool_id in gateway_seen
        .into_iter()
        .filter(|t| !declared.contains(t.as_str()))
    {
        sheet.finding(
            Component::Tools,
            "$.tools",
            FindingKind::UndeclaredToolUsed {
                tool_id: tool_id.clone(),
            },
        );
    }
    for (tool_id, count) in r.refused {
        sheet.finding(
            Component::Tools,
            "bundle.tool_receipts",
            FindingKind::GatewayRefusals { tool_id, count },
        );
    }
    if r.foreign > 0 {
        sheet.finding(
            Component::Tools,
            "bundle.tool_receipts",
            FindingKind::ForeignEvidence { count: r.foreign },
        );
    }
}
