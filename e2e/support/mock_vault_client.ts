import {
  IEvidenceVaultClient,
  EvidenceSummary,
  EvidenceFilter,
  EvidencePacket,
  VerificationContext,
  VerificationReport,
  AccountabilityGraph,
} from "./types.js";
import { verifyEvidencePacketOracle } from "./reference_oracle.js";
import { reconstructAccountabilityGraph } from "./dag_oracle.js";
import {
  validHonestCounterpartyPacket,
  createAuthorityBoundPacket,
  createAgentSignedPacket,
  createTamperedSummaryPacket,
} from "../fixtures/evidence_packets.js";
import { createSampleAuditBundleFiles } from "../fixtures/audit_bundles.js";

export class MockEvidenceVaultClient implements IEvidenceVaultClient {
  private packets: Map<string, EvidencePacket> = new Map();
  private liveState: boolean = false;

  constructor(isLiveMode = false) {
    this.liveState = isLiveMode;
    // Seed initial multi-tenant packets
    this.seedPacket("pkt-001-acme-loan", validHonestCounterpartyPacket);

    const authBound = createAuthorityBoundPacket();
    authBound.decision.summary = "Internal treasury authority grant";
    this.seedPacket("pkt-002-internal-auth", authBound);

    const agentSolo = createAgentSignedPacket();
    agentSolo.decision.summary = "Agent diagnostic self-test action";
    this.seedPacket("pkt-003-agent-solo", agentSolo);

    const tampered = createTamperedSummaryPacket();
    tampered.decision.summary = "Manipulated invoice processing";
    this.seedPacket("pkt-004-tampered", tampered);
  }

  public seedPacket(id: string, packet: EvidencePacket) {
    this.packets.set(id, packet);
  }

  public setLive(live: boolean) {
    this.liveState = live;
  }

  isLive(): boolean {
    return this.liveState;
  }

  async listEvidence(filter?: EvidenceFilter): Promise<EvidenceSummary[]> {
    const list: EvidenceSummary[] = [];
    for (const [id, packet] of this.packets.entries()) {
      const summary: EvidenceSummary = {
        id,
        tenant_id: "tenant-enterprise-primary",
        agent_id: packet.agent.aip_id,
        principal_id: packet.root_authority.principal_id,
        decision_summary: packet.decision.summary,
        trust_floor: packet.claimed_trust_floor,
        created_at: packet.decision.decided_at,
      };

      if (filter?.trust_floor && summary.trust_floor !== filter.trust_floor) {
        continue;
      }
      if (
        filter?.query &&
        !summary.decision_summary.toLowerCase().includes(filter.query.toLowerCase()) &&
        !summary.id.toLowerCase().includes(filter.query.toLowerCase())
      ) {
        continue;
      }
      list.push(summary);
    }
    return list;
  }

  async getEvidence(id: string): Promise<EvidencePacket> {
    const packet = this.packets.get(id);
    if (!packet) {
      throw new Error(`404: EvidencePacket ${id} not found`);
    }
    return JSON.parse(JSON.stringify(packet));
  }

  async verifyEvidence(
    packet: EvidencePacket,
    context?: VerificationContext
  ): Promise<VerificationReport> {
    const { DEFAULT_VERIFICATION_CONTEXT } = await import("../fixtures/evidence_packets.js");
    return verifyEvidencePacketOracle(packet, context || DEFAULT_VERIFICATION_CONTEXT);
  }

  async getAuthorityGraph(id: string): Promise<AccountabilityGraph> {
    const packet = await this.getEvidence(id);
    const report = await this.verifyEvidence(packet);
    return reconstructAccountabilityGraph(packet, report);
  }

  async exportBundle(id: string): Promise<Uint8Array> {
    const packet = await this.getEvidence(id);
    const bundleFiles = createSampleAuditBundleFiles(packet);
    const serialized = JSON.stringify(bundleFiles);
    return new TextEncoder().encode(serialized);
  }
}
