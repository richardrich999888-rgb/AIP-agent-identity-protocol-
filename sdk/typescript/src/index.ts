/** Read-only service client. No cryptography or agent telemetry implementation. */
export interface Agent {
  agent_id: string;
  evidence_count: number;
  latest_created_at_ms: number;
  identity_source: "agent_signed_evidence_packet";
  independent_identity_verified: false;
}
export interface EvidenceMetadata {
  evidence_id: string;
  agent_id: string;
  created_at_ms: number;
  decision_id: string;
  action_count: number;
  evidence_source: "agent_signed_evidence_packet";
  independent_execution_verified: false;
}
export interface Page<T> {items: T[]; limit: number; offset: number; next_offset: number | null}
export interface Coverage {status: "unavailable"; reason: string; independent_execution_verified: false}
export interface Verification {evidence_id: string; verification_scope: "integrity_only"; report: Record<string, unknown>; limitations: string[]}
export interface Access {tenant_id: string; key_id: string; role: "reader" | "machine" | "admin"}
export interface Options {timeoutMs?: number; retries?: number; maxResponseBytes?: number; allowLoopbackHttp?: boolean}

export class VanianError extends Error {
  readonly status: number;
  readonly code: string;
  constructor(status: number, code: string) {
    super(`VANIAN API ${code} (HTTP ${status})`);
    this.status = status;
    this.code = code;
  }
}

function identifier(value: string): string {
  if (!value || value.length > 256 || /[\x00-\x1f\x7f]/.test(value) || value === "." || value === "..") {
    throw new Error("invalid identifier");
  }
  return encodeURIComponent(value);
}

function pageQuery(limit = 50, offset = 0): string {
  if (!Number.isInteger(limit) || limit < 1 || limit > 100 || !Number.isInteger(offset) || offset < 0 || offset > 100000) {
    throw new Error("invalid pagination");
  }
  return `?limit=${limit}&offset=${offset}`;
}

export class VanianClient {
  private readonly origin: string;
  private readonly credentialProvider: () => string | Promise<string>;
  private readonly timeoutMs: number;
  private readonly retries: number;
  private readonly maxResponseBytes: number;

  constructor(baseUrl: string, credentialProvider: () => string | Promise<string>, options: Options = {}) {
    const url = new URL(baseUrl);
    if (url.username || url.password || url.search || url.hash || url.pathname !== "/") throw new Error("baseUrl must be a service origin");
    const loopback = ["127.0.0.1", "[::1]", "localhost"].includes(url.hostname);
    if (url.protocol !== "https:" && !(url.protocol === "http:" && options.allowLoopbackHttp && loopback)) throw new Error("HTTPS required");
    this.origin = url.origin;
    this.credentialProvider = credentialProvider;
    this.timeoutMs = options.timeoutMs ?? 10000;
    this.retries = options.retries ?? 1;
    this.maxResponseBytes = options.maxResponseBytes ?? 1048576;
    if (!Number.isInteger(this.timeoutMs) || this.timeoutMs < 1 || this.timeoutMs > 120000 || !Number.isInteger(this.retries) || this.retries < 0 || this.retries > 3 || !Number.isInteger(this.maxResponseBytes) || this.maxResponseBytes < 1 || this.maxResponseBytes > 16777216) throw new Error("invalid client bounds");
  }

  private async get<T>(path: string): Promise<T> {
    for (let attempt = 0; attempt <= this.retries; attempt++) {
      const token = await this.credentialProvider();
      if (typeof token !== "string" || !token || /\s/.test(token)) throw new Error("invalid bearer credential");
      try {
        const response = await fetch(this.origin + path, {
          headers: {Authorization: `Bearer ${token}`, Accept: "application/json"},
          redirect: "error", signal: AbortSignal.timeout(this.timeoutMs),
        });
        if (!response.ok) {
          await response.body?.cancel();
          if ([429, 502, 503, 504].includes(response.status) && attempt < this.retries) {
            await new Promise(resolve => setTimeout(resolve, 100 * 2 ** attempt));
            continue;
          }
          throw new VanianError(response.status, "request_refused");
        }
        if (response.headers.get("content-type")?.split(";")[0].trim() !== "application/json" || !response.body) {
          await response.body?.cancel();
          throw new VanianError(response.status, "invalid_content_type");
        }
        const reader = response.body.getReader();
        let total = 0;
        const chunks: Uint8Array[] = [];
        try {
          for (;;) {
            const {done, value} = await reader.read();
            if (done) break;
            total += value.length;
            if (total > this.maxResponseBytes) throw new VanianError(response.status, "response_too_large");
            chunks.push(value);
          }
        } finally {
          await reader.cancel();
          reader.releaseLock();
        }
        const bytes = new Uint8Array(total);
        let offset = 0;
        for (const chunk of chunks) {bytes.set(chunk, offset); offset += chunk.length;}
        let data: unknown;
        try {data = JSON.parse(new TextDecoder("utf-8", {fatal: true}).decode(bytes));}
        catch {throw new VanianError(response.status, "invalid_json");}
        if (!data || typeof data !== "object" || Array.isArray(data)) throw new VanianError(response.status, "invalid_response");
        return data as T;
      } catch (error) {
        if (error instanceof VanianError) throw error;
        if (attempt === this.retries) throw new VanianError(0, "transport_failed");
        await new Promise(resolve => setTimeout(resolve, 100 * 2 ** attempt));
      }
    }
    throw new Error("unreachable");
  }

  access(): Promise<Access> {return this.get("/v1/access");}
  listAgents(limit = 50, offset = 0): Promise<Page<Agent>> {return this.get("/v1/agents" + pageQuery(limit, offset));}
  getAgent(agentId: string): Promise<Agent> {return this.get("/v1/agents/" + identifier(agentId));}
  getAgentActivity(agentId: string, limit = 50, offset = 0): Promise<Page<EvidenceMetadata> & {agent_id: string}> {return this.get("/v1/agents/" + identifier(agentId) + "/activity" + pageQuery(limit, offset));}
  getVerdict(verdictId: string): Promise<Record<string, unknown>> {return this.get("/v1/verdicts/" + identifier(verdictId));}
  getEvidenceMetadata(evidenceId: string): Promise<EvidenceMetadata> {return this.get("/v1/evidence/" + identifier(evidenceId) + "/metadata");}
  verifyEvidence(evidenceId: string): Promise<Verification> {return this.get("/v1/evidence/" + identifier(evidenceId) + "/verification");}
  getCoverage(): Promise<Coverage> {return this.get("/v1/coverage");}
  getObservationMetadata(observationId: string): Promise<Record<string, unknown>> {return this.get("/v1/observations/" + identifier(observationId) + "/metadata");}
  verifyObservation(observationId: string): Promise<Record<string, unknown>> {return this.get("/v1/observations/" + identifier(observationId) + "/verification");}
  getHealth(): Promise<Record<string, unknown>> {return this.get("/v1/health");}
}
