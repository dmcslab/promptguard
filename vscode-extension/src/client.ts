/** * PromptGuard API Client * Typed fetch wrapper — works with any provider. */

export interface PolicyViolation {
  rule_id: string;
  severity: string;
  message: string;
  decision: string;
  stage: string;
}

export interface ProxyRequest {
  prompt: string;
  file_path?: string;
  language?: string;
  provider?: string;
  model?: string;
  stream?: boolean;
  repo_root?: string;
  branch?: string;
  instruction_file_content?: string;
  extra_params?: Record<string, unknown>;
}

export interface ProxyResponse {
  content: string;
  decision: string;
  block_reason?: string;
  violations: PolicyViolation[];
  redaction_count: number;
  envelope_hash?: string;
  audit_id?: string;
}

export interface InstructionFileRequest {
  content: string;
  file_path: string;
  provider: string;
  repo_root?: string;
}

export interface InstructionFileResponse {
  decision: string;
  findings: PolicyViolation[];
  sanitized_content?: string;
  provider: string;
  file_path: string;
}

export interface WorkspaceScanResult {
  workspace_root: string;
  detected_providers: string[];
  instruction_file_results: Array<{
    provider: string;
    file: string;
    decision: string;
    finding_count: number;
    findings: PolicyViolation[];
  }>;
}

export interface HealthResponse {
  status: string;
  version: string;
  rules_loaded: number;
  providers_supported: string[];
}

export type StreamChunk =
  | { text: string }
  | { blocked: true; decision: string; reason: string }
  | { warnings: PolicyViolation[] }
  | { envelope_hash: string }
  | { error: string };


export interface SigningStatus {
  verified: boolean;
  mode: string;
  config_path?: string;
  sig_path?: string;
  signed_at?: string;
  error?: string;
  message: string;
}

export interface ClientOptions {
  failClosed?: boolean;
  providers?: Record<string, boolean>;
  apiKey?: string;
}

export class PromptGuardClient {
  private baseUrl: string;
  private options: ClientOptions;

  constructor(baseUrl = "http://127.0.0.1:7474", options?: ClientOptions) {
    this.baseUrl = baseUrl.replace(/\/$/, "");
    this.options = options ?? {};
  }

  private get headers(): Record<string, string> {
    const h: Record<string, string> = { "Content-Type": "application/json" };
    if (this.options.apiKey) {
      h["X-PromptGuard-API-Key"] = this.options.apiKey;
    }
    return h;
  }

  async health(): Promise<HealthResponse> {
    const res = await fetch(`${this.baseUrl}/health`);
    if (!res.ok) throw new Error(`Health check failed: ${res.status}`);
    return res.json() as Promise<HealthResponse>;
  }

  async complete(req: ProxyRequest): Promise<ProxyResponse> {
    const res = await fetch(`${this.baseUrl}/complete`, {
      method: "POST",
      headers: this.headers,
      body: JSON.stringify(req),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: res.statusText }));
      throw new Error(`PromptGuard ${res.status}: ${(err as any).detail}`);
    }
    return res.json() as Promise<ProxyResponse>;
  }

  async *streamComplete(
    req: ProxyRequest,
    signal?: AbortSignal
  ): AsyncGenerator<StreamChunk> {
    const res = await fetch(`${this.baseUrl}/stream`, {
      method: "POST",
      headers: this.headers,
      body: JSON.stringify({ ...req, stream: true }),
      signal,
    });
    if (!res.ok || !res.body) throw new Error(`Stream failed: ${res.status}`);

    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split("\n");
      buffer = lines.pop() ?? "";
      for (const line of lines) {
        if (!line.startsWith("data: ")) continue;
        const data = line.slice(6);
        if (data === "[DONE]") return;
        try { yield JSON.parse(data) as StreamChunk; } catch { /* skip */ }
      }
    }
  }

  async validateInstructionFile(
    req: InstructionFileRequest
  ): Promise<InstructionFileResponse> {
    const res = await fetch(`${this.baseUrl}/validate/instruction-file`, {
      method: "POST",
      headers: this.headers,
      body: JSON.stringify(req),
    });
    if (!res.ok) throw new Error(`Validation failed: ${res.status}`);
    return res.json() as Promise<InstructionFileResponse>;
  }

  async scanWorkspace(workspaceRoot: string): Promise<WorkspaceScanResult> {
    const url = new URL(`${this.baseUrl}/validate/workspace`);
    url.searchParams.set("workspace_root", workspaceRoot);
    const res = await fetch(url.toString());
    if (!res.ok) throw new Error(`Workspace scan failed: ${res.status}`);
    return res.json() as Promise<WorkspaceScanResult>;
  }

  async reloadPolicy(): Promise<{ status: string; rules_loaded: number }> {
    const res = await fetch(`${this.baseUrl}/reload`, { method: "POST" });
    if (!res.ok) throw new Error(`Reload failed: ${res.status}`);
    return res.json() as Promise<{ status: string; rules_loaded: number }>;
  }

  /** Readiness probe — returns 503 if shutting down or no config. */
  async ready(): Promise<{ status: string; session: Record<string, unknown> }> {
    const res = await fetch(`${this.baseUrl}/ready`);
    if (!res.ok) throw new Error(`Readiness check failed: ${res.status}`);
    return res.json() as Promise<{ status: string; session: Record<string, unknown> }>;
  }

  /** Liveness probe — always 200 if process is alive. */
  async liveness(): Promise<{ status: string }> {
    const res = await fetch(`${this.baseUrl}/live`);
    if (!res.ok) throw new Error(`Liveness check failed: ${res.status}`);
    return res.json() as Promise<{ status: string }>;
  }

  /** Reset session state for a fresh VDI session. */
  async sessionReset(): Promise<{ status: string; session: Record<string, unknown> }> {
    const res = await fetch(`${this.baseUrl}/session/reset`, { method: "POST" });
    if (!res.ok) throw new Error(`Session reset failed: ${res.status}`);
    return res.json() as Promise<{ status: string; session: Record<string, unknown> }>;
  }

  /** Register a per-user session API key. */
  async registerSessionKey(key: string, source = "vdi_session"): Promise<{ status: string; source: string }> {
    const res = await fetch(`${this.baseUrl}/session/key`, {
      method: "POST",
      headers: { ...this.headers, "Content-Type": "application/json" },
      body: JSON.stringify({ key, source }),
    });
    if (!res.ok) throw new Error(`Register session key failed: ${res.status}`);
    return res.json() as Promise<{ status: string; source: string }>;
  }

  /** Revoke a session API key. */
  async revokeSessionKey(key: string): Promise<{ status: string }> {
    const res = await fetch(`${this.baseUrl}/session/key`, {
      method: "DELETE",
      headers: { ...this.headers, "Content-Type": "application/json" },
      body: JSON.stringify({ key }),
    });
    if (!res.ok) throw new Error(`Revoke session key failed: ${res.status}`);
    return res.json() as Promise<{ status: string }>;
  }

  /** List all registered session keys (hashes only). */
  async listSessionKeys(): Promise<{ keys: Array<Record<string, unknown>> }> {
    const res = await fetch(`${this.baseUrl}/session/keys`, { headers: this.headers });
    if (!res.ok) throw new Error(`List session keys failed: ${res.status}`);
    return res.json() as Promise<{ keys: Array<Record<string, unknown>> }>;
  }

  async auditStats(): Promise<Record<string, unknown>> {
    const res = await fetch(`${this.baseUrl}/audit/stats`);
    if (!res.ok) throw new Error(`Audit stats failed: ${res.status}`);
    return res.json() as Promise<Record<string, unknown>>;
  }

  async auditRecent(): Promise<{ events: unknown[] }> {
    const res = await fetch(`${this.baseUrl}/audit/recent`);
    if (!res.ok) throw new Error(`Audit recent failed: ${res.status}`);
    return res.json() as Promise<{ events: unknown[] }>;
  }

  async signingStatus(): Promise<SigningStatus> {
    const res = await fetch(`${this.baseUrl}/policy/signing-status`);
    if (!res.ok) throw new Error(`Signing status failed: ${res.status}`);
    return res.json() as Promise<SigningStatus>;
  }
}
