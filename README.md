<p align="center">
  <img src="docs/promptguard-banner.svg" alt="PromptGuard — Prompt Security for AI Coding Assistants" width="900"/>
</p>

<p align="center">
  <strong>Policy enforcement sidecar for AI-assisted development</strong> — validates prompts and tool calls before execution.
  <br/>
  Works with Claude Code, GitHub Copilot, Continue.dev, Cursor, and Codeium.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.11+-blue?logo=python" alt="Python 3.11+"/>
  <img src="https://img.shields.io/badge/deploy-one_command-brightgreen" alt="One command deploy"/>
  <img src="https://img.shields.io/badge/detection-37_patterns-orange" alt="37 patterns"/>
  <img src="https://img.shields.io/badge/license-MIT-blue" alt="MIT"/>
</p>

---

---

## How It Works

PromptGuard runs as a local FastAPI service. AI coding assistants send every tool call to PromptGuard via the PreToolUse hook (Claude Code), extension API, MCP gateway, or direct `/hook/pre-tool` call. The 8-stage pipeline inspects, classifies, redacts, and enforces policy — then returns a decision: allow, allow with redactions, quarantine, or block session.

```
                              ┌─────────────────────────────────────────────┐
                              │           PromptGuard Pipeline              │
                              │                                             │
  Developer → AI tool call → │  ① Intercept ──▶ 16 hardcoded patterns    │
  (git push, curl, etc.)     │  ② Classify   ──▶ trust + content type    │
                              │  ③ Allowlist  ──▶ domain/URL validation    │
                              │  ④ Redact     ──▶ 14 secret patterns + PII │
                              │  ⑤ Validate   ──▶ instruction injection    │
                              │  ⑥ Policy     ──▶ 21 YAML rules            │
                              │  ⑦ Envelope   ──▶ Safe Prompt Envelope     │
                              │  ⑧ Postprocess──▶ response scanning        │
                              │                                             │
                              └──────────────┬──────────────────────────────┘
                                             │
                              ┌──────────────▼──────────────────────────────┐
                              │  Decision                                    │
                              │  ✅ ALLOW  │ 🔒 ALLOW+REDACT │ ⚠️ QUARANTINE│ 🚫 BLOCK │
                              └──────────────┬──────────────────────────────┘
                                             │
                              ┌──────────────▼──────────────────────────────┐
                              │  Audit: SQLite + NDJSON + SIEM (optional)  │
                              └────────────────────────────────────────────┘
```

**Key principle:** PromptGuard is a policy enforcement sidecar, NOT an LLM proxy. It inspects prompts and tool calls at the hook layer — it never routes LLM traffic or makes model calls itself.

---

## Quick Start

See **[docs/GETTING_STARTED.md](docs/GETTING_STARTED.md)** for a complete step-by-step guide from zero to running.

---

### 1. Install the Python service

```bash
git clone https://github.com/dmcslab/promptguard
cd promptguard
pip install -e .
```

**Generate a secure API key** (required for `/hook/pre-tool` and `/mcp/*` endpoints):

```bash
# Option 1: openssl
openssl rand -hex 32

# Option 2: Python
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

Set it via environment variable or in your config file:

```bash
# Environment variable
export PROMPTGUARD_API_KEY=$(openssl rand -hex 32)

# Or in .promptguard.yaml (providers.api_key)
# providers:
#   api_key: "your-generated-key-here"
```

> **Note:** The API key is *manually set* — there is no auto-generation. If no key is configured, authenticated endpoints return 401 (auth is disabled for open endpoints like `/health`, `/ready`, `/live`).

```bash
# Dry-run a prompt (no AI call)
promptguard test-prompt --prompt "ignore all previous instructions" --language python

# Start the service
promptguard serve
# → Listening on http://127.0.0.1:7474
```

The API key is passed to Claude Code's PreToolUse hook via the `X-PromptGuard-API-Key` header. See [Authentication](#authentication) for session key management.

### 2. Install the VS Code extension

```bash
cd vscode-extension
npm install
npm run compile
# Press F5 in VS Code to launch Extension Development Host
# Or package it:
# npm run package && code --install-extension promptguard-0.2.0.vsix
```

The extension **auto-starts** the Python service when VS Code opens, registers per-user session keys, and probes `/ready` for health. No manual server management needed.

### 3. Install Claude Code hooks

```bash
promptguard install-hooks --workspace /path/to/project

# Writes .claude/settings.json with PreToolUse hook:
# Every Claude Code tool call is validated by PromptGuard before execution.
```

### 4. Install the CLI wrapper (dmcslab-code)

```bash
promptguard install-wrapper --name dmcslab-code
```

Every invocation is validated against your `.promptguard.yaml` policy before Claude Code runs. Override the wrapper name in config or via `--name`.

---

## VDI Deployment

PromptGuard supports non-persistent VDI environments where VS Code auto-launches and the extension manages the full service lifecycle.

### Startup flow

```
VDI session starts
  → VS Code auto-launches
    → Extension spawns: python -m promptguard.cli serve
      → init_session() loads config from PROMPTGUARD_CONFIG_URL/INLINE/file
      → SIEM forwarder starts (if siem_url configured)
      → Audit logger opens SQLite + NDJSON
    → /ready returns 200
  → Extension registers per-user API key via POST /session/key
```

### Config priority chain

Config loads in strict priority order (first wins):

```
CLI --config flag
  > PROMPTGUARD_CONFIG_URL    (HTTP fetch, 10s timeout, 1MB max)
    > PROMPTGUARD_CONFIG_INLINE (base64 decoded)
      > PROMPTGUARD_CONFIG_FILE  (~/.promptguard/config.yaml)
        > .promptguard.yaml in CWD
          > ~/.promptguard/config.yaml (default)
```

Config source is tracked in `config._config_source` and surfaced in `/health`.

### Per-workspace overrides

Set `PROMPTGUARD_OVERRIDE_PATH` to layer workspace-specific rules on top of the global config. Overrides are deep-merged with a severity floor — overrides cannot lower a CRITICAL rule to LOW.

### Authentication

Two tiers of API key authentication:

1. **Global key** — `PROMPTGUARD_API_KEY` env var or `providers.api_key` in YAML. Constant-time comparison with length normalization.
2. **Session keys** — Registered via `POST /session/key`. Stored as SHA-256 hashes (no plaintext in memory). Accepted as fallback when the global key doesn't match. Auto-expire after 24 hours.

Both are checked per-request via the `X-PromptGuard-API-Key` header.

### Shutdown flow

```
SIGTERM received
  → request_shutdown() sets flag
    → Shutdown middleware returns 503 for new requests
      → drain_and_shutdown() waits for in-flight (up to 30s)
        → SIEM forwarder flushes remaining queue
          → os._exit(0)

POST /session/reset  →  Fresh session without restart
```

---

## Detection Patterns

### Interceptor (Stage 1) — 16 hardcoded patterns, always on

| Pattern ID | Category | What it catches |
|---|---|---|
| PP-JB-001 | Jailbreak | "You are DAN", "ignore instructions" |
| PP-JB-002 | Jailbreak | "developer mode", "god mode", "unrestricted" |
| PP-AUTH-001 | Authority | "I am your developer", "I modified your rules" |
| PP-AUTH-002 | Authority | Social engineering coercion phrases |
| PP-CCA-001 | Context compliance | Microsoft March 2025 attack patterns |
| PP-LEAK-001 | System prompt extraction | "repeat your instructions", "output your prompt" |
| PP-OBFUSC-001 | Obfuscation | Base64-encoded instructions |
| PP-OBFUSC-002 | Obfuscation | Bracket stuffing (l[[i]]ke th[[i]]s) |
| PP-IND-001 | Indirect injection | `<!-- INJECT -->`, `<system>` markers in code/docs |
| PP-IND-002 | Indirect injection | Injection markers in markdown, HTML comments |
| PP-EXFIL-001 | Data exfiltration | Markdown image exfil, email exfil, "steal" keywords |
| PP-MULTITURN-001 | Multi-turn escalation | "As I said before", "per our previous conversation" |
| PP-INJ-001 | Injection | `\bDAN\b`, `\bjailbroken\b`, `\bunrestricted\b` |
| PP-INJ-002 | Injection | Classic prompt injection patterns |
| PP-INJ-003 | Injection | "system:" role override attempts |
| PP-INJ-004 | Injection | "ignore previous", "disregard above" |

All patterns are **pre-compiled at module load** for performance. A hard cap of 100,000 characters (`_MAX_PROMPT_LENGTH`) prevents regex DoS.

### Policy Rules (Stage 6) — 21 YAML-configured rules across 12+ families

Rules are declared in `.promptguard.yaml` with `applies_to` source filtering and per-severity thresholds. Critical findings always block; high is configurable. See `docs/JAILBREAK_REFERENCE.md` for the complete pattern reference and §12 mapping table.

**YAML patterns must use `|-` block scalars** — single/double quotes break on regex metacharacters like `\s`, `\d`, `\'`.

---

## Pipeline Stages

### Stage 1 — Intercept
- 16 pre-compiled regex patterns for jailbreak, authority, exfiltration, obfuscation, and injection
- Token size limit (configurable, default 8000)
- Language detection from file extension
- `_MAX_PROMPT_LENGTH = 100_000` hard cap prevents regex DoS

### Stage 2 — Classify
- Assigns `TrustLevel` (1–7 priority hierarchy) to every context block
- Detects risky file references (`.env`, `id_rsa`, `kubeconfig`, `*.pem`, etc.)
- Detects external URLs in lower-trust blocks

### Stage 3 — Allowlist
- Strips non-allow-listed URLs from lower-trust context blocks
- Default approved: `api.anthropic.com`, `api.openai.com`, `pypi.org`, `npmjs.com`, etc.

### Stage 4 — Redact
- 14 built-in secret patterns (OpenAI, Anthropic, AWS, GitHub, Stripe, JWT, DB URLs, etc.)
- Shannon entropy scan for unrecognized high-entropy tokens
- PII: email, SSN, phone, credit card
- Context deduplication by `(source, content_hash)` after stages 1 and 5

### Stage 5 — Instruction File Validator
- Scans `CLAUDE.md`, `copilot-instructions.md`, `.cursorrules`, etc.
- Detects injection, exfiltration, privilege escalation, jailbreak personas
- Sanitizes (removes flagged lines) or blocks session

### Stage 6 — Policy Engine
- 4-way decision: `ALLOW` / `ALLOW_WITH_REDACTION` / `QUARANTINE` / `BLOCK_SESSION`
- 21 YAML-configured rules with `applies_to` source filtering
- Per-severity thresholds (critical always blocks; high configurable)

### Stage 7 — Safe Prompt Envelope
Seven ordered sections, composed by trust priority:

```
[1. SECURITY_POLICY]          ← non-overridable, always first
[2. PLATFORM_CONFIGURATION]
[3. APPROVED_PROJECT_GUIDANCE]  ← sanitized instruction file
[4. DEVELOPER_TASK]             ← sanitized prompt
[5. SANITIZED_CONTEXT]          ← each block labeled with trust metadata
[6. QUARANTINE_SUMMARY]         ← what was excluded and why
[7. SECURITY_FOOTER]            ← final policy reminder
```

SHA-256 hash of the envelope is returned and stored in the audit log.

### Stage 8 — Response Postprocessor
Scans AI response for dangerous patterns before surfacing to developer.
Annotates with inline `⚠ PromptGuard` warnings.

---

## Enterprise Audit & SIEM

Every pipeline execution is logged to:

| Sink | Format | Config |
|---|---|---|
| SQLite | Structured rows | `audit.log_path` (default: `~/.promptguard/audit.db`) |
| NDJSON file | Elastic Common Schema | `audit.json_log_path` |
| SIEM HTTP | Batched POST with retry | `audit.siem_url` |

### SIEM forwarding

Configure in `.promptguard.yaml`:

```yaml
audit:
  enabled: true
  log_path: ~/.promptguard/audit.db
  json_log_path: ~/.promptguard/audit.jsonl
  retention_days: 90
  siem_url: "https://siem.example.com/api/v1/ingest"
  siem_auth_header: "Authorization: Bearer your-token-here"
  siem_batch_size: 50          # events per batch (default: 50)
  siem_flush_interval: 5.0    # seconds between flushes (default: 5.0)
  siem_max_retries: 3         # max retries per batch (default: 3)
```

Features: batched HTTP POST, exponential backoff with jitter, queue overflow protection (10K max, drops oldest), thread-safe background flush thread. Auth header supports `"Header-Name: value"` format. URL validation requires `http(s)` scheme.

Audit values are sanitized: control characters stripped (except tab/newline/CR), HTML entities escaped, SQL wildcards escaped, truncated to 4096 chars.

---

## REST API

### Meta endpoints

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/health` | No | Service health + rules count + config source + SIEM stats |
| GET | `/ready` | No | Readiness probe (checks shutdown state + config loaded) |
| GET | `/live` | No | Liveness probe (always 200 if process is up) |

### Core endpoints

| Method | Path | Auth | Description |
|---|---|---|---|
| POST | `/hook/pre-tool` | API key | Claude Code PreToolUse hook endpoint |
| POST | `/complete` | API key | Guarded completion (blocking) |
| POST | `/stream` | API key | Guarded completion (SSE streaming) |
| POST | `/validate/instruction-file` | API key | Validate a single instruction file |
| GET | `/validate/workspace` | API key | Scan all instruction files |

### Management endpoints

| Method | Path | Auth | Description |
|---|---|---|---|
| POST | `/reload` | API key | Hot-reload policy config |
| GET | `/audit/stats` | API key | Aggregate audit statistics (incl. SIEM stats) |
| GET | `/audit/recent` | API key | Recent audit events |
| POST | `/audit/prune` | API key | Delete old audit records |
| GET | `/policy/signing-status` | API key | Policy bundle signing status |

### Session & lifecycle endpoints

| Method | Path | Auth | Description |
|---|---|---|---|
| POST | `/session/reset` | No | Reset all in-memory state (fresh VDI session) |
| POST | `/session/key` | Global key | Register a per-user session API key |
| DELETE | `/session/key` | Global key | Revoke a session API key |
| GET | `/session/keys` | Global key | List registered session keys (hashes only) |

### MCP endpoints

| Method | Path | Auth | Description |
|---|---|---|---|
| POST | `/mcp/initialize` | API key | MCP protocol initialization |
| POST | `/mcp/tools/list` | API key | List available MCP tools |
| POST | `/mcp/tools/call` | API key | Execute an MCP tool |

---

## CLI Reference

```bash
promptguard serve                          # Start service (default: 127.0.0.1:7474)
  --host HOST --port PORT
  --config PATH                            # Config file override
  --reload                                 # Dev: auto-reload on code changes

promptguard validate --config PATH         # Validate config file

promptguard validate-file \
  --file CLAUDE.md \
  --provider claude_code \
  --output sanitized_CLAUDE.md            # Validate + optionally write sanitized version

promptguard scan-workspace \
  --workspace /path/to/project            # Scan all provider instruction files

promptguard install-hooks \
  --workspace /path/to/project \
  --port 7474                             # Write Claude Code PreToolUse hooks

promptguard install-wrapper \
  --name dmcslab-code                     # Install CLI wrapper script

promptguard test-prompt \
  --prompt "your prompt here" \
  --language python \
  --provider claude_code                  # Dry-run pipeline, no AI call

promptguard audit stats                   # Show audit statistics
promptguard audit recent                  # Show last 20 audit events
promptguard audit prune                   # Delete records older than retention_days
```

---

## VS Code Extension

### Commands

| Command | Description |
|---|---|
| `PromptGuard: Open Panel` | Provider-agnostic guarded prompt relay |
| `PromptGuard: Ask AI About Selection` | Send selection to panel |
| `PromptGuard: Scan Workspace Instruction Files` | Re-scan all provider files |
| `PromptGuard: Validate Current File` | Validate the file in active editor |
| `PromptGuard: Install Claude Code Hooks` | Write `.claude/settings.json` hooks |
| `PromptGuard: Reload Policy Rules` | Hot-reload without restart |
| `PromptGuard: Show Audit Stats` | Summary notification |
| `PromptGuard: Show Service Log` | Open service output channel |
| `PromptGuard: Restart Service` | Kill and restart Python process |

### VS Code Settings

```json
{
  "promptguard.port": 7474,
  "promptguard.pythonPath": "",
  "promptguard.configPath": "",
  "promptguard.configUrl": "",
  "promptguard.configInline": "",
  "promptguard.sessionId": "",
  "promptguard.apiKey": "",
  "promptguard.anthropicApiKey": "",
  "promptguard.openaiApiKey": "",
  "promptguard.defaultProvider": "generic",
  "promptguard.streamResponses": true,
  "promptguard.autoScanOnOpen": true,
  "promptguard.showViolationDecorations": true
}
```

The extension auto-registers the per-user API key with the PromptGuard service on startup via `POST /session/key`.

---

## CI Integration

### GitHub Actions

Add `.github/workflows/promptguard-ci.yaml` to your repository. The workflow:

1. **Validates instruction files** — Scans `CLAUDE.md`, `.cursorrules`, `copilot-instructions.md`, etc.
2. **Fails closed** — Any `BLOCK_SESSION` or `QUARANTINE` result fails the check
3. **Validates Claude Code hooks** — Confirms `.claude/settings.json` points to PromptGuard
4. **Service health check** — Verifies PromptGuard installs and starts cleanly

Only triggers on changes to instruction files, avoiding unnecessary runs on code-only commits.

### Bitbucket Pipelines

Copy `bitbucket-pipelines.yml` to your repo root. Same validation pipeline, configured for Bitbucket self-hosted runners.

---

## Provider Support

| Provider | Instruction File Validated | Runtime Hook | LM API Wrap |
|---|---|---|---|
| Claude Code | `CLAUDE.md`, `.claude/CLAUDE.md` | ✅ PreToolUse | via Panel |
| GitHub Copilot | `.github/copilot-instructions.md` | ❌ | via Panel |
| Continue.dev | `.continuerc.json`, `.continue/config.json` | ❌ | via Panel |
| Cursor | `.cursorrules`, `.cursor/rules.md` | ❌ | via Panel |
| Codeium/Windsurf | `.codeium/instructions.md`, `.windsurf/rules.md` | ❌ | via Panel |

All providers benefit from instruction file validation. Claude Code additionally gets runtime hook interception and the MCP gateway.

---

## Security Hardening

PromptGuard v0.2 includes defense-in-depth protections:

| Protection | Detail |
|---|---|
| Regex DoS mitigation | All patterns pre-compiled at module load + 100K char hard cap |
| Path traversal | `_sanitize_path()` resolves `..`, rejects absolute paths outside cwd/home |
| Config size limit | 1MB max on YAML config files |
| Timing-safe auth | `hmac.compare_digest()` with length normalization for API key comparison |
| Log sanitization | Control chars stripped, HTML entities escaped, SQL wildcards escaped, 4096 char truncation |
| Log path validation | `_validate_log_path()` ensures paths resolve under home/tmp/cwd |
| SIEM URL validation | `field_validator` requires `http(s)` scheme and hostname |
| SIEM header safety | Rejects `Content-Length`, `Host`, `Transfer-Encoding` injection |
| Context deduplication | `_dedup_context_blocks()` by `(source, content_hash)` after stages 1 and 5 |
| Shutdown drain | SIGTERM → 503 for new requests → drain in-flight → flush SIEM → exit |
| Rate limiting | 60 req/min default, periodic sweep of stale keys |

---

## Project Structure

```
promptguard/
├── promptguard/
│   ├── main.py                    FastAPI app + all routes + shutdown middleware
│   ├── models.py                  Full type system (TrustLevel, Decision, Envelope, etc.)
│   ├── config.py                  Config loader (YAML + env vars + overrides + URL/inline injection)
│   ├── lifecycle.py               VDI session lifecycle (init, reset, shutdown, drain)
│   ├── session_keys.py            Per-user session key management (SHA-256 hashed, TTL, thread-safe)
│   ├── providers_registry.py       Provider → instruction file + hook mapping
│   ├── ai_providers.py             Anthropic / OpenAI / Ollama adapters
│   ├── signing.py                  Policy bundle signing and verification
│   ├── cli.py                      CLI: serve, validate, scan, install-hooks, audit
│   ├── pipeline/
│   │   ├── __init__.py             Orchestrator (8 stages + context dedup)
│   │   ├── interceptor.py          Stage 1 — 16 pre-compiled patterns + size limit
│   │   ├── classifier.py           Stage 2 — trust + content type
│   │   ├── allowlist.py            Stage 3 — URL allow-list
│   │   ├── redactor.py             Stage 4 — 14 secret patterns + entropy + PII
│   │   ├── instr_validator.py      Stage 5 — instruction file validator
│   │   ├── policy.py               Stage 6 — 4-way decision engine
│   │   ├── envelope.py             Stage 7 — Safe Prompt Envelope (7 sections + SHA-256)
│   │   └── postprocessor.py        Stage 8 — response scanner
│   └── audit/
│       ├── logger.py               SQLite + NDJSON + SIEM forwarding audit logger
│       └── siem_forwarder.py        Batched HTTP POST with retry + backoff + overflow protection
├── vscode-extension/
│   ├── src/
│   │   ├── extension.ts            Activation + all commands
│   │   ├── serviceManager.ts       Auto-spawn + VDI config injection + session key registration
│   │   ├── workspaceGuardian.ts    Instruction file watcher + validator
│   │   ├── client.ts               Typed API client (health/ready/live/reset/session keys)
│   │   ├── ui.ts                   Status bar + violation decorations
│   │   └── panel.ts                Webview sidebar panel
│   ├── package.json
│   └── tsconfig.json
├── docs/
│   ├── GETTING_STARTED.md          Step-by-step setup guide
│   ├── JAILBREAK_REFERENCE.md      Pattern reference + §12 mapping table
│   ├── SCENARIOS.md                End-to-end scenario diagrams (Mermaid)
│   └── FLOW_DIAGRAMS.md            Flow + pipeline + lifecycle diagrams (Mermaid)
├── tests/
│   ├── test_pipeline.py            Core pipeline tests
│   ├── test_config_injection.py   Config priority chain + URL/inline injection tests
│   ├── test_override_config.py     Per-workspace override + severity floor tests
│   ├── test_lifecycle.py           VDI session lifecycle tests
│   ├── test_siem_forwarder.py      SIEM batching + retry + auth + stats tests
│   ├── test_session_keys.py        Session key CRUD + thread safety + endpoint tests
│   └── ...                         Total: 281 tests
├── .promptguard.yaml               Example annotated config (21 rules)
├── .github/workflows/promptguard-ci.yaml
├── bitbucket-pipelines.yml
└── pyproject.toml
```

---

## Running Tests

```bash
pip install -e ".[dev]"
pytest tests/ -v
# 281 tests across all 8 stages + config injection + overrides + lifecycle + SIEM + session keys
```

---

## Detection Pattern Reference

See `docs/JAILBREAK_REFERENCE.md` for the complete pattern catalog, intent documentation, and the §12 mapping table showing which patterns are enforced in both `interceptor.py` (stage 1, always-on) and `.promptguard.yaml` (stage 6, config-driven).

---

## Security Pattern Transparency

PromptGuard detects a well-known class of prompt injection attacks sometimes called "jailbreaks." Pattern names like **DAN**, **jailbreak**, and **developer mode** reflect language that has appeared in real-world adversarial prompts targeting AI coding assistants. These are defense-in-depth measures — PromptGuard's primary security boundary is the 8-stage pipeline and envelope design, not pattern matching alone.

---

## License

See [LICENSE](LICENSE) for the full text.