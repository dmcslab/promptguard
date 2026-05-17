/**
 * PromptGuard Webview Panel
 *
 * Provider-agnostic sidebar panel:
 * - Provider selector (Claude Code, Copilot, Continue, Cursor, Codeium)
 * - Streaming guarded prompt input
 * - Decision badge (ALLOW / REDACTED / QUARANTINE / BLOCKED)
 * - Violation list with severity + rule ID
 * - Envelope hash display for audit traceability
 */
import * as vscode from "vscode";
import type { PromptGuardClient, PolicyViolation } from "./client";

const PROVIDERS = [
  { value: "claude_code",    label: "Claude Code" },
  { value: "github_copilot", label: "GitHub Copilot" },
  { value: "continue_dev",   label: "Continue.dev" },
  { value: "cursor",         label: "Cursor" },
  { value: "codeium",        label: "Codeium" },
  { value: "generic",        label: "Generic" },
];

export class PromptGuardPanel {
  public static currentPanel: PromptGuardPanel | undefined;
  private readonly _panel: vscode.WebviewPanel;
  private readonly _client: PromptGuardClient;
  private _abort: AbortController | undefined;

  static createOrShow(
    extensionUri: vscode.Uri,
    client: PromptGuardClient
  ): PromptGuardPanel {
    const col = vscode.ViewColumn.Beside;
    if (PromptGuardPanel.currentPanel) {
      PromptGuardPanel.currentPanel._panel.reveal(col);
      return PromptGuardPanel.currentPanel;
    }
    const panel = vscode.window.createWebviewPanel(
      "promptguardPanel", "PromptGuard",
      col,
      { enableScripts: true, retainContextWhenHidden: true }
    );
    PromptGuardPanel.currentPanel = new PromptGuardPanel(panel, client);
    return PromptGuardPanel.currentPanel;
  }

  private constructor(panel: vscode.WebviewPanel, client: PromptGuardClient) {
    this._panel = panel;
    this._client = client;
    this._panel.webview.html = this._html();
    this._panel.onDidDispose(() => {
      PromptGuardPanel.currentPanel = undefined;
    });
    this._panel.webview.onDidReceiveMessage(this._onMsg.bind(this));
  }

  prefillPrompt(text: string, language?: string): void {
    this._panel.webview.postMessage({ type: "prefill", text, language: language ?? "" });
    this._panel.reveal(vscode.ViewColumn.Beside);
  }

  private async _onMsg(msg: Record<string, unknown>): Promise<void> {
    switch (msg.type) {
      case "submit": await this._submit(msg); break;
      case "cancel": this._abort?.abort(); break;
      case "getStats": this._sendStats(); break;
      case "reload":  this._reload(); break;
    }
  }

  private async _submit(msg: Record<string, unknown>): Promise<void> {
    const prompt = String(msg.prompt ?? "").trim();
    if (!prompt) return;

    this._abort = new AbortController();
    this._post({ type: "streamStart" });

    const editor = vscode.window.activeTextEditor;
    const cfg = vscode.workspace.getConfiguration("promptguard");

    const req = {
      prompt,
      provider:   String(msg.provider ?? cfg.get("defaultProvider", "generic")),
      model:      String(msg.model ?? "").trim() || undefined,
      language:   String(msg.language ?? "").trim() || editor?.document.languageId,
      file_path:  editor?.document.fileName,
      repo_root:  vscode.workspace.workspaceFolders?.[0]?.uri.fsPath,
    };

    try {
      const useStream = cfg.get<boolean>("streamResponses", true);
      if (useStream) {
        for await (const chunk of this._client.streamComplete(req, this._abort.signal)) {
          if ("text" in chunk)          this._post({ type: "chunk", text: chunk.text });
          else if ("blocked" in chunk)  { this._post({ type: "blocked", decision: chunk.decision, reason: chunk.reason }); break; }
          else if ("warnings" in chunk) this._post({ type: "warnings", violations: chunk.warnings });
          else if ("envelope_hash" in chunk) this._post({ type: "envelopeHash", hash: chunk.envelope_hash });
          else if ("error" in chunk)    { this._post({ type: "error", message: chunk.error }); break; }
        }
      } else {
        const resp = await this._client.complete(req);
        if (resp.decision === "BLOCK_SESSION") {
          this._post({ type: "blocked", decision: resp.decision, reason: resp.block_reason });
        } else {
          this._post({ type: "chunk", text: resp.content });
          if (resp.violations.length) this._post({ type: "warnings", violations: resp.violations });
          if (resp.envelope_hash) this._post({ type: "envelopeHash", hash: resp.envelope_hash });
        }
      }
    } catch (e: unknown) {
      if ((e as Error).name !== "AbortError") {
        this._post({ type: "error", message: String(e) });
      }
    } finally {
      this._post({ type: "streamEnd" });
    }
  }

  private async _sendStats(): Promise<void> {
    const stats = await this._client.auditStats().catch(() => ({ enabled: false }));
    this._post({ type: "stats", stats });
  }

  private async _reload(): Promise<void> {
    const r = await this._client.reloadPolicy().catch((e) => ({ status: "error", rules_loaded: 0, error: String(e) }));
    this._post({ type: "reloaded", result: r });
  }

  private _post(msg: Record<string, unknown>): void {
    this._panel.webview.postMessage(msg);
  }

  private _html(): string {
    const providerOptions = PROVIDERS
      .map((p) => `<option value="${p.value}">${p.label}</option>`)
      .join("");

    return /* html */`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>PromptGuard</title>
<style>
  :root {
    --pg-gold:    #c9a84c;
    --pg-red:     #f85149;
    --pg-orange:  #e3722a;
    --pg-yellow:  #d29922;
    --pg-blue:    #58a6ff;
    --pg-green:   #3fb950;
    --pg-border:  var(--vscode-widget-border, #444);
    --pg-input:   var(--vscode-input-background);
    --pg-btn:     var(--vscode-button-background);
    --pg-btn-fg:  var(--vscode-button-foreground);
    --pg-bg:      var(--vscode-editor-background);
    --pg-fg:      var(--vscode-editor-foreground);
    --pg-side:    var(--vscode-sideBar-background);
  }
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: var(--vscode-font-family);
    font-size: var(--vscode-font-size, 13px);
    background: var(--pg-bg); color: var(--pg-fg);
    display: flex; flex-direction: column; height: 100vh; overflow: hidden;
  }

  /* ── Header ── */
  #header {
    display: flex; align-items: center; gap: 8px;
    padding: 8px 14px; border-bottom: 1px solid var(--pg-border);
    background: var(--pg-side); flex-shrink: 0;
  }
  #header h1 { font-size: 13px; font-weight: 700; color: var(--pg-gold); flex: 1; letter-spacing: 0.03em; }
  #svc-dot { width: 8px; height: 8px; border-radius: 50%; background: var(--pg-green); flex-shrink: 0; transition: background 0.3s; }
  #svc-dot.error { background: var(--pg-red); }
  #svc-dot.warn  { background: var(--pg-yellow); }
  #svc-dot.spin  { animation: pulse 1.2s infinite; background: var(--pg-blue); }
  @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.4} }

  /* ── Controls ── */
  #controls {
    display: flex; gap: 6px; padding: 8px 14px; flex-wrap: wrap;
    border-bottom: 1px solid var(--pg-border); background: var(--pg-side); flex-shrink: 0;
  }
  select, input[type="text"] {
    background: var(--pg-input); color: var(--pg-fg);
    border: 1px solid var(--pg-border); border-radius: 4px;
    padding: 3px 7px; font-size: 12px; outline: none;
  }
  select:focus, input:focus { border-color: var(--pg-gold); }

  /* ── Decision badge ── */
  #decision-bar {
    display: none; align-items: center; gap: 8px;
    padding: 5px 14px; font-size: 11px; font-weight: 600;
    border-bottom: 1px solid var(--pg-border); flex-shrink: 0;
  }
  #decision-bar.visible { display: flex; }
  #decision-badge {
    border-radius: 4px; padding: 2px 8px; font-size: 11px;
    font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em;
  }
  #decision-badge.ALLOW                { background: var(--pg-green);  color: #000; }
  #decision-badge.ALLOW_WITH_REDACTION { background: var(--pg-yellow); color: #000; }
  #decision-badge.QUARANTINE           { background: var(--pg-orange); color: #fff; }
  #decision-badge.BLOCK_SESSION        { background: var(--pg-red);    color: #fff; }
  #envelope-hash { color: var(--vscode-descriptionForeground); font-size: 10px; font-family: monospace; }

  /* ── Response ── */
  #response-area {
    flex: 1; overflow-y: auto; padding: 12px 14px;
    font-family: var(--vscode-editor-font-family, monospace);
    font-size: 12px; line-height: 1.65; white-space: pre-wrap; word-break: break-word;
  }
  .placeholder { color: var(--vscode-descriptionForeground); font-style: italic; }

  /* ── Blocked banner ── */
  #blocked-banner {
    display: none; margin: 0; padding: 10px 14px;
    background: rgba(248,81,73,0.12); border-top: 1px solid var(--pg-red);
    border-bottom: 1px solid var(--pg-red); color: var(--pg-red); font-size: 12px;
  }
  #blocked-banner.visible { display: block; }

  /* ── Violations ── */
  #violations {
    display: none; border-top: 1px solid var(--pg-border);
    max-height: 150px; overflow-y: auto; flex-shrink: 0;
  }
  #violations.visible { display: block; }
  #violations-header {
    padding: 4px 14px; font-size: 11px; font-weight: 600;
    color: var(--vscode-descriptionForeground);
    background: var(--pg-side); border-bottom: 1px solid var(--pg-border);
  }
  .violation {
    display: flex; gap: 8px; align-items: flex-start;
    padding: 5px 14px; border-bottom: 1px solid var(--pg-border); font-size: 11px;
  }
  .violation:last-child { border-bottom: none; }
  .badge {
    border-radius: 3px; padding: 1px 6px; font-size: 10px; font-weight: 700;
    text-transform: uppercase; letter-spacing: 0.04em; flex-shrink: 0; line-height: 1.6;
  }
  .badge.critical, .badge.high   { background: var(--pg-red);    color: #fff; }
  .badge.medium                  { background: var(--pg-yellow);  color: #000; }
  .badge.low, .badge.info        { background: var(--pg-blue);    color: #000; }
  .v-content { flex: 1; }
  .v-msg { display: block; }
  .v-meta { font-size: 10px; color: var(--vscode-descriptionForeground); }

  /* ── Input ── */
  #input-area {
    border-top: 1px solid var(--pg-border); padding: 10px 14px;
    display: flex; flex-direction: column; gap: 8px;
    background: var(--pg-side); flex-shrink: 0;
  }
  textarea {
    width: 100%; min-height: 76px; max-height: 200px; resize: vertical;
    background: var(--pg-input); color: var(--pg-fg);
    border: 1px solid var(--pg-border); border-radius: 4px;
    padding: 8px; font-family: inherit; font-size: 12px; outline: none;
    transition: border-color 0.2s;
  }
  textarea:focus { border-color: var(--pg-gold); }
  #btn-row { display: flex; gap: 8px; }
  button {
    border: none; border-radius: 4px; padding: 5px 14px;
    font-size: 12px; font-family: inherit; cursor: pointer;
  }
  #btn-submit { background: var(--pg-btn); color: var(--pg-btn-fg); flex: 1; font-weight: 600; }
  #btn-submit:disabled { opacity: 0.45; cursor: not-allowed; }
  #btn-cancel { display: none; background: transparent; color: var(--pg-red); border: 1px solid var(--pg-red); }
  #btn-cancel.visible { display: block; }
  #btn-reload { background: transparent; color: var(--vscode-descriptionForeground); border: 1px solid var(--pg-border); }
  #char-count { font-size: 10px; color: var(--vscode-descriptionForeground); text-align: right; }
</style>
</head>
<body>

<div id="header">
  <div id="svc-dot" class="spin"></div>
  <h1>⚔ PromptGuard</h1>
  <span id="rules-label" style="font-size:10px;color:var(--vscode-descriptionForeground)"></span>
</div>

<div id="controls">
  <select id="sel-provider" title="AI Provider">${providerOptions}</select>
  <input id="inp-model"    type="text" placeholder="model override" style="width:130px" title="Model (leave blank for default)"/>
  <input id="inp-language" type="text" placeholder="language"       style="width:90px"  title="Language hint"/>
</div>

<div id="decision-bar">
  <span id="decision-badge">ALLOW</span>
  <span id="envelope-hash"></span>
</div>

<div id="blocked-banner"></div>

<div id="response-area">
  <span class="placeholder">Guarded AI response will appear here…</span>
</div>

<div id="violations">
  <div id="violations-header">PromptGuard Findings</div>
</div>

<div id="input-area">
  <textarea id="prompt-input" placeholder="Describe your task… (Enter to send, Shift+Enter for newline)"></textarea>
  <div id="char-count"></div>
  <div id="btn-row">
    <button id="btn-submit">Send ⇒</button>
    <button id="btn-cancel">✕ Cancel</button>
    <button id="btn-reload" title="Hot-reload policy rules">↺ Rules</button>
  </div>
</div>

<script>
(function() {
  const vscode = acquireVsCodeApi();

  // Elements
  const responseArea   = document.getElementById('response-area');
  const violationsDiv  = document.getElementById('violations');
  const blockedBanner  = document.getElementById('blocked-banner');
  const promptInput    = document.getElementById('prompt-input');
  const btnSubmit      = document.getElementById('btn-submit');
  const btnCancel      = document.getElementById('btn-cancel');
  const btnReload      = document.getElementById('btn-reload');
  const svcDot         = document.getElementById('svc-dot');
  const rulesLabel     = document.getElementById('rules-label');
  const decisionBar    = document.getElementById('decision-bar');
  const decisionBadge  = document.getElementById('decision-badge');
  const envelopeHash   = document.getElementById('envelope-hash');
  const charCount      = document.getElementById('char-count');

  let streaming = false;

  // ── Helpers ──────────────────────────────────────────────────────────────
  function esc(s) {
    return String(s)
      .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
      .replace(/"/g,'&quot;');
  }

  function setStreaming(on) {
    streaming = on;
    btnSubmit.disabled = on;
    btnCancel.classList.toggle('visible', on);
    svcDot.className = on ? 'spin' : '';
  }

  function clearPanel() {
    responseArea.innerHTML = '<span class="placeholder">Guarded AI response will appear here…</span>';
    violationsDiv.innerHTML = '<div id="violations-header">PromptGuard Findings</div>';
    violationsDiv.classList.remove('visible');
    blockedBanner.textContent = '';
    blockedBanner.classList.remove('visible');
    decisionBar.classList.remove('visible');
    envelopeHash.textContent = '';
  }

  function appendText(text) {
    if (responseArea.querySelector('.placeholder')) responseArea.innerHTML = '';
    // Accumulate as plain text to preserve code formatting
    const node = document.createTextNode(text);
    responseArea.appendChild(node);
    responseArea.scrollTop = responseArea.scrollHeight;
  }

  function showDecision(decision) {
    decisionBadge.textContent = decision.replace(/_/g,' ');
    decisionBadge.className = 'badge ' + decision;
    decisionBar.classList.add('visible');
  }

  function showViolations(violations) {
    if (!violations || !violations.length) return;
    violationsDiv.classList.add('visible');
    for (const v of violations) {
      const row = document.createElement('div');
      row.className = 'violation';
      row.innerHTML =
        '<span class="badge ' + esc(v.severity) + '">' + esc(v.severity) + '</span>' +
        '<span class="v-content">' +
          '<span class="v-msg">' + esc(v.message) + '</span>' +
          '<span class="v-meta">' + esc(v.rule_id) + ' · ' + esc(v.decision) + '</span>' +
        '</span>';
      violationsDiv.appendChild(row);
    }
    // Infer decision from worst violation
    const order = ['ALLOW','ALLOW_WITH_REDACTION','QUARANTINE','BLOCK_SESSION'];
    const worst = violations.reduce((w, v) => {
      const d = v.decision;
      return order.indexOf(d) > order.indexOf(w) ? d : w;
    }, 'ALLOW');
    showDecision(worst);
  }

  // ── Submit ────────────────────────────────────────────────────────────────
  function submit() {
    const prompt = promptInput.value.trim();
    if (!prompt || streaming) return;
    clearPanel();
    setStreaming(true);
    vscode.postMessage({
      type:     'submit',
      prompt,
      provider: document.getElementById('sel-provider').value,
      model:    document.getElementById('inp-model').value.trim() || undefined,
      language: document.getElementById('inp-language').value.trim() || undefined,
    });
  }

  btnSubmit.addEventListener('click', submit);
  btnCancel.addEventListener('click', () => vscode.postMessage({ type: 'cancel' }));
  btnReload.addEventListener('click', () => {
    btnReload.textContent = '↻…';
    vscode.postMessage({ type: 'reload' });
  });
  promptInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); submit(); }
  });
  promptInput.addEventListener('input', () => {
    const len = promptInput.value.length;
    charCount.textContent = len > 0 ? len + ' chars' : '';
  });

  // ── Message handler ───────────────────────────────────────────────────────
  window.addEventListener('message', (e) => {
    const msg = e.data;
    switch (msg.type) {
      case 'prefill':
        promptInput.value = msg.text || '';
        if (msg.language) document.getElementById('inp-language').value = msg.language;
        promptInput.focus();
        charCount.textContent = promptInput.value.length + ' chars';
        break;

      case 'streamStart':
        clearPanel();
        showDecision('ALLOW');
        break;

      case 'chunk':
        appendText(msg.text);
        break;

      case 'blocked':
        blockedBanner.textContent =
          '🚫 ' + (msg.decision || 'BLOCKED') + ': ' + (msg.reason || 'Policy violation');
        blockedBanner.classList.add('visible');
        showDecision(msg.decision || 'BLOCK_SESSION');
        svcDot.className = 'error';
        break;

      case 'warnings':
        showViolations(msg.violations);
        svcDot.className = 'warn';
        break;

      case 'envelopeHash':
        envelopeHash.textContent = 'env:' + (msg.hash || '').slice(0, 12) + '…';
        envelopeHash.title = 'Envelope hash: ' + msg.hash;
        break;

      case 'error':
        responseArea.innerHTML =
          '<span style="color:var(--pg-red)">Error: ' + esc(msg.message) + '</span>';
        svcDot.className = 'error';
        break;

      case 'streamEnd':
        setStreaming(false);
        svcDot.className = '';
        // If no decision shown yet, default ALLOW
        if (!decisionBar.classList.contains('visible')) showDecision('ALLOW');
        break;

      case 'stats': {
        const s = msg.stats;
        if (s && s.enabled) {
          const text = [
            s.total        != null ? s.total        + ' requests' : null,
            s.blocked      != null ? s.blocked      + ' blocked'  : null,
            s.quarantined  != null ? s.quarantined  + ' quarantined' : null,
            s.total_redactions != null ? s.total_redactions + ' redactions' : null,
          ].filter(Boolean).join(' · ');
          rulesLabel.textContent = text;
        }
        break;
      }

      case 'reloaded':
        btnReload.textContent = '↺ Rules';
        if (msg.result && msg.result.rules_loaded != null) {
          rulesLabel.textContent = msg.result.rules_loaded + ' rules';
        }
        break;

      case 'serverReady':
        svcDot.className = '';
        rulesLabel.textContent = (msg.rulesLoaded || 0) + ' rules';
        break;
    }
  });

  // Request initial stats
  vscode.postMessage({ type: 'getStats' });
})();
</script>
</body>
</html>`;
  }
}
