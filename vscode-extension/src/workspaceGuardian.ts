/**
 * WorkspaceGuardian
 *
 * Runs automatically when a workspace opens (or instruction files change).
 * Validates ALL provider instruction files found in the workspace and sets
 * per-file diagnostics in VS Code's Problems panel.
 *
 * Providers scanned:
 *   - Claude Code         → CLAUDE.md, .claude/CLAUDE.md
 *   - GitHub Copilot      → .github/copilot-instructions.md
 *   - Continue.dev        → .continuerc.json, .continue/config.json
 *   - Cursor              → .cursorrules
 *   - Codeium/Windsurf    → .codeium/instructions.md, .windsurf/rules.md
 */
import * as vscode from "vscode";
import * as fs from "fs";
import * as path from "path";
import type { PromptGuardClient } from "./client";

interface FileStatus {
  provider: string;
  file: string;
  decision: "ALLOW" | "ALLOW_WITH_REDACTION" | "QUARANTINE" | "BLOCK_SESSION";
  findings: Array<{ rule_id: string; severity: string; message: string; decision: string }>;
}

const INSTRUCTION_FILE_PATHS: Array<{ provider: string; relative: string }> = [
  { provider: "claude_code",    relative: "CLAUDE.md" },
  { provider: "claude_code",    relative: ".claude/CLAUDE.md" },
  { provider: "github_copilot", relative: ".github/copilot-instructions.md" },
  { provider: "github_copilot", relative: ".copilot-instructions.md" },
  { provider: "continue_dev",   relative: ".continuerc.json" },
  { provider: "continue_dev",   relative: ".continue/config.json" },
  { provider: "cursor",         relative: ".cursorrules" },
  { provider: "cursor",         relative: ".cursor/rules.md" },
  { provider: "codeium",        relative: ".codeium/instructions.md" },
  { provider: "codeium",        relative: ".windsurf/rules.md" },
];

const DECISION_SEVERITY: Record<string, vscode.DiagnosticSeverity> = {
  ALLOW:                vscode.DiagnosticSeverity.Information,
  ALLOW_WITH_REDACTION: vscode.DiagnosticSeverity.Warning,
  QUARANTINE:           vscode.DiagnosticSeverity.Warning,
  BLOCK_SESSION:        vscode.DiagnosticSeverity.Error,
};

const FINDING_SEVERITY: Record<string, vscode.DiagnosticSeverity> = {
  critical: vscode.DiagnosticSeverity.Error,
  high:     vscode.DiagnosticSeverity.Error,
  medium:   vscode.DiagnosticSeverity.Warning,
  low:      vscode.DiagnosticSeverity.Information,
  info:     vscode.DiagnosticSeverity.Information,
};

export class WorkspaceGuardian implements vscode.Disposable {
  private readonly _diagnostics: vscode.DiagnosticCollection;
  private readonly _watchers: vscode.FileSystemWatcher[] = [];
  private _lastResults: FileStatus[] = [];
  private _scanInProgress = false;

  constructor(
    private readonly _client: PromptGuardClient,
    private readonly _onScanComplete: (results: FileStatus[]) => void
  ) {
    this._diagnostics = vscode.languages.createDiagnosticCollection("promptguard");
    this._startFileWatchers();
  }

  /** Scan all workspace instruction files immediately. */
  async scan(workspaceRoot?: string): Promise<FileStatus[]> {
    if (this._scanInProgress) return this._lastResults;
    this._scanInProgress = true;

    const root = workspaceRoot
      ?? vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
    if (!root) {
      this._scanInProgress = false;
      return [];
    }

    const results: FileStatus[] = [];
    this._diagnostics.clear();

    for (const { provider, relative } of INSTRUCTION_FILE_PATHS) {
      const absPath = path.join(root, relative);
      if (!fs.existsSync(absPath)) continue;

      let content: string;
      try {
        content = fs.readFileSync(absPath, "utf-8");
      } catch {
        continue;
      }

      try {
        const resp = await this._client.validateInstructionFile({
          content,
          file_path: absPath,
          provider,
        });

        const status: FileStatus = {
          provider: resp.provider,
          file: absPath,
          decision: resp.decision as FileStatus["decision"],
          findings: resp.findings,
        };
        results.push(status);
        this._applyDiagnostics(absPath, resp.findings, content);
      } catch (e) {
        // Service not reachable — skip silently, status bar shows error state
        continue;
      }
    }

    this._lastResults = results;
    this._scanInProgress = false;
    this._onScanComplete(results);
    return results;
  }

  /** Get the worst decision across all scanned files. */
  worstDecision(): FileStatus["decision"] {
    const order: FileStatus["decision"][] = [
      "ALLOW", "ALLOW_WITH_REDACTION", "QUARANTINE", "BLOCK_SESSION",
    ];
    return this._lastResults.reduce<FileStatus["decision"]>(
      (worst, r) =>
        order.indexOf(r.decision) > order.indexOf(worst) ? r.decision : worst,
      "ALLOW"
    );
  }

  getResults(): FileStatus[] {
    return this._lastResults;
  }

  private _applyDiagnostics(
    filePath: string,
    findings: FileStatus["findings"],
    content: string
  ): void {
    const uri = vscode.Uri.file(filePath);
    if (!findings.length) {
      this._diagnostics.set(uri, []);
      return;
    }

    const lines = content.split("\n");
    const diags: vscode.Diagnostic[] = findings.map((f) => {
      // Try to find the matching line for better UX; default to line 0
      const matchLine = lines.findIndex((l) =>
        f.message && l.toLowerCase().includes((f.rule_id || "").toLowerCase().slice(3, 10))
      );
      const line = matchLine >= 0 ? matchLine : 0;
      const range = new vscode.Range(line, 0, line, lines[line]?.length ?? 0);

      const diag = new vscode.Diagnostic(
        range,
        `[PromptGuard ${f.rule_id}] ${f.message}`,
        FINDING_SEVERITY[f.severity] ?? vscode.DiagnosticSeverity.Warning
      );
      diag.source = "PromptGuard";
      diag.code = f.rule_id;
      return diag;
    });

    this._diagnostics.set(uri, diags);
  }

  private _startFileWatchers(): void {
    const patterns = [
      "CLAUDE.md",
      ".claude/CLAUDE.md",
      ".github/copilot-instructions.md",
      ".copilot-instructions.md",
      ".continuerc.json",
      ".continue/config.json",
      ".cursorrules",
      ".cursor/rules.md",
      ".codeium/instructions.md",
      ".windsurf/rules.md",
    ];

    for (const pattern of patterns) {
      const watcher = vscode.workspace.createFileSystemWatcher(
        new vscode.RelativePattern(
          vscode.workspace.workspaceFolders?.[0]?.uri ?? vscode.Uri.file(""),
          pattern
        )
      );
      const rescan = () => setTimeout(() => this.scan(), 500);
      watcher.onDidChange(rescan);
      watcher.onDidCreate(rescan);
      watcher.onDidDelete(rescan);
      this._watchers.push(watcher);
    }
  }

  dispose(): void {
    this._diagnostics.dispose();
    this._watchers.forEach((w) => w.dispose());
  }
}

export type { FileStatus };
