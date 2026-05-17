import * as vscode from "vscode";
import type { PolicyViolation } from "./client";

export class StatusBar implements vscode.Disposable {
  private readonly item: vscode.StatusBarItem;

  constructor() {
    this.item = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
    this.item.command = "promptguard.openPanel";
    this.setConnecting();
    this.item.show();
  }

  setConnecting(): void {
    this._set("$(loading~spin) PG", "PromptGuard: Starting service...");
  }

  setServiceReady(): void {
    this._set("$(shield) PG", "PromptGuard: Service ready — scanning workspace...");
  }

  setServiceError(msg: string): void {
    this._set("$(shield-x) PG", `PromptGuard: ${msg}`, "statusBarItem.errorBackground");
  }

  setScanning(): void {
    this._set("$(loading~spin) PG: Scanning", "PromptGuard: Scanning instruction files...");
  }

  setNoInstructionFiles(): void {
    this._set("$(shield) PG: No files", "PromptGuard: No AI instruction files found in workspace");
  }

  setWorkspaceClean(fileCount: number): void {
    this._set(
      `$(shield-check) PG: ${fileCount} file${fileCount !== 1 ? "s" : ""} ✓`,
      `PromptGuard: ${fileCount} instruction file(s) validated — all clear`
    );
  }

  setWorkspaceWarning(count: number): void {
    this._set(
      `$(warning) PG: ${count} warning${count !== 1 ? "s" : ""}`,
      `PromptGuard: ${count} instruction file warning(s) — check Problems panel`,
      "statusBarItem.warningBackground"
    );
  }

  setWorkspaceBlocked(count: number, reason?: string): void {
    this._set(
      `$(shield-x) PG: BLOCKED`,
      `PromptGuard: ${count} instruction file(s) BLOCKED${reason ? " — " + reason : ""}`,
      "statusBarItem.errorBackground"
    );
  }

  setPolicyUnsigned(mode: string): void {
    this._set(
      `$(warning) PG: UNSIGNED`,
      `PromptGuard: Policy bundle not signed (mode=${mode}) — run: promptguard sign-policy`,
      "statusBarItem.warningBackground"
    );
  }

  setPolicySigningFailed(error: string): void {
    this._set(
      `$(shield-x) PG: SIG FAIL`,
      `PromptGuard: Policy signature INVALID — ${error}`,
      "statusBarItem.errorBackground"
    );
  }

  setPolicySigned(signedAt?: string): void {
    const when = signedAt ? ` (${signedAt.slice(0, 10)})` : "";
    this._set(
      `$(verified) PG: Signed${when}`,
      `PromptGuard: Policy bundle signature verified${when}`
    );
  }

  setProcessing(): void {
    this._set("$(loading~spin) PG: Processing", "PromptGuard: Processing prompt...");
  }

  setIdle(): void {
    this._set("$(shield) PG", "PromptGuard: Ready — click to open panel");
  }

  private _set(text: string, tooltip: string, bgColor?: string): void {
    this.item.text = text;
    this.item.tooltip = tooltip;
    this.item.backgroundColor = bgColor
      ? new vscode.ThemeColor(bgColor)
      : undefined;
  }

  dispose(): void {
    this.item.dispose();
  }
}

// ── Violation decorations ─────────────────────────────────────────────────────

const _errorDec = vscode.window.createTextEditorDecorationType({
  overviewRulerColor: new vscode.ThemeColor("editorError.foreground"),
  overviewRulerLane: vscode.OverviewRulerLane.Right,
});
const _warnDec = vscode.window.createTextEditorDecorationType({
  overviewRulerColor: new vscode.ThemeColor("editorWarning.foreground"),
  overviewRulerLane: vscode.OverviewRulerLane.Right,
});

export function applyViolationDecorations(
  editor: vscode.TextEditor,
  violations: PolicyViolation[]
): void {
  const errorDecs: vscode.DecorationOptions[] = [];
  const warnDecs: vscode.DecorationOptions[] = [];
  const line = Math.max(0, editor.selection.end.line);
  const lineEnd = editor.document.lineAt(line).range.end;

  for (const v of violations) {
    const icon =
      v.severity === "critical" || v.severity === "high" ? "🔴" :
      v.severity === "medium" ? "🟡" : "🔵";
    const dec: vscode.DecorationOptions = {
      range: new vscode.Range(lineEnd, lineEnd),
      renderOptions: { after: { contentText: `  ${icon} ${v.rule_id}: ${v.message.slice(0, 80)}`, margin: "0 0 0 1rem" } },
      hoverMessage: new vscode.MarkdownString(
        `**[${v.severity.toUpperCase()}] ${v.rule_id}** (${v.decision})\n\n${v.message}`
      ),
    };
    if (v.severity === "critical" || v.severity === "high") {
      errorDecs.push(dec);
    } else {
      warnDecs.push(dec);
    }
  }
  editor.setDecorations(_errorDec, errorDecs);
  editor.setDecorations(_warnDec, warnDecs);
}

export function clearDecorations(editor: vscode.TextEditor): void {
  editor.setDecorations(_errorDec, []);
  editor.setDecorations(_warnDec, []);
}
