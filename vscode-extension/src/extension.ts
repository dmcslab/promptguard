/**
 * PromptGuard VS Code Extension
 *
 * Activation flow:
 *  1. ServiceManager starts the Python service (auto, no Docker)
 *  2. WorkspaceGuardian scans all provider instruction files
 *  3. StatusBar reflects health of both service + workspace
 *  4. Panel available for guarded prompt relay
 *  5. Hook installer writes .claude/settings.json for Claude Code
 */
import * as vscode from "vscode";
import * as cp from "child_process";
import { ServiceManager } from "./serviceManager";
import { WorkspaceGuardian, FileStatus } from "./workspaceGuardian";
import { PromptGuardClient } from "./client";
import { StatusBar } from "./ui";
import { PromptGuardPanel } from "./panel";
import { PromptGuardSettingsProvider, registerSettingsCommands } from "./settings";

let serviceManager: ServiceManager;
let workspaceGuardian: WorkspaceGuardian;
let statusBar: StatusBar;
let client: PromptGuardClient;
let settingsProvider: PromptGuardSettingsProvider;

export async function activate(context: vscode.ExtensionContext): Promise<void> {
  const cfg = vscode.workspace.getConfiguration("promptguard");
  const port = cfg.get<number>("port", 7474);
  const serviceUrl = cfg.get<string>("serviceUrl", `http://localhost:${port}`);
  const failClosed = cfg.get<boolean>("failClosed", true);
  const apiKey = cfg.get<string>("apiKey", "");
  const providers = cfg.get<Record<string, boolean>>("providers", {});

  // ── Bootstrap ─────────────────────────────────────────────────────────────
  serviceManager = new ServiceManager(port);
  client = new PromptGuardClient(serviceUrl, { failClosed, providers, apiKey });
  statusBar = new StatusBar();

  workspaceGuardian = new WorkspaceGuardian(
    client,
    (results: FileStatus[]) => _onScanComplete(results)
  );

  // ── Start service ─────────────────────────────────────────────────────────
  serviceManager.onStateChange((state) => {
    if (state === "running") {
      statusBar.setServiceReady();
      settingsProvider.setServiceOnline(true);
      // Run workspace scan and signing check concurrently
      Promise.all([
        workspaceGuardian.scan(),
        _checkSigningStatus(client, statusBar),
      ]).then(([results]) => _onScanComplete(results));
    } else if (state === "error") {
      statusBar.setServiceError("Service failed — check PromptGuard Service log");
      settingsProvider.setServiceOnline(false);
    } else if (state === "starting") {
      statusBar.setConnecting();
      settingsProvider.setServiceOnline(false);
    }
  });

  // Auto-start (non-blocking)
  serviceManager.start().catch(() => {
    statusBar.setServiceError("Failed to start service");
  });

  // ── Settings TreeView ─────────────────────────────────────────────────────
  settingsProvider = new PromptGuardSettingsProvider(client);
  const settingsView = vscode.window.createTreeView("promptguardSettings", {
    treeDataProvider: settingsProvider,
    showCollapseAll: true,
  });
  registerSettingsCommands(context, settingsProvider);

  // Wire file scan results into settings provider
  const origOnScan = _onScanComplete;
  // Override to also push to settings
  // (We'll call setFileStatuses after scan)

  // ── Commands ──────────────────────────────────────────────────────────────
  context.subscriptions.push(
    // Open the prompt relay panel
    vscode.commands.registerCommand("promptguard.openPanel", () => {
      PromptGuardPanel.createOrShow(context.extensionUri, client);
    }),

    // Ask AI about selected code
    vscode.commands.registerCommand("promptguard.askAIWithSelection", async () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor) return;
      const selection = editor.document.getText(editor.selection);
      if (!selection) {
        vscode.window.showWarningMessage("PromptGuard: No text selected.");
        return;
      }
      const panel = PromptGuardPanel.createOrShow(context.extensionUri, client);
      panel.prefillPrompt(selection, editor.document.languageId);
    }),

    // Re-scan workspace instruction files
    vscode.commands.registerCommand("promptguard.scanWorkspace", async () => {
      statusBar.setScanning();
      const results = await workspaceGuardian.scan();
      _onScanComplete(results);
      vscode.window.showInformationMessage(
        `PromptGuard: Scanned ${results.length} instruction file(s)`
      );
    }),

    // Validate instruction file in active editor
    vscode.commands.registerCommand("promptguard.validateCurrentFile", async () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor) return;
      const content = editor.document.getText();
      const filePath = editor.document.fileName;
      const provider = _guessProvider(filePath);

      try {
        const resp = await client.validateInstructionFile({ content, file_path: filePath, provider });
        const icon = _decisionIcon(resp.decision);
        vscode.window.showInformationMessage(
          `${icon} PromptGuard: ${filePath.split("/").pop()} → ${resp.decision} (${resp.findings.length} finding(s))`
        );
      } catch (e) {
        vscode.window.showErrorMessage(`PromptGuard validation failed: ${e}`);
      }
    }),

    // Install Claude Code hooks
    vscode.commands.registerCommand("promptguard.installClaudeHooks", async () => {
      const root = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
      if (!root) return;

      try {
        cp.execSync(`promptguard install-hooks --workspace "${root}" --port ${port}`);
        vscode.window.showInformationMessage(
          "PromptGuard: Claude Code PreToolUse hooks installed in .claude/settings.json"
        );
      } catch (e) {
        vscode.window.showErrorMessage(`Hook installation failed: ${e}`);
      }
    }),

    // Reload policy
    vscode.commands.registerCommand("promptguard.reloadPolicy", async () => {
      try {
        const result = await client.reloadPolicy();
        vscode.window.showInformationMessage(
          `PromptGuard: Policy reloaded — ${result.rules_loaded} rules`
        );
      } catch (e) {
        vscode.window.showErrorMessage(`Reload failed: ${e}`);
      }
    }),

    // Show signing status
    vscode.commands.registerCommand("promptguard.signingStatus", async () => {
      try {
        const sig = await client.signingStatus();
        const icon = sig.verified ? "✅" : sig.mode === "strict" ? "🔴" : "🟡";
        const detail = [
          `Mode: ${sig.mode}`,
          sig.signed_at ? `Signed: ${sig.signed_at.slice(0, 19)}` : "Not signed",
          sig.config_path ? `Config: ${sig.config_path}` : "",
          sig.error ? `Error: ${sig.error}` : "",
        ].filter(Boolean).join(" | ");

        if (sig.verified) {
          vscode.window.showInformationMessage(`${icon} PromptGuard: ${sig.message}  (${detail})`);
        } else {
          vscode.window.showWarningMessage(
            `${icon} PromptGuard: ${sig.message}`,
            "How to sign"
          ).then((c) => {
            if (c === "How to sign") {
              vscode.window.showInformationMessage(
                "Run in your terminal:\n" +
                "  1. promptguard generate-key\n" +
                "  2. promptguard sign-policy --config .promptguard.yaml"
              );
            }
          });
        }
      } catch (e) {
        vscode.window.showErrorMessage(`Signing status check failed: ${e}`);
      }
    }),

    // Show audit stats
    vscode.commands.registerCommand("promptguard.auditStats", async () => {
      try {
        const stats = await client.auditStats();
        vscode.window.showInformationMessage(
          `Audit: ${stats["total"] ?? 0} total | ${stats["blocked"] ?? 0} blocked | ` +
          `${stats["quarantined"] ?? 0} quarantined | ${stats["total_redactions"] ?? 0} redactions`
        );
      } catch (e) {
        vscode.window.showErrorMessage(`Audit stats failed: ${e}`);
      }
    }),

    // Show service log
    vscode.commands.registerCommand("promptguard.showServiceLog", () => {
      serviceManager.showLog();
    }),

    // Restart service
    vscode.commands.registerCommand("promptguard.restartService", async () => {
      statusBar.setConnecting();
      const ok = await serviceManager.restart();
      if (ok) {
        statusBar.setServiceReady();
        vscode.window.showInformationMessage("PromptGuard: Service restarted");
      } else {
        statusBar.setServiceError("Restart failed");
      }
    }),

    // Config change handler
    vscode.workspace.onDidChangeConfiguration((e) => {
      if (e.affectsConfiguration("promptguard.serviceUrl") ||
          e.affectsConfiguration("promptguard.port") ||
          e.affectsConfiguration("promptguard.failClosed") ||
          e.affectsConfiguration("promptguard.providers") ||
          e.affectsConfiguration("promptguard.apiKey")) {
        vscode.window.showInformationMessage(
          "PromptGuard: Config changed — restart service to apply.",
          "Restart"
        ).then((c) => {
          if (c === "Restart") vscode.commands.executeCommand("promptguard.restartService");
        });
      }
    }),

    // Workspace folder change → rescan
    vscode.workspace.onDidChangeWorkspaceFolders(() => {
      workspaceGuardian.scan();
    }),

    serviceManager,
    workspaceGuardian,
    statusBar,
  );
}

export function deactivate(): void {
  serviceManager?.stop().catch(() => {});
}

// ── Helpers ───────────────────────────────────────────────────────────────────

async function _checkSigningStatus(
  client: PromptGuardClient,
  bar: StatusBar
): Promise<void> {
  try {
    const sig = await client.signingStatus();
    if (!sig.verified) {
      if (sig.mode === "strict") {
        bar.setPolicySigningFailed(sig.error ?? "Unknown error");
        vscode.window.showErrorMessage(
          `🔴 PromptGuard: Policy signature INVALID — ${sig.error}`,
          "How to fix"
        ).then((c) => {
          if (c === "How to fix") {
            vscode.window.showInformationMessage(
              "Run:\n  1. promptguard generate-key\n  2. promptguard sign-policy --config .promptguard.yaml"
            );
          }
        });
      } else if (sig.mode === "warn") {
        bar.setPolicyUnsigned(sig.mode);
        // Silent warning — don't interrupt the developer with a popup on every open
      }
      // mode=off: no action
    } else if (sig.signed_at) {
      // Policy is signed — show briefly then revert to workspace scan result
      bar.setPolicySigned(sig.signed_at);
      setTimeout(() => bar.setServiceReady(), 3000);
    }
  } catch {
    // Service not yet ready or endpoint not available — ignore silently
  }
}

function _onScanComplete(results: FileStatus[]): void {
  settingsProvider?.setFileStatuses(results);
  if (!results.length) {
    statusBar.setNoInstructionFiles();
    return;
  }

  const worst = workspaceGuardian.worstDecision();
  const blocked = results.filter((r) => r.decision === "BLOCK_SESSION");
  const quarantined = results.filter((r) => r.decision === "QUARANTINE");
  const warned = results.filter((r) => r.decision === "ALLOW_WITH_REDACTION");

  if (blocked.length > 0) {
    statusBar.setWorkspaceBlocked(blocked.length, blocked[0].findings[0]?.message);
    vscode.window.showErrorMessage(
      `PromptGuard: 🔴 ${blocked.length} instruction file(s) BLOCKED. ` +
      "AI session should not proceed — check Problems panel.",
      "Show Problems"
    ).then((c) => {
      if (c === "Show Problems") vscode.commands.executeCommand("workbench.actions.view.problems");
    });
  } else if (quarantined.length > 0) {
    statusBar.setWorkspaceWarning(quarantined.length + warned.length);
  } else if (warned.length > 0) {
    statusBar.setWorkspaceWarning(warned.length);
  } else {
    statusBar.setWorkspaceClean(results.length);
  }
}

function _guessProvider(filePath: string): string {
  const lower = filePath.toLowerCase();
  if (lower.includes("claude")) return "claude_code";
  if (lower.includes("copilot")) return "github_copilot";
  if (lower.includes("continuerc") || lower.includes(".continue/")) return "continue_dev";
  if (lower.includes("cursorrules") || lower.includes(".cursor/")) return "cursor";
  if (lower.includes("codeium") || lower.includes("windsurf")) return "codeium";
  return "generic";
}

function _decisionIcon(decision: string): string {
  return { ALLOW: "✅", ALLOW_WITH_REDACTION: "🟡", QUARANTINE: "🟠", BLOCK_SESSION: "🔴" }[decision] ?? "❓";
}
