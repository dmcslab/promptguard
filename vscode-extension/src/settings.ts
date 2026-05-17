/**
 * PromptGuard Settings Provider
 *
 * TreeView-based settings panel showing:
 *  - Service connection status
 *  - Fail-closed toggle
 *  - Per-provider enable/disable
 *  - Detected instruction files with validation status
 *  - API key (masked)
 */
import * as vscode from "vscode";
import { PromptGuardClient } from "./client";
import { FileStatus } from "./workspaceGuardian";

// ── Tree item types ──────────────────────────────────────────────────────────

interface PGTreeItem extends vscode.TreeItem {
  children?: PGTreeItem[];
}

// ── Provider ────────────────────────────────────────────────────────────────

export class PromptGuardSettingsProvider
  implements vscode.TreeDataProvider<PGTreeItem>
{
  private _onDidTreeChange = new vscode.EventEmitter<void>();
  onDidChangeTreeData = this._onDidTreeChange.event;

  private client: PromptGuardClient;
  private fileStatuses: FileStatus[] = [];
  private serviceOnline = false;

  constructor(client: PromptGuardClient) {
    this.client = client;

    // Refresh when config changes
    vscode.workspace.onDidChangeConfiguration((e) => {
      if (e.affectsConfiguration("promptguard")) {
        this.refresh();
      }
    });
  }

  refresh(): void {
    this._onDidTreeChange.fire();
  }

  setFileStatuses(statuses: FileStatus[]): void {
    this.fileStatuses = statuses;
    this.refresh();
  }

  setServiceOnline(online: boolean): void {
    this.serviceOnline = online;
    this.refresh();
  }

  getTreeItem(element: PGTreeItem): vscode.TreeItem {
    return element;
  }

  getChildren(element?: PGTreeItem): PGTreeItem[] {
    if (!element) return this.getRootItems();
    return element.children ?? [];
  }

  // ── Root items ───────────────────────────────────────────────────────────

  private getRootItems(): PGTreeItem[] {
    const cfg = vscode.workspace.getConfiguration("promptguard");
    const items: PGTreeItem[] = [];

    // Service status
    const serviceUrl = cfg.get<string>("serviceUrl", "http://localhost:7474");
    const statusIcon = this.serviceOnline ? "🟢" : "🔴";
    items.push({
      label: `${statusIcon} Service: ${serviceUrl}`,
      description: this.serviceOnline ? "Connected" : "Disconnected",
      collapsibleState: vscode.TreeItemCollapsibleState.None,
      command: {
        command: "promptguard.restartService",
        title: "Restart Service",
      },
    });

    // Fail-closed toggle
    const failClosed = cfg.get<boolean>("failClosed", true);
    items.push({
      label: `${failClosed ? "🔒" : "🔓"} Fail Closed: ${failClosed ? "Enabled" : "Disabled"}`,
      description: failClosed ? "Blocks on trigger" : "Warns only",
      collapsibleState: vscode.TreeItemCollapsibleState.None,
      command: {
        command: "promptguard.toggleFailClosed",
        title: "Toggle Fail Closed",
      },
    });

    // Providers subtree
    const providers = cfg.get<Record<string, boolean>>("providers", {});
    const providerChildren: PGTreeItem[] = Object.entries({
      claudeCode: true,
      copilot: true,
      cursor: true,
      continue: true,
      codeium: true,
      ...providers,
    }).map(([key, enabled]) => ({
      label: `${enabled ? "✅" : "⬜"} ${key}`,
      description: enabled ? "Enabled" : "Disabled",
      collapsibleState: vscode.TreeItemCollapsibleState.None,
      command: {
        command: "promptguard.toggleProvider",
        title: "Toggle Provider",
        arguments: [key],
      },
    }));

    items.push({
      label: "⚡ AI Providers",
      description: `${Object.entries({ claudeCode: true, copilot: true, cursor: true, continue: true, codeium: true, ...providers }).filter(([, v]) => v).length} active`,
      collapsibleState: vscode.TreeItemCollapsibleState.Expanded,
      children: providerChildren,
    });

    // Instruction files subtree
    const fileChildren: PGTreeItem[] = this.fileStatuses.map((fs) => {
      const icon = _decisionIcon(fs.decision);
      const provider = _guessProviderLabel(fs.file);
      return {
        label: `${icon} ${fs.file.split("/").pop()}`,
        description: `${provider} · ${fs.decision}`,
        tooltip: `Path: ${fs.file}\nProvider: ${provider}\nDecision: ${fs.decision}\nFindings: ${fs.findings.length}`,
        collapsibleState: vscode.TreeItemCollapsibleState.None,
      };
    });

    if (fileChildren.length === 0) {
      fileChildren.push({
        label: "No instruction files detected",
        description: "Run Scan Workspace",
        collapsibleState: vscode.TreeItemCollapsibleState.None,
        command: {
          command: "promptguard.scanWorkspace",
          title: "Scan Workspace",
        },
      });
    }

    items.push({
      label: "📄 Instruction Files",
      description: `${this.fileStatuses.length} found`,
      collapsibleState: vscode.TreeItemCollapsibleState.Expanded,
      children: fileChildren,
    });

    // API Key
    const apiKey = cfg.get<string>("apiKey", "");
    items.push({
      label: `🔑 API Key: ${apiKey ? "••••••••" : "Not set"}`,
      description: apiKey ? "Configured" : "Set in Settings",
      collapsibleState: vscode.TreeItemCollapsibleState.None,
      command: {
        command: "promptguard.openSettings",
        title: "Open Settings",
      },
    });

    return items;
  }
}

// ── Command registrations ────────────────────────────────────────────────────

export function registerSettingsCommands(
  context: vscode.ExtensionContext,
  settingsProvider: PromptGuardSettingsProvider
): void {
  context.subscriptions.push(
    // Toggle fail-closed
    vscode.commands.registerCommand("promptguard.toggleFailClosed", async () => {
      const cfg = vscode.workspace.getConfiguration("promptguard");
      const current = cfg.get<boolean>("failClosed", true);
      await cfg.update("failClosed", !current, vscode.ConfigurationTarget.Global);
      vscode.window.showInformationMessage(
        `PromptGuard: Fail Closed ${!current ? "enabled" : "disabled"}`
      );
    }),

    // Toggle per-provider
    vscode.commands.registerCommand(
      "promptguard.toggleProvider",
      async (providerKey: string) => {
        const cfg = vscode.workspace.getConfiguration("promptguard");
        const providers = cfg.get<Record<string, boolean>>("providers", {});
        const current = providers[providerKey] ?? true;
        providers[providerKey] = !current;
        await cfg.update("providers", providers, vscode.ConfigurationTarget.Global);
        vscode.window.showInformationMessage(
          `PromptGuard: ${providerKey} ${!current ? "enabled" : "disabled"}`
        );
      }
    ),

    // Open VS Code settings filtered to PromptGuard
    vscode.commands.registerCommand("promptguard.openSettings", () => {
      vscode.commands.executeCommand(
        "workbench.action.openSettings",
        "@ext:dmcslab.promptguard"
      );
    })
  );
}

// ── Helpers ──────────────────────────────────────────────────────────────────

function _decisionIcon(decision: string): string {
  return (
    {
      ALLOW: "✅",
      ALLOW_WITH_REDACTION: "🟡",
      QUARANTINE: "🟠",
      BLOCK_SESSION: "🔴",
    } as Record<string, string>
  )[decision] ?? "❓";
}

function _guessProviderLabel(filePath: string): string {
  const lower = filePath.toLowerCase();
  if (lower.includes("claude")) return "Claude Code";
  if (lower.includes("copilot")) return "Copilot";
  if (lower.includes("continuerc") || lower.includes(".continue")) return "Continue";
  if (lower.includes("cursorrules") || lower.includes(".cursor")) return "Cursor";
  if (lower.includes("codeium") || lower.includes("windsurf")) return "Codeium";
  return "Unknown";
}