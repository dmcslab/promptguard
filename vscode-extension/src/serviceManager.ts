/**
 * ServiceManager
 *
 * Spawns the PromptGuard Python service as a child process when
 * VS Code opens. The extension never requires the user to manually
 * start the server — it manages the full lifecycle automatically.
 *
 * VDI support:
 *  - Forwards PROMPTGUARD_CONFIG_URL, PROMPTGUARD_CONFIG_INLINE,
 *    PROMPTGUARD_SESSION_ID, and PROMPTGUARD_API_KEY from env/settings.
 *  - Uses /ready endpoint for readiness probes (respects shutdown state).
 *  - Sends SIGTERM for graceful drain-and-shutdown on exit.
 */
import * as vscode from "vscode";
import * as cp from "child_process";

export type ServiceState = "stopped" | "starting" | "running" | "draining" | "error";

export class ServiceManager implements vscode.Disposable {
  private _proc: cp.ChildProcess | undefined;
  private _state: ServiceState = "stopped";
  private _outputChannel: vscode.OutputChannel;
  private _onStateChange = new vscode.EventEmitter<ServiceState>();

  readonly onStateChange = this._onStateChange.event;

  constructor(private readonly _port: number = 7474) {
    this._outputChannel = vscode.window.createOutputChannel("PromptGuard Service");
  }

  get state(): ServiceState {
    return this._state;
  }

  get baseUrl(): string {
    return `http://127.0.0.1:${this._port}`;
  }

  /**
   * Build environment variables for the Python process.
   *
   * In VDI environments, the session launcher sets PROMPTGUARD_CONFIG_URL
   * or PROMPTGUARD_CONFIG_INLINE before starting VS Code. We forward those
   * to the Python service so it can load config from the right source.
   */
  private _buildEnv(): NodeJS.ProcessEnv {
    const cfg = vscode.workspace.getConfiguration("promptguard");
    const env: NodeJS.ProcessEnv = { ...process.env, PYTHONUNBUFFERED: "1" };

    // Config injection (VDI: set by session launcher)
    const configUrl = process.env.PROMPTGUARD_CONFIG_URL || cfg.get<string>("configUrl", "");
    const configInline = process.env.PROMPTGUARD_CONFIG_INLINE || cfg.get<string>("configInline", "");
    const sessionId = process.env.PROMPTGUARD_SESSION_ID || cfg.get<string>("sessionId", "");
    if (configUrl) env.PROMPTGUARD_CONFIG_URL = configUrl;
    if (configInline) env.PROMPTGUARD_CONFIG_INLINE = configInline;
    if (sessionId) env.PROMPTGUARD_SESSION_ID = sessionId;

    // API keys (legacy — kept for backward compat, but providers.*_api_key
    // in YAML is the preferred path)
    env.ANTHROPIC_API_KEY = cfg.get<string>("anthropicApiKey") || process.env.ANTHROPIC_API_KEY || "";
    env.OPENAI_API_KEY = cfg.get<string>("openaiApiKey") || process.env.OPENAI_API_KEY || "";

    // Auth key for the /hook/pre-tool and /mcp/* endpoints
    const apiKey = cfg.get<string>("apiKey", "");
    if (apiKey) env.PROMPTGUARD_API_KEY = apiKey;

    return env;
  }

  async start(): Promise<boolean> {
    if (this._state === "running") return true;
    this._setState("starting");

    // Check if already running externally (e.g. user started manually)
    if (await this._ping()) {
      this._setState("running");
      this._log("Service already running on port " + this._port);
      // If running externally, request a session reset for VDI freshness
      try {
        await fetch(`${this.baseUrl}/session/reset`, { method: "POST" });
        this._log("Reset session state on existing service");
      } catch { /* ignore — endpoint may not exist on older versions */ }
      return true;
    }

    const python = await this._findPython();
    if (!python) {
      this._setState("error");
      this._log("ERROR: Python 3.11+ not found. Install Python and run: pip install promptguard");
      vscode.window.showErrorMessage(
        "PromptGuard: Python 3.11+ not found. Install it and run: pip install promptguard",
        "Open Docs"
      );
      return false;
    }

    const cfg = vscode.workspace.getConfiguration("promptguard");
    const configPath = cfg.get<string>("configPath", "");
    const args = ["-m", "promptguard.cli", "serve", "--port", String(this._port)];
    if (configPath) args.push("--config", configPath);

    this._log(`Starting: ${python} ${args.join(" ")}`);

    this._proc = cp.spawn(python, args, {
      env: this._buildEnv(),
      stdio: ["ignore", "pipe", "pipe"],
    });

    this._proc.stdout?.on("data", (d: Buffer) => this._log(d.toString()));
    this._proc.stderr?.on("data", (d: Buffer) => this._log("[ERR] " + d.toString()));
    this._proc.on("exit", (code) => {
      this._log(`Service exited with code ${code}`);
      this._setState(code === 0 ? "stopped" : "error");
      this._proc = undefined;
    });

    // Poll until ready (max 15s)
    const started = await this._waitUntilReady(15_000);
    if (started) {
      await this._registerSessionKey();
    }
    return started;
  }

  /**
   * Send SIGTERM for graceful shutdown.
   * The Python service will set shutdown_requested=True,
   * reject new requests with 503, drain in-flight, then exit.
   */
  async stop(): Promise<void> {
    if (this._proc) {
      this._proc.kill("SIGTERM");
      // Give it time to drain; don't wait forever
      await new Promise<void>((resolve) => {
        const timeout = setTimeout(() => {
          this._proc?.kill("SIGKILL");
          resolve();
        }, 5000);
        this._proc?.on("exit", () => { clearTimeout(timeout); resolve(); });
      });
      this._proc = undefined;
    }
    this._setState("stopped");
  }

  async restart(): Promise<boolean> {
    await this.stop();
    await new Promise((r) => setTimeout(r, 500));
    return this.start();
  }

  showLog(): void {
    this._outputChannel.show();
  }

  private async _waitUntilReady(timeoutMs: number): Promise<boolean> {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 500));
      if (await this._ping()) {
        this._setState("running");
        return true;
      }
      if (this._state === "error") return false;
    }
    this._setState("error");
    this._log("Timed out waiting for service to start.");
    return false;
  }

  private async _ping(): Promise<boolean> {
    try {
      const ctrl = new AbortController();
      const timer = setTimeout(() => ctrl.abort(), 1000);
      // Use /ready for readiness — it checks shutdown state and config
      const res = await fetch(`${this.baseUrl}/ready`, { signal: ctrl.signal });
      clearTimeout(timer);
      return res.ok;
    } catch {
      return false;
    }
  }

  /** Register the local API key as a session key with the PromptGuard server.
   *  In VDI deployments, each user gets a unique PROMPTGUARD_API_KEY injected
   *  by the session launcher, and the extension registers it on startup.
   */
  private async _registerSessionKey(): Promise<void> {
    const cfg = vscode.workspace.getConfiguration("promptguard");
    const apiKey = process.env.PROMPTGUARD_API_KEY || cfg.get<string>("apiKey", "");
    if (!apiKey) return; // No key to register
    try {
      await fetch(`${this.baseUrl}/session/key`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-PromptGuard-API-Key": apiKey,
        },
        body: JSON.stringify({ key: apiKey, source: "vscode_extension" }),
      });
      this._log("Registered session key with PromptGuard server");
    } catch (e) {
      this._log(`Session key registration failed: ${e}`);
    }
  }

  private async _findPython(): Promise<string | undefined> {
    const cfg = vscode.workspace.getConfiguration("promptguard");
    const explicit = cfg.get<string>("pythonPath");
    if (explicit) return explicit;

    // Try common locations in priority order
    const candidates = ["python3", "python", "python3.12", "python3.11"];
    for (const cmd of candidates) {
      try {
        const result = cp.execSync(`${cmd} --version 2>&1`).toString();
        const match = result.match(/Python (\d+)\.(\d+)/);
        if (match && (parseInt(match[1]) > 3 || parseInt(match[2]) >= 11)) {
          return cmd;
        }
      } catch {
        continue;
      }
    }
    return undefined;
  }

  private _setState(state: ServiceState): void {
    this._state = state;
    this._onStateChange.fire(state);
  }

  private _log(msg: string): void {
    this._outputChannel.appendLine(`[${new Date().toISOString()}] ${msg.trim()}`);
  }

  dispose(): void {
    this._proc?.kill("SIGTERM");
    this._outputChannel.dispose();
    this._onStateChange.dispose();
  }
}