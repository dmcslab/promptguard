"""
Provider Registry

Maps each supported AI coding assistant to:
- Instruction files it reads from the workspace
- Hook config file (if it supports hooks)
- VS Code LM API model ID patterns
- Whether it supports runtime hook interception
"""
from __future__ import annotations
from dataclasses import dataclass, field
from pathlib import Path
from promptguard.models import AIProvider, TrustLevel


@dataclass
class ProviderSpec:
    provider: AIProvider
    display_name: str
    instruction_files: list[str]           # relative to workspace root, in priority order
    hook_config: str | None                # path to write hooks into, if supported
    lm_model_patterns: list[str]           # glob patterns for vscode.lm model IDs
    supports_runtime_hooks: bool = False
    content_type_hint: str = "project_guidance"
    trust_level: TrustLevel = TrustLevel.APPROVED_PROJECT


PROVIDER_REGISTRY: dict[AIProvider, ProviderSpec] = {
    AIProvider.claude_code: ProviderSpec(
        provider=AIProvider.claude_code,
        display_name="Claude Code",
        instruction_files=[
            "CLAUDE.md",
            ".claude/CLAUDE.md",
        ],
        hook_config=".claude/settings.json",
        lm_model_patterns=["claude-*", "anthropic/*"],
        supports_runtime_hooks=True,
    ),
    AIProvider.github_copilot: ProviderSpec(
        provider=AIProvider.github_copilot,
        display_name="GitHub Copilot",
        instruction_files=[
            ".github/copilot-instructions.md",
            ".copilot-instructions.md",
        ],
        hook_config=None,
        lm_model_patterns=["copilot-*", "gpt-4o*", "o1*", "o3*", "github/*"],
        supports_runtime_hooks=False,
    ),
    AIProvider.continue_dev: ProviderSpec(
        provider=AIProvider.continue_dev,
        display_name="Continue.dev",
        instruction_files=[
            ".continuerc.json",
            ".continue/config.json",
            ".continue/config.yaml",
        ],
        hook_config=None,
        lm_model_patterns=["*"],   # Continue proxies many backends
        supports_runtime_hooks=False,
    ),
    AIProvider.cursor: ProviderSpec(
        provider=AIProvider.cursor,
        display_name="Cursor",
        instruction_files=[
            ".cursorrules",
            ".cursor/rules",
            ".cursor/rules.md",
        ],
        hook_config=None,
        lm_model_patterns=["cursor/*"],
        supports_runtime_hooks=False,
    ),
    AIProvider.codeium: ProviderSpec(
        provider=AIProvider.codeium,
        display_name="Codeium / Windsurf",
        instruction_files=[
            ".codeium/instructions.md",
            ".windsurf/rules.md",
        ],
        hook_config=None,
        lm_model_patterns=["codeium/*", "windsurf/*"],
        supports_runtime_hooks=False,
    ),
    AIProvider.generic: ProviderSpec(
        provider=AIProvider.generic,
        display_name="Generic AI Provider",
        instruction_files=[],
        hook_config=None,
        lm_model_patterns=["*"],
        supports_runtime_hooks=False,
    ),
}


def detect_provider(workspace_root: str | Path) -> list[AIProvider]:
    """
    Scan the workspace and return all detected AI providers
    based on presence of their instruction files.
    """
    root = Path(workspace_root)
    detected: list[AIProvider] = []
    for provider, spec in PROVIDER_REGISTRY.items():
        if provider == AIProvider.generic:
            continue
        for rel_path in spec.instruction_files:
            if (root / rel_path).exists():
                detected.append(provider)
                break
    return detected or [AIProvider.generic]


def get_instruction_files(workspace_root: str | Path) -> list[tuple[AIProvider, Path]]:
    """
    Return all existing instruction files in the workspace,
    paired with their provider.
    """
    root = Path(workspace_root)
    results: list[tuple[AIProvider, Path]] = []
    for provider, spec in PROVIDER_REGISTRY.items():
        if provider == AIProvider.generic:
            continue
        for rel_path in spec.instruction_files:
            p = root / rel_path
            if p.exists():
                results.append((provider, p))
    return results


def provider_from_string(s: str) -> AIProvider:
    """Parse a provider string loosely."""
    s = s.lower().replace("-", "_").replace(" ", "_")
    mapping = {
        "claude_code":    AIProvider.claude_code,
        "claude":         AIProvider.claude_code,
        "copilot":        AIProvider.github_copilot,
        "github_copilot": AIProvider.github_copilot,
        "continue":       AIProvider.continue_dev,
        "continue_dev":   AIProvider.continue_dev,
        "cursor":         AIProvider.cursor,
        "codeium":        AIProvider.codeium,
        "windsurf":       AIProvider.codeium,
        "generic":        AIProvider.generic,
    }
    return mapping.get(s, AIProvider.generic)


def get_spec(provider: AIProvider) -> ProviderSpec:
    return PROVIDER_REGISTRY[provider]
