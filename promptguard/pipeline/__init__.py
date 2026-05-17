"""
Pipeline orchestrator — runs all 8 pre-send stages.
"""
from __future__ import annotations
from promptguard.models import PipelineContext, ProxyRequest, AIProvider, Decision
from promptguard.config import PromptGuardConfig
from promptguard.providers_registry import provider_from_string
# Submodule imports — use relative form inside a package __init__
from . import interceptor
from . import classifier
from . import allowlist
from . import redactor
from . import instr_validator
from . import policy
from . import envelope


def build_context(req: ProxyRequest) -> PipelineContext:
    from promptguard.models import ContentType, TrustLevel, SanitizationStatus, ContextBlock
    from promptguard.config import load_config
    from promptguard.mcp_gateway import MCPToolResult, process_mcp_results

    provider = provider_from_string(req.provider)
    ctx = PipelineContext(
        raw_prompt=req.prompt,
        file_path=req.file_path,
        language=req.language,
        provider=provider,
        extra_params=req.extra_params,
        repo_root=req.repo_root,
        branch=req.branch,
        instruction_file_path=None,
    )

    # If caller passed instruction file content, add it as a context block
    if req.instruction_file_content:
        from promptguard.providers_registry import get_spec
        spec = get_spec(provider)
        instr_path = (
            spec.instruction_files[0] if spec.instruction_files
            else "instruction_file"
        )
        ctx.instruction_file_path = instr_path
        block = ContextBlock(
            source=instr_path,
            content_type=ContentType.project_guidance,
            trust_level=TrustLevel.APPROVED_PROJECT,
            sanitization_status=SanitizationStatus.passed,
            content=req.instruction_file_content,
            original_hash=ContextBlock.make_hash(req.instruction_file_content),
            content_hash=ContextBlock.make_hash(req.instruction_file_content),
        )
        ctx.context_blocks.append(block)

    # If caller passed MCP tool results, run them through the MCP gateway
    # and add the sanitized ContextBlocks (TrustLevel.TOOL_OUTPUT) to the pipeline
    if req.mcp_tool_results:
        cfg = load_config()
        mcp_results = [
            MCPToolResult(
                server_url=r.get("server_url", "unknown"),
                server_name=r.get("server_name"),
                tool_name=r.get("tool_name", "unknown"),
                tool_output=r.get("tool_output", ""),
                is_error=r.get("is_error", False),
            )
            for r in req.mcp_tool_results
        ]
        mcp_blocks = process_mcp_results(mcp_results, cfg)
        ctx.context_blocks.extend(mcp_blocks)
        # Propagate any MCP-level findings into ctx
        for block in mcp_blocks:
            ctx.all_findings.extend(block.findings)

    return ctx


def _dedup_context_blocks(ctx: PipelineContext) -> None:
    """Remove duplicate context blocks (same source + content_hash)."""
    seen: set[tuple[str, str]] = set()
    unique: list = []
    for block in ctx.context_blocks:
        key = (block.source, block.content_hash)
        if key not in seen:
            seen.add(key)
            unique.append(block)
    ctx.context_blocks = unique


def run_pipeline(ctx: PipelineContext, config: PromptGuardConfig) -> PipelineContext:
    """Execute all pre-send stages. Returns ctx with decision + envelope."""
    ctx = interceptor.run(ctx, config)       # 1. Intercept
    if ctx.blocked:
        return ctx

    # Deduplicate context blocks after intercept adds its block
    _dedup_context_blocks(ctx)

    ctx = classifier.run(ctx, config)        # 2. Classify
    ctx = allowlist.run(ctx, config)         # 3. Allow-list
    ctx = redactor.run(ctx, config)          # 4. Redact
    ctx = instr_validator.run(ctx, config)   # 5. Instruction file
    if ctx.blocked:
        return ctx

    # Deduplicate again after instruction file adds blocks
    _dedup_context_blocks(ctx)

    ctx = policy.run(ctx, config)            # 6. Policy
    # Fail-closed: if policy set BLOCK_SESSION, ensure block_reason is populated
    # and return immediately — no later stage should modify this decision.
    if ctx.blocked:
        if not ctx.block_reason:
            ctx.block_reason = "; ".join(
                f.message for f in ctx.all_findings
                if f.decision == Decision.BLOCK_SESSION
            ) or "Policy violation blocked session."
        return ctx

    ctx = envelope.run(ctx, config)          # 7. Build envelope
    return ctx
