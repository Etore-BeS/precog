from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from agent.audit.logger import AuditLogger
from agent.policies.confirm import ConfirmGate
from agent.policies.scope import ScopeError, assert_in_scope, load_scope
from agent.settings import Settings, get_settings
from agent.tools.builtin import extract_cnpj, extract_target
from agent.tools.kali import kali_running
from agent.tools.registry import ToolRegistry, default_registry
from agent.workflows.catalog import WORKFLOWS, workflow_steps

PASSIVE = ["dns_lookup", "whois", "http_headers", "crtsh_subdomains", "security_headers_check", "brazil_sources"]


@dataclass
class PlanStep:
    tool: str
    args: dict[str, Any]
    risk: str
    requires_confirm: bool = False


@dataclass
class Plan:
    id: str
    objective: str
    target: str | None
    steps: list[PlanStep]
    mode: str
    workflow: str | None = None
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "objective": self.objective,
            "target": self.target,
            "mode": self.mode,
            "workflow": self.workflow,
            "created_at": self.created_at,
            "steps": [asdict(s) for s in self.steps],
        }

    def summary_text(self) -> str:
        lines = [
            f"Plan `{self.id}`",
            f"Objective: {self.objective}",
            f"Workflow: {self.workflow or 'generic'}",
            f"Target: {self.target or '(none)'}",
            f"Mode: {self.mode}",
            "Steps:",
        ]
        for i, s in enumerate(self.steps, 1):
            flag = " [CONFIRM]" if s.requires_confirm else ""
            lines.append(f"  {i}. {s.tool} {s.args} risk={s.risk}{flag}")
        return "\n".join(lines)


@dataclass
class RunResult:
    plan_id: str
    approved: bool
    results: list[dict[str, Any]]
    report_path: str | None = None


class PrecogAgent:
    def __init__(
        self,
        settings: Settings | None = None,
        registry: ToolRegistry | None = None,
        confirm: ConfirmGate | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.registry = registry or default_registry()
        self.confirm = confirm or ConfirmGate(require_confirm=self.settings.require_confirm)
        self.audit = AuditLogger(self.settings.audit_dir)
        self.plans: dict[str, Plan] = {}

    def doctor(self) -> dict[str, Any]:
        scope = load_scope(self.settings.authorized_scope_file)
        reachable = kali_running(self.settings.kali_container)
        checks = {
            "ok": self.settings.authorized_scope_file.exists() and len(scope) > 0,
            "agent_mode": self.settings.agent_mode,
            "scope_file": str(self.settings.authorized_scope_file),
            "scope_entries": len(scope),
            "llm_provider": self.settings.llm_provider,
            "openai_key_set": bool(self.settings.openai_api_key),
            "openrouter_key_set": bool(self.settings.openrouter_api_key),
            "telegram_token_set": bool(self.settings.telegram_bot_token),
            "telegram_allowlist": len(self.settings.allowed_chat_ids),
            "kali_enabled": self.settings.kali_enabled,
            "kali_reachable": reachable,
            "kali_container": self.settings.kali_container,
            "workflows": list(WORKFLOWS),
            "tools": [t.name for t in self.registry.list()],
        }
        self.audit.log("doctor", checks=checks)
        return checks

    def plan(
        self,
        objective: str,
        target: str | None = None,
        include_active: bool = False,
        workflow: str | None = None,
        cnpj: str | None = None,
    ) -> Plan:
        # auto-pick workflow hints
        low = objective.lower()
        if workflow is None:
            if "kyc" in low or extract_cnpj(objective):
                if "kyc" in low or "empresa" in low:
                    workflow = "kyc_empresa"
            elif "vuln" in low or "nmap" in low:
                workflow = "vuln_map"
            elif "br osint" in low or low.startswith("br "):
                workflow = "br_osint"
            elif "recon" in low or "domain" in low:
                workflow = "domain_recon"

        tgt = target or extract_target(objective)
        cnpj_v = cnpj or extract_cnpj(objective)

        if workflow:
            raw = workflow_steps(
                workflow,
                objective,
                self.registry,
                target=tgt,
                cnpj=cnpj_v,
                include_active=include_active or workflow == "vuln_map",
            )
            steps = [
                PlanStep(
                    tool=s["tool"],
                    args=s["args"],
                    risk=s["risk"],
                    requires_confirm=s["requires_confirm"],
                )
                for s in raw
            ]
        else:
            steps = []
            for name in PASSIVE:
                tool = self.registry.get(name)
                args: dict[str, Any] = {}
                if name != "brazil_sources":
                    if not tgt:
                        continue
                    args = {"target": tgt}
                steps.append(
                    PlanStep(
                        tool=name,
                        args=args,
                        risk=tool.risk,
                        requires_confirm=tool.requires_confirm,
                    )
                )
            if cnpj_v:
                tool = self.registry.get("cnpj_lookup")
                steps.append(PlanStep(tool="cnpj_lookup", args={"cnpj": cnpj_v}, risk=tool.risk))
            if include_active and tgt and self.settings.agent_mode == "authorized-recon":
                tool = self.registry.get("nmap_top_ports")
                steps.append(
                    PlanStep(
                        tool="nmap_top_ports",
                        args={"target": tgt},
                        risk=tool.risk,
                        requires_confirm=True,
                    )
                )
            if not steps:
                steps.append(PlanStep(tool="brazil_sources", args={}, risk="passive"))

        plan = Plan(
            id=str(uuid4())[:8],
            objective=objective,
            target=tgt,
            steps=steps,
            mode=self.settings.agent_mode,
            workflow=workflow,
        )
        self.plans[plan.id] = plan
        self.audit.log("plan_created", plan=plan.to_dict())
        return plan

    def approve(self, plan_id: str) -> None:
        self.confirm.approve(plan_id)
        self.audit.log("plan_approved", plan_id=plan_id)

    def reject(self, plan_id: str) -> None:
        self.confirm.reject(plan_id)
        self.audit.log("plan_rejected", plan_id=plan_id)

    def run(self, plan_id: str, force: bool = False) -> RunResult:
        plan = self.plans.get(plan_id)
        if plan is None:
            raise KeyError(f"Unknown plan_id: {plan_id}")

        if self.settings.require_confirm and not force and not self.confirm.is_approved(plan_id):
            self.audit.log("run_blocked_confirm", plan_id=plan_id)
            return RunResult(plan_id, False, [{"error": "confirmation required"}])

        if plan.target and self.settings.agent_mode == "authorized-recon":
            try:
                assert_in_scope(plan.target, self.settings.authorized_scope_file)
            except ScopeError as e:
                self.audit.log("run_blocked_scope", plan_id=plan_id, error=str(e))
                return RunResult(plan_id, False, [{"error": str(e)}])

        results: list[dict[str, Any]] = []
        for step in plan.steps:
            tgt = step.args.get("target")
            if tgt:
                try:
                    assert_in_scope(str(tgt), self.settings.authorized_scope_file)
                except ScopeError as e:
                    results.append({"tool": step.tool, "error": str(e)})
                    continue
            tool = self.registry.get(step.tool)
            try:
                out = tool.handler(**step.args)
            except Exception as e:  # noqa: BLE001
                out = {"ok": False, "tool": step.tool, "error": str(e)}
            results.append(out)
            self.audit.log("step_ran", tool=step.tool, ok=out.get("ok"), plan_id=plan_id)

        report = self._write_report(plan, results)
        self.audit.log("run_complete", plan_id=plan_id, report=report)
        return RunResult(plan_id, True, results, report)

    def list_tools(self) -> list[dict[str, str]]:
        return [
            {
                "name": t.name,
                "description": t.description,
                "category": t.category,
                "risk": t.risk,
                "requires_confirm": str(t.requires_confirm),
            }
            for t in self.registry.list()
        ]

    def list_workflows(self) -> dict[str, str]:
        return dict(WORKFLOWS)

    def _write_report(self, plan: Plan, results: list[dict[str, Any]]) -> str:
        self.settings.report_dir.mkdir(parents=True, exist_ok=True)
        md = self.settings.report_dir / f"report-{plan.id}.md"
        md.write_text(
            "\n".join(
                [
                    f"# Precog report — {plan.id}",
                    "",
                    f"- Created: {plan.created_at}",
                    f"- Mode: {plan.mode}",
                    f"- Workflow: {plan.workflow or 'generic'}",
                    f"- Objective: {plan.objective}",
                    f"- Target: {plan.target}",
                    "",
                    "## Results",
                    "",
                    "```json",
                    json.dumps(results, indent=2, ensure_ascii=False, default=str),
                    "```",
                    "",
                    "---",
                    "Authorized use only. Kali tools via allowlisted docker exec. Inspired by Firegod AI (clean-room).",
                ]
            ),
            encoding="utf-8",
        )
        (self.settings.report_dir / f"report-{plan.id}.json").write_text(
            json.dumps({"plan": plan.to_dict(), "results": results}, indent=2, default=str),
            encoding="utf-8",
        )
        return str(md)
