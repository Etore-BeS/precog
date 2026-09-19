from pathlib import Path

from agent.core import PrecogAgent
from agent.settings import Settings


def test_plan_run_with_scope(tmp_path: Path):
    scope = tmp_path / "scope.txt"
    scope.write_text("example.com\n", encoding="utf-8")
    settings = Settings(
        authorized_scope_file=scope,
        require_confirm=True,
        audit_dir=tmp_path / "audit",
        report_dir=tmp_path / "reports",
        agent_mode="authorized-recon",
    )
    agent = PrecogAgent(settings=settings)
    plan = agent.plan("passive recon example.com", target="example.com")
    assert plan.target == "example.com"
    blocked = agent.run(plan.id)
    assert blocked.approved is False
    agent.approve(plan.id)
    result = agent.run(plan.id)
    assert result.approved is True
    assert result.report_path
    assert Path(result.report_path).exists()


def test_out_of_scope_blocked(tmp_path: Path):
    scope = tmp_path / "scope.txt"
    scope.write_text("example.com\n", encoding="utf-8")
    settings = Settings(
        authorized_scope_file=scope,
        require_confirm=False,
        audit_dir=tmp_path / "a",
        report_dir=tmp_path / "r",
    )
    agent = PrecogAgent(settings=settings)
    plan = agent.plan("recon not-allowed.test", target="not-allowed.test")
    result = agent.run(plan.id)
    assert result.approved is False
