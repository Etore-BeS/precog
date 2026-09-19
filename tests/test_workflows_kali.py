from pathlib import Path

from agent.core import PrecogAgent
from agent.settings import Settings
from agent.tools.kali import SAFE_BINARIES


def test_domain_recon_workflow_plan(tmp_path: Path):
    scope = tmp_path / "scope.txt"
    scope.write_text("example.com\n", encoding="utf-8")
    settings = Settings(
        authorized_scope_file=scope,
        require_confirm=True,
        audit_dir=tmp_path / "a",
        report_dir=tmp_path / "r",
        kali_enabled=False,
    )
    agent = PrecogAgent(settings=settings)
    plan = agent.plan("map example.com", workflow="domain_recon", target="example.com")
    names = [s.tool for s in plan.steps]
    assert "crtsh_subdomains" in names
    assert "security_headers_check" in names
    assert "nmap_top_ports" not in names


def test_vuln_map_includes_nmap(tmp_path: Path):
    scope = tmp_path / "scope.txt"
    scope.write_text("example.com\n", encoding="utf-8")
    settings = Settings(
        authorized_scope_file=scope,
        require_confirm=True,
        audit_dir=tmp_path / "a",
        report_dir=tmp_path / "r",
    )
    agent = PrecogAgent(settings=settings)
    plan = agent.plan("vuln example.com", workflow="vuln_map", target="example.com")
    assert any(s.tool == "nmap_top_ports" and s.requires_confirm for s in plan.steps)


def test_kyc_workflow_needs_cnpj(tmp_path: Path):
    settings = Settings(
        authorized_scope_file=tmp_path / "s.txt",
        require_confirm=False,
        audit_dir=tmp_path / "a",
        report_dir=tmp_path / "r",
    )
    (tmp_path / "s.txt").write_text("example.com\n", encoding="utf-8")
    agent = PrecogAgent(settings=settings)
    try:
        agent.plan("kyc", workflow="kyc_empresa")
        assert False, "expected error"
    except ValueError:
        pass


def test_kali_allowlist():
    assert "nmap" in SAFE_BINARIES
    assert "bash" not in SAFE_BINARIES
