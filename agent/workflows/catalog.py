from __future__ import annotations

from typing import Any

from agent.tools.builtin import extract_cnpj, extract_target
from agent.tools.registry import ToolRegistry


WORKFLOWS = {
    "domain_recon": "Passive domain mapping (dns/whois/headers/crt.sh/security headers)",
    "vuln_map": "Domain vuln map: security headers + Kali nmap (confirm)",
    "kyc_empresa": "Company KYC via CNPJ + OpenSanctions + BR sources",
    "br_osint": "Brazil OSINT catalog + optional CNPJ",
}


def workflow_steps(
    name: str,
    objective: str,
    registry: ToolRegistry,
    target: str | None = None,
    cnpj: str | None = None,
    include_active: bool = False,
) -> list[dict[str, Any]]:
    """Return step dicts {tool, args, risk, requires_confirm} — no import from core."""
    name = name.lower().strip()
    tgt = target or extract_target(objective)
    cnpj = cnpj or extract_cnpj(objective)
    steps: list[dict[str, Any]] = []

    def add(tool: str, args: dict[str, Any], confirm: bool | None = None) -> None:
        t = registry.get(tool)
        steps.append(
            {
                "tool": tool,
                "args": args,
                "risk": t.risk,
                "requires_confirm": t.requires_confirm if confirm is None else confirm,
            }
        )

    if name == "domain_recon":
        if not tgt:
            raise ValueError("domain_recon needs a domain/IP target")
        for tool in ("dns_lookup", "whois", "http_headers", "crtsh_subdomains", "security_headers_check"):
            add(tool, {"target": tgt})
        if include_active:
            add("nmap_top_ports", {"target": tgt}, confirm=True)
    elif name == "vuln_map":
        if not tgt:
            raise ValueError("vuln_map needs a domain/IP target")
        add("security_headers_check", {"target": tgt})
        add("http_headers", {"target": tgt})
        add("dns_lookup", {"target": tgt})
        add("nmap_top_ports", {"target": tgt}, confirm=True)
    elif name == "kyc_empresa":
        if not cnpj:
            raise ValueError("kyc_empresa needs a 14-digit CNPJ")
        add("kyc_empresa", {"cnpj": cnpj})
        add("brazil_sources", {"category": "company"})
    elif name == "br_osint":
        add("brazil_sources", {})
        if cnpj:
            add("cnpj_lookup", {"cnpj": cnpj})
            add("opensanctions_search", {"query": cnpj})
    else:
        raise ValueError(f"unknown workflow: {name}. Known: {', '.join(WORKFLOWS)}")

    return steps
