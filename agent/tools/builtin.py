from __future__ import annotations

import re
import socket
import subprocess
from pathlib import Path
from typing import Any

import httpx
import yaml

from agent.settings import get_settings
from agent.tools.kali import kali_running, kali_safe_exec, nmap_top_ports as kali_nmap
from agent.tools.registry import Tool


def whois_lookup(target: str, **_: Any) -> dict[str, Any]:
    settings = get_settings()
    if settings.kali_enabled and kali_running(settings.kali_container):
        out = kali_safe_exec("whois", [target], container=settings.kali_container, timeout=30)
        out.update({"tool": "whois", "target": target, "via": "kali"})
        return out
    try:
        p = subprocess.run(["whois", target], capture_output=True, text=True, timeout=15, check=False)
        return {"ok": True, "tool": "whois", "target": target, "output": (p.stdout or p.stderr or "")[:4000]}
    except FileNotFoundError:
        return {"ok": True, "tool": "whois", "target": target, "stub": True, "output": f"[stub] whois {target}"}


def dns_lookup(target: str, **_: Any) -> dict[str, Any]:
    settings = get_settings()
    if settings.kali_enabled and kali_running(settings.kali_container):
        out = kali_safe_exec("dig", ["+short", target, "A"], container=settings.kali_container, timeout=20)
        lines = [ln.strip() for ln in (out.get("stdout") or "").splitlines() if ln.strip()]
        if out.get("ok") and lines:
            return {"ok": True, "tool": "dns_lookup", "target": target, "addrs": lines, "via": "kali"}
    try:
        addrs = sorted({i[4][0] for i in socket.getaddrinfo(target, None)})
        return {"ok": True, "tool": "dns_lookup", "target": target, "addrs": addrs}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "tool": "dns_lookup", "target": target, "error": str(e)}


def http_headers(target: str, **_: Any) -> dict[str, Any]:
    url = target if target.startswith("http") else f"https://{target}"
    try:
        with httpx.Client(timeout=10.0, follow_redirects=True) as c:
            r = c.head(url)
            return {
                "ok": True,
                "tool": "http_headers",
                "url": str(r.url),
                "status": r.status_code,
                "headers": dict(r.headers),
            }
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "tool": "http_headers", "target": target, "error": str(e)}


def crtsh_subdomains(target: str, **_: Any) -> dict[str, Any]:
    """Passive subdomain enum via crt.sh (JSON)."""
    try:
        with httpx.Client(timeout=20.0, follow_redirects=True) as c:
            r = c.get("https://crt.sh/", params={"q": f"%.{target}", "output": "json"})
            if r.status_code != 200:
                return {"ok": False, "tool": "crtsh_subdomains", "target": target, "status": r.status_code}
            rows = r.json()
            names: set[str] = set()
            for row in rows if isinstance(rows, list) else []:
                nv = str(row.get("name_value") or "")
                for part in nv.split("\n"):
                    host = part.strip().lower().lstrip("*.")
                    if host.endswith(target.lower()):
                        names.add(host)
            return {
                "ok": True,
                "tool": "crtsh_subdomains",
                "target": target,
                "count": len(names),
                "subdomains": sorted(names)[:200],
            }
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "tool": "crtsh_subdomains", "target": target, "error": str(e)}


def security_headers_check(target: str, **_: Any) -> dict[str, Any]:
    base = http_headers(target)
    if not base.get("ok"):
        return {**base, "tool": "security_headers_check"}
    h = {k.lower(): v for k, v in (base.get("headers") or {}).items()}
    wanted = [
        "strict-transport-security",
        "content-security-policy",
        "x-content-type-options",
        "x-frame-options",
        "referrer-policy",
        "permissions-policy",
    ]
    missing = [k for k in wanted if k not in h]
    return {
        "ok": True,
        "tool": "security_headers_check",
        "url": base.get("url"),
        "present": {k: h.get(k) for k in wanted if k in h},
        "missing": missing,
        "risk_hint": "medium" if missing else "low",
    }


def nmap_top_ports(target: str, **_: Any) -> dict[str, Any]:
    settings = get_settings()
    if not settings.kali_enabled:
        return {
            "ok": False,
            "tool": "nmap_top_ports",
            "target": target,
            "error": "KALI_ENABLED=false — set true and start kali sidecar",
        }
    return kali_nmap(target, container=settings.kali_container)


def kali_exec(target: str = "", cmd: str | None = None, binary: str = "nmap", **kwargs: Any) -> dict[str, Any]:
    """Allowlisted kali exec only — ignores free-form shell strings."""
    settings = get_settings()
    # Ignore legacy free-form cmd for safety; use binary+args pattern
    args = kwargs.get("args") or ([] if not target else ["-sV", "-Pn", "--top-ports", "20", target])
    if isinstance(args, str):
        args = args.split()
    return kali_safe_exec(binary, list(args), container=settings.kali_container)


def cnpj_lookup(cnpj: str, **_: Any) -> dict[str, Any]:
    from osint.brazil.cnpj import lookup_cnpj

    return lookup_cnpj(cnpj)


def cpf_guard(cpf: str, **_: Any) -> dict[str, Any]:
    from osint.brazil.cpf_guard import guard_cpf

    return guard_cpf(cpf)


def brazil_sources(category: str | None = None, **_: Any) -> dict[str, Any]:
    data = yaml.safe_load(Path("osint/brazil/sources.yaml").read_text(encoding="utf-8"))
    sources = data.get("sources") or []
    if category:
        sources = [s for s in sources if s.get("type") == category or category in (s.get("tags") or [])]
    return {"ok": True, "tool": "brazil_sources", "sources": sources, "skills": data.get("skills") or []}


def opensanctions_search(query: str, **_: Any) -> dict[str, Any]:
    """Public OpenSanctions search API."""
    q = (query or "").strip()
    if len(q) < 2:
        return {"ok": False, "tool": "opensanctions_search", "error": "query too short"}
    try:
        with httpx.Client(timeout=20.0) as c:
            r = c.get("https://api.opensanctions.org/search/default", params={"q": q, "limit": 10})
            if r.status_code >= 400:
                return {"ok": False, "tool": "opensanctions_search", "status": r.status_code, "error": r.text[:500]}
            data = r.json()
            results = []
            for item in (data.get("results") or [])[:10]:
                results.append(
                    {
                        "id": item.get("id"),
                        "caption": item.get("caption") or item.get("name"),
                        "schema": item.get("schema"),
                        "countries": item.get("countries"),
                    }
                )
            return {"ok": True, "tool": "opensanctions_search", "query": q, "results": results}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "tool": "opensanctions_search", "query": q, "error": str(e)}


def kyc_empresa(cnpj: str, **_: Any) -> dict[str, Any]:
    """Company KYC pack: CNPJ + sanctions search + BR company sources."""
    cnpj_res = cnpj_lookup(cnpj)
    name = ""
    if cnpj_res.get("ok"):
        name = cnpj_res.get("razao_social") or cnpj_res.get("nome_fantasia") or ""
    sanctions = opensanctions_search(name) if name else {"ok": False, "skipped": True}
    catalog = brazil_sources(category="company")
    return {
        "ok": bool(cnpj_res.get("ok")),
        "tool": "kyc_empresa",
        "cnpj": cnpj_res,
        "sanctions": sanctions,
        "sources": catalog.get("sources"),
    }


def all_tools() -> list[Tool]:
    return [
        Tool("whois", "WHOIS lookup (host or Kali)", "osint", "passive", whois_lookup),
        Tool("dns_lookup", "DNS resolution (host or Kali dig)", "osint", "passive", dns_lookup),
        Tool("http_headers", "HTTP headers (passive)", "recon", "passive", http_headers),
        Tool("crtsh_subdomains", "Passive subdomains via crt.sh", "recon", "passive", crtsh_subdomains),
        Tool("security_headers_check", "Security header gap analysis", "recon", "passive", security_headers_check),
        Tool("nmap_top_ports", "Nmap top-ports via Kali sidecar", "recon", "active", nmap_top_ports, True),
        Tool("kali_exec", "Allowlisted Kali binary exec", "recon", "active", kali_exec, True),
        Tool("cnpj_lookup", "Brazil CNPJ public lookup", "brazil", "passive", cnpj_lookup),
        Tool("cpf_guard", "CPF PII guardrail", "brazil", "passive", cpf_guard),
        Tool("brazil_sources", "Brazil OSINT catalog", "brazil", "passive", brazil_sources),
        Tool("opensanctions_search", "OpenSanctions entity search", "brazil", "passive", opensanctions_search),
        Tool("kyc_empresa", "Company KYC pack (CNPJ+sanctions)", "brazil", "passive", kyc_empresa),
    ]


def extract_target(text: str) -> str | None:
    m = re.search(r"https?://([^\s/]+)", text)
    if m:
        return m.group(1).lower()
    m = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", text)
    if m:
        return m.group(1)
    m = re.search(r"\b([a-z0-9-]+(?:\.[a-z0-9-]+)+)\b", text, re.I)
    if m:
        return m.group(1).lower()
    return None


def extract_cnpj(text: str) -> str | None:
    digits = re.sub(r"\D", "", text)
    # find 14 consecutive digits
    m = re.search(r"\d{14}", digits)
    if m:
        return m.group(0)
    m = re.search(r"\b(\d{2}\.?\d{3}\.?\d{3}/?\d{4}-?\d{2})\b", text)
    if m:
        return re.sub(r"\D", "", m.group(1))
    return None
