from __future__ import annotations

import re
import socket
import subprocess
from pathlib import Path
from typing import Any

import httpx
import yaml

from agent.tools.registry import Tool


def whois_lookup(target: str, **_: Any) -> dict[str, Any]:
    try:
        p = subprocess.run(["whois", target], capture_output=True, text=True, timeout=15, check=False)
        return {"ok": True, "tool": "whois", "target": target, "output": (p.stdout or p.stderr or "")[:4000]}
    except FileNotFoundError:
        return {"ok": True, "tool": "whois", "target": target, "stub": True, "output": f"[stub] whois {target}"}


def dns_lookup(target: str, **_: Any) -> dict[str, Any]:
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


def nmap_top_ports(target: str, **_: Any) -> dict[str, Any]:
    return {
        "ok": True,
        "tool": "nmap_top_ports",
        "target": target,
        "stub": True,
        "suggested_cmd": f"nmap -sV --top-ports 20 {target}",
    }


def kali_exec(target: str = "", cmd: str | None = None, kali_container: str = "precog-kali", **_: Any) -> dict[str, Any]:
    command = cmd or (f"nmap -sn {target}" if target else "echo kali-ok")
    try:
        p = subprocess.run(
            ["docker", "exec", kali_container, "bash", "-lc", command],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        return {
            "ok": p.returncode == 0,
            "tool": "kali_exec",
            "cmd": command,
            "stdout": (p.stdout or "")[-8000:],
            "stderr": (p.stderr or "")[-2000:],
            "returncode": p.returncode,
        }
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "tool": "kali_exec", "error": str(e), "cmd": command}


def cnpj_lookup(cnpj: str, **_: Any) -> dict[str, Any]:
    from osint.brazil.cnpj import lookup_cnpj

    return lookup_cnpj(cnpj)


def cpf_guard(cpf: str, **_: Any) -> dict[str, Any]:
    from osint.brazil.cpf_guard import guard_cpf

    return guard_cpf(cpf)


def brazil_sources(**_: Any) -> dict[str, Any]:
    data = yaml.safe_load(Path("osint/brazil/sources.yaml").read_text(encoding="utf-8"))
    return {"ok": True, "tool": "brazil_sources", "sources": data}


def all_tools() -> list[Tool]:
    return [
        Tool("whois", "WHOIS lookup (passive)", "osint", "passive", whois_lookup),
        Tool("dns_lookup", "DNS resolution (passive)", "osint", "passive", dns_lookup),
        Tool("http_headers", "HTTP headers (passive)", "recon", "passive", http_headers),
        Tool("nmap_top_ports", "Nmap top-ports stub/kali", "recon", "active", nmap_top_ports, True),
        Tool("kali_exec", "Exec in Kali sidecar", "recon", "active", kali_exec, True),
        Tool("cnpj_lookup", "Brazil CNPJ public lookup", "brazil", "passive", cnpj_lookup),
        Tool("cpf_guard", "CPF PII guardrail", "brazil", "passive", cpf_guard),
        Tool("brazil_sources", "Brazil OSINT catalog", "brazil", "passive", brazil_sources),
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
