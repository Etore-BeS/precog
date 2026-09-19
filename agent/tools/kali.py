from __future__ import annotations

import re
import shutil
import subprocess
from typing import Any


SAFE_BINARIES = {"nmap", "whois", "dig", "host", "curl"}


def kali_running(container: str = "precog-kali") -> bool:
    if not shutil.which("docker"):
        return False
    try:
        p = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Running}}", container],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        return p.returncode == 0 and p.stdout.strip().lower() == "true"
    except Exception:
        return False


def _validate_target(target: str) -> str:
    t = target.strip()
    if not re.fullmatch(r"[A-Za-z0-9._:-]+", t) or ".." in t:
        raise ValueError(f"unsafe target: {target!r}")
    return t


def docker_exec(container: str, argv: list[str], timeout: int = 120) -> dict[str, Any]:
    if not argv or argv[0] not in SAFE_BINARIES:
        return {"ok": False, "error": f"binary not allowlisted: {argv[:1]}", "argv": argv}
    cmd = ["docker", "exec", container, *argv]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        return {
            "ok": p.returncode == 0,
            "argv": argv,
            "stdout": (p.stdout or "")[-12000:],
            "stderr": (p.stderr or "")[-3000:],
            "returncode": p.returncode,
        }
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": str(e), "argv": argv}


def nmap_top_ports(target: str, container: str = "precog-kali", top: int = 20) -> dict[str, Any]:
    t = _validate_target(target)
    top = max(1, min(int(top), 100))
    if not kali_running(container):
        return {
            "ok": False,
            "tool": "nmap_top_ports",
            "target": t,
            "error": f"kali container {container} not running — docker compose --profile kali up -d kali",
        }
    out = docker_exec(container, ["nmap", "-sV", "-Pn", "--top-ports", str(top), t], timeout=180)
    out.update({"tool": "nmap_top_ports", "target": t})
    return out


def kali_safe_exec(
    binary: str,
    args: list[str],
    container: str = "precog-kali",
    timeout: int = 120,
) -> dict[str, Any]:
    if binary not in SAFE_BINARIES:
        return {"ok": False, "tool": "kali_exec", "error": "binary not allowlisted"}
    clean: list[str] = []
    for a in args:
        if not re.fullmatch(r"[A-Za-z0-9._:/=+\-*%?&]+", a):
            return {"ok": False, "tool": "kali_exec", "error": f"unsafe arg: {a!r}"}
        clean.append(a)
    if not kali_running(container):
        return {"ok": False, "tool": "kali_exec", "error": f"kali {container} not running"}
    out = docker_exec(container, [binary, *clean], timeout=timeout)
    out.update({"tool": "kali_exec", "binary": binary})
    return out
