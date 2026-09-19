from __future__ import annotations

import ipaddress
from pathlib import Path


class ScopeError(ValueError):
    pass


def load_scope(path: Path) -> list[str]:
    if not path.exists():
        return []
    out: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            out.append(line.lower())
    return out


def _match(target: str, entry: str) -> bool:
    t, e = target.lower().strip(), entry.lower().strip()
    if t == e or t.endswith("." + e):
        return True
    try:
        return ipaddress.ip_address(t) in ipaddress.ip_network(e, strict=False)
    except ValueError:
        return False


def is_in_scope(target: str, scope: list[str]) -> bool:
    return bool(scope) and any(_match(target, e) for e in scope)


def assert_in_scope(target: str, scope_file: Path) -> None:
    scope = load_scope(scope_file)
    if not is_in_scope(target, scope):
        raise ScopeError(f"Target {target!r} outside authorized scope ({scope_file})")
