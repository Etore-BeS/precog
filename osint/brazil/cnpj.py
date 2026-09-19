from __future__ import annotations

import re
from typing import Any

import httpx


def _digits(cnpj: str) -> str:
    return re.sub(r"\D", "", cnpj)


def validate_cnpj(cnpj: str) -> bool:
    n = _digits(cnpj)
    if len(n) != 14 or n == n[0] * 14:
        return False

    def calc(base: str, factors: list[int]) -> int:
        s = sum(int(a) * b for a, b in zip(base, factors))
        r = s % 11
        return 0 if r < 2 else 11 - r

    d1 = calc(n[:12], [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2])
    d2 = calc(n[:12] + str(d1), [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2])
    return n[-2:] == f"{d1}{d2}"


def lookup_cnpj(cnpj: str, client: httpx.Client | None = None) -> dict[str, Any]:
    """Public CNPJ lookup via BrasilAPI (mockable)."""
    n = _digits(cnpj)
    if not validate_cnpj(n):
        return {"ok": False, "tool": "cnpj_lookup", "error": "invalid_cnpj", "cnpj": n}

    url = f"https://brasilapi.com.br/api/cnpj/v1/{n}"
    own = client is None
    client = client or httpx.Client(timeout=20.0)
    try:
        r = client.get(url)
        if r.status_code == 404:
            return {"ok": False, "tool": "cnpj_lookup", "error": "not_found", "cnpj": n}
        r.raise_for_status()
        data = r.json()
        return {
            "ok": True,
            "tool": "cnpj_lookup",
            "cnpj": n,
            "razao_social": data.get("razao_social"),
            "nome_fantasia": data.get("nome_fantasia"),
            "uf": data.get("uf"),
            "municipio": data.get("municipio"),
            "cnae": data.get("cnae_fiscal_descricao"),
            "raw": data,
        }
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "tool": "cnpj_lookup", "cnpj": n, "error": str(e)}
    finally:
        if own:
            client.close()
