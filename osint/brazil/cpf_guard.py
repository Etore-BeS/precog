from __future__ import annotations

import re
from typing import Any


def guard_cpf(cpf: str, **_: Any) -> dict[str, Any]:
    """Hard guardrail: Precog will not look up CPF / personal tax IDs.

    LGPD + ethics: no fishing for natural-person identifiers.
    """
    digits = re.sub(r"\D", "", cpf or "")
    return {
        "ok": False,
        "tool": "cpf_guard",
        "blocked": True,
        "reason": "CPF lookups are disabled. Use public-figure OSINT without personal tax IDs.",
        "cpf_len": len(digits),
        "policy": "LGPD_no_pii_fishing",
    }
