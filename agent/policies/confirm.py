from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ConfirmGate:
    require_confirm: bool = True
    _approved: set[str] = field(default_factory=set)

    def approve(self, token: str) -> None:
        self._approved.add(token)

    def reject(self, token: str) -> None:
        self._approved.discard(token)

    def is_approved(self, token: str) -> bool:
        return (not self.require_confirm) or (token in self._approved)
