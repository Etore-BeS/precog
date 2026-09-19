from pathlib import Path

import pytest

from agent.policies.confirm import ConfirmGate
from agent.policies.scope import ScopeError, assert_in_scope, is_in_scope, load_scope


def test_load_scope(tmp_path: Path):
    f = tmp_path / "scope.txt"
    f.write_text("# c\nexample.com\n10.0.0.0/8\n", encoding="utf-8")
    scope = load_scope(f)
    assert "example.com" in scope
    assert is_in_scope("www.example.com", scope)
    assert is_in_scope("10.1.2.3", scope)
    assert not is_in_scope("evil.com", scope)
    with pytest.raises(ScopeError):
        assert_in_scope("evil.com", f)


def test_confirm_gate():
    g = ConfirmGate(require_confirm=True)
    assert not g.is_approved("p1")
    g.approve("p1")
    assert g.is_approved("p1")
    g.reject("p1")
    assert not g.is_approved("p1")
    g2 = ConfirmGate(require_confirm=False)
    assert g2.is_approved("x")
