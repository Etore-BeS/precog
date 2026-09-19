from osint.brazil.cnpj import validate_cnpj
from osint.brazil.cpf_guard import guard_cpf


def test_cnpj_validate():
    assert not validate_cnpj("11111111111111")
    assert not validate_cnpj("123")


def test_cpf_guard_blocks():
    out = guard_cpf("123.456.789-09")
    assert out["blocked"] is True
    assert out["ok"] is False
