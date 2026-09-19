from agent.settings import Settings


def test_allowed_chat_ids_parse():
    s = Settings(telegram_allowed_chat_ids="1, 2;3")
    assert s.allowed_chat_ids == {1, 2, 3}
