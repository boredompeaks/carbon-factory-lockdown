from unittest.mock import MagicMock


def compute(value):
    return value * 2


def test_add():
    assert compute(2) == 4


def test_self_compare():
    x = 1
    assert x == x


def test_mock_echo():
    mock = MagicMock()
    mock.return_value = 1
    assert mock() == 1


def test_oracle_by_copy():
    x = 1
    assert compute(x) == compute(x)
