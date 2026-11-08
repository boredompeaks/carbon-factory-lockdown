import time
from unittest.mock import MagicMock


def add(a, b):
    return a + b


def test_add():
    expected = 3
    assert add(1, 2) == expected


def test_no_assertion():
    value = 1


def test_sleeps():
    time.sleep(1)
    assert True


def test_broad_except():
    try:
        value = 1
    except:
        pass
    assert value == 1


def test_magic_number():
    assert add(1, 2) > 42


def test_mock_only():
    mock = MagicMock()
    expected = 5
    mock.return_value = expected
    assert mock() == expected


def test_duplicate():
    expected = 2
    assert add(1, 1) == expected


def test_duplicate():
    expected = 4
    assert add(2, 2) == expected
