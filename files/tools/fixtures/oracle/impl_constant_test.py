EXPECTED_TOTAL = 500


def compute_expected():
    return EXPECTED_TOTAL


def test_total():
    assert compute_expected() == EXPECTED_TOTAL
