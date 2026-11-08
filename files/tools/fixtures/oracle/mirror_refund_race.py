"""Known mirror: the patched gateway's configured return value.

The weak oracle is:

* ``assertEqual(gateway.return_value, "rfnd_TEST")`` echoes the value the test
  itself just configured on the mock.

The two other assertions are the clean pair that must NOT be flagged:

* ``len(calls) == 1`` is a call count on the test's own side_effect list, not a
  configured mock value;
* ``Decimal("600.00")`` is the expected balance.

ORACLE_PROVENANCE must flag exactly MOCK_ECHO. This file is a permanent
control case.
"""

from decimal import Decimal
from unittest import mock
from unittest.mock import MagicMock


class MirrorRefundRace:
    def test_two_concurrent_partials_that_exceed_the_capture(self):
        order = object()
        calls = []

        def slow_gateway(*, payment_id, amount):
            calls.append(amount)
            return "rfnd_TEST"

        with mock.patch("orders.refunds.refund_payment", side_effect=slow_gateway):
            issue_refund(order, payment_id="pay_TEST", amount="600.00")

        gateway = MagicMock()
        gateway.return_value = "rfnd_TEST"

        self.assertEqual(gateway.return_value, "rfnd_TEST")
        self.assertEqual(len(calls), 1)
        self.assertEqual(Refund.refunded_total(order), Decimal("600.00"))
