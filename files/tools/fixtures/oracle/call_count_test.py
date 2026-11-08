"""ORACLE-04: a call-count assertion plus money literals is clean.

``len(calls)`` counts the calls the test's own side_effect recorded, and
``Decimal("300.00")`` is the expected remaining balance. Neither asserts a
value configured on a mock, so the expected finding count is 0.
"""

from decimal import Decimal
from unittest.mock import MagicMock


class CallCountCase:
    def test_refund_called_once(self):
        order = object()
        calls = []

        def slow_gateway(*, payment_id, amount):
            calls.append(amount)
            return "rfnd_TEST"

        gateway = MagicMock()
        gateway.side_effect = slow_gateway

        gateway(payment_id="pay_TEST", amount="300.00")

        self.assertEqual(len(calls), 1)
        self.assertEqual(order.refundable_remaining, Decimal("300.00"))
