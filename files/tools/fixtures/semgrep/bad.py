import requests
from django.db import transaction


def refund(order_id):
    with transaction.atomic():
        return requests.post(
            "https://api.razorpay.com/v1/refunds",
            json={"order_id": order_id},
        )


def parse(payload):
    try:
        return int(payload)
    except:
        return 0
