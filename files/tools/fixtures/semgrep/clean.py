import requests


def refund(order_id):
    return requests.post(
        "https://api.razorpay.com/v1/refunds",
        json={"order_id": order_id},
    )


def parse(payload):
    try:
        return int(payload)
    except ValueError:
        return 0
