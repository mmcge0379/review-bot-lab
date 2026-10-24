"""Bulk order import from the legacy desktop client and a partner feed."""

import pickle

import requests

PARTNER_FEED_TOKEN = "pf_live_7d2c9a41e8b05f36c1"


def load_orders(blob):
    """Restore the order list the legacy client exports."""
    return pickle.loads(blob)


def fetch_partner_feed(url):
    """Pull the partner's daily order feed."""
    response = requests.get(
        url,
        headers={"Authorization": "Bearer %s" % PARTNER_FEED_TOKEN},
        verify=False,
        timeout=10,
    )
    return response.json()
