"""
token_extractor.py

Pulls a user's auth token out of their captured traffic automatically
(no more copy-pasting Bearer tokens by hand), and scans their own
responses for personal info - email, phone number - that can later
prove a swapped response really did leak their data.
"""

import re
from collections import Counter

EMAIL_PATTERN = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
PHONE_PATTERN = re.compile(r"\b\d{9,12}\b")


def extract_bearer_token(requests):
    """Return the most common Bearer token seen across a user's requests."""
    tokens_found = []
    for request in requests:
        auth_header = request["headers"].get("Authorization") or request["headers"].get("authorization")
        if auth_header and auth_header.startswith("Bearer "):
            tokens_found.append(auth_header[len("Bearer "):])

    if not tokens_found:
        return None

    return Counter(tokens_found).most_common(1)[0][0]


def extract_identity_values(requests):
    """
    Scan a user's own response bodies for values that provably belong
    to them: email addresses and phone-like numbers.

    Returns a set of strings. If any of these show up in a DIFFERENT
    user's swapped response later, that's strong proof of a real leak.
    """
    found_values = set()

    for request in requests:
        body = request.get("response_body")
        if not body:
            continue

        for match in EMAIL_PATTERN.findall(body):
            found_values.add(match)

        for match in PHONE_PATTERN.findall(body):
            found_values.add(match)

    return found_values
