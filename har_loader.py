"""
har_loader.py

Reads a HAR file (exported from browser DevTools) and turns it into a
plain list of request/response dicts. Also strips out junk requests
(images, css, trackers) we don't care about for access control testing.
"""

import json
from urllib.parse import urlparse, parse_qsl

# anything containing these strings gets thrown out - static assets,
# ad/analytics calls, chatbot widget noise, etc.
JUNK_KEYWORDS = [
    ".css", ".woff", ".woff2", ".png", ".jpg", ".jpeg", ".svg", ".ico",
    "google", "facebook", "analytics", "gstatic", "hot-update", "favicon",
    "chatbot/genai",
]


def load_har(path):
    """Read a HAR file and return a list of simplified request dicts."""
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    entries = data["log"]["entries"]
    parsed_requests = []

    for entry in entries:
        req = entry["request"]
        res = entry["response"]

        # HAR stores headers as a list of {name, value} pairs, not a
        # dict, so convert it - lets us just do headers["Authorization"]
        headers = {h["name"]: h["value"] for h in req.get("headers", [])}

        request_body = None
        if "postData" in req:
            request_body = req["postData"].get("text")

        response_body = None
        content = res.get("content", {})
        if content.get("text"):
            response_body = content["text"]

        url_parts = urlparse(req["url"])

        parsed_requests.append({
            "url": req["url"],
            "path": url_parts.path,
            "query": dict(parse_qsl(url_parts.query)),
            "method": req["method"],
            "headers": headers,
            "body": request_body,
            "status": res["status"],
            "response_body": response_body,
        })

    return parsed_requests


def is_junk(request):
    """True if this request is static/tracking noise, not real app data."""
    url = request["url"].lower()
    return any(keyword in url for keyword in JUNK_KEYWORDS)


def remove_junk(requests):
    """Drop junk requests, keep the rest."""
    return [r for r in requests if not is_junk(r)]


def load_clean(path):
    """Load a HAR file and strip the junk in one call."""
    return remove_junk(load_har(path))
