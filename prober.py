"""
prober.py

Builds and sends the actual swapped ("probing") requests: takes one
user's credentials and swaps in the other user's resource ID, then
sends it and captures the response.
"""

import requests
from urllib.parse import urlparse, urlunparse, urlencode, parse_qsl


def replace_path_segment(path, target_index, new_value):
    parts = path.split("/")
    count = -1
    for i, segment in enumerate(parts):
        if segment == "":
            continue
        count += 1
        if count == target_index:
            parts[i] = new_value
            break
    return "/".join(parts)


def build_swapped_url(original_url, diff_location, diff_index, diff_key, new_value):
    parsed_url = urlparse(original_url)

    if diff_location == "path":
        new_path = replace_path_segment(parsed_url.path, diff_index, new_value)
        return urlunparse(parsed_url._replace(path=new_path))

    if diff_location == "query":
        query_pairs = parse_qsl(parsed_url.query)
        updated_pairs = [
            (key, new_value) if key == diff_key else (key, value)
            for key, value in query_pairs
        ]
        return urlunparse(parsed_url._replace(query=urlencode(updated_pairs)))

    raise ValueError(f"Unknown diff_location: {diff_location}")


def send_probe(url, token, method="GET", body=None, extra_headers=None):
    """Send a single probing request and return status + body."""
    headers = {"Authorization": f"Bearer {token}"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    if extra_headers:
        headers.update(extra_headers)

    try:
        response = requests.request(method, url, headers=headers, data=body, timeout=10)
        return {"status": response.status_code, "body": response.text, "error": None}
    except requests.RequestException as e:
        return {"status": None, "body": None, "error": str(e)}


def run_pair_probe(match, token_a, token_b):
    url_a_to_b = build_swapped_url(
        match.request_a["url"], match.diff_location, match.diff_index,
        match.diff_key, match.id_value_b,
    )
    url_b_to_a = build_swapped_url(
        match.request_b["url"], match.diff_location, match.diff_index,
        match.diff_key, match.id_value_a,
    )

    response_a_to_b = send_probe(url_a_to_b, token_a, method=match.method)
    response_b_to_a = send_probe(url_b_to_a, token_b, method=match.method)

    return {
        "a_credentials_b_resource": {"swapped_url": url_a_to_b, "response": response_a_to_b},
        "b_credentials_a_resource": {"swapped_url": url_b_to_a, "response": response_b_to_a},
    }
