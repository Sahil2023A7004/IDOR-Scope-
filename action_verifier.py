"""
action_verifier.py

Engine 2: catches ACTION-type vulnerabilities that Engine 1 can't see.
A broken delete/update/trigger endpoint often returns the exact same
"200 OK" response body regardless of whose resource actually got
affected - so reading the response tells you nothing.

Instead, this checks the real side effect: read the resource's actual
state before the swapped action, send the action, read the state
again, and compare. If it changed, the action genuinely went through -
no matter what the response claimed.

WARNING: this actually performs the state-changing action (a real
delete, a real update, etc.) against real data. Only ever run this
against accounts you control - your own test accounts, never a third
party's, same rule as the rest of this tool.
"""

import requests

STATE_CHANGING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def is_state_changing(method):
    return method.upper() in STATE_CHANGING_METHODS


def read_resource_state(url, token):
   
    headers = {"Authorization": f"Bearer {token}"}
    try:
        response = requests.get(url, headers=headers, timeout=10)
        return {"status": response.status_code, "body": response.text, "error": None}
    except requests.RequestException as e:
        return {"status": None, "body": None, "error": str(e)}


def verify_action_swap(read_back_url, owner_token, send_action_fn):
   
    before = read_resource_state(read_back_url, owner_token)
    action_result = send_action_fn()
    after = read_resource_state(read_back_url, owner_token)

    state_changed = (
        before.get("body") != after.get("body")
        or before.get("status") != after.get("status")
    )

    return {
        "before": before,
        "action_result": action_result,
        "after": after,
        "state_changed": state_changed,
    }
