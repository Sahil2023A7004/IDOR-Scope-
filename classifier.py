"""
classifier.py

The leak-detection logic for read-type requests ("Engine 1"). Given a
swapped response, plus both users' own baseline responses, decides
whether a real vulnerability occurred.

Four signals feed the decision, checked in order:
  1. HTTP status - a clean 401/403/404 is an easy "properly denied"
  2. shape comparison - does a 200 OK actually look like a disguised
     error, matching the site's own known "denied" response shapes?
  3. known-value provenance - does the response contain the resource
     owner's email or phone number?
  4. personal-field provenance - does the response match the resource
     owner's own value in ANY field that genuinely differs between the
     two users (catches leaks that aren't an email or phone number)
"""

import json

LEAK = "confirmed_leak"
DENIED_STATUS = "no_leak_denied_by_status"
DENIED_SHAPE = "no_leak_matches_error_baseline"
CORRECTLY_SCOPED = "no_leak_correctly_scoped"
NO_STATE_CHANGE = "no_leak_state_unchanged"
AMBIGUOUS = "ambiguous_needs_manual_review"
REQUEST_FAILED = "request_failed"


def try_parse_json(body):
    if not body:
        return None
    try:
        return json.loads(body)
    except (json.JSONDecodeError, TypeError):
        return None


def extract_schema(data, prefix=""):
   
    schema = set()
    if isinstance(data, dict):
        for key, value in data.items():
            path = f"{prefix}.{key}" if prefix else key
            schema |= extract_schema(value, path)
    elif isinstance(data, list):
        for item in data[:1]:  # just sample the first item's shape
            schema |= extract_schema(item, prefix + "[]")
    else:
        schema.add(f"{prefix}:{type(data).__name__}")
    return schema


def extract_values(data, prefix=""):
    
    values = {}
    if isinstance(data, dict):
        for key, value in data.items():
            path = f"{prefix}.{key}" if prefix else key
            values.update(extract_values(value, path))
    elif isinstance(data, list):
        for item in data[:1]:
            values.update(extract_values(item, prefix + "[]"))
    else:
        values[prefix] = data
    return values


def schema_similarity(schema_a, schema_b):
    """Jaccard similarity between two schema sets. 1.0 = identical shape."""
    if not schema_a and not schema_b:
        return 1.0
    if not schema_a or not schema_b:
        return 0.0
    return len(schema_a & schema_b) / len(schema_a | schema_b)


def build_error_baseline(all_requests):
    
    baseline_schemas = []
    for request in all_requests:
        if request["status"] in (401, 403, 404):
            parsed_body = try_parse_json(request.get("response_body"))
            if parsed_body is not None:
                baseline_schemas.append(extract_schema(parsed_body))
    return baseline_schemas


def matches_error_baseline(schema, baseline_schemas, threshold=0.7):
    if not baseline_schemas:
        return False
    best_match = max(schema_similarity(schema, b) for b in baseline_schemas)
    return best_match >= threshold


def check_provenance(response_text, owner_values):
   
    if not response_text:
        return []
    return [value for value in owner_values if value in response_text]


def find_personal_fields(credential_owner_body, resource_owner_body):
    
    cred_values = extract_values(try_parse_json(credential_owner_body) or {})
    owner_values = extract_values(try_parse_json(resource_owner_body) or {})

    personal_fields = {}
    for path, owner_value in owner_values.items():
        if path in cred_values and cred_values[path] != owner_value:
            personal_fields[path] = owner_value
    return personal_fields


def check_field_leak(swapped_body, personal_fields):
    swapped_values = extract_values(try_parse_json(swapped_body) or {})
    matches = []
    for path, owner_value in personal_fields.items():
        if swapped_values.get(path) == owner_value:
            matches.append((path, owner_value))
    return matches


def classify(swapped_response, baseline_schemas, owner_values,
             owner_own_body=None, credential_owner_own_body=None):
    if swapped_response.get("error") or swapped_response.get("status") is None:
        return {"label": REQUEST_FAILED, "confidence": 0.0,
                "evidence": [f"Request error: {swapped_response.get('error')}"]}

    status = swapped_response["status"]
    body = swapped_response.get("body")

    if status in (401, 403, 404):
        return {"label": DENIED_STATUS, "confidence": 0.95,
                "evidence": [f"HTTP status {status}"]}

    parsed_body = try_parse_json(body)
    if parsed_body is None:
        matched_values = check_provenance(body, owner_values)
        if matched_values:
            return {"label": LEAK, "confidence": 0.8,
                    "evidence": [f"Status {status}, non-JSON body contains "
                                 f"owner-specific value(s): {matched_values}"]}
        return {"label": AMBIGUOUS, "confidence": 0.3,
                "evidence": [f"Status {status}, non-JSON/empty body, "
                              "no provenance match - needs manual look"]}

    response_shape = extract_schema(parsed_body)

    if matches_error_baseline(response_shape, baseline_schemas):
        return {"label": DENIED_SHAPE, "confidence": 0.75,
                "evidence": [f"Status {status} but body shape matches "
                              "known error-response baseline"]}

    # signal 3: known email/phone values
    matched_values = check_provenance(body, owner_values)
    if matched_values:
        return {"label": LEAK, "confidence": 0.95,
                "evidence": [f"Status {status}, response contains resource "
                              f"owner's own value(s): {matched_values}"]}

    # signal 4: any personal field, not just email/phone
    if owner_own_body and credential_owner_own_body:
        personal_fields = find_personal_fields(credential_owner_own_body, owner_own_body)
        field_matches = check_field_leak(body, personal_fields)
        if field_matches:
            return {"label": LEAK, "confidence": 0.9,
                    "evidence": [f"Status {status}, response matches resource "
                                  f"owner's own value in personal field(s): {field_matches}"]}

        # personal fields exist, but the swapped response still shows
        # the CREDENTIAL owner's own values there - the server ignored
        # the swap and correctly scoped the data. Not ambiguous, just fine.
        if personal_fields:
            cred_values = extract_values(try_parse_json(credential_owner_own_body) or {})
            swapped_values = extract_values(parsed_body)
            still_credential_owners_data = all(
                swapped_values.get(path) == cred_values.get(path)
                for path in personal_fields
            )
            if still_credential_owners_data:
                return {"label": CORRECTLY_SCOPED, "confidence": 0.85,
                        "evidence": [f"Status {status}, but personal field(s) "
                                      f"{list(personal_fields.keys())} still show the "
                                      "credential owner's own data - server ignored "
                                      "the swapped ID and scoped correctly"]}

    # fallback: looks like a real record but nothing provably confirmed
    if owner_own_body:
        owner_parsed = try_parse_json(owner_own_body)
        if owner_parsed is not None:
            similarity = schema_similarity(response_shape, extract_schema(owner_parsed))
            if similarity > 0.8:
                return {"label": AMBIGUOUS, "confidence": 0.5,
                        "evidence": [f"Status {status}, shape strongly matches "
                                      "resource owner's own response "
                                      f"(similarity={similarity:.2f}), but no provenance "
                                      "value confirmed - likely leak, verify manually"]}

    return {"label": AMBIGUOUS, "confidence": 0.4,
            "evidence": [f"Status {status}, real-looking JSON, no clear "
                          "denial or confirmation signal - needs manual review"]}


def classify_action(verification_result):
    
    before = verification_result["before"]
    after = verification_result["after"]

    if before.get("error") or after.get("error"):
        return {"label": REQUEST_FAILED, "confidence": 0.0,
                "evidence": ["Could not read resource state before/after - "
                              "network error during verification"]}

    if verification_result["state_changed"]:
        return {"label": LEAK, "confidence": 0.9,
                "evidence": ["Resource owner's data changed after the swapped "
                              "action - the action genuinely went through on "
                              "their resource, regardless of what the response said"]}

    return {"label": NO_STATE_CHANGE, "confidence": 0.7,
            "evidence": ["Resource owner's data is unchanged after the swapped "
                          "action - the response may have said 200 OK, but "
                          "nothing actually happened to their resource"]}
