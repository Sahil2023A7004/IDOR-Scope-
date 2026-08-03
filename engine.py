#!/usr/bin/env python3
"""
engine.py

VSF-Mini: an automated access control leak detection engine.

Takes two HAR files and runs the whole pipeline end to end:

  1. Load + clean both HAR files              (har_loader.py)
  2. Auto-match requests to the same endpoint  (matcher.py)
  3. Pull each user's token + identity values  (token_extractor.py)
  4. Send swapped requests and classify them   (prober.py, classifier.py)
     - GET endpoints -> Engine 1 (response-based leak detection)
     - state-changing endpoints -> Engine 2 (before/after verification,
       only runs with --test-actions since it performs real actions)
  6. Print a results table + save a JSON report

Usage:
    python3 engine.py alice.har bob.har
    python3 engine.py alice.har bob.har -v
    python3 engine.py alice.har bob.har --test-actions
    python3 engine.py alice.har bob.har --report findings.json
"""

import sys
import os
import json
import argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from har_loader import load_clean, load_har
from matcher import find_matches
from token_extractor import extract_bearer_token, extract_identity_values
from prober import run_pair_probe, build_swapped_url, send_probe
from classifier import build_error_baseline, classify, classify_action
from action_verifier import is_state_changing, verify_action_swap


def shorten(text, max_length):
    if len(text) <= max_length:
        return text
    return text[:max_length - 3] + "..."


def shorten_token(token):
    """Show just enough of a token to recognize it, never the full thing."""
    if not token:
        return "(none)"
    return token[:16] + "..." + token[-6:]


def print_results_table(rows):
    """Print a clean, aligned results table instead of scattered prints."""
    col_widths = {"endpoint": 42, "direction": 20, "status": 8, "verdict": 30, "confidence": 10}

    header = (
        f"{'ENDPOINT':<{col_widths['endpoint']}} "
        f"{'DIRECTION':<{col_widths['direction']}} "
        f"{'STATUS':<{col_widths['status']}} "
        f"{'VERDICT':<{col_widths['verdict']}} "
        f"{'CONFIDENCE':<{col_widths['confidence']}}"
    )
    print(header)
    print("-" * len(header))

    for row in rows:
        print(
            f"{shorten(row['endpoint'], col_widths['endpoint']):<{col_widths['endpoint']}} "
            f"{row['direction']:<{col_widths['direction']}} "
            f"{str(row['status']):<{col_widths['status']}} "
            f"{row['verdict']:<{col_widths['verdict']}} "
            f"{row['confidence']:<{col_widths['confidence']}.2f}"
        )


def run_read_match(match, token_a, token_b, identity_a, identity_b, baseline_schemas, verbose):
    """Engine 1: swap + classify a GET (read-type) match."""
    endpoint_label = f"{match.method} {match.path_template}"

    if verbose:
        print(f"\n  [verbose] probing (read): {endpoint_label}")

    probe_results = run_pair_probe(match, token_a, token_b)

    if verbose:
        print(f"    A's creds -> B's resource: "
              f"{probe_results['a_credentials_b_resource']['swapped_url']}")
        print(f"    B's creds -> A's resource: "
              f"{probe_results['b_credentials_a_resource']['swapped_url']}")

    verdict_a_to_b = classify(
        probe_results["a_credentials_b_resource"]["response"],
        baseline_schemas, identity_b,
        owner_own_body=match.request_b.get("response_body"),
        credential_owner_own_body=match.request_a.get("response_body"),
    )
    verdict_b_to_a = classify(
        probe_results["b_credentials_a_resource"]["response"],
        baseline_schemas, identity_a,
        owner_own_body=match.request_a.get("response_body"),
        credential_owner_own_body=match.request_b.get("response_body"),
    )

    if verbose:
        print(f"    verdict A->B: {verdict_a_to_b['label']} (confidence {verdict_a_to_b['confidence']:.2f})")
        for ev in verdict_a_to_b["evidence"]:
            print(f"      reason: {ev}")
        print(f"    verdict B->A: {verdict_b_to_a['label']} (confidence {verdict_b_to_a['confidence']:.2f})")
        for ev in verdict_b_to_a["evidence"]:
            print(f"      reason: {ev}")

    table_rows = [
        {"endpoint": endpoint_label, "direction": "A creds -> B data",
         "status": probe_results["a_credentials_b_resource"]["response"].get("status"),
         "verdict": verdict_a_to_b["label"], "confidence": verdict_a_to_b["confidence"]},
        {"endpoint": endpoint_label, "direction": "B creds -> A data",
         "status": probe_results["b_credentials_a_resource"]["response"].get("status"),
         "verdict": verdict_b_to_a["label"], "confidence": verdict_b_to_a["confidence"]},
    ]

    report_entry = {
        "type": "read",
        "endpoint": endpoint_label,
        "diff_location": match.diff_location,
        "id_value_a": match.id_value_a,
        "id_value_b": match.id_value_b,
        "a_credentials_b_resource": {
            "swapped_url": probe_results["a_credentials_b_resource"]["swapped_url"],
            "response_status": probe_results["a_credentials_b_resource"]["response"].get("status"),
            "response_body": probe_results["a_credentials_b_resource"]["response"].get("body"),
            "verdict": verdict_a_to_b,
        },
        "b_credentials_a_resource": {
            "swapped_url": probe_results["b_credentials_a_resource"]["swapped_url"],
            "response_status": probe_results["b_credentials_a_resource"]["response"].get("status"),
            "response_body": probe_results["b_credentials_a_resource"]["response"].get("body"),
            "verdict": verdict_b_to_a,
        },
    }

    return table_rows, report_entry


def run_action_match(match, token_a, token_b, verbose):
    """Engine 2: before/after verification for a state-changing match."""
    endpoint_label = f"{match.method} {match.path_template}"

    if verbose:
        print(f"\n  [verbose] verifying (action): {endpoint_label}")

    url_a_to_b = build_swapped_url(match.request_a["url"], match.diff_location,
                                    match.diff_index, match.diff_key, match.id_value_b)
    url_b_to_a = build_swapped_url(match.request_b["url"], match.diff_location,
                                    match.diff_index, match.diff_key, match.id_value_a)

    send_a_to_b = lambda: send_probe(url_a_to_b, token_a, method=match.method,
                                      body=match.request_a.get("body"))
    send_b_to_a = lambda: send_probe(url_b_to_a, token_b, method=match.method,
                                      body=match.request_b.get("body"))

    result_a_to_b = verify_action_swap(match.request_b["url"], token_b, send_a_to_b)
    result_b_to_a = verify_action_swap(match.request_a["url"], token_a, send_b_to_a)

    verdict_a_to_b = classify_action(result_a_to_b)
    verdict_b_to_a = classify_action(result_b_to_a)

    if verbose:
        print(f"    A's creds -> B's resource: state_changed={result_a_to_b['state_changed']}")
        print(f"      verdict: {verdict_a_to_b['label']} (confidence {verdict_a_to_b['confidence']:.2f})")
        for ev in verdict_a_to_b["evidence"]:
            print(f"      reason: {ev}")
        print(f"    B's creds -> A's resource: state_changed={result_b_to_a['state_changed']}")
        print(f"      verdict: {verdict_b_to_a['label']} (confidence {verdict_b_to_a['confidence']:.2f})")
        for ev in verdict_b_to_a["evidence"]:
            print(f"      reason: {ev}")

    table_rows = [
        {"endpoint": endpoint_label, "direction": "A creds -> B action",
         "status": result_a_to_b["action_result"].get("status"),
         "verdict": verdict_a_to_b["label"], "confidence": verdict_a_to_b["confidence"]},
        {"endpoint": endpoint_label, "direction": "B creds -> A action",
         "status": result_b_to_a["action_result"].get("status"),
         "verdict": verdict_b_to_a["label"], "confidence": verdict_b_to_a["confidence"]},
    ]

    report_entry = {
        "type": "action",
        "endpoint": endpoint_label,
        "diff_location": match.diff_location,
        "id_value_a": match.id_value_a,
        "id_value_b": match.id_value_b,
        "a_credentials_b_resource": {**result_a_to_b, "verdict": verdict_a_to_b},
        "b_credentials_a_resource": {**result_b_to_a, "verdict": verdict_b_to_a},
    }

    return table_rows, report_entry


def main():
    parser = argparse.ArgumentParser(description="VSF-Mini access control leak detection engine")
    parser.add_argument("har_a", help="HAR file for user A (e.g. alice.har)")
    parser.add_argument("har_b", help="HAR file for user B (e.g. bob.har)")
    parser.add_argument("--report", default="findings.json", help="Output JSON report path")
    parser.add_argument("-v", "--verbose", action="store_true",
                         help="Show step-by-step detail.")
    parser.add_argument("--test-actions", action="store_true",
                         help="Also verify state-changing endpoints (POST/PUT/PATCH/DELETE). "
                              "WARNING: this performs the real action (delete/update/etc) "
                              "against your test accounts. Only use on accounts you control.")
    args = parser.parse_args()
    verbose = args.verbose

    print(f"Loading {args.har_a} and {args.har_b}...")
    all_requests_a = load_har(args.har_a)
    all_requests_b = load_har(args.har_b)
    clean_requests_a = load_clean(args.har_a)
    clean_requests_b = load_clean(args.har_b)

    print(f"  User A: {len(all_requests_a)} total, "
          f"{len(all_requests_a) - len(clean_requests_a)} removed as junk, "
          f"{len(clean_requests_a)} remain")
    print(f"  User B: {len(all_requests_b)} total, "
          f"{len(all_requests_b) - len(clean_requests_b)} removed as junk, "
          f"{len(clean_requests_b)} remain")

    token_a = extract_bearer_token(clean_requests_a)
    token_b = extract_bearer_token(clean_requests_b)
    if not token_a or not token_b:
        print("ERROR: couldn't find a Bearer token for one or both users.")
        sys.exit(1)

    identity_a = extract_identity_values(clean_requests_a)
    identity_b = extract_identity_values(clean_requests_b)

    if verbose:
        print(f"\n  [verbose] user A token: {shorten_token(token_a)}")
        print(f"  [verbose] user B token: {shorten_token(token_b)}")
        print(f"  [verbose] user A identity values found: {identity_a or '(none found)'}")
        print(f"  [verbose] user B identity values found: {identity_b or '(none found)'}")

    baseline_schemas = build_error_baseline(all_requests_a + all_requests_b)
    print(f"\n  Collected {len(baseline_schemas)} known 'denied' response shapes")

    matches = find_matches(clean_requests_a, clean_requests_b)
    read_matches = [m for m in matches if not is_state_changing(m.method)]
    action_matches = [m for m in matches if is_state_changing(m.method)]

    print(f"  Found {len(read_matches)} read-type candidate(s), "
          f"{len(action_matches)} action-type candidate(s)\n")

    if not matches:
        print("No swappable candidates found. Try browsing more matching "
              "actions in both sessions and re-capturing.")
        sys.exit(0)

    table_rows = []
    full_report = []

    for match in read_matches:
        rows, entry = run_read_match(match, token_a, token_b, identity_a, identity_b,
                                      baseline_schemas, verbose)
        table_rows += rows
        full_report.append(entry)

    for match in action_matches:
        endpoint_label = f"{match.method} {match.path_template}"
        if not args.test_actions:
            print(f"  [skipped] {endpoint_label} is state-changing - "
                  f"re-run with --test-actions to verify it (this performs "
                  f"the real action against your test accounts)")
            full_report.append({
                "type": "action", "endpoint": endpoint_label,
                "status": "skipped_pending_test_actions_flag",
            })
            continue
        rows, entry = run_action_match(match, token_a, token_b, verbose)
        table_rows += rows
        full_report.append(entry)

    print()
    if table_rows:
        print_results_table(table_rows)
    else:
        print("(no endpoints were actually tested - action-type candidates "
              "were skipped; re-run with --test-actions)")

    with open(args.report, "w") as f:
        json.dump(full_report, f, indent=2)

    leak_count = sum(1 for row in table_rows if row["verdict"] == "confirmed_leak")
    print(f"\n{len(table_rows)} test(s) run, {leak_count} confirmed leak(s)")
    print(f"Full report saved to {args.report}")


if __name__ == "__main__":
    main()
