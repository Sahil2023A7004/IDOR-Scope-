# IDOR-Scope-
#Automated Broken Access Control Detection

Project IDOR-Scope is a self-contained engine that automates the manaul gap in [VSF paper](https://doi.org/10.1109/SP61157.2025.00252)
(*"403 Forbidden? Ethically Evaluating Broken Access Control in the Wild,"*
IEEE S&P 2025) explicitly leaves as manual and open for future work:
deciding whether a successful (`200 OK`) response to a swapped-credential
request is an actual data leak, or just a false positive.

> "...automating this requires understanding the semantics of the
> response, the context of the request, and the user's state; we regard
> this as a distinct open problem for future work." — Section 8.2

This project closes this specific gap for both read-type (data disclosure)
and action-type (delete/update/trigger) vulnerabilities: given two
users' captured browser traffic, it automatically matches requests to
the same endpoint, swaps their resource identifiers, sends the probing
request, and **classifies the result** without a human manually
diffing JSON bodies by eye or re-checking a resource by hand.

## How it works

```
alice.har, bob.har
        │
        ▼
 [har_loader.py]     load + strip noise (static assets, analytics, etc.)
        │
        ▼
  [matcher.py]        find requests hitting the same endpoint shape,
                       identify which URL segment / query param differs
                       (the candidate resource identifier)
        │
        ▼
[token_extractor.py]  pull each user's auth token + personal identity
                       values (email, phone) straight out of their own
                       traffic
        │
        ├─── GET requests ──────────────┐
        │                                ▼
        │                         [prober.py]  build + send the swap
        │                                │
        │                                ▼
        │                       [classifier.py]  "Engine 1": leak /
        │                        no-leak / ambiguous, using shape
        │                        comparison, error-baseline matching,
        │                        and value/field provenance
        │
        └─── POST/PUT/PATCH/DELETE ─────┐
                                          ▼
                              [action_verifier.py]  "Engine 2": snapshot
                              the resource before, send the swapped
                              action, snapshot again, compare - only
                              runs with --test-actions since it performs
                              a real action
        │
        ▼
   findings.json + console summary table
```

## Why this design (and its limits)

This automates two distinct halves of the "deep semantic assessment"
problem the original paper leaves open:

- **Engine 1 (read-type leaks)**: swaps a resource identifier in a GET
  request and classifies the response. It doesn't rely only on finding
  an email address or phone number, it also compares each user's own
  baseline response field-by-field, so a leaked username, balance, or
  any other value tied to one specific user gets caught too.
- **Engine 2 (action-type vulnerabilities)**: for state-changing
  endpoints (POST/PUT/PATCH/DELETE), the response body often looks
  identical regardless of whose resource was actually affected, a
  broken delete endpoint just says `200 OK, deleted` either way. So
  Engine 2 doesn't read the response at all: it reads the resource's
  real state before the swapped action, sends it, reads the state
  again, and compares. If the resource owner's data actually changed,
  that's proof, independent of what the response claimed.

**Engine 2 genuinely performs the action it's testing** (a real
delete, a real update). It's gated behind an explicit `--test-actions`
flag for exactly that reason, without it, state-changing endpoints
are detected and listed but never touched.

The classifier is rule-based, not ML-based, by design: the labeled
dataset available at this scale (a handful of confirmed/denied
endpoints) is nowhere near enough to train a supervised model without
overfitting.

## Requirements
Venv

```bash
sudo apt update && sudo apt install -y python3-venv

```

```bash
python3 -m venv myenv
```

```bash
source myenv/bin/activate

```

```bash
pip install requests
```
Only after you are done with your work use the below command

```bash
deactivate

```

Everything else is Python standard library, deliberately, so this runs
anywhere without fighting dependency versions.

## Usage

1. Capture two users' traffic as HAR files (Firefox/Chrome DevTools →
   Network tab → Persist Logs → Save All As HAR), performing the same
   sequence of actions in both sessions.
2. Run:

```bash
python3 engine.py alice.har bob.har
```

Add `-v` for a full step-by-step trace of what got filtered, matched,
probed, and why each verdict was reached:

```bash
python3 engine.py alice.har bob.har -v
```

Add `--test-actions` to also verify state-changing endpoints found in
the traffic (POST/PUT/PATCH/DELETE). **This performs the real action**
against your test accounts — only use it on accounts you control:

```bash
python3 engine.py alice.har bob.har --test-actions
```

3. Read the console summary table, or open `findings.json` for full
   detail on every tested endpoint, including evidence for each verdict.

### Verdict labels

| Label | Meaning |
|---|---|
| `confirmed_leak` | 
| `no_leak_denied_by_status` | Server correctly returned 401/403/404 |
| `no_leak_matches_error_baseline` | `200 OK` but the body's shape matches the site's own known error responses (disguised denial) |
| `no_leak_correctly_scoped` | `200 OK`, but personal fields still show the credential owner's own data, the server ignored the swapped ID and served the right person |
| `no_leak_state_unchanged` | (action-type only) the resource owner's data is unchanged after the swapped action, the response may have claimed success, but nothing really happened |
| `ambiguous_needs_manual_review` | Couldn't confidently decide either way, needs a human to look |
| `request_failed` | Network-level failure sending the probe or reading state |

## Ethical scope

This tool is intended for use **only against accounts you control**
either your own two test accounts on a live system (mirroring the
original VSF paper's ethical model), or intentionally-vulnerable
practice applications such as [OWASP crAPI](https://github.com/OWASP/crAPI)
or [VAmPI](https://github.com/erev0s/VAmPI). It should not be pointed at
third-party resources without authorization. This applies with extra
force to `--test-actions`, since it performs real state-changing
operations, not just reads.

## Known limitations (v1)

- Bearer-token auth only (no cookie-session support yet)
- Matches on URL path/query structure only, does not yet parse GraphQL
  queries or complex POST bodies
- Only tests peer-to-peer (same-role) access control, not vertical
  (role-escalation) access control
- Engine 2's "read back the state" step defaults to GETting the same
  URL the action targeted (standard REST convention), this won't work
  for APIs where the read-back lives at a different URL
- Rule-based thresholds (e.g. schema similarity cutoffs) were tuned on
  a small test set and may need adjustment for other applications

PROJECT & RESEARCH BY: Sahil Mushtaq (Lead Developer and Researcher of Project IDOR-Scope)
