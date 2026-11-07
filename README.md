# PolicyChecker

[![tests](https://github.com/efrenC/PolicyChecker/actions/workflows/tests.yml/badge.svg)](https://github.com/efrenC/PolicyChecker/actions/workflows/tests.yml)
![Python 3.10–3.13](https://img.shields.io/badge/python-3.10%E2%80%933.13-blue)

> **Showcase project, available for review.** See [Use of this code](#use-of-this-code).

A small service that answers one governance question: **when you combine datasets, how sensitive is the result?**

It applies the **max-risk (high-water mark) rule**: combined data is classified at the level of its most sensitive input. Every decision, including every rejected request, is written to an audit log with a unique ID.

## Why it matters

Analytics pipelines and AI agents increasingly pull from several sources at once. Joining a low-sensitivity dataset with a high-sensitivity one silently produces high-sensitivity output, and most pipelines never notice. PolicyChecker makes that step explicit, deterministic, and auditable.

## Features

- Validates dataset metadata: name, description, classification, and an HTTPS policy link
- Compares 2 to 4 datasets per request
- Checks that each policy link resolves, without letting callers point the service at internal networks
- Computes the resulting classification with the max-risk rule
- Logs every decision and every rejection to a JSON Lines audit log
- Exposes a FastAPI endpoint with interactive docs at `/docs`

Classification levels, lowest to highest risk: `Public < Internal < Confidential < Restricted`. The scheme is defined in one place, [`classifications.py`](classifications.py), so it can be swapped for an organization's own levels.

## Requirements

Python 3.10 or later. Tested on 3.10, 3.11, 3.12 and 3.13.

## Run locally

```bash
pip install -r requirements.txt
uvicorn app:app --reload
```

Then open http://127.0.0.1:8000/docs, or call the API directly:

```bash
curl -X POST http://127.0.0.1:8000/classify \
  -H "Content-Type: application/json" \
  -d '{
    "Datasets": [
      {"Name": "Store footfall", "Description": "Aggregated visitor counts",
       "SecurityClassification": "Internal", "PolicyLink": "https://example.com/policy/footfall"},
      {"Name": "Loyalty members", "Description": "Customer contact details",
       "SecurityClassification": "Restricted", "PolicyLink": "https://example.com/policy/loyalty"}
    ]
  }'
```

Response from a run where the second policy link returned 404:

```json
{
  "Datasets": [
    {
      "Name": "Store footfall",
      "Description": "Aggregated visitor counts",
      "SecurityClassification": "Internal",
      "PolicyLink": "https://example.com/policy/footfall"
    },
    {
      "Name": "Loyalty members",
      "Description": "Customer contact details",
      "SecurityClassification": "Restricted",
      "PolicyLink": "https://example.com/policy/loyalty"
    }
  ],
  "ResultingSecurityClassification": "Restricted",
  "AllPolicyLinksReachable": false,
  "PolicyChecks": [
    {
      "Name": "Store footfall",
      "PolicyLink": "https://example.com/policy/footfall",
      "Status": "reachable",
      "Reachable": true,
      "StatusCode": 200,
      "Error": null
    },
    {
      "Name": "Loyalty members",
      "PolicyLink": "https://example.com/policy/loyalty",
      "Status": "unreachable",
      "Reachable": false,
      "StatusCode": 404,
      "Error": null
    }
  ],
  "AuditLogId": "audit-bfb5061f-67c2-4e86-83f3-2d41cc98be1d"
}
```

A failed policy link is flagged, not fatal: the classification is still returned.

Each link check reports one of four statuses: `reachable`, `unreachable` (error response, timeout, or a domain that doesn't exist), `blocked` (refused for safety, see below) or `not checked` (link checks switched off). `AllPolicyLinksReachable` is `true` only when every link responded, `false` when any failed or was blocked, and `null` when nothing failed but some links weren't checked.

Invalid requests are rejected and still get an audit ID:

| Problem | Response |
|---|---|
| Fewer than 2 or more than 4 datasets, unknown classification, non-HTTPS link, blank or missing fields, unknown fields | `422` |
| Request body over 16 KB | `413` |

```json
{
  "detail": [
    {
      "type": "too_short",
      "loc": ["body", "Datasets"],
      "msg": "List should have at least 2 items after validation, not 1"
    }
  ],
  "AuditLogId": "audit-488237a2-e4bc-4874-b723-d96da0ce6ed6"
}
```

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `POLICYCHECKER_AUDIT_LOG` | `audit_log.jsonl` | Where audit entries are appended |
| `POLICYCHECKER_SKIP_LINK_CHECK` | unset | Set to `1` to skip network link checks (offline demos) |
| `POLICYCHECKER_DISABLE_DOCS` | unset | Set to `1` to hide `/docs`, `/redoc` and `/openapi.json` |

Limits (datasets per request, field lengths, body size, timeouts, redirects) are in [`config.py`](config.py).

## Security

The service was reviewed against the [OWASP API Security Top 10](https://owasp.org/API-Security/).

**Built in**
- **Server-side request forgery protection.** Policy links are only fetched over HTTPS, and only when the host resolves to public internet addresses. Private networks, localhost and cloud metadata endpoints are refused. Redirects are followed manually (up to 3) and each hop is checked again, so a redirect can't leave HTTPS or reach an internal address. Response bodies are never downloaded.
- **Resource limits.** At most 4 datasets per request, capped field lengths, a 16 KB request body limit (also enforced when no length is declared), 5-second timeouts, and link checks run in parallel.
- **Strict input.** Unknown fields are rejected, and names and descriptions can't be blank.
- **Safe errors.** Unexpected failures return a generic `500` with no internal details.
- **Response headers.** `X-Content-Type-Options: nosniff` and `Cache-Control: no-store`.
- **Dependencies.** Minimum versions sit above releases with known security fixes. Dependabot proposes updates weekly, and CI runs the Bandit security rules through Ruff.

**Your deployment's job**
- **Authentication and rate limiting.** The service has neither; run it behind an API gateway that provides both.
- **Audit log integrity.** The log is an append-only file, but not tamper-evident. Ship it to write-once storage or a SIEM if it needs to stand up in a compliance review. Rotate it with your usual log tooling.
- **DNS rebinding.** Addresses are checked just before each request. A hostile DNS server could, in theory, return a different address between the check and the connection. For high-assurance environments, also restrict outbound traffic at the network level.

## Tests

```bash
pip install -r requirements-dev.txt
ruff check .
pytest
```

The tests run fully offline: DNS and web servers are simulated, and audit logs go to a temporary folder. GitHub Actions runs lint and tests on every push across Python 3.10 to 3.13.

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) for the pipeline design and data flow.

## Use of this code

This repository is a showcase of architecture and engineering practice, published so it can be reviewed. You're welcome to read the code, run it locally to evaluate it, and reference it.

Copyright © 2026 Efren Carattini. All rights reserved. No license is granted to use, copy, modify or distribute this code beyond that. If you'd like to use it, or talk about applying the approach in your organization, reach out to me on LinkedIn.
