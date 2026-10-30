# Playwright Endpoint Discovery

A passive endpoint inventory tool for websites and web applications you own or are authorized to assess.

It combines:
- Playwright browser network observation (Fetch/XHR, document, scripts, styles, WebSocket)
- Same-origin link crawling
- Candidate route extraction from loaded JavaScript bundles
- API/OpenAPI/GraphQL/WebSocket classification
- JSON reporting with evidence, methods, status codes, content types and source pages

## Important coverage limitation

No browser crawler can prove that it has discovered **100% of all server endpoints**. It can only report endpoints observed during tested workflows and routes extracted from accessible client-side assets. Backend-only routes, unvisited pages, role-specific flows, mobile clients, scheduled jobs and private integrations may not be discoverable from a browser session.

Only scan systems for which you have explicit authorization. The scanner is designed for inventory and passive observation. It does not brute-force paths, fuzz parameters, submit forms, attempt authentication bypasses, or exploit endpoints.

## Install

Python 3.10+

```bash
python -m venv .venv
# Windows PowerShell:
.\.venv\Scripts\Activate.ps1
# macOS/Linux:
source .venv/bin/activate

pip install -r requirements.txt
python -m playwright install chromium
```

## Run

Basic crawl:

```bash
python endpoint_mapper.py https://example.com --max-pages 150 --max-depth 3 --output endpoint_map.json
```

Visible browser with time to sign in and explore manually:

```bash
python endpoint_mapper.py https://example.com --headed --manual-seconds 180 --max-pages 200 --output endpoint_map.json
```

Use an existing Playwright storage-state file from an authorized test account:

```bash
python endpoint_mapper.py https://example.com --storage-state auth-state.json --headed --manual-seconds 120
```

Limit the scanner to a specific origin (default is the start URL's origin). Do not enable cross-origin crawling unless you own or have permission to assess those hosts.

```bash
python endpoint_mapper.py https://app.example.com --max-pages 250 --delay 0.4
```

## Output

The JSON report includes:
- `scan`: start URL, timestamps, limits, and coverage caveat
- `summary`: counts by category, method, status and source
- `endpoints`: deduplicated URL+method observations
- `pages`: visited pages and crawl metadata
- `assets`: JavaScript assets inspected
- `errors`: navigation and response-observation errors

Each endpoint contains a normalized URL (query values redacted by default), method, category, resource type, status codes, content types, referring pages, discovery sources, and whether authentication-related headers/cookies were present. Secret values and request/response bodies are never written to the report.

## Authentication state

Create a storage-state file only for a dedicated test account. Do not commit it to Git. Add it to `.gitignore`. Treat it as a password because it can contain session cookies.

## Safety and privacy

- Uses GET-style navigation and passive browser observation; manual interaction is controlled by the operator.
- Does not record Authorization header values, cookies, request bodies, response bodies, or query parameter values.
- Redacts common token-like query parameters.
- Does not crawl off-origin links by default.
- Includes a per-navigation delay and page/depth limits.
- Browser traffic may still trigger application-side analytics or normal page-load side effects. Use a test environment whenever possible.
