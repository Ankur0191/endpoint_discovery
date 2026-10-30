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

Use Python 3.10 or newer. Playwright's current PyPI release metadata lists classifiers through Python 3.14; for now, use Python 3.14 rather than an unlisted newer interpreter when troubleshooting browser/runtime issues.

Windows PowerShell:

\`\`\`powershell
py -3.14 -m venv .venv
.\\.venv\\Scripts\\Activate.ps1

python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m playwright install chromium
\`\`\`

macOS/Linux:

\`\`\`bash
python3.14 -m venv .venv
source .venv/bin/activate

python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m playwright install chromium
\`\`\`

## Updating an existing checkout

After pulling code changes, upgrade dependencies with the same Python interpreter that you use to run the script, then install the matching browser binary:

```powershell
git pull origin main
python -m pip install --upgrade -r requirements.txt
python -m playwright install chromium
```

Using `python -m pip` avoids upgrading a different Python installation from the one running the scanner.

## Run

Basic crawl:

\`\`\`bash
python endpoint_mapper.py https://example.com --max-pages 150 --max-depth 3 --output endpoint_map.json
\`\`\`

Visible browser with time to sign in and explore manually:

\`\`\`bash
python endpoint_mapper.py https://example.com --headed --manual-seconds 180 --max-pages 200 --concurrency 15 --output endpoint_map.json
\`\`\`

Use an existing Playwright storage-state file from an authorized test account:

\`\`\`bash
python endpoint_mapper.py https://example.com --storage-state auth-state.json --headed --manual-seconds 120
\`\`\`

The crawler opens pages in separate tabs using a bounded worker pool. The default is 15 concurrent tabs; set --concurrency 15 (allowed range: 1–15). Tabs share one browser context, so the same login/session state is used. If Chromium or its context closes unexpectedly, the scanner attempts recovery and retries the current URL. High concurrency increases browser and target-site load; reduce to 3–5 if you see HTTP 429/503 responses or browser instability.

Limit the scanner to a specific origin (default is the start URL's origin). Additional origins must be explicitly authorized and supplied separately using \`--allow-origin https://api.example.com\`.

## Output

The JSON report includes:
- \`scan\`: start URL, timestamps, limits, recovery count, and coverage caveat
- \`summary\`: counts by category, method, status, and browser restarts
- \`endpoints\`: deduplicated URL+method observations
- \`pages\`: visited pages and crawl metadata
- \`assets\`: JavaScript assets inspected
- \`errors\`: navigation, response-observation, and browser-recovery errors

Each endpoint contains a normalized URL (sensitive query values redacted by default), method, category, resource type, status codes, content types, referring pages, discovery sources, and whether authentication-related headers/cookies were present. Secret values and request/response bodies are never written to the report.

## Authentication state

Use a dedicated test account. Treat the Playwright storage-state file as a password because it can contain session cookies. It is excluded by \`.gitignore\`; never commit it.

## Safety and privacy

- Uses passive browser observation and bounded same-origin page crawling.
- Does not brute-force paths, fuzz parameters, exploit endpoints, or attempt authentication bypasses.
- Does not record Authorization values, cookies, request bodies, or response bodies.
- Redacts common token-like query parameter values.
- Does not crawl off-origin links by default.
- Includes per-navigation delays, page/depth limits, and bounded browser recovery.
- Browser traffic may still trigger normal application-side analytics or page-load side effects. Use a test environment whenever possible.


## External architecture and capacity analysis

After a scan, create an offline intelligence report from the endpoint inventory:

```powershell
python intelligence_report.py endpoint_map.json --facts ten_public_facts.json --assumptions intelligence_assumptions.json --output-prefix architecture_intelligence
```

This writes:
- `architecture_intelligence.json`: normalized routes, first-party/third-party hosts, observed vendor integrations, technology clues, public facts, and explicit assumptions.
- `architecture_intelligence.md`: a human-readable assessment.

The analyzer makes **no network requests**. It separates:
- observed browser evidence;
- publicly disclosed company metrics supplied in the facts JSON;
- technology hypotheses, such as the public site's CMS;
- low/base/high capacity and storage scenarios;
- illustrative GBP cost scenarios driven by editable values in `intelligence_assumptions.json`.

The included `ten_public_facts.json` uses public FY2026 trading-update metrics for Ten Technologies Group plc. Update it when newer company disclosures are available. The included capacity and cost numbers are example assumptions, not a prediction of Ten's actual database size, MAU, infrastructure bill, or private architecture.

For custom assessments, replace the facts JSON with verified data for the organization under assessment and edit the scenario inputs/rates. For a real internal estimate, ask the platform owner for aggregated MAU, API volume, peak concurrency, storage by data class, retention, and redacted cloud cost allocation.

Run the standard-library tests with:

```powershell
python -m unittest discover -s tests
```

