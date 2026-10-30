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
- publicly disclosed company technology-investment evidence, kept separate from cloud infrastructure costs.

The included `ten_public_facts.json` uses public FY2026 trading-update metrics for Ten Technologies Group plc. Update it when newer company disclosures are available. The capacity and storage numbers are example assumptions, not a prediction of Ten's actual database size or MAU. The analyzer deliberately does not invent a cloud bill: the scan does not identify infrastructure resources, negotiated rates, utilisation or the company's cloud-cost allocation.

For custom assessments, replace the facts JSON with verified data for the organization under assessment and edit the scenario inputs. For a real internal estimate, ask the platform owner for aggregated MAU, API volume, peak concurrency, storage by data class, retention, and redacted cloud cost allocation.

Run the standard-library tests with:

```powershell
python -m unittest discover -s tests
```



## Visual dashboard

The repository includes a local Streamlit dashboard with a built-in, sanitised Ten scan snapshot. It has views for:
- Scan overview and first-party vs third-party split
- Searchable/filterable normalized endpoint routes
- Third-party integration and host inventory
- Technology fingerprints and architecture hypotheses
- Editable MAU, API traffic, peak RPS and database-storage scenarios
- Public company facts, technology-investment disclosures, sources and limitations

Install the optional UI dependencies:

```powershell
python -m pip install -r requirements-dashboard.txt
```

Start the dashboard locally:

```powershell
streamlit run dashboard.py --server.address 127.0.0.1
```

Open the local address printed by Streamlit (normally `http://localhost:8501`). Keep it bound to `127.0.0.1`; scan reports may contain sensitive asset and endpoint metadata, so do not expose the dashboard to a public network without adding appropriate authentication and access controls.

The dashboard opens with a demo snapshot so you can explore the interface immediately. Upload either:
- the raw `endpoint_map.json` generated by `endpoint_mapper.py`, or
- a precomputed `architecture_intelligence.json` report.

When you upload a raw endpoint scan, the dashboard runs the local offline analyzer using `ten_public_facts.json` and `intelligence_assumptions.json`. You can optionally upload replacement company facts and scenario assumptions in the sidebar. The dashboard itself makes no requests to Ten or any target website.

The scale tab recalculates illustrative traffic and storage figures from editable assumptions. It does not estimate an actual cloud bill or claim to reveal private database size.



## Group-level subsidiary and domain intelligence

The repository also includes a group-level workflow for Ten Technologies Group. Its scope file contains the 24 subsidiaries disclosed in the FY2025 Annual Report (18 operating and 6 dormant as at 31 August 2025), two separately listed branch entries, and four domains described in Ten's current official FAQ. The entity register is historical to the reporting date; verify current legal status before using it as a current corporate register.

Install the optional DNS dependency:

~~~powershell
python -m pip install -r requirements-intelligence.txt
~~~

Run the default low-impact discovery workflow:

~~~powershell
python group_intelligence.py --config ten_group_scope.json --output-dir intelligence_output --max-hosts 200
~~~

This queries public certificate-transparency records for hostnames and resolves DNS metadata (A/AAAA/CNAME for hostnames; NS/MX/TXT/SOA for root domains). It does not crawl discovered hostnames. The output directory contains:

- scope_discovery.json — discovered hostnames, certificate record counts, DNS records, public IPs, DNS provider hints, shared-IP groupings and hostname role clues.
- group_intelligence_report.json and .md — subsidiary/domain inventory plus discovery findings and explicit limitations.

Optional root-path HTTP metadata (one HTTPS HEAD / request per eligible host, up to 30 hosts; no redirects or response bodies):

~~~powershell
python group_intelligence.py --config ten_group_scope.json --output-dir intelligence_output --max-hosts 200 --http-metadata
~~~

### Browser scans for subsidiaries or member-facing services

Certificate-transparency and DNS discovery can reveal hostnames, but it does not prove which subsidiary owns a host or whether the host is in scope. Review the owner's written authorization first. Then edit ten_group_scope.json:

1. Add each exact owner-approved URL under authorized_scan_targets.
2. Set the correct entity label/key only when Ten confirms the system-to-entity relationship.
3. Add an approved_origins entry only for API origins explicitly listed in the authorization.
4. Keep client-branded portals, member portals, and other hosts out of the list unless the written scope explicitly includes them.

Then run:

~~~powershell
python group_intelligence.py --config ten_group_scope.json --output-dir intelligence_output --max-hosts 200 --scan-authorized --confirm-authorized-scope
~~~

The explicit confirmation flag is required. Browser scans are performed sequentially with a bounded page limit, low concurrency, normal page navigation and the existing endpoint mapper's redaction rules. Each target gets separate endpoint-map and intelligence JSON/Markdown files, in addition to the group roll-up. For authenticated journeys, use a dedicated test account and configure its local Playwright storage-state file only on the specific approved target; never commit that file.

### What the discovery can and cannot tell you

- DNS CNAME/NS/MX clues may indicate a CDN, DNS provider, email provider or hosting ecosystem. Shared public IPs may be shared infrastructure; they do not prove common databases.
- Hostnames containing labels such as db, postgres, redis or mongo are recorded as naming clues only. The tool never connects to those services, performs port scans, tests credentials, sends database queries or retrieves application data.
- Actual database size, schema, row count, replica count, query performance and cloud costs cannot be measured from public DNS or a public marketing-site scan.
- To estimate those internal values defensibly, ask the system owner for aggregated database/storage metrics, table-size summaries, anonymised request volume, peak concurrency, retention/backup policy and redacted cloud-cost allocations.
- Discovered domains remain group-level and unattributed until the owner confirms the mapping to a subsidiary or application.

For the existing dashboard, upload group_intelligence_report.json to see the new Group & subdomains view alongside the endpoint and architecture tabs.
