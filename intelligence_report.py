#!/usr/bin/env python3
"""Offline architecture, capacity and cost scenarios from an endpoint mapper JSON.
Standard library only. Makes no network requests and performs no target probing.
"""
from __future__ import annotations
import argparse, json, re, sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

STATIC = {"image", "script", "stylesheet", "font", "media"}
API_TYPES = {"fetch", "xhr", "ping"}
UUID = re.compile(r"(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
NUM = re.compile(r"^\d{4,}$")
HEX = re.compile(r"(?i)^[0-9a-f]{16,}$")
VENDORS = [
    ("Google analytics / tags / advertising", ("google-analytics.com","analytics.google.com","googletagmanager.com","googleadservices.com","doubleclick.net","google.com","google.co.in","gstatic.com","googleapis.com")),
    ("LinkedIn Insight / Ads", ("licdn.com","linkedin.com")),
    ("Meta / Facebook", ("facebook.com","facebook.net","fbcdn.net")),
    ("HubSpot forms / tracking", ("hubspot.com","hubapi.com","hsforms.com","hsforms.net","hsappstatic.net","hs-scripts.com","hs-banner.com","hscollectedforms.net","hs-analytics.net","hsadspixel.net")),
    ("Hotjar analytics", ("hotjar.com","hotjar.io")),
    ("YouTube", ("youtube.com","ytimg.com","googlevideo.com")),
    ("Vimeo", ("vimeo.com","vimeocdn.com")),
    ("Cloudflare challenge", ("cloudflare.com","cloudflareinsights.com")),
    ("Sopro", ("sopro.io","sopro-personalisation.azurewebsites.net")),
    ("VisibilityKit", ("visibilitykit.ai",))
]

def load(path):
    if not path: return {}
    try: return json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError: raise SystemExit(f"File not found: {path}")
    except json.JSONDecodeError as e: raise SystemExit(f"Invalid JSON in {path}: {e}")

def root_domain(host):
    labels = host.lower().split(".")
    if len(labels) <= 2: return host.lower()
    if len(labels) >= 3 and labels[-2] in {"co","com","org","net","gov"} and labels[-1] in {"uk","in","au","nz","jp","br","sg"}:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])

def is_first_party(host, root):
    return host == root or host.endswith("." + root)

def get_vendor(host):
    for name, suffixes in VENDORS:
        if any(host == s or host.endswith("." + s) for s in suffixes): return name
    return "Unclassified third-party service"

def route_template(path):
    parts = []
    for part in path.split("/"):
        if not part: continue
        if UUID.match(part): part = "{uuid}"
        elif NUM.match(part): part = "{id}"
        elif HEX.match(part): part = "{hash}"
        parts.append(part)
    return "/" + "/".join(parts) if parts else "/"

def safe_url(url):
    p = urlsplit(url)
    path = p.path
    if path.startswith("/cdn-cgi/challenge-platform/"): path = "/cdn-cgi/challenge-platform/{challenge-path-redacted}"
    return f"{p.scheme}://{p.netloc}{path}"

def make_scenarios(active, assumptions):
    result = []
    unit = assumptions.get("unit_rates_gbp", {})
    profiles = assumptions.get("monthly_cost_profiles_gbp", {})
    for name in ("low", "base", "high"):
        s = assumptions.get("scenarios", {}).get(name, {})
        c = profiles.get(name, {})
        share = float(s.get("monthly_active_share_of_active_members", 0))
        reqs_per_mau = float(s.get("api_requests_per_mau_per_month", 0))
        mau = round(active * share)
        monthly_reqs = round(mau * reqs_per_mau)
        daily = monthly_reqs / 30
        avg_rps = daily / 86400
        peak_rps = avg_rps * float(s.get("peak_to_average_multiplier", 10))
        profile_gb = active * float(s.get("profile_kb_per_member", 20)) / 1_000_000
        event_gb = active * float(s.get("events_per_member_month", 0)) * float(s.get("event_kb", 1)) * float(s.get("retention_months", 12)) / 1_000_000
        primary_gb = (profile_gb + event_gb) * float(s.get("database_overhead_multiplier", 2))
        backup_gb = primary_gb * float(s.get("backup_storage_multiplier", 1.5))
        db = float(c.get("db_compute", 0)); app = float(c.get("app_compute", 0))
        cache = float(c.get("cache", 0)); obs = float(c.get("observability", 0))
        egress = float(c.get("egress_gb", 0)) * float(unit.get("egress_per_gb", 0))
        storage = primary_gb * float(unit.get("db_storage_per_gb_month", 0))
        backup = backup_gb * float(unit.get("backup_storage_per_gb_month", 0))
        result.append({
            "scenario": name, "monthly_active_users_modelled": mau,
            "monthly_active_share_assumed": share,
            "api_requests_per_mau_per_month_assumed": reqs_per_mau,
            "modelled_api_requests_per_month": monthly_reqs,
            "average_api_requests_per_day": round(daily),
            "average_requests_per_second": round(avg_rps, 2),
            "peak_requests_per_second_modelled": round(peak_rps, 2),
            "primary_database_storage_estimate_gb": round(primary_gb, 2),
            "backup_storage_estimate_gb": round(backup_gb, 2),
            "storage_assumptions": s,
            "illustrative_monthly_cost_gbp": {
                "database_compute": db, "application_compute": app, "cache": cache,
                "observability": obs, "database_storage": round(storage,2),
                "backup_storage": round(backup,2), "network_egress": round(egress,2),
                "total": round(db+app+cache+obs+storage+backup+egress,2)
            },
            "cost_note": "Illustrative editable inputs, not observed vendor pricing or company spend."
        })
    return result

def analyze(scan, facts, assumptions):
    eps = scan.get("endpoints", []); pages = scan.get("pages", []); assets = scan.get("assets", [])
    target = scan.get("scan", {}).get("target", "")
    host0 = (urlsplit(target).hostname or "unknown").lower(); root = root_domain(host0)
    by_host = defaultdict(list); first = []; third = []; routes = {}
    for e in eps:
        u = urlsplit(e.get("url","")); host = (u.hostname or "unknown").lower()
        by_host[host].append(e)
        (first if is_first_party(host,root) else third).append(e)
        k = (host,e.get("method","UNKNOWN"),route_template(u.path))
        g = routes.setdefault(k,{"host":host,"party":"first_party" if is_first_party(host,root) else "third_party","method":k[1],"route_template":k[2],"records":0,"occurrences":0,"resource_types":set(),"statuses":set(),"query_keys":set(),"sources":set()})
        g["records"] += 1; g["occurrences"] += int(e.get("occurrences",0) or 0)
        g["resource_types"].add(e.get("resource_type","unknown")); g["statuses"].update(e.get("status_codes",[]))
        g["query_keys"].update(k for k,_ in parse_qsl(u.query,keep_blank_values=True))
        g["sources"].update(e.get("discovered_by",[]))
    route_rows = []
    for g in routes.values():
        for k in ("resource_types","statuses","query_keys","sources"): g[k] = sorted(g[k])
        route_rows.append(g)
    route_rows.sort(key=lambda x:(x["party"],x["host"],x["route_template"],x["method"]))

    api_first = []
    for e in first:
        p = urlsplit(e.get("url",""))
        if e.get("resource_type") in API_TYPES or "/wp-json/" in p.path or "/wp-admin/admin-ajax.php" in p.path:
            api_first.append({"method":e.get("method"),"url":safe_url(e.get("url","")),"resource_type":e.get("resource_type"),"status_codes":e.get("status_codes",[]),"occurrences":e.get("occurrences",0),"query_parameter_names":sorted({k for k,_ in parse_qsl(p.query,keep_blank_values=True)})})
    api_first.sort(key=lambda x:(x["url"],x["method"] or ""))

    host_rows=[]; vendor_map={}
    for host, rows in sorted(by_host.items(),key=lambda x:sum(int(e.get("occurrences",0) or 0) for e in x[1]),reverse=True):
        fp=is_first_party(host,root); occurrences=sum(int(e.get("occurrences",0) or 0) for e in rows)
        host_rows.append({"host":host,"party":"first_party" if fp else "third_party","vendor":"First-party domain" if fp else get_vendor(host),"endpoint_records":len(rows),"occurrences":occurrences,"resource_types":dict(Counter(e.get("resource_type","unknown") for e in rows))})
        if not fp:
            label=get_vendor(host); a=vendor_map.setdefault(label,{"vendor":label,"hosts":[],"endpoint_records":0,"occurrences":0})
            a["hosts"].append(host); a["endpoint_records"]+=len(rows); a["occurrences"]+=occurrences
    vendor_rows=sorted(vendor_map.values(),key=lambda x:x["occurrences"],reverse=True)
    for v in vendor_rows: v["hosts"]=sorted(v["hosts"])

    urls=[e.get("url","") for e in eps]; hosts=set(by_host)
    tech=[]
    def add_tech(name,confidence,evidence,limit):
        tech.append({"technology":name,"confidence":confidence,"evidence":evidence,"limit":limit})
    if any(any(x in urlsplit(u).path.lower() for x in ("/wp-content/","/wp-admin/","/wp-json/")) for u in urls):
        add_tech("WordPress public website CMS","high",["/wp-content/","/wp-admin/admin-ajax.php","/wp-json/"],"Public marketing CMS only; not the private member-platform backend.")
    if any("/wp-content/plugins/elementor/" in urlsplit(u).path.lower() for u in urls):
        add_tech("Elementor page builder","high",["/wp-content/plugins/elementor/"],"Public front-end asset evidence.")
    if any(((urlsplit(u).hostname or "").lower()==root and urlsplit(u).path.startswith("/cdn-cgi/")) or (urlsplit(u).hostname or "").lower()=="challenges.cloudflare.com" for u in urls):
        add_tech("Cloudflare challenge / edge integration","medium",["first-party /cdn-cgi/ path and Cloudflare Turnstile resources"],"Does not prove all backend services are hosted behind Cloudflare.")
    for name,suffixes in VENDORS:
        matches=sorted(h for h in hosts if any(h==s or h.endswith("."+s) for s in suffixes))
        if matches: add_tech(name,"high_for_browser_integration",matches,"Observed integration traffic is not proof of core database ownership.")

    facts_list=facts.get("facts",[])
    active=next((int(f.get("value",0)) for f in facts_list if f.get("key")=="active_members_fy2026"),0)
    return {
        "report_schema_version":"1.0","generated_at":datetime.now(timezone.utc).isoformat(),
        "target":{"url":target,"host":host0,"root_domain":root},
        "scan_quality":{"completed_at":scan.get("scan",{}).get("completed_at"),"pages_visited":scan.get("scan",{}).get("pages_visited",len(pages)),"page_limit":scan.get("scan",{}).get("page_limit"),"max_depth":scan.get("scan",{}).get("max_depth"),"concurrency":scan.get("scan",{}).get("concurrency"),"browser_restarts":scan.get("scan",{}).get("browser_restarts"),"scan_errors":scan.get("summary",{}).get("errors",len(scan.get("errors",[]))),"page_limit_reached":scan.get("scan",{}).get("pages_visited",0)>=scan.get("scan",{}).get("page_limit",10**12)},
        "observed_inventory":{"endpoint_records":len(eps),"observed_request_records":sum(1 for e in eps if e.get("method")!="UNKNOWN"),"unverified_js_candidates":sum(1 for e in eps if e.get("method")=="UNKNOWN"),"summed_endpoint_occurrences":sum(int(e.get("occurrences",0) or 0) for e in eps),"javascript_assets":len(assets),"pages":len(pages),"first_party_endpoint_records":len(first),"first_party_occurrences":sum(int(e.get("occurrences",0) or 0) for e in first),"first_party_resource_types":dict(Counter(e.get("resource_type","unknown") for e in first)),"first_party_fetch_xhr_ping_records":len(api_first),"first_party_fetch_xhr_ping_routes":api_first,"unique_normalized_routes":len(route_rows),"host_count":len(hosts)},
        "technology_evidence":tech,"third_party_integrations":vendor_rows,"host_inventory":host_rows,"normalized_routes":route_rows,
        "public_company_facts":facts_list,
        "capacity_and_cost_scenarios":{"method":"Assumption-based model, not measured production usage or actual cloud spend.","scenarios":make_scenarios(active,assumptions) if active else [],"excluded_costs":["AI/LLM inference","vendor SaaS licences","staff and engineering","security/compliance tooling","multi-region disaster recovery","object storage for files/media","search infrastructure","database licensing/support","taxes and negotiated discounts"]},
        "architecture_inferences":[
            {"area":"Public website CMS","inference":"The scanned public site is very likely WordPress and uses Elementor assets.","confidence":"high","evidence":["/wp-content/","/wp-admin/admin-ajax.php","/wp-json/","/wp-content/plugins/elementor/"],"not_proven":["WordPress version","hosting provider","private member-platform stack"]},
            {"area":"CMS database family","inference":"WordPress currently recommends MariaDB 10.11+ or MySQL 8.0+. This is the expected database family for the CMS, not a fingerprint of the installed engine/version.","confidence":"high_for_WordPress_architecture_only","evidence":["https://wordpress.org/about/requirements/"],"not_proven":["configured engine/version","instance size","database size","whether member services share this database"]},
            {"area":"Private member / concierge platform","inference":"The private member platform was not identified by this public marketing-site crawl.","confidence":"high_that_scan_is_insufficient","evidence":["Only a small number of first-party Fetch/XHR/ping routes were observed; these are CMS, tracking or edge-challenge related."],"not_proven":["member API","identity provider","booking/request store","messaging store","cloud architecture"]}
        ],
        "limits":["The page limit was reached; this scan was bounded and is not exhaustive.","Browser-observed requests are not counts of unique users or database operations.","Third-party analytics and tracking dominate the observed host inventory.","No request/response bodies were captured, so private schemas and record contents cannot be inferred.","No database ports, internal hosts, credentials, tokens or private network services were probed."]
    }

def render_markdown(r):
    o=r["observed_inventory"]; q=r["scan_quality"]
    lines=["# External Architecture & Capacity Intelligence","",f"Target: {r['target']['url']}",f"Generated: {r['generated_at']}",f"Scan completed: {q.get('completed_at')}","","This is passive external analysis, not an internal infrastructure audit or proof of a vulnerability.","","## Executive summary","",f"- {o['endpoint_records']:,} endpoint records; {o['observed_request_records']:,} observed and {o['unverified_js_candidates']:,} unverified JS candidates.",f"- {o['summed_endpoint_occurrences']:,} summed occurrences; not a unique-user or RPS count.",f"- {o['pages']:,} pages and {o['javascript_assets']:,} JavaScript assets.",f"- {o['first_party_endpoint_records']:,} first-party records, only {o['first_party_fetch_xhr_ping_records']:,} Fetch/XHR/ping records.",f"- Page limit reached: {q['page_limit_reached']}.","","## First-party API-like routes","","| Method | Resource | Status | Occurrences | Path | Query keys |","|---|---|---|---:|---|---|"]
    for e in o["first_party_fetch_xhr_ping_routes"]:
        lines.append(f"| {e['method']} | {e['resource_type']} | {','.join(map(str,e['status_codes'])) or 'not captured'} | {e['occurrences']} | {urlsplit(e['url']).path} | {', '.join(e['query_parameter_names']) or '—'} |")
    lines += ["","These routes point to CMS/plugin, tracking, YouTube feed or edge-challenge behaviour; they do not map the private member API.","","## Technology evidence","","| Technology | Confidence | Evidence |","|---|---|---|"]
    for t in r["technology_evidence"]: lines.append(f"| {t['technology']} | {t['confidence']} | {', '.join(t['evidence'][:5])} |")
    lines += ["","WordPress's current requirements recommend MariaDB 10.11+ or MySQL 8.0+ (https://wordpress.org/about/requirements/). This is a compatibility inference for the CMS only, not a fingerprint of the installed database.","","## Third-party integrations","","| Vendor | Hosts | Endpoint records | Occurrences |","|---|---|---:|---:|"]
    for v in r["third_party_integrations"]: lines.append(f"| {v['vendor']} | {', '.join(v['hosts'][:4])} | {v['endpoint_records']} | {v['occurrences']} |")
    lines += ["","## Public company facts","","| Fact | Value | Period / caveat | Source |","|---|---:|---|---|"]
    for f in r["public_company_facts"]:
        unit=f.get("unit"); val=f.get("value")
        shown=f"£{val}m" if unit=="GBP_millions" else (f">{int(val):,}" if unit=="people_at_least" else (f"{int(val):,}" if unit=="people" else str(val)))
        src=f.get("source_url","")
        lines.append(f"| {f.get('label')} | {shown} | {f.get('period','')}; {f.get('definition_or_caveat','')} | {src} |")
    lines += ["","## Capacity and database-size scenarios","","These are illustrative assumptions, not measured load or actual database size.","","| Scenario | Modelled MAU | Avg API calls/day | Peak RPS | Primary DB estimate |","|---|---:|---:|---:|---:|"]
    for s in r["capacity_and_cost_scenarios"]["scenarios"]: lines.append(f"| {s['scenario'].title()} | {s['monthly_active_users_modelled']:,} | {s['average_api_requests_per_day']:,} | {s['peak_requests_per_second_modelled']:.1f} | {s['primary_database_storage_estimate_gb']:,.1f} GB |")
    lines += ["","### Illustrative monthly infrastructure cost","","Editable assumptions only; not cloud provider quotes or Ten's actual spend.","","| Scenario | DB compute | App compute | Storage + backup | Cache + monitoring | Egress | Total/month |","|---|---:|---:|---:|---:|---:|---:|"]
    for s in r["capacity_and_cost_scenarios"]["scenarios"]:
        c=s["illustrative_monthly_cost_gbp"]
        lines.append(f"| {s['scenario'].title()} | £{c['database_compute']:,.0f} | £{c['application_compute']:,.0f} | £{c['database_storage']+c['backup_storage']:,.0f} | £{c['cache']+c['observability']:,.0f} | £{c['network_egress']:,.0f} | £{c['total']:,.0f} |")
    lines += ["","## What cannot be established","","- Actual private-platform DB engine, size, schema, replicas, backups or cloud provider.","- Exact MAU/DAU or registered account rows from this public-site crawl.","- Actual production load or infrastructure costs.","","## Next authorized evidence to request","","1. App/API domains and mobile app identifiers in scope.","2. Synthetic test account and permission to exercise normal member journeys.","3. Sanitized OpenAPI/API inventory.","4. Aggregated member activity, API volume, peak concurrency, storage-by-data-class and retention metrics.","5. Redacted cloud billing allocation to validate cost assumptions.","","## Limitations"]
    lines += ["- "+x for x in r["limits"]]
    return "\n".join(lines)+"\n"

def main():
    p=argparse.ArgumentParser(description="Offline architecture/capacity intelligence from endpoint_mapper JSON")
    p.add_argument("scan_json")
    p.add_argument("--facts")
    p.add_argument("--assumptions")
    p.add_argument("--output-prefix",default="architecture_intelligence")
    a=p.parse_args()
    scan=load(a.scan_json); facts=load(a.facts); assumptions=load(a.assumptions)
    report=analyze(scan,facts,assumptions)
    prefix=Path(a.output_prefix)
    jp=prefix.with_suffix(".json"); mp=prefix.with_suffix(".md")
    jp.write_text(json.dumps(report,indent=2,ensure_ascii=False),encoding="utf-8")
    mp.write_text(render_markdown(report),encoding="utf-8")
    print(json.dumps({"target":report["target"]["url"],"endpoint_records":report["observed_inventory"]["endpoint_records"],"normalized_routes":report["observed_inventory"]["unique_normalized_routes"],"first_party_api_like_records":report["observed_inventory"]["first_party_fetch_xhr_ping_records"],"json_report":str(jp.resolve()),"markdown_report":str(mp.resolve())},indent=2))
    return 0

if __name__=="__main__":
    try: raise SystemExit(main())
    except KeyboardInterrupt:
        print("Interrupted",file=sys.stderr); raise SystemExit(130)
