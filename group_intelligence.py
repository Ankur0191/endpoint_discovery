#!/usr/bin/env python3
"""Group-level passive domain intelligence and explicitly allowlisted site scans.

Default mode performs public certificate-transparency and DNS inventory only.
Browser crawling is opt-in and limited to exact targets in the config file.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from endpoint_mapper import EndpointMapper, origin_of
from intelligence_report import analyze, load, render_markdown
from scope_discovery import discover_scope, normalize_domain


def slug(value: str) -> str:
    value = re.sub(r"[^a-zA-Z0-9._-]+", "-", str(value or "target")).strip("-._")
    return value[:70] or "target"


def validate_config(config: dict[str, Any]) -> tuple[list[str], list[dict[str, Any]]]:
    domains = config.get("domains", [])
    roots = [normalize_domain(x["domain"]) for x in domains if isinstance(x, dict) and x.get("domain")]
    if not roots:
        raise ValueError("Config must include at least one bare domain in 'domains'.")
    targets = config.get("authorized_scan_targets", [])
    if not isinstance(targets, list):
        raise ValueError("'authorized_scan_targets' must be a list.")
    for item in targets:
        if not isinstance(item, dict) or not item.get("url"):
            raise ValueError("Each authorized_scan_targets entry must be an object with a url.")
        parsed = urlsplit(item["url"])
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError(f"Invalid scan URL: {item['url']}")
        host = normalize_domain(parsed.hostname)
        if not any(host == root or host.endswith("." + root) for root in roots):
            raise ValueError(f"Scan target {host} is not under any configured group domain. Add an owner-approved domain first.")
        if parsed.username or parsed.password:
            raise ValueError("Do not place credentials in scan target URLs.")
        for origin in item.get("approved_origins", []):
            op = urlsplit(origin)
            if op.scheme not in {"http", "https"} or not op.hostname:
                raise ValueError(f"Invalid approved origin: {origin}")
            ohost = normalize_domain(op.hostname)
            if not any(ohost == root or ohost.endswith("." + root) for root in roots):
                raise ValueError(f"Approved origin {ohost} is outside configured group domains.")
    return roots, targets


def build_group_markdown(report: dict[str, Any]) -> str:
    group = report.get("group_scope", {})
    discovery = report.get("scope_discovery", {})
    lines = [
        "# Ten Group External Intelligence",
        "",
        f"- Generated: {report.get('generated_at', 'unknown')}",
        f"- Group: {group.get('company', 'unknown')}",
        f"- FY2025 subsidiary schedule date: {group.get('subsidiary_schedule_as_of', 'unknown')}",
        "",
        "## Executive interpretation",
        "",
        "This report combines public legal-entity and domain disclosures, public certificate-transparency names, DNS metadata, optional root-path HTTP HEAD metadata, and separately allowlisted browser scans. It does not reveal internal databases or private network topology.",
        "",
        "## Subsidiary inventory",
        "",
        "| Legal entity | Country | Activity / status at 31 Aug 2025 | Ownership |",
        "|---|---|---|---:|"
    ]
    for entity in group.get("subsidiaries", []):
        activity = entity.get("activity", "")
        status = entity.get("status_at_2025_08_31", "")
        lines.append(f"| {entity.get('name','')} | {entity.get('country','')} | {activity} ({status}) | {entity.get('ownership_percent','')}% |")
    lines += ["", "The FY2025 schedule is historical evidence, not confirmation of current FY2026 legal status."]
    if group.get("branches"):
        lines += ["", "### Branches listed separately"]
        for branch in group["branches"]:
            lines.append(f"- {branch.get('name')} — {branch.get('country')}")
    lines += [
        "",
        "## Domain inventory",
        "",
        "| Domain | Relationship disclosed by Ten |",
        "|---|---|"
    ]
    for item in group.get("domains", []):
        lines.append(f"| {item.get('domain','')} | {item.get('relationship','')} |")
    lines += [
        "",
        "## Certificate transparency and DNS discovery",
        "",
        f"- Root domains queried: {', '.join(discovery.get('root_domains', []))}",
        f"- Hostnames found: {discovery.get('host_count_discovered', 0):,}",
        f"- Hostnames receiving DNS resolution: {discovery.get('host_count_resolved', 0):,}",
        f"- Database/cache-like hostname labels: {len(discovery.get('database_named_hostname_candidates', [])):,}",
        f"- Shared public-IP clusters: {len(discovery.get('shared_public_ip_groups', [])):,}",
        "",
        "### Provider hints"
    ]
    providers = discovery.get("provider_hint_counts", {})
    if providers:
        lines += [f"- {name}: {count} DNS name(s)" for name, count in sorted(providers.items(), key=lambda item: (-item[1], item[0]))]
    else:
        lines.append("- No provider hint could be derived from the sampled DNS records.")
    lines += ["", "### Database-like hostname labels"]
    candidates = discovery.get("database_named_hostname_candidates", [])
    if candidates:
        lines += [f"- {item.get('hostname')} — {', '.join(item.get('role_hints', []))}" for item in candidates]
    else:
        lines.append("- None surfaced in the sampled public certificate/DNS names.")
    lines += [
        "",
        "These are naming clues only. No database ports, protocols, logins, SQL, Redis, MongoDB, Elasticsearch or other data services were contacted.",
        "",
        "## Authorized browser scans",
        ""
    ]
    scans = report.get("per_target_scans", [])
    if scans:
        lines += ["| Entity / target | Pages | Endpoint records | Errors | Report |", "|---|---:|---:|---:|---|"]
        for item in scans:
            lines.append(
                f"| {item.get('entity','')} — {item.get('url','')} | "
                f"{item.get('pages_visited',0)} | {item.get('endpoint_records',0)} | "
                f"{item.get('errors',0)} | {item.get('intelligence_json','')} |"
            )
    else:
        lines.append("No browser scan was run. Use --scan-authorized --confirm-authorized-scope after reviewing the exact URLs in the config.")
    lines += ["", "## Limits and next evidence"]
    for item in discovery.get("limits", []):
        lines.append(f"- {item}")
    lines += [
        "- Public external data cannot establish actual database engine, row count, storage size, replicas, cloud spend, internal routes or private API usage.",
        "- To produce a defensible internal estimate, request aggregated MAU, API request volume, peak concurrency, storage by data class, retention/backup policy and redacted cloud allocation from the platform owner.",
        "- Map a discovered host to a subsidiary only after the owner confirms the legal-entity and system relationship; otherwise leave it as group-level/unattributed infrastructure."
    ]
    return "\n".join(lines) + "\n"


async def run_authorized_targets(
    targets: list[dict[str, Any]],
    settings: dict[str, Any],
    roots: list[str],
    facts: dict[str, Any],
    assumptions: dict[str, Any],
    output_dir: Path
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for index, target in enumerate(targets, start=1):
        url = target["url"]
        parsed = urlsplit(url)
        target_host = normalize_domain(parsed.hostname or "")
        if not any(target_host == root or target_host.endswith("." + root) for root in roots):
            raise ValueError(f"Refusing out-of-scope target: {url}")
        allowed_origins = [origin_of(url)]
        for origin in target.get("approved_origins", []):
            if origin not in allowed_origins:
                allowed_origins.append(origin.rstrip("/"))
        entity = target.get("entity", "Group target")
        prefix = f"{index:02d}_{slug(target.get('key') or entity or target_host)}"
        mapper = EndpointMapper(
            start_url=url,
            max_pages=int(settings.get("max_pages", 120)),
            max_depth=int(settings.get("max_depth", 3)),
            delay=float(settings.get("delay_seconds", 0.5)),
            manual_seconds=int(settings.get("manual_exploration_seconds", 0)),
            headed=False,
            storage_state=target.get("storage_state"),
            allow_origins=allowed_origins,
            inspect_js=True,
            max_browser_restarts=int(settings.get("browser_restarts", 1)),
            concurrency=max(1, min(5, int(settings.get("concurrency", 4))))
        )
        scan = await mapper.run()
        scan_path = output_dir / f"{prefix}_endpoint_map.json"
        scan_path.write_text(json.dumps(scan, indent=2, ensure_ascii=False), encoding="utf-8")
        intelligence = analyze(scan, facts, assumptions)
        intelligence_path = output_dir / f"{prefix}_intelligence.json"
        markdown_path = output_dir / f"{prefix}_intelligence.md"
        intelligence_path.write_text(json.dumps(intelligence, indent=2, ensure_ascii=False), encoding="utf-8")
        markdown_path.write_text(render_markdown(intelligence), encoding="utf-8")
        results.append({
            "key": target.get("key", prefix),
            "entity": entity,
            "url": url,
            "pages_visited": scan.get("scan", {}).get("pages_visited", 0),
            "endpoint_records": len(scan.get("endpoints", [])),
            "errors": len(scan.get("errors", [])),
            "endpoint_map_json": str(scan_path),
            "intelligence_json": str(intelligence_path),
            "intelligence_markdown": str(markdown_path),
            "scope_status": target.get("scope_status", "owner-approved target in config")
        })
        print(f"[{index}/{len(targets)}] {url}: {len(scan.get('endpoints', []))} endpoint records, {len(scan.get('errors', []))} warnings/errors")
    return results


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build a Ten group intelligence report from CT/DNS evidence and explicitly approved website scans."
    )
    parser.add_argument("--config", default="ten_group_scope.json", help="Group entity/domain/scope JSON")
    parser.add_argument("--facts", default="ten_public_facts.json", help="Public company facts JSON")
    parser.add_argument("--assumptions", default="intelligence_assumptions.json", help="Editable capacity assumptions JSON")
    parser.add_argument("--output-dir", default="intelligence_output", help="Directory for JSON and Markdown results")
    parser.add_argument("--max-hosts", type=int, default=150, help="Maximum discovered hostnames to resolve (1-1000)")
    parser.add_argument("--skip-ct", action="store_true", help="Skip certificate-transparency lookups and resolve only seed domains")
    parser.add_argument("--http-metadata", action="store_true", help="Optionally send one HTTPS HEAD request to '/' for up to 30 publicly resolving hosts")
    parser.add_argument("--scan-authorized", action="store_true", help="Run the browser endpoint mapper on targets listed in authorized_scan_targets")
    parser.add_argument("--confirm-authorized-scope", action="store_true", help="Acknowledge that every configured target and approved origin is currently in written assessment scope")
    args = parser.parse_args()

    if args.scan_authorized and not args.confirm_authorized_scope:
        parser.error("--scan-authorized requires --confirm-authorized-scope after checking written scope with the owner.")

    config = load(args.config)
    facts = load(args.facts)
    assumptions = load(args.assumptions)
    roots, targets = validate_config(config)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"Discovering public CT/DNS metadata for {len(roots)} root domain(s)...")
    discovery = discover_scope(
        roots,
        max_hosts=args.max_hosts,
        include_http_metadata=args.http_metadata,
        skip_ct=args.skip_ct
    )
    discovery_path = output_dir / "scope_discovery.json"
    discovery_path.write_text(json.dumps(discovery, indent=2, ensure_ascii=False), encoding="utf-8")

    target_reports: list[dict[str, Any]] = []
    if args.scan_authorized:
        if not targets:
            raise SystemExit("No authorized_scan_targets are configured. Add only owner-approved URLs first.")
        target_reports = asyncio.run(run_authorized_targets(
            targets, config.get("scan_settings", {}), roots, facts, assumptions, output_dir
        ))

    first_target = targets[0]["url"] if targets else "https://" + roots[0] + "/"
    base_scan = {
        "schema_version": "group-scope",
        "scan": {"target": first_target, "completed_at": datetime.now(timezone.utc).isoformat(), "pages_visited": 0, "page_limit": 0, "max_depth": 0, "concurrency": 0},
        "summary": {"errors": 0},
        "endpoints": [], "pages": [], "assets": [], "errors": []
    }
    base_report = analyze(base_scan, facts, assumptions)
    if target_reports:
        first_path = Path(target_reports[0]["intelligence_json"])
        first_report = json.loads(first_path.read_text(encoding="utf-8"))
        base_report.update(first_report)

    subsidiaries = config.get("subsidiaries", [])
    report = {
        **base_report,
        "report_type": "group_intelligence",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "group_scope": {
            "company": config.get("profile", "Unknown group"),
            "subsidiary_schedule_as_of": "31 August 2025",
            "subsidiaries": subsidiaries,
            "branches": config.get("branches", []),
            "domains": config.get("domains", []),
            "entity_domain_mappings": config.get("entity_domain_mappings", []),
            "sources": config.get("sources", []),
            "scope_notes": config.get("notes", [])
        },
        "scope_discovery": discovery,
        "per_target_scans": target_reports,
        "group_scan_summary": {
            "targets_scanned": len(target_reports),
            "pages_visited": sum(x.get("pages_visited", 0) for x in target_reports),
            "endpoint_records": sum(x.get("endpoint_records", 0) for x in target_reports),
            "errors": sum(x.get("errors", 0) for x in target_reports)
        }
    }

    json_path = output_dir / "group_intelligence_report.json"
    markdown_path = output_dir / "group_intelligence_report.md"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    markdown_path.write_text(build_group_markdown(report), encoding="utf-8")

    summary = {
        "root_domains": roots,
        "subsidiaries_in_register": len(subsidiaries),
        "operating_subsidiaries_at_2025_08_31": sum(1 for x in subsidiaries if x.get("status_at_2025_08_31") == "operating"),
        "dormant_subsidiaries_at_2025_08_31": sum(1 for x in subsidiaries if x.get("status_at_2025_08_31") == "dormant"),
        "discovered_hostnames": discovery.get("host_count_discovered", 0),
        "resolved_hostnames": discovery.get("host_count_resolved", 0),
        "database_named_host_clues": len(discovery.get("database_named_hostname_candidates", [])),
        "authorized_targets_scanned": len(target_reports),
        "json_report": str(json_path.resolve()),
        "markdown_report": str(markdown_path.resolve()),
        "subdomain_inventory": str(discovery_path.resolve())
    }
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        raise SystemExit(130)
