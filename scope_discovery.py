#!/usr/bin/env python3
"""Low-impact group domain intelligence from public certificate and DNS data.

This module does not scan ports, enumerate paths, submit forms, authenticate,
query databases, or retrieve application data. HTTP metadata is an optional
single HEAD request to the root URL of publicly-resolving hostnames.
"""
from __future__ import annotations

import concurrent.futures
import ipaddress
import json
import re
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any

try:
    import dns.resolver  # type: ignore
except ImportError:  # DNS A/AAAA fallback remains available in the standard library.
    dns = None  # type: ignore
else:
    dns = dns  # type: ignore


USER_AGENT = "External-Architecture-Inventory/1.0 (authorized assessment; contact: security owner)"
DATABASE_LABELS = {
    "db", "database", "sql", "mysql", "mariadb", "postgres", "postgresql",
    "mongo", "mongodb", "redis", "elastic", "elasticsearch", "opensearch",
    "cassandra", "cockroach", "dynamodb", "memcache", "memcached"
}
SERVICE_LABELS = {
    "api": "API/service naming clue",
    "app": "application naming clue",
    "auth": "identity/authentication naming clue",
    "sso": "single-sign-on naming clue",
    "login": "identity/login naming clue",
    "member": "member-service naming clue",
    "members": "member-service naming clue",
    "portal": "portal naming clue",
    "admin": "administrative naming clue",
    "staff": "staff-tool naming clue",
    "booking": "booking-service naming clue",
    "bookings": "booking-service naming clue",
    "stage": "staging-environment naming clue",
    "staging": "staging-environment naming clue",
    "dev": "development-environment naming clue",
    "test": "test-environment naming clue",
    "uat": "UAT-environment naming clue",
    "sandbox": "sandbox-environment naming clue",
    "internal": "internal-service naming clue",
    "vpn": "remote-access naming clue",
    "remote": "remote-access naming clue"
}
PROVIDER_MARKERS = {
    "Cloudflare": ("cloudflare",),
    "Amazon Web Services": ("amazonaws.com", "awsdns-", "cloudfront.net", "elb.amazonaws.com"),
    "Microsoft Azure": ("azurewebsites.net", "azureedge.net", "trafficmanager.net", "cloudapp.azure.com", "windows.net"),
    "Google Cloud / Google-hosted": ("googlehosted.com", "googleusercontent.com", "run.app", "appspot.com", "googleapis.com"),
    "Akamai": ("akamai", "akamaiedge.net", "akamaized.net"),
    "Fastly": ("fastly.net", "fastlylb.net"),
    "Heroku": ("herokuapp.com", "herokudns.com"),
    "Vercel": ("vercel.app", "vercel-dns.com"),
    "Netlify": ("netlify.app", "netlify.com"),
    "Shopify": ("myshopify.com", "shopify.com"),
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize_domain(value: str) -> str:
    value = (value or "").strip().lower().rstrip(".")
    if value.startswith("*."):
        value = value[2:]
    if not value or "/" in value or ":" in value or "://" in value:
        raise ValueError(f"Expected a bare DNS domain, got: {value!r}")
    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError(f"Invalid internationalized domain: {value}") from exc
    if len(value) > 253 or not re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", value):
        raise ValueError(f"Invalid DNS domain: {value}")
    return value


def is_under_root(host: str, root: str) -> bool:
    return host == root or host.endswith("." + root)


def _valid_hostname(raw: str, root: str) -> str | None:
    name = raw.strip().lower().rstrip(".")
    if name.startswith("*."):
        name = name[2:]
    if not name:
        return None
    try:
        name = normalize_domain(name)
    except ValueError:
        return None
    return name if is_under_root(name, root) else None


def _certificate_transparency(domain: str, timeout: float = 25.0) -> tuple[set[str], Counter, dict[str, Any]]:
    """Read names already present in crt.sh certificate-transparency records."""
    query = urllib.parse.urlencode({"q": "%." + domain, "output": "json"})
    url = "https://crt.sh/?" + query
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    names: set[str] = {domain}
    cert_ids: set[str] = set()
    per_name_certificates: Counter = Counter()
    metadata: dict[str, Any] = {"source": "crt.sh certificate-transparency search", "query": domain, "certificate_records": 0}
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read(18 * 1024 * 1024 + 1)
        if len(raw) > 18 * 1024 * 1024:
            metadata["warning"] = "Response exceeded the 18 MiB safety cap and was truncated."
            raw = raw[:18 * 1024 * 1024]
        records = json.loads(raw.decode("utf-8", errors="replace"))
        if not isinstance(records, list):
            raise ValueError("Unexpected CT response shape.")
        metadata["certificate_records"] = len(records)
        for item in records:
            if not isinstance(item, dict):
                continue
            cert_id = str(item.get("id", ""))
            if cert_id:
                cert_ids.add(cert_id)
            record_names = set()
            for field in ("name_value", "common_name"):
                value = item.get(field)
                if isinstance(value, str):
                    for candidate in value.splitlines():
                        host = _valid_hostname(candidate, domain)
                        if host:
                            record_names.add(host)
            for host in record_names:
                names.add(host)
                if cert_id:
                    per_name_certificates[host] += 1
        metadata["unique_certificate_ids"] = len(cert_ids)
        metadata["unique_names"] = len(names)
    except Exception as exc:
        metadata["error"] = f"{type(exc).__name__}: {str(exc)[:240]}"
    return names, per_name_certificates, metadata


def _provider_hints(values: list[str]) -> list[str]:
    joined = " ".join(values).lower()
    return sorted(name for name, markers in PROVIDER_MARKERS.items() if any(marker in joined for marker in markers))


def _role_hints(host: str) -> list[str]:
    labels = set(re.split(r"[-_.]", host.lower()))
    hints = [description for token, description in SERVICE_LABELS.items() if token in labels]
    if labels & DATABASE_LABELS:
        hints.append("database/cache technology naming clue only; no connection attempted")
    return sorted(set(hints))


def _safe_public_ips(values: list[str]) -> list[str]:
    result = []
    for value in values:
        try:
            address = ipaddress.ip_address(value)
            if address.is_global:
                result.append(str(address))
        except ValueError:
            continue
    return sorted(set(result))


def _query_dns(host: str, root: str) -> dict[str, Any]:
    result: dict[str, Any] = {
        "hostname": host,
        "a": [],
        "aaaa": [],
        "cname": [],
        "ns": [],
        "mx": [],
        "txt_security_signals": [],
        "errors": []
    }
    query_types = ["A", "AAAA", "CNAME"]
    if host == root:
        query_types += ["NS", "MX", "TXT", "SOA"]

    if dns is None:
        try:
            infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
            for family, _, _, _, sockaddr in infos:
                address = sockaddr[0]
                if family == socket.AF_INET:
                    result["a"].append(address)
                elif family == socket.AF_INET6:
                    result["aaaa"].append(address)
        except Exception as exc:
            result["errors"].append(f"getaddrinfo: {type(exc).__name__}")
    else:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 1.2
        resolver.lifetime = 2.0
        for record_type in query_types:
            try:
                answer = resolver.resolve(host, record_type, raise_on_no_answer=False, lifetime=2.0)
                if answer.rrset is None:
                    continue
                for record in answer:
                    if record_type == "A":
                        result["a"].append(record.address)
                    elif record_type == "AAAA":
                        result["aaaa"].append(record.address)
                    elif record_type == "CNAME":
                        result["cname"].append(str(record.target).rstrip("."))
                    elif record_type == "NS":
                        result["ns"].append(str(record.target).rstrip("."))
                    elif record_type == "MX":
                        result["mx"].append({"priority": int(record.preference), "exchange": str(record.exchange).rstrip(".")})
                    elif record_type == "TXT":
                        pieces = [part.decode("utf-8", errors="ignore") if isinstance(part, bytes) else str(part) for part in record.strings]
                        joined = "".join(pieces).lower()
                        if "v=spf1" in joined:
                            result["txt_security_signals"].append("SPF record present")
                            if "-all" in joined:
                                result["txt_security_signals"].append("SPF hard-fail policy advertised")
                            elif "~all" in joined:
                                result["txt_security_signals"].append("SPF soft-fail policy advertised")
                        if "google-site-verification" in joined:
                            result["txt_security_signals"].append("Google site-verification TXT record present")
                        if "v=dkim1" in joined or "k=rsa" in joined:
                            result["txt_security_signals"].append("DKIM-like TXT record present")
                    elif record_type == "SOA":
                        result["soa_primary_ns"] = str(record.mname).rstrip(".")
                        result["soa_serial"] = int(record.serial)
            except Exception as exc:
                # NXDOMAIN and no-answer are ordinary for many CT names; retain concise metadata only.
                result["errors"].append(f"{record_type}: {type(exc).__name__}")
    for key in ("a", "aaaa", "cname", "ns", "txt_security_signals"):
        result[key] = sorted(set(result[key]))
    result["mx"] = sorted(result["mx"], key=lambda row: (row["priority"], row["exchange"]))
    result["public_ips"] = _safe_public_ips(result["a"] + result["aaaa"])
    return result


def _head_metadata(host: str, timeout: float = 4.0) -> dict[str, Any]:
    """Make one HTTPS HEAD request to '/' only; never follows redirects."""
    result: dict[str, Any] = {"hostname": host, "method": "HEAD", "path": "/", "requested": False}
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None
    opener = urllib.request.build_opener(NoRedirect())
    request = urllib.request.Request(
        "https://" + host + "/",
        method="HEAD",
        headers={"User-Agent": USER_AGENT, "Accept": "*/*"}
    )
    try:
        result["requested"] = True
        try:
            response = opener.open(request, timeout=timeout)
        except urllib.error.HTTPError as exc:
            response = exc
        headers = response.headers
        result["status"] = getattr(response, "code", None)
        result["headers"] = {
            key: headers.get(key)
            for key in (
                "Server", "Via", "X-Powered-By", "Content-Type", "Content-Length",
                "Strict-Transport-Security", "Content-Security-Policy",
                "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy",
                "Permissions-Policy"
            ) if headers.get(key) is not None
        }
        result["security_header_presence"] = {
            "hsts": bool(headers.get("Strict-Transport-Security")),
            "csp": bool(headers.get("Content-Security-Policy")),
            "x_frame_options": bool(headers.get("X-Frame-Options")),
            "x_content_type_options": bool(headers.get("X-Content-Type-Options")),
            "referrer_policy": bool(headers.get("Referrer-Policy"))
        }
        # Do not store Set-Cookie, response bodies, or redirect query parameters.
        if headers.get("Location"):
            location = urllib.parse.urlsplit(headers.get("Location"))
            result["redirect_host"] = location.hostname
            result["redirect_path"] = location.path
        response.close()
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {str(exc)[:180]}"
    return result


def discover_scope(
    root_domains: list[str],
    max_hosts: int = 150,
    include_http_metadata: bool = False,
    skip_ct: bool = False,
) -> dict[str, Any]:
    """Discover CT names and low-impact DNS metadata for explicitly supplied roots."""
    if max_hosts < 1 or max_hosts > 1000:
        raise ValueError("max_hosts must be between 1 and 1000")
    roots = sorted(set(normalize_domain(x) for x in root_domains))
    if not roots:
        raise ValueError("At least one root domain is required.")

    all_hosts: dict[str, dict[str, Any]] = {}
    root_results: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    for root in roots:
        if skip_ct:
            names, cert_counts, ct_meta = {root}, Counter(), {"source": "skipped", "certificate_records": 0}
        else:
            names, cert_counts, ct_meta = _certificate_transparency(root)
        root_results.append({"root_domain": root, "certificate_transparency": ct_meta})
        for host in names:
            if host not in all_hosts:
                all_hosts[host] = {
                    "hostname": host,
                    "root_domain": root,
                    "is_root_domain": host == root,
                    "certificate_records_for_name": int(cert_counts.get(host, 0)),
                    "discovery_sources": ["seed_domain" if host == root else "certificate_transparency"]
                }
            else:
                all_hosts[host]["certificate_records_for_name"] += int(cert_counts.get(host, 0))
                all_hosts[host]["discovery_sources"] = sorted(set(all_hosts[host]["discovery_sources"] + ["certificate_transparency"]))

    ordered_hosts = sorted(all_hosts)
    truncated = len(ordered_hosts) > max_hosts
    selected = ordered_hosts[:max_hosts]
    dns_rows: dict[str, dict[str, Any]] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(16, max(1, len(selected)))) as pool:
        futures = {pool.submit(_query_dns, host, all_hosts[host]["root_domain"]): host for host in selected}
        for future in concurrent.futures.as_completed(futures):
            host = futures[future]
            try:
                dns_rows[host] = future.result()
            except Exception as exc:
                dns_rows[host] = {"hostname": host, "errors": [f"{type(exc).__name__}: {str(exc)[:160]}"]}
                errors.append({"hostname": host, "stage": "dns", "error": str(exc)[:200]})

    hosts: list[dict[str, Any]] = []
    ip_to_hosts: dict[str, list[str]] = defaultdict(list)
    provider_counts: Counter = Counter()
    for host in selected:
        row = all_hosts[host]
        dns_row = dns_rows.get(host, {})
        provider_sources = dns_row.get("cname", []) + dns_row.get("ns", []) + [x.get("exchange", "") for x in dns_row.get("mx", [])]
        provider_hints = _provider_hints([str(x) for x in provider_sources])
        provider_counts.update(provider_hints)
        roles = _role_hints(host)
        public_ips = dns_row.get("public_ips", [])
        for address in public_ips:
            ip_to_hosts[address].append(host)
        hosts.append({
            **row,
            "dns": dns_row,
            "public_ip_addresses": public_ips,
            "provider_hints": provider_hints,
            "hostname_role_hints": roles,
            "database_named_hostname_candidate": any(token in set(re.split(r"[-_.]", host.lower())) for token in DATABASE_LABELS)
        })

    http_rows = []
    if include_http_metadata:
        eligible = [row["hostname"] for row in hosts if row.get("public_ip_addresses")]
        # Bound optional metadata collection to the first 30 public hosts, one HEAD per host.
        for host in eligible[:30]:
            http_rows.append(_head_metadata(host))
            time.sleep(0.2)

    shared_ip_groups = [
        {"public_ip": address, "hostnames": sorted(set(names)), "hostname_count": len(set(names)),
         "interpretation": "Shared address observed; may be CDN, reverse proxy, shared hosting or common origin. Not proof of a shared backend."}
        for address, names in sorted(ip_to_hosts.items()) if len(set(names)) > 1
    ]
    db_candidates = [
        {"hostname": row["hostname"], "role_hints": row["hostname_role_hints"],
         "resolved_public_ips": row["public_ip_addresses"],
         "note": "Name/DNS clue only. No database protocol, port, login or query was attempted."}
        for row in hosts if row["database_named_hostname_candidate"]
    ]
    dns_counts = Counter()
    for row in hosts:
        for key in ("a", "aaaa", "cname", "ns", "mx", "txt_security_signals"):
            if row.get("dns", {}).get(key):
                dns_counts[key] += 1

    return {
        "generated_at": utc_now(),
        "method": "Public certificate-transparency names plus DNS metadata; optional HTTPS HEAD to '/' only.",
        "root_domains": roots,
        "certificate_transparency": root_results,
        "host_count_discovered": len(all_hosts),
        "host_count_resolved": len(selected),
        "host_limit": max_hosts,
        "host_list_truncated": truncated,
        "hosts": hosts,
        "database_named_hostname_candidates": db_candidates,
        "provider_hint_counts": dict(provider_counts),
        "shared_public_ip_groups": shared_ip_groups,
        "dns_record_type_host_counts": dict(dns_counts),
        "http_head_metadata": http_rows,
        "errors": errors,
        "limits": [
            "Certificate transparency is incomplete and can include expired or unused hostnames; it does not prove a host is live.",
            "DNS answers show current public DNS responses only; they do not reveal an origin hidden behind a CDN, private records, or the complete network.",
            "Provider labels are heuristic hints from public DNS names and may describe a CDN or DNS provider rather than application hosting.",
            "A database-like hostname is only a naming clue. The tool does not connect to databases, test ports, authenticate, or retrieve data.",
            "Shared public IPs commonly belong to CDNs, reverse proxies or shared hosting and do not prove systems share a database.",
            "Legal subsidiaries are not mapped to hosts unless an explicit, evidence-backed entry is added to entity_domain_mappings.",
            "The optional HTTP mode sends one HTTPS HEAD request to the root path only, does not follow redirects, and stores no response body or cookies."
        ]
    }
