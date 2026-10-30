#!/usr/bin/env python3
"""Local Streamlit dashboard for endpoint and architecture intelligence.

Run:
    streamlit run dashboard.py --server.address 127.0.0.1

Accepts raw endpoint_mapper.py JSON or a precomputed intelligence report.
The dashboard makes no requests to the assessed target.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pandas as pd
import plotly.express as px
import streamlit as st

ROOT = Path(__file__).resolve().parent
SAMPLE_REPORT = ROOT / "sample_data" / "ten_demo_report.json"
FACTS_FILE = ROOT / "ten_public_facts.json"
ASSUMPTIONS_FILE = ROOT / "intelligence_assumptions.json"

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

try:
    from intelligence_report import analyze
except Exception as exc:
    analyze = None
    ANALYZER_IMPORT_ERROR = str(exc)
else:
    ANALYZER_IMPORT_ERROR = ""

st.set_page_config(
    page_title="External Architecture Intelligence",
    page_icon="◈",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
    <style>
      :root { --ink:#edf3fb; --muted:#91a2b8; --panel:#111d2d; --line:#24354b; --accent:#53d5c4; }
      .stApp { background: radial-gradient(circle at 10% 0%, #172942 0, #0a1220 38%, #08111d 100%); }
      [data-testid="stSidebar"] { background: #0b1524; border-right: 1px solid #24354b; }
      [data-testid="stHeader"] { background: rgba(8,17,29,.85); }
      .block-container { padding-top: 1.45rem; padding-bottom: 3rem; max-width: 1560px; }
      h1,h2,h3 { letter-spacing: -.025em; }
      .eyebrow { color:#72dccc; font-size:.72rem; font-weight:800; letter-spacing:.16em; text-transform:uppercase; }
      .hero-title { color:#f2f6fc; font-size:2.1rem; font-weight:780; letter-spacing:-.055em; margin:.1rem 0 .25rem; }
      .hero-copy { color:#9fb0c4; font-size:.94rem; margin-bottom:.8rem; }
      .panel { background:linear-gradient(145deg,rgba(21,35,54,.96),rgba(12,24,40,.96)); border:1px solid #263a52; border-radius:15px; padding:16px 18px; min-height:105px; }
      .metric-label { color:#91a2b8; text-transform:uppercase; letter-spacing:.10em; font-size:.68rem; font-weight:750; }
      .metric-value { color:#f3f7fc; font-size:1.85rem; line-height:1.25; font-weight:760; margin-top:7px; }
      .metric-note { color:#8194ab; font-size:.75rem; margin-top:3px; }
      .section-kicker { color:#6fdaca; font-size:.7rem; font-weight:800; letter-spacing:.14em; text-transform:uppercase; margin-bottom:4px; }
      .evidence-card { background:#111d2d; border:1px solid #263a52; border-radius:12px; padding:15px 16px; margin-bottom:10px; }
      .evidence-title { color:#edf3fb; font-weight:750; font-size:.98rem; }
      .evidence-body { color:#a9b8ca; font-size:.85rem; line-height:1.5; margin-top:7px; }
      .pill { display:inline-block; border:1px solid #31536a; border-radius:99px; color:#7fe2d2; font-size:.68rem; font-weight:750; padding:3px 8px; margin:5px 4px 0 0; }
      div[data-testid="stMetric"] { background:#111d2d; border:1px solid #263a52; padding:13px 15px; border-radius:13px; }
      div[data-testid="stMetric"] label { color:#9aacc1; }
      div[data-testid="stMetric"] [data-testid="stMetricValue"] { color:#f3f7fc; }
      .stTabs [data-baseweb="tab-list"] { gap:7px; border-bottom:1px solid #263a52; }
      .stTabs [data-baseweb="tab"] { background:#111d2d; color:#aab9cb; border-radius:8px 8px 0 0; padding:10px 15px; }
      .stTabs [aria-selected="true"] { color:#7be2d3 !important; border-bottom:2px solid #53d5c4; }
      div[data-testid="stDataFrame"] { border:1px solid #263a52; border-radius:10px; overflow:hidden; }
      a { color:#73ddcf !important; }
    </style>
    """,
    unsafe_allow_html=True,
)


def read_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except json.JSONDecodeError as exc:
        st.error(f"Could not parse {path.name}: {exc}")
        return {}


def get_any(obj: dict[str, Any], *keys: str, default: Any = None) -> Any:
    for key in keys:
        value = obj.get(key)
        if value is not None:
            return value
    return default


def make_report(raw: dict[str, Any], facts: dict[str, Any], assumptions: dict[str, Any]) -> dict[str, Any]:
    if isinstance(raw.get("observed_inventory"), dict) and isinstance(raw.get("target"), dict):
        return raw
    if isinstance(raw.get("endpoints"), list) and isinstance(raw.get("scan"), dict):
        if analyze is None:
            raise RuntimeError(f"Could not load intelligence_report.py: {ANALYZER_IMPORT_ERROR}")
        return analyze(raw, facts, assumptions)
    raise ValueError("JSON is neither an endpoint_mapper scan nor an architecture intelligence report.")


def as_list(value: Any) -> list:
    return value if isinstance(value, list) else []


def display_name(item: dict[str, Any], *keys: str, default: str = "—") -> str:
    value = get_any(item, *keys, default=default)
    return str(value) if value not in (None, "") else default


def route_rows(report: dict[str, Any]) -> list[dict[str, Any]]:
    inv = report.get("observed_inventory", {})
    routes = as_list(report.get("normalized_routes"))
    if routes:
        return [{
            "Party": display_name(route, "party"),
            "Host": display_name(route, "host"),
            "Method": display_name(route, "method"),
            "Route": display_name(route, "route_template", "path"),
            "Classification": display_name(route, "classification", "category"),
            "Resource types": ", ".join(map(str, get_any(route, "resource_types", default=[]))),
            "Status codes": ", ".join(map(str, get_any(route, "status_codes", "statuses", default=[]))),
            "Records": get_any(route, "records", default=1),
            "Occurrences": get_any(route, "occurrences", default=0),
            "Query keys": ", ".join(map(str, get_any(route, "query_parameter_names", "query_keys", default=[]))),
        } for route in routes]
    candidates = as_list(get_any(inv, "first_party_fetch_xhr_ping_routes", "first_party_fetch_xhr_ping_route_records", default=[]))
    return [{
        "Party": "first_party",
        "Host": report.get("target", {}).get("host", "—"),
        "Method": e.get("method", "—"),
        "Route": e.get("url", "—"),
        "Classification": get_any(e, "classification", "category", default="—"),
        "Resource types": e.get("resource_type", "—"),
        "Status codes": ", ".join(map(str, e.get("status_codes", []))),
        "Records": 1,
        "Occurrences": e.get("occurrences", 0),
        "Query keys": ", ".join(map(str, e.get("query_parameter_names", []))),
    } for e in candidates]


def fact_rows(report: dict[str, Any]) -> list[dict[str, Any]]:
    return [{
        "Fact": get_any(f, "label", "key", default="—"),
        "Value": f.get("value", "—"),
        "Unit": f.get("unit", ""),
        "Period": f.get("period", ""),
        "Status": f.get("status", ""),
        "Caveat": f.get("definition_or_caveat", ""),
        "Source": f.get("source_url", ""),
    } for f in as_list(report.get("public_company_facts"))]


def vendor_rows(report: dict[str, Any]) -> list[dict[str, Any]]:
    return [{
        "Vendor": get_any(x, "vendor", "vendor_group", "name", default="Unclassified"),
        "Hosts": ", ".join(as_list(x.get("hosts"))),
        "Endpoint records": get_any(x, "endpoint_records", "records", default=0),
        "Observed occurrences": get_any(x, "observed_occurrences", "occurrences", default=0),
    } for x in as_list(report.get("third_party_integrations"))]


def evidence_fields(item: dict[str, Any]) -> tuple[str, str, list[str], str]:
    title = display_name(item, "technology_or_pattern", "technology", "area")
    confidence = display_name(item, "confidence", default="unrated").replace("_", " ")
    evidence = as_list(get_any(item, "observed_clues", "evidence", default=[]))
    limitation = display_name(item, "limitations", "limit", "inference", default="")
    return title, confidence, evidence, limitation


def render_overview(report: dict[str, Any]) -> None:
    inv = report.get("observed_inventory", {})
    quality = report.get("scan_quality", {})
    target = report.get("target", {})
    endpoint_count = get_any(inv, "endpoint_records", "total_endpoint_records", default=0)
    observed = get_any(inv, "observed_request_records", "observed_requests", default=0)
    candidates = get_any(inv, "unverified_js_candidates", "unverified_candidates", default=0)
    pages = get_any(inv, "pages", default=quality.get("pages_visited", 0))
    js_assets = get_any(inv, "javascript_assets", default=0)
    first_party = get_any(inv, "first_party_endpoint_records", default=0)
    api_count = get_any(inv, "first_party_fetch_xhr_ping_route_records", "first_party_fetch_xhr_ping_records", default=0)
    routes = get_any(inv, "unique_normalized_routes", default=len(as_list(report.get("normalized_routes"))))
    hosts = get_any(inv, "host_count", default=len(as_list(report.get("host_inventory"))))
    occurrences = get_any(inv, "record_occurrence_sum", "summed_endpoint_occurrences", default=0)

    st.markdown('<div class="section-kicker">Scan overview</div>', unsafe_allow_html=True)
    cols = st.columns(4)
    cards = [
        ("Endpoint records", f"{endpoint_count:,}", "Observed + unverified candidates"),
        ("Observed requests", f"{observed:,}", "Actual browser network requests"),
        ("First-party records", f"{first_party:,}", f"{api_count} Fetch/XHR/ping route records"),
        ("Pages / JS assets", f"{pages:,} / {js_assets:,}", f"{hosts} hosts · {routes:,} normalized routes"),
    ]
    for col, (label, value, note) in zip(cols, cards):
        with col:
            st.markdown(
                f'<div class="panel"><div class="metric-label">{label}</div><div class="metric-value">{value}</div><div class="metric-note">{note}</div></div>',
                unsafe_allow_html=True,
            )

    st.write("")
    left, right = st.columns([1.25, 1])
    with left:
        st.markdown("### What the scan actually saw")
        st.markdown(
            f"""
            - **Target:** {target.get('url', 'Unknown')}
            - **Completed:** {quality.get('completed_at', 'Not supplied')}
            - **Concurrency:** {quality.get('concurrency', 'Not supplied')}
            - **Page limit reached:** {quality.get('page_limit_reached', 'Unknown')}
            - **Scan errors:** {quality.get('scan_errors', 0)}
            - **Summed request occurrences:** {occurrences:,}
            - **Unverified JavaScript candidates:** {candidates:,}
            """
        )
        st.caption("Occurrences are repeated requests, not unique users, sessions, database queries or API calls per day.")
    with right:
        st.markdown("### First-party vs third-party")
        party_data = [
            {"Group": "First-party", "Records": int(first_party or 0)},
            {"Group": "Third-party / other", "Records": max(int(endpoint_count or 0) - int(first_party or 0), 0)},
        ]
        fig = px.pie(party_data, names="Group", values="Records", hole=0.68,
                     color_discrete_sequence=["#53d5c4", "#53749a"], template="plotly_dark")
        fig.update_layout(height=265, margin=dict(l=5, r=5, t=5, b=5), paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", legend=dict(orientation="h", y=-0.05))
        fig.update_traces(textposition="inside", textinfo="percent")
        st.plotly_chart(fig, use_container_width=True)

    st.info("Coverage caveat: this is a bounded browser crawl. It cannot discover backend-only routes, unvisited role-specific workflows, mobile-only APIs or internal services that are not exposed to the browser.")


def render_routes(report: dict[str, Any]) -> None:
    rows = route_rows(report)
    if not rows:
        st.warning("No normalized route records were found in this report.")
        return
    df = pd.DataFrame(rows)
    c1, c2, c3 = st.columns(3)
    parties = ["All"] + sorted(df["Party"].dropna().astype(str).unique().tolist())
    methods = ["All"] + sorted(df["Method"].dropna().astype(str).unique().tolist())
    resources = ["All"] + sorted({x.strip() for cell in df["Resource types"].dropna() for x in str(cell).split(",") if x.strip()})
    with c1:
        party_filter = st.selectbox("Ownership", parties, key="route_party")
    with c2:
        method_filter = st.selectbox("HTTP method", methods, key="route_method")
    with c3:
        resource_filter = st.selectbox("Resource type", resources, key="route_resource")
    search = st.text_input("Search host, route or classification", placeholder="e.g. wp-json, graphql, auth")
    filtered = df.copy()
    if party_filter != "All":
        filtered = filtered[filtered["Party"] == party_filter]
    if method_filter != "All":
        filtered = filtered[filtered["Method"] == method_filter]
    if resource_filter != "All":
        filtered = filtered[filtered["Resource types"].str.contains(resource_filter, case=False, na=False)]
    if search:
        mask = filtered.astype(str).apply(lambda col: col.str.contains(search, case=False, na=False)).any(axis=1)
        filtered = filtered[mask]
    st.caption(f"Showing {len(filtered):,} of {len(df):,} normalized routes. Candidate classifications are not confirmed vulnerabilities.")
    st.dataframe(filtered, use_container_width=True, hide_index=True, height=460)
    st.download_button("Download filtered routes CSV", data=filtered.to_csv(index=False).encode("utf-8"),
                       file_name="normalized_routes.csv", mime="text/csv")
    api_rows = as_list(get_any(report.get("observed_inventory", {}), "first_party_fetch_xhr_ping_routes", "first_party_fetch_xhr_ping_route_records", default=[]))
    if api_rows:
        st.markdown("### First-party Fetch / XHR / ping observations")
        api_df = pd.DataFrame([{
            "Method": e.get("method"),
            "URL": e.get("url"),
            "Resource": e.get("resource_type"),
            "Status": ", ".join(map(str, e.get("status_codes", []))),
            "Occurrences": e.get("occurrences", 0),
            "Query parameter names": ", ".join(e.get("query_parameter_names", [])),
        } for e in api_rows])
        st.dataframe(api_df, use_container_width=True, hide_index=True)


def render_integrations(report: dict[str, Any]) -> None:
    vendors = vendor_rows(report)
    hosts = as_list(report.get("host_inventory"))
    left, right = st.columns([1.15, 1])
    with left:
        st.markdown("### Third-party integration activity")
        if vendors:
            vdf = pd.DataFrame(vendors).sort_values("Observed occurrences", ascending=True)
            fig = px.bar(vdf, x="Observed occurrences", y="Vendor", orientation="h", color="Observed occurrences",
                         color_continuous_scale=["#29415d", "#53d5c4"], template="plotly_dark")
            fig.update_layout(height=max(330, len(vdf) * 34), margin=dict(l=5, r=5, t=12, b=5),
                              paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", coloraxis_showscale=False)
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No third-party vendor groups were included in this report.")
    with right:
        st.markdown("### Vendor detail")
        if vendors:
            st.dataframe(pd.DataFrame(vendors).sort_values("Observed occurrences", ascending=False),
                         use_container_width=True, hide_index=True, height=420)
        else:
            st.info("No vendor data.")
    if hosts:
        st.markdown("### Host inventory")
        st.dataframe(pd.DataFrame(hosts), use_container_width=True, hide_index=True, height=360)
    st.caption("Third-party request counts show browser integration activity. They do not identify Ten's internal system of record or core database vendor.")


def render_architecture(report: dict[str, Any]) -> None:
    st.markdown("### Observed technology fingerprints")
    tech = as_list(report.get("technology_evidence"))
    if tech:
        cols = st.columns(2)
        for index, item in enumerate(tech):
            title, confidence, evidence, limitation = evidence_fields(item)
            evidence_html = "".join(
                f'<span class="pill">{str(x).replace("<", "&lt;").replace(">", "&gt;")}</span>'
                for x in evidence[:7]
            )
            with cols[index % 2]:
                st.markdown(
                    f'<div class="evidence-card"><div class="evidence-title">{title}</div>'
                    f'<span class="pill">{confidence}</span><div>{evidence_html}</div>'
                    f'<div class="evidence-body">{limitation}</div></div>',
                    unsafe_allow_html=True,
                )
    else:
        st.info("No technology evidence list was supplied.")

    st.markdown("### Architecture inferences")
    inferences = as_list(report.get("architecture_inferences"))
    if inferences:
        for item in inferences:
            with st.expander(f"{item.get('area', 'Architecture hypothesis')} · {str(item.get('confidence', 'unrated')).replace('_', ' ')}"):
                st.write(item.get("inference", ""))
                evidence = as_list(item.get("evidence"))
                if evidence:
                    st.markdown("**Supporting evidence**")
                    for line in evidence:
                        st.markdown(f"- {line}")
                not_proven = as_list(item.get("not_proven"))
                if not_proven:
                    st.markdown("**Not established**")
                    for line in not_proven:
                        st.markdown(f"- {line}")

    st.markdown("### Likely logical data domains · hypotheses")
    domains = [
        ("Member and programme identity", "Eligibility, programme membership, profile, preferences and entitlements."),
        ("Concierge operations", "Requests, case state, service history, Lifestyle Manager assignment and handoffs."),
        ("Bookings and suppliers", "Reservations, supplier catalogue, offers, availability and transaction references."),
        ("Engagement and personalisation", "Channel events, segmentation, campaign responses and member experience signals."),
        ("Agent and AI workflows", "Assistant interactions, staff co-pilot context, quality signals and escalation state."),
        ("Analytics and client reporting", "Ingestion, normalisation, aggregated operational metrics and corporate client reporting."),
    ]
    cols = st.columns(3)
    for i, (name, desc) in enumerate(domains):
        with cols[i % 3]:
            st.markdown(
                f'<div class="evidence-card"><div class="evidence-title">{name}</div>'
                f'<div class="evidence-body">{desc}</div><span class="pill">Hypothesis · validate with owner</span></div>',
                unsafe_allow_html=True,
            )


def render_scale(report: dict[str, Any]) -> None:
    scenarios = as_list(report.get("capacity_and_cost_scenarios", {}).get("scenarios"))
    if not scenarios:
        st.warning("No capacity scenarios are present in this report.")
        return
    default_active = 461000
    for fact in as_list(report.get("public_company_facts")):
        if fact.get("key") == "active_members_fy2026":
            try:
                default_active = int(fact.get("value", default_active))
            except (TypeError, ValueError):
                pass

    labels = [str(s.get("assumption_label", s.get("scenario", "Scenario"))).title() for s in scenarios]
    chosen = st.selectbox("Scenario to inspect", labels, index=min(1, len(labels) - 1))
    selected = scenarios[labels.index(chosen)]
    storage = selected.get("storage_assumptions", {})

    active = st.number_input("12-month Active Members baseline", min_value=1, value=default_active, step=1000)
    c1, c2, c3 = st.columns(3)
    with c1:
        share = st.number_input("Assumed monthly-active share", min_value=0.01, max_value=1.0,
                                value=float(selected.get("monthly_active_share_assumed", 0.3)), step=0.05, format="%.2f")
        calls_per_mau = st.number_input("API requests per MAU / month", min_value=1, max_value=100000,
                                        value=int(selected.get("api_requests_per_mau_per_month_assumed", 100)), step=10)
    with c2:
        peak_multiplier = st.number_input("Peak / average multiplier", min_value=1.0, max_value=100.0, value=10.0, step=1.0)
        profile_kb = st.number_input("Profile KB per active member", min_value=0.1, max_value=10000.0,
                                     value=float(get_any(storage, "profile_kb_per_active_member", "profile_kb_per_member", default=20.0)), step=1.0)
    with c3:
        events_per_mau = st.number_input("Events per MAU / month", min_value=0, max_value=100000,
                                         value=int(storage.get("events_per_mau_month", storage.get("events_per_member_month", 50))), step=10)
        event_kb = st.number_input("Average event KB", min_value=0.01, max_value=10000.0,
                                   value=float(get_any(storage, "average_event_kb", "event_kb", default=1.0)), step=0.25)

    c4, c5, c6 = st.columns(3)
    with c4:
        retention = st.number_input("Retention (months)", min_value=1, max_value=120, value=int(storage.get("retention_months", 12)))
    with c5:
        overhead = st.number_input("DB/index overhead multiplier", min_value=1.0, max_value=10.0,
                                   value=float(storage.get("database_overhead_multiplier", 2.0)), step=0.25)
    with c6:
        backup_multiplier = st.number_input("Backup storage multiplier", min_value=1.0, max_value=10.0,
                                            value=float(storage.get("backup_storage_multiplier", 1.5)), step=0.25)

    mau = round(active * share)
    monthly_calls = mau * calls_per_mau
    calls_day = monthly_calls / 30
    avg_rps = calls_day / 86400
    peak_rps = avg_rps * peak_multiplier
    profile_raw = active * profile_kb / 1_000_000
    event_raw = mau * events_per_mau * event_kb * retention / 1_000_000
    primary = (profile_raw + event_raw) * overhead
    backup = primary * backup_multiplier

    st.markdown("### Recalculated scenario")
    cards = st.columns(4)
    calculated = [
        ("Modelled MAU", f"{mau:,}"),
        ("API calls / day", f"{calls_day:,.0f}"),
        ("Peak requests / sec", f"{peak_rps:,.1f}"),
        ("Primary DB storage", f"{primary:,.1f} GB"),
    ]
    for col, (label, value) in zip(cards, calculated):
        with col:
            st.markdown(
                f'<div class="panel"><div class="metric-label">{label}</div>'
                f'<div class="metric-value">{value}</div><div class="metric-note">Editable assumption model</div></div>',
                unsafe_allow_html=True,
            )

    comparison = [{
        "Scenario": str(s.get("assumption_label", s.get("scenario", "Scenario"))),
        "MAU": int(s.get("monthly_active_users_modelled", 0)),
        "Peak RPS": float(s.get("peak_requests_per_second_modelled", 0)),
        "Primary DB GB": float(s.get("primary_database_storage_estimate_gb", 0)),
        "Backup GB": float(s.get("backup_storage_estimate_gb", 0)),
    } for s in scenarios]
    st.markdown("### Scenario comparison")
    p1, p2 = st.columns(2)
    with p1:
        fig = px.bar(pd.DataFrame(comparison), x="Scenario", y="Primary DB GB", color="Scenario",
                     color_discrete_sequence=["#3c6b89", "#53d5c4", "#d2a85d"], template="plotly_dark")
        fig.update_layout(height=330, showlegend=False, margin=dict(l=5, r=5, t=10, b=5),
                          paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)")
        st.plotly_chart(fig, use_container_width=True)
    with p2:
        fig = px.bar(pd.DataFrame(comparison), x="Scenario", y="Peak RPS", color="Scenario",
                     color_discrete_sequence=["#3c6b89", "#53d5c4", "#d2a85d"], template="plotly_dark")
        fig.update_layout(height=330, showlegend=False, margin=dict(l=5, r=5, t=10, b=5),
                          paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)")
        st.plotly_chart(fig, use_container_width=True)
    st.dataframe(pd.DataFrame(comparison), use_container_width=True, hide_index=True)
    st.warning("This is a hypothetical logical data footprint, not a measured database. It does not estimate cloud spend.")


def render_facts(report: dict[str, Any]) -> None:
    facts = fact_rows(report)
    if not facts:
        st.info("No public-company facts were provided in this report.")
        return
    df = pd.DataFrame(facts)
    st.dataframe(df.drop(columns=["Source"]), use_container_width=True, hide_index=True, height=420)
    st.markdown("### Source links")
    for fact in facts:
        if fact["Source"]:
            st.markdown(f"- **{fact['Fact']}** — [Open source]({fact['Source']})")

    investment_facts = as_list(report.get("technology_investment_facts"))
    if not investment_facts:
        investment_facts = [f for f in as_list(report.get("public_company_facts"))
                            if "investment" in str(f.get("key", "")) or "capitalised_development" in str(f.get("key", ""))]
    if investment_facts:
        st.markdown("### Technology investment disclosures")
        cols = st.columns(min(3, len(investment_facts)))
        for i, fact in enumerate(investment_facts):
            if fact.get("unit") == "GBP_millions":
                with cols[i % len(cols)]:
                    st.metric(fact.get("label", "Investment"), f"£{float(fact.get('value', 0)):,.3f}m",
                              help=fact.get("definition_or_caveat", ""))
        st.caption("These disclosures cover broader technology/platform, content and communications investment. They are not a cloud/database bill.")


def render_limits(report: dict[str, Any]) -> None:
    st.markdown("### What this dataset cannot establish")
    for item in as_list(report.get("limits")):
        st.markdown(f"- {item}")
    st.markdown("### Evidence discipline")
    st.markdown(
        """
        - **Observed:** directly present in the browser scan or company disclosure.
        - **Advertised:** named in a public recruitment requirement; not proof of production deployment.
        - **Inferred:** a reasoned hypothesis supported by visible product or technology clues.
        - **Unknown:** requires owner-provided evidence, internal telemetry or an agreed test environment.
        """
    )
    st.info("For the private member platform, request an approved synthetic account, official API hostnames, sanitised OpenAPI documentation, aggregated metrics and redacted cloud-cost allocation from the platform owner.")


def main() -> None:
    st.sidebar.markdown('<div class="eyebrow">Assessment workspace</div>', unsafe_allow_html=True)
    st.sidebar.title("External Intelligence")
    st.sidebar.caption("Offline report viewer · this dashboard does not contact the assessed target.")

    facts = read_json(FACTS_FILE)
    assumptions = read_json(ASSUMPTIONS_FILE)
    upload = st.sidebar.file_uploader("Upload scan or intelligence JSON", type=["json"])

    local_options = ["Built-in Ten demo snapshot"]
    if (ROOT / "architecture_intelligence.json").exists():
        local_options.append("Local architecture_intelligence.json")
    if (ROOT / "endpoint_map.json").exists():
        local_options.append("Local endpoint_map.json")
    source = st.sidebar.radio("Or load a local file", local_options, index=0)

    facts_upload = st.sidebar.file_uploader("Optional company facts JSON", type=["json"], key="facts_upload")
    assumptions_upload = st.sidebar.file_uploader("Optional assumptions JSON", type=["json"], key="assumptions_upload")
    try:
        if facts_upload:
            facts = json.loads(facts_upload.getvalue().decode("utf-8-sig"))
        if assumptions_upload:
            assumptions = json.loads(assumptions_upload.getvalue().decode("utf-8-sig"))

        if upload is not None:
            raw = json.loads(upload.getvalue().decode("utf-8-sig"))
            report = make_report(raw, facts, assumptions)
            source_label = f"Uploaded: {upload.name}"
        else:
            if source == "Local architecture_intelligence.json":
                raw = read_json(ROOT / "architecture_intelligence.json")
            elif source == "Local endpoint_map.json":
                raw = read_json(ROOT / "endpoint_map.json")
            else:
                raw = read_json(SAMPLE_REPORT)
            report = make_report(raw, facts, assumptions)
            source_label = source
    except Exception as exc:
        st.error(f"Unable to load report: {exc}")
        st.stop()

    target = report.get("target", {})
    target_url = target.get("url", "Unknown target")
    st.markdown('<div class="eyebrow">External technology · platform · scale</div>', unsafe_allow_html=True)
    st.markdown('<div class="hero-title">Architecture Intelligence</div>', unsafe_allow_html=True)
    st.markdown(
        '<div class="hero-copy">A visual workspace for observed endpoints, technology clues, public company disclosures and assumption-based capacity scenarios.</div>',
        unsafe_allow_html=True,
    )
    st.caption(f"Target: {target_url}  ·  Dataset: {source_label}  ·  Generated: {report.get('generated_at', 'sample snapshot')}")

    tabs = st.tabs(["Overview", "Endpoint map", "Integrations", "Architecture", "Scale & storage", "Company facts", "Evidence & limits"])
    with tabs[0]:
        render_overview(report)
    with tabs[1]:
        render_routes(report)
    with tabs[2]:
        render_integrations(report)
    with tabs[3]:
        render_architecture(report)
    with tabs[4]:
        render_scale(report)
    with tabs[5]:
        render_facts(report)
    with tabs[6]:
        render_limits(report)

    st.sidebar.divider()
    st.sidebar.caption("The demo is a sanitised summary of the 30 Oct 2026 Ten public-site scan. Upload a fresh scan/report to replace it.")
    st.sidebar.download_button(
        "Download current report JSON",
        data=json.dumps(report, indent=2, ensure_ascii=False).encode("utf-8"),
        file_name="architecture_intelligence.json",
        mime="application/json",
        use_container_width=True,
    )


if __name__ == "__main__":
    main()
