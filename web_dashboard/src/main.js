import "./style.css";

const NAV = [
  ["overview", "Overview", "◫"],
  ["group", "Group & subdomains", "⌁"],
  ["endpoints", "Endpoint map", "⌘"],
  ["integrations", "Integrations", "◈"],
  ["architecture", "Architecture", "⌂"],
  ["scale", "Scale & storage", "↗"],
  ["facts", "Company facts", "▤"],
  ["limits", "Evidence & limits", "ⓘ"]
];

const state = { report: null, active: "overview", source: "Loading demo report", filter: "", error: "" };
const root = document.querySelector("#app");

function esc(value) {
  return String(value == null ? "" : value).replace(/[&<>"']/g, function (ch) {
    return ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[ch];
  });
}
function list(value) { return Array.isArray(value) ? value : []; }
function number(value) { return Number(value || 0); }
function fmt(value) { return number(value).toLocaleString("en-US"); }
function short(value, max) {
  const text = String(value == null ? "" : value);
  return text.length > max ? text.slice(0, max - 1) + "…" : text;
}
function report() { return state.report || {}; }
function inventory() { return report().observed_inventory || {}; }
function discovery() { return report().scope_discovery || {}; }
function groupScope() { return report().group_scope || {}; }
function routes() {
  const data = list(report().normalized_routes);
  if (data.length) return data;
  const first = list(inventory().first_party_fetch_xhr_ping_routes || inventory().first_party_fetch_xhr_ping_route_records);
  if (first.length) return first;
  return list(report().endpoints);
}
function integrations() { return list(report().third_party_integrations); }
function hostInventory() {
  const discovered = list(discovery().hosts);
  return discovered.length ? discovered : list(report().host_inventory);
}
function facts() { return list(report().public_company_facts); }
function evidence() { return list(report().technology_evidence); }
function inferences() { return list(report().architecture_inferences); }
function scenarios() { return list((report().capacity_and_cost_scenarios || {}).scenarios); }

function metric(label, value, note, icon) {
  return '<article class="metric-card"><div class="metric-top"><span>' + esc(label) + '</span><span class="metric-icon">' + (icon || "↗") + '</span></div><div class="metric-value">' + esc(value) + '</div><div class="metric-note">' + esc(note || "") + '</div></article>';
}
function badge(text, cls) { return '<span class="badge ' + (cls || "") + '">' + esc(text) + '</span>'; }
function empty(title, copy) {
  return '<div class="empty-state"><div class="empty-mark">⌁</div><strong>' + esc(title) + '</strong><p>' + esc(copy) + '</p></div>';
}
function table(headers, rows, key) {
  if (!rows.length) return empty("Nothing to show yet", "Load a JSON report or run the group intelligence workflow to populate this view.");
  const body = rows.map(function (row) {
    return "<tr>" + headers.map(function (head) {
      const value = row[head.key];
      const cls = head.className ? ' class="' + head.className + '"' : "";
      return "<td" + cls + ">" + (head.render ? head.render(value, row) : esc(value == null ? "—" : value)) + "</td>";
    }).join("") + "</tr>";
  }).join("");
  return '<div class="table-wrap"><table><thead><tr>' + headers.map(function (h) { return "<th>" + esc(h.label) + "</th>"; }).join("") + '</tr></thead><tbody>' + body + "</tbody></table></div>";
}
function searchableTable(data, headers, opts) {
  const o = opts || {};
  const needle = (o.filter === undefined ? state.filter : o.filter).trim().toLowerCase();
  const filtered = needle ? data.filter(function (item) {
    return headers.some(function (head) {
      const value = item[head.key];
      return String(value == null ? "" : value).toLowerCase().includes(needle);
    });
  }) : data;
  const shown = filtered.slice(0, o.limit || 300);
  const note = '<div class="table-foot"><span>Showing ' + fmt(shown.length) + ' of ' + fmt(filtered.length) + ' matching records</span>' +
    (filtered.length > shown.length ? '<span>Refine search to narrow results</span>' : "") + "</div>";
  return note + table(headers, shown);
}
function barList(items, labelKey, valueKey, formatter) {
  if (!items.length) return empty("No chart data", "No matching records were included in this report.");
  const max = Math.max.apply(null, items.map(function (x) { return number(x[valueKey]); }).concat([1]));
  return '<div class="bar-list">' + items.map(function (item) {
    const value = number(item[valueKey]);
    const width = Math.max(1, (value / max) * 100);
    return '<div class="bar-row"><div class="bar-label">' + esc(item[labelKey]) + '</div><div class="bar-track"><span style="width:' + width + '%"></span></div><div class="bar-value">' + esc(formatter ? formatter(value) : fmt(value)) + '</div></div>';
  }).join("") + "</div>";
}
function sectionHead(kicker, title, description, action) {
  return '<div class="section-head"><div><div class="kicker">' + esc(kicker) + '</div><h2>' + esc(title) + '</h2><p>' + esc(description || "") + '</p></div>' + (action || "") + "</div>";
}
function panel(title, content, extra) {
  return '<section class="panel ' + (extra || "") + '"><div class="panel-head"><h3>' + esc(title) + '</h3></div>' + content + "</section>";
}
function statCards(items) { return '<div class="metric-grid">' + items.join("") + "</div>"; }
function sourceLink(url, label) {
  if (!url) return esc(label || "Source not supplied");
  return '<a href="' + esc(url) + '" target="_blank" rel="noreferrer">' + esc(label || "Open source") + " ↗</a>";
}

function renderOverview() {
  const q = inventory();
  const s = report().scan_quality || {};
  const g = groupScope();
  const d = discovery();
  const isGroup = report().report_type === "group_intelligence";
  const routeCount = q.unique_normalized_routes || list(report().normalized_routes).length;
  const cards = [
    metric("Endpoint records", fmt(q.endpoint_records || q.total_endpoint_records || list(report().endpoints).length), "Observed and candidate records", "⌘"),
    metric("Normalized routes", fmt(routeCount), "Deduplicated route patterns", "↳"),
    metric("Hostnames", fmt(d.host_count_discovered || q.host_count || list(report().host_inventory).length), "Public DNS / scan inventory", "⌁"),
    metric("JavaScript assets", fmt(q.javascript_assets || s.javascript_assets || 0), "Inspected client-side assets", "◈")
  ];
  const vendors = integrations().slice(0, 7).map(function (x) {
    return { name: x.vendor || x.vendor_group || x.name || "Unclassified", count: x.observed_occurrences || x.occurrences || 0 };
  });
  const resourceMap = q.first_party_resource_types || {};
  const resources = Object.keys(resourceMap).map(function (key) { return { name: key, count: resourceMap[key] }; }).sort(function (a,b) { return b.count-a.count; }).slice(0,8);
  const quality = '<div class="quality-grid">' +
    '<div><span>Target</span><strong>' + esc((report().target || {}).url || (d.root_domains || [])[0] || "Group report") + '</strong></div>' +
    '<div><span>Pages visited</span><strong>' + fmt(s.pages_visited || 0) + (s.page_limit ? " / " + fmt(s.page_limit) : "") + '</strong></div>' +
    '<div><span>Scan errors</span><strong>' + fmt(s.scan_errors || 0) + '</strong></div>' +
    '<div><span>Completed</span><strong>' + esc(short(s.completed_at || report().generated_at || "—", 28)) + '</strong></div></div>';
  const factsPanel = isGroup ? '<div class="callout"><strong>' + fmt(list(g.subsidiaries).length) + ' subsidiaries in the FY2025 register</strong><span>' + fmt(d.host_count_discovered || 0) + ' public hostnames discovered from configured group domains. Entity-to-host mappings remain unverified until confirmed.</span></div>' : "";
  return sectionHead("Intelligence workspace", "Overview", "A compact view of observed web surface, group infrastructure clues and evidence quality.") +
    statCards(cards) + factsPanel +
    '<div class="content-grid two">' +
      panel("Scan quality", quality) +
      panel("First-party resource mix", barList(resources, "name", "count")) +
      panel("Third-party integration activity", barList(vendors, "name", "count")) +
      panel("Coverage notes", '<ul class="clean-list"><li>Browser observations describe only the workflows actually visited.</li><li>Certificate records can contain expired or unused hostnames.</li><li>DNS provider hints are not proof of origin hosting or database ownership.</li><li>Storage and traffic scenarios are assumptions, not measured telemetry.</li></ul>') +
    "</div>";
}

function renderGroup() {
  const g = groupScope();
  const d = discovery();
  const subsidiaries = list(g.subsidiaries);
  const branches = list(g.branches);
  const domains = list(g.domains);
  const hosts = hostInventory().map(function (h) {
    return {
      hostname: h.hostname || "",
      root_domain: h.root_domain || "",
      public_ips: list(h.public_ip_addresses).join(", "),
      cname: list((h.dns || {}).cname).join(", "),
      provider: list(h.provider_hints).join(", "),
      role: list(h.hostname_role_hints).join(", "),
      database: h.database_named_hostname_candidate ? "Name clue only" : "—",
      raw: h
    };
  });
  const candidates = list(d.database_named_hostname_candidates).map(function (x) {
    return { hostname: x.hostname, role: list(x.role_hints).join(", "), note: x.note || "Name clue only" };
  });
  const registerRows = subsidiaries.map(function (x) {
    return { name: x.name, country: x.country, activity: x.activity, status: x.status_at_2025_08_31, ownership: String(x.ownership_percent || "—") + "%", voting: String(x.voting_power_percent || "—") + "%" };
  });
  const domainRows = domains.map(function (x) { return { domain: x.domain, relation: x.relationship }; });
  const hostHeaders = [
    { key: "hostname", label: "Hostname" }, { key: "root_domain", label: "Root domain" },
    { key: "public_ips", label: "Public IPs" }, { key: "cname", label: "CNAME" },
    { key: "provider", label: "Provider hints" }, { key: "role", label: "Service clues" },
    { key: "database", label: "DB label" }
  ];
  const candidateHeaders = [{key:"hostname",label:"Hostname"},{key:"role",label:"Name clues"},{key:"note",label:"Interpretation"}];
  const providers = Object.keys(d.provider_hint_counts || {}).map(function (k) {
    return { name: k, count: d.provider_hint_counts[k] };
  }).sort(function(a,b){return b.count-a.count;});
  const ipRows = list(d.shared_public_ip_groups).map(function (x) {
    return { ip: x.public_ip, count: x.hostname_count, hosts: list(x.hostnames).join(", "), note: x.interpretation || "" };
  });
  const scanRows = list(report().per_target_scans).map(function (x) {
    return { entity: x.entity, url: x.url, pages: fmt(x.pages_visited), endpoints: fmt(x.endpoint_records), errors: fmt(x.errors) };
  });
  const hostMarkup = hosts.length ? searchableTable(hosts, hostHeaders, {limit:500, filter: state.filter}) : empty("No discovered hosts yet", "Run group_intelligence.py to collect public certificate-transparency and DNS inventory.");
  return sectionHead("Corporate structure", "Group & subdomains", "Subsidiary register, disclosed domains and public DNS observations. Legal entities do not automatically map one-to-one to applications.") +
    statCards([
      metric("Subsidiaries", fmt(subsidiaries.length), "As disclosed at 31 Aug 2025", "▤"),
      metric("Operating", fmt(subsidiaries.filter(x=>x.status_at_2025_08_31==="operating").length), "At reporting date", "●"),
      metric("Dormant", fmt(subsidiaries.filter(x=>x.status_at_2025_08_31==="dormant").length), "At reporting date", "○"),
      metric("Hostnames found", fmt(d.host_count_discovered || hosts.length), "Certificate transparency", "⌁")
    ]) +
    '<div class="callout"><strong>Historical corporate register</strong><span>Subsidiary statuses are sourced from the FY2025 annual report and reflect 31 August 2025—not a live FY2026 legal register.</span></div>' +
    '<div class="content-grid two">' +
      panel("Disclosed subsidiaries", table([
        {key:"name",label:"Legal entity"},{key:"country",label:"Country"},{key:"activity",label:"Activity"},{key:"status",label:"Status"},{key:"ownership",label:"Ownership"},{key:"voting",label:"Voting"}
      ], registerRows)) +
      panel("Ten domains disclosed in its FAQ", table([{key:"domain",label:"Domain"},{key:"relation",label:"Disclosed relationship"}], domainRows)) +
    "</div>" +
    (branches.length ? panel("Branches listed separately", table([{key:"name",label:"Branch"},{key:"country",label:"Country"},{key:"note",label:"Note"}], branches)) : "") +
    panel("Discovered hostnames", '<div class="table-toolbar"><input class="table-search" data-global-filter placeholder="Filter hostname, provider, role…" value="' + esc(state.filter) + '"><span>' + fmt(hosts.length) + ' records</span></div>' + hostMarkup) +
    '<div class="content-grid two">' +
      panel("Database/cache-like hostname labels", candidates.length ? table(candidateHeaders,candidates) : empty("No matching name labels", "No db/postgres/redis-style hostname label appeared in the processed certificate names.")) +
      panel("DNS-derived provider hints", providers.length ? barList(providers,"name","count") : empty("No provider clues","No matching public DNS provider markers were observed.")) +
      panel("Shared public-IP groups", ipRows.length ? table([{key:"ip",label:"Public IP"},{key:"count",label:"Hosts"},{key:"hosts",label:"Hostnames"},{key:"note",label:"Interpretation"}], ipRows) : empty("No shared IP groups","No public address was associated with multiple discovered names.")) +
      panel("Authorized browser scans", scanRows.length ? table([{key:"entity",label:"Entity / target"},{key:"url",label:"URL"},{key:"pages",label:"Pages"},{key:"endpoints",label:"Endpoints"},{key:"errors",label:"Errors"}],scanRows) : empty("No subsidiary browser scans", "Only public domain/DNS discovery was run. Add only owner-approved URLs to authorized_scan_targets.")) +
    "</div>" +
    '<p class="fineprint">Database labels are naming clues only. No database ports, protocols, credentials or queries are tested. Shared IPs may represent a CDN or reverse proxy.</p>';
}

function renderEndpoints() {
  const data = routes().map(function (x) {
    return {
      host: x.host || safeHost(x.url),
      party: x.party || (x.host && (x.host === ((report().target||{}).host) || x.host.endsWith("." + ((report().target||{}).root_domain||"___"))) ? "first_party" : "—"),
      method: x.method || "UNKNOWN",
      route: x.route_template || x.url || x.path || "—",
      classification: x.classification || x.category || "—",
      type: list(x.resource_types).join(", ") || x.resource_type || "—",
      status: list(x.status_codes || x.statuses).join(", ") || "—",
      records: x.records == null ? 1 : x.records,
      occurrences: x.occurrences || 0,
      keys: list(x.query_parameter_names || x.query_keys).join(", ")
    };
  });
  const headers = [
    {key:"party",label:"Ownership"},{key:"host",label:"Host"},{key:"method",label:"Method"},
    {key:"route",label:"Route"},{key:"classification",label:"Classification"},
    {key:"type",label:"Resource type"},{key:"status",label:"Status"},
    {key:"records",label:"Records"},{key:"occurrences",label:"Hits"},{key:"keys",label:"Query keys"}
  ];
  return sectionHead("Surface map", "Endpoint inventory", "Search discovered routes, methods, status codes and resource types.") +
    statCards([
      metric("Routes",fmt(data.length),"Normalized route records","⌘"),
      metric("Observed requests",fmt(inventory().observed_request_records || 0),"HTTP observations","↗"),
      metric("Unverified candidates",fmt(inventory().unverified_js_candidates || 0),"Extracted from JS only","?"),
      metric("First-party API-like",fmt(inventory().first_party_fetch_xhr_ping_records || 0),"Fetch/XHR/ping records","⌁")
    ]) +
    panel("Route explorer", '<div class="table-toolbar"><input class="table-search" data-global-filter placeholder="Search route, host, type, status…" value="' + esc(state.filter) + '"><button class="quiet-button" data-export="routes">Export CSV</button></div>' + searchableTable(data,headers,{limit:600,filter:state.filter}));
}
function safeHost(url) {
  try { return new URL(url).hostname; } catch(e) { return "—"; }
}

function renderIntegrations() {
  const vendors = integrations().map(function (x) {
    return { vendor: x.vendor || x.vendor_group || x.name || "Unclassified", hosts: list(x.hosts).join(", "), records: x.endpoint_records || x.records || 0, hits: x.observed_occurrences || x.occurrences || 0 };
  });
  const headers = [{key:"vendor",label:"Vendor / integration"},{key:"hosts",label:"Observed hosts"},{key:"records",label:"Records"},{key:"hits",label:"Occurrences"}];
  const top = vendors.slice().sort(function(a,b){return number(b.hits)-number(a.hits);});
  return sectionHead("Third-party ecosystem", "Integrations", "Observed third-party browser traffic. High request counts do not prove internal system ownership.") +
    statCards([
      metric("Integration groups",fmt(vendors.length),"Vendor clusters","◈"),
      metric("Third-party records",fmt(vendors.reduce((a,x)=>a+number(x.records),0)),"Endpoint records","⌘"),
      metric("Third-party hits",fmt(vendors.reduce((a,x)=>a+number(x.hits),0)),"Summed occurrences","↗"),
      metric("Observed hosts",fmt(list(report().host_inventory).filter(x=>x.party==="third_party").length),"Host inventory","⌁")
    ]) +
    '<div class="content-grid two">' +
      panel("Activity by vendor",barList(top.slice(0,12).map(x=>({name:x.vendor,count:x.hits})),"name","count")) +
      panel("Integration register",'<div class="table-toolbar"><input class="table-search" data-global-filter placeholder="Filter vendor or host…" value="' + esc(state.filter) + '"><button class="quiet-button" data-export="integrations">Export CSV</button></div>' + searchableTable(vendors,headers,{filter:state.filter,limit:300})) +
    '</div><p class="fineprint">Marketing analytics, form tracking, video and CDN integrations are not evidence of the core member database or private platform design.</p>';
}

function renderArchitecture() {
  const tech = evidence().map(function (x) {
    return { name:x.technology_or_pattern || x.technology || "Technology clue", confidence:x.confidence || "unrated",
      evidence:list(x.observed_clues || x.evidence).join(" · "), limit:x.limitations || x.limit || "No limitation supplied" };
  });
  const inf = inferences().map(function(x) {
    return {area:x.area || x.technology_or_pattern || "Inference", hypothesis:x.inference || x.hypothesis || "—", confidence:x.confidence || "unrated", evidence:list(x.evidence).join(" · "), unknown:list(x.not_proven).join(" · ")};
  });
  return sectionHead("Evidence and hypotheses", "Architecture", "Distinguishes observed technology clues from likely architecture and unresolved questions.") +
    panel("Technology fingerprints",table([
      {key:"name",label:"Technology / pattern"},{key:"confidence",label:"Confidence",render:v=>badge(v || "unrated")},{key:"evidence",label:"Observed clues"},{key:"limit",label:"Limitations"}
    ],tech)) +
    panel("Architecture hypotheses",table([
      {key:"area",label:"Area"},{key:"hypothesis",label:"Inference"},{key:"confidence",label:"Confidence",render:v=>badge(v || "unrated")},{key:"evidence",label:"Evidence"},{key:"unknown",label:"Not proven"}
    ],inf));
}

function renderScale() {
  const sc = scenarios();
  const rows = sc.map(function(x) {
    return {
      scenario:x.scenario || x.label || "Scenario",
      mau:fmt(x.monthly_active_users_modelled),
      requests:fmt(x.modelled_api_requests_per_month),
      avg: x.average_requests_per_second == null ? "—" : Number(x.average_requests_per_second).toFixed(2),
      peak: x.peak_requests_per_second_modelled == null ? "—" : Number(x.peak_requests_per_second_modelled).toFixed(2),
      primary: x.primary_database_storage_estimate_gb == null ? "—" : Number(x.primary_database_storage_estimate_gb).toLocaleString("en-US") + " GB",
      backup: x.backup_storage_estimate_gb == null ? "—" : Number(x.backup_storage_estimate_gb).toLocaleString("en-US") + " GB",
      note:x.cost_note || "Infrastructure cost not estimated."
    };
  });
  const factsScale = (report().capacity_and_cost_scenarios || {});
  return sectionHead("Illustrative sizing", "Scale & storage", "Low/base/high scenarios from editable assumptions—not production measurements.") +
    (rows.length ? panel("Capacity scenarios",table([
      {key:"scenario",label:"Scenario"},{key:"mau",label:"Modelled MAU"},{key:"requests",label:"API calls / month"},
      {key:"avg",label:"Average RPS"},{key:"peak",label:"Peak RPS"},{key:"primary",label:"Primary storage"},
      {key:"backup",label:"Backup storage"}
    ],rows)) : empty("No scenario data","The report did not include capacity_and_cost_scenarios.")) +
    panel("Model interpretation",'<div class="callout"><strong>Not a measured database estimate</strong><span>' + esc(factsScale.method || "The public website scan cannot measure production load, data size or resource utilisation.") + '</span></div><p class="fineprint">' + esc(factsScale.infrastructure_cost_conclusion || "No infrastructure cost is inferred from the scan.") + "</p>");
}

function renderFacts() {
  const data = facts().map(function(x) {
    return { label:x.label || x.key || "Fact", value:typeof x.value === "object" ? JSON.stringify(x.value) : x.value,
      unit:x.unit || "", period:x.period || "", status:x.status || "", caveat:x.definition_or_caveat || "",
      source:x.source_url || "" };
  });
  return sectionHead("Public disclosures", "Company facts", "Company-published metrics and third-party evidence with their definitions and caveats.") +
    panel("Disclosed facts",table([
      {key:"label",label:"Metric"},{key:"value",label:"Value"},{key:"unit",label:"Unit"},
      {key:"period",label:"Period"},{key:"status",label:"Evidence type",render:v=>badge(v || "unrated")},
      {key:"caveat",label:"Definition / caveat"},{key:"source",label:"Source",render:v=>sourceLink(v,"Open ↗")}
    ],data));
}

function renderLimits() {
  const limits = list(report().limits);
  const discLimits = list(discovery().limits);
  const notes = list(groupScope().scope_notes);
  const sourceRows = list(groupScope().sources).map(function(x) {
    return {label:x.label || "Source",date:x.date || "",url:x.url || "",details:x.details || ""};
  });
  const evidenceText = [
    ["Observed","Directly visible in the browser scan, DNS response or company disclosure."],
    ["Advertised","Named in a job advertisement or vendor material; not proof of production deployment."],
    ["Inferred","A reasoned hypothesis supported by public product or technical clues."],
    ["Unknown","Requires owner-provided telemetry, architecture documentation or an approved internal assessment."]
  ];
  return sectionHead("Assessment discipline", "Evidence & limits", "Know exactly what the data proves—and what it cannot establish.") +
    panel("Evidence levels",table([{key:"level",label:"Evidence label",render:v=>badge(v)},{key:"definition",label:"Meaning"}],evidenceText.map(x=>({level:x[0],definition:x[1]})))) +
    '<div class="content-grid two">' +
      panel("Report limitations",'<ul class="clean-list">' + limits.concat(discLimits).map(x=>"<li>"+esc(x)+"</li>").join("") + "</ul>") +
      panel("Scope notes",'<ul class="clean-list">' + notes.map(x=>"<li>"+esc(x)+"</li>").join("") + "</ul>") +
    "</div>" +
    panel("Sources",table([{key:"label",label:"Source"},{key:"date",label:"Date"},{key:"details",label:"Details"},{key:"url",label:"Link",render:v=>sourceLink(v,"Open ↗")}],sourceRows));
}

function renderContent() {
  const map = {
    overview:renderOverview, group:renderGroup, endpoints:renderEndpoints, integrations:renderIntegrations,
    architecture:renderArchitecture, scale:renderScale, facts:renderFacts, limits:renderLimits
  };
  return (map[state.active] || renderOverview)();
}

function render() {
  const current = NAV.find(x=>x[0]===state.active) || NAV[0];
  const target = (report().target || {}).url || (discovery().root_domains || []).join(", ") || "Group-level assessment";
  const hasGroup = report().report_type === "group_intelligence" || !!report().group_scope;
  root.innerHTML =
    '<div class="app-shell">' +
      '<aside class="sidebar">' +
        '<a class="brand" href="#"><span class="brand-mark">◈</span><span><b>FIELDNOTES</b><small>ARCHITECTURE INTELLIGENCE</small></span></a>' +
        '<div class="side-label">WORKSPACE</div>' +
        '<nav class="nav-list">' + NAV.map(function(x) {
          return '<button class="nav-item ' + (state.active===x[0]?"active":"") + '" data-nav="' + x[0] + '"><span class="nav-icon">' + x[2] + '</span><span>' + esc(x[1]) + '</span>' + (x[0]==="group" && hasGroup ? '<i class="nav-dot"></i>' : "") + '</button>';
        }).join("") + '</nav>' +
        '<div class="sidebar-bottom"><div class="local-tag"><span></span> LOCAL WORKSPACE</div><small>Reports stay in your browser. Nothing is uploaded.</small></div>' +
      '</aside>' +
      '<main class="main-area">' +
        '<header class="topbar"><div class="crumb">INTELLIGENCE <span>/</span> ' + esc(current[1].toUpperCase()) + '</div><div class="top-actions"><span class="source-name">' + esc(state.source) + '</span><button class="button secondary" data-action="load">Load JSON</button><button class="button primary" data-action="export">Export report</button><input id="file-input" type="file" accept=".json,application/json" hidden></div></header>' +
        '<div class="page-wrap"><div class="page-intro"><div><div class="eyebrow">EXTERNAL TECHNOLOGY · PLATFORM · SCALE</div><h1>Architecture <em>Intelligence</em></h1><p class="target-line">' + esc(target) + '</p></div><div class="intro-actions"><button class="text-button" data-action="demo">Restore demo data ↻</button></div></div>' +
        (state.error ? '<div class="error-banner">' + esc(state.error) + '</div>' : "") +
        '<div id="view-content">' + renderContent() + '</div>' +
        '<footer><span>Evidence-led analysis · Local report viewer</span><span>VITE / VANILLA JS</span></footer></div>' +
      '</main>' +
    '</div>';
  bindEvents();
}

function bindEvents() {
  root.querySelectorAll("[data-nav]").forEach(function(el) {
    el.addEventListener("click",function(){state.active=el.dataset.nav;state.filter="";render();});
  });
  root.querySelectorAll('[data-action="load"]').forEach(el=>el.addEventListener("click",()=>root.querySelector("#file-input").click()));
  root.querySelectorAll('[data-action="demo"]').forEach(el=>el.addEventListener("click",loadDemo));
  const input = root.querySelector("#file-input");
  if (input) input.addEventListener("change", function() {
    if (input.files && input.files[0]) loadFile(input.files[0]);
  });
  root.querySelectorAll("[data-global-filter]").forEach(function(el) {
    el.addEventListener("input", function() {
      state.filter=el.value;
      const start=el.selectionStart;
      const end=el.selectionEnd;
      const scroller=root.querySelector("#view-content");
      const y=window.scrollY;
      render();
      const replacement=root.querySelector("[data-global-filter]");
      if(replacement){replacement.focus();replacement.setSelectionRange(start,end);}
      if(scroller) window.scrollTo(0,y);
    });
  });
  root.querySelectorAll("[data-export]").forEach(function(el) {
    el.addEventListener("click",function(){exportCsv(el.dataset.export);});
  });
  root.querySelectorAll('[data-action="export"]').forEach(el=>el.addEventListener("click",exportReport));
}

async function loadDemo() {
  try {
    const response = await fetch("/demo-report.json", {cache:"no-store"});
    if (!response.ok) throw new Error("Could not load the bundled demo report.");
    state.report = await response.json();
    state.source = "Bundled demo snapshot";
    state.active = "overview";
    state.filter = "";
    state.error = "";
    render();
  } catch (error) {
    state.error = error.message || "Unable to load demo report.";
    render();
  }
}
function loadFile(file) {
  const reader = new FileReader();
  reader.onload = function() {
    try {
      const data = JSON.parse(String(reader.result || ""));
      if (!data || typeof data !== "object") throw new Error("JSON root must be an object.");
      if (!data.report_type && !data.scan && !data.endpoints && !data.observed_inventory && !data.scope_discovery) {
        throw new Error("This does not look like an endpoint, intelligence or group report JSON.");
      }
      state.report=data;
      state.source=file.name;
      state.active=data.scope_discovery || data.group_scope ? "group" : "overview";
      state.filter="";
      state.error="";
    } catch(error) {
      state.error="Could not load report: "+error.message;
    }
    render();
  };
  reader.onerror = function(){state.error="Browser could not read that file.";render();};
  reader.readAsText(file);
}
function exportReport() {
  download("group_intelligence_report.json",JSON.stringify(report(),null,2),"application/json");
}
function download(name, content, type) {
  const blob = new Blob([content],{type:type});
  const url=URL.createObjectURL(blob);
  const link=document.createElement("a");
  link.href=url;link.download=name;link.click();
  URL.revokeObjectURL(url);
}
function exportCsv(which) {
  let rows=[];
  if(which==="routes") rows=routes().map(x=>({
    host:x.host||safeHost(x.url),method:x.method||"",route:x.route_template||x.url||x.path||"",
    classification:x.classification||x.category||"",resource_types:list(x.resource_types).join("|"),
    status_codes:list(x.status_codes||x.statuses).join("|"),records:x.records||1,occurrences:x.occurrences||0
  }));
  if(which==="integrations") rows=integrations().map(x=>({
    vendor:x.vendor||x.vendor_group||x.name,hosts:list(x.hosts).join("|"),
    endpoint_records:x.endpoint_records||x.records||0,occurrences:x.observed_occurrences||x.occurrences||0
  }));
  if(!rows.length)return;
  const keys=Object.keys(rows[0]);
  const cell=value=>'"'+String(value==null?"":value).replace(/"/g,'""')+'"';
  const csv=[keys.map(cell).join(","),...rows.map(row=>keys.map(key=>cell(row[key])).join(","))].join("\r\n");
  download(which+".csv",csv,"text/csv");
}

loadDemo();
