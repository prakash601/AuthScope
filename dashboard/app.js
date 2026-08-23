/* AuthScope dashboard */
const $ = (id) => document.getElementById(id);
const state = { report: null };

function headers() {
  return { "X-API-Key": localStorage.getItem("authscope-key") || "" };
}
function key() { return localStorage.getItem("authscope-key") || ""; }

async function api(path, opts = {}) {
  const resp = await fetch(path, {
    ...opts,
    headers: { "Content-Type": "application/json", ...headers(), ...(opts.headers || {}) },
  });
  if (resp.status === 401) throw new Error("invalid API key");
  return resp;
}

// nav
document.querySelectorAll("nav button[data-view]").forEach((b) => {
  b.onclick = () => {
    document.querySelectorAll("nav button").forEach((x) => x.classList.remove("active"));
    document.querySelectorAll(".view").forEach((v) => v.classList.add("hidden"));
    b.classList.add("active");
    $(`view-${b.dataset.view}`).classList.remove("hidden");
  };
});

$("save-key").onclick = () => {
  localStorage.setItem("authscope-key", $("api-key").value.trim());
  $("key-status").textContent = "saved";
  $("app").classList.remove("hidden");
};
if (key()) { $("api-key").value = key(); $("key-status").textContent = "loaded"; }
else { $("app").classList.remove("hidden"); }

// submit scan
$("btn-scan").onclick = async () => {
  const url = $("scan-url").value.trim();
  $("scan-status").textContent = "submitting...";
  try {
    const r = await api("/v1/scans", {
      method: "POST",
      body: JSON.stringify({ url, options: {
        deep_scan: $("opt-deep").checked,
        force: $("opt-force").checked,
      }}),
    });
    const body = await r.json();
    $("scan-status").textContent =
      `scan ${body.scan_id} — ${body.status}\n(polling...)`;
    pollScan(body.scan_id, $("scan-status"));
  } catch (e) { $("scan-status").textContent = `error: ${e.message}`; }
};

async function pollScan(id, el) {
  for (;;) {
    const r = await api(`/v1/scans/${id}`);
    const body = await r.json();
    if (!["queued", "running"].includes(body.status)) {
      el.textContent += `\n→ ${body.status}`;
      loadReport(id);
      switchView("report");
      return;
    }
    await new Promise((res) => setTimeout(res, 2000));
  }
}

function switchView(name) {
  document.querySelector(`nav button[data-view="${name}"]`).click();
}

// list
async function loadList() {
  const p = new URLSearchParams();
  if ($("f-provider").value) p.set("provider", $("f-provider").value);
  if ($("f-captcha").value) p.set("captcha_type", $("f-captcha").value);
  if ($("f-min-diff").value) p.set("min_difficulty", $("f-min-diff").value);
  if ($("f-status").value) p.set("status", $("f-status").value);
  p.set("limit", "100");
  const r = await api(`/v1/scans?${p}`);
  const body = await r.json();
  const tbody = $("scans-table tbody");
  tbody.innerHTML = "";
  for (const it of body.items) {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td class="mono">${it.scan_id.slice(0, 8)}</td>
      <td>${it.url}</td><td>${it.status}</td>
      <td>${it.difficulty_score ?? "—"}</td><td>${it.security_score ?? "—"}</td>
      <td><button data-id="${it.scan_id}" class="view-report">view</button></td>`;
    tbody.appendChild(tr);
  }
  tbody.querySelectorAll(".view-report").forEach((b) => {
    b.onclick = () => { loadReport(b.dataset.id); switchView("report"); };
  });
}
$("btn-filter").onclick = loadList;
$("btn-refresh").onclick = loadList;
let timer = null;
$("auto-refresh").onchange = (e) => {
  clearInterval(timer);
  if (e.target.checked) timer = setInterval(loadList, 5000);
};

// report
async function loadReport(id) {
  const r = await api(`/v1/scans/${id}`);
  const body = await r.json();
  state.report = body;
  $("report-id").textContent = id;
  $("report-summary").innerHTML = `
    <div class="score big">${body.antibot?.difficulty_score ?? "—"}</div>
    <div class="score-label">difficulty</div>
    <div class="score big">${body.security?.risk_score ?? "—"}</div>
    <div class="score-label">risk</div>
    <div class="status ${body.status}">${body.status}</div>`;
  $("report-auth").innerHTML = sectionTable("Authentication",
    [["Provider", body.auth?.provider], ["Confidence", body.auth?.confidence],
     ["Flows", (body.auth?.flows || []).join(", ")]]);
  $("report-security").innerHTML = sectionTable("Security",
    [["HSTS", body.security?.has_hsts], ["CSP", body.security?.has_csp],
     ["CSRF", body.security?.has_csrf], ["MFA signal", body.security?.mfa_detected]]);
  const ab = body.antibot || {};
  $("report-antibot").innerHTML = sectionTable("Anti-bot",
    [["Captcha", ab.captcha?.type], ["WAF", (ab.waf_providers || []).join(", ")],
     ["Fingerprinting", (ab.fingerprinting_signals || []).join(", ")],
     ["Cookies", (ab.cookies_detected || []).join(", ")],
     ["Reasoning", ab.difficulty_reasoning]]);
  const art = body.artifacts || {};
  $("report-artifacts").innerHTML = [
    art.screenshot_url ? `<a href="${art.screenshot_url}" target="_blank">
      <img src="${art.screenshot_url}" class="thumb"></a>` : "",
    art.har_url ? `<a href="${art.har_url}" target="_blank">HAR file</a>` : "",
    art.dom_snapshot_url ? `<a href="${art.dom_snapshot_url}" target="_blank">DOM snapshot</a>` : "",
  ].filter(Boolean).join(" · ");
  $("report-raw").textContent = JSON.stringify(body, null, 2).slice(0, 20000);
}

function sectionTable(title, rows) {
  const trs = rows.map(([k, v]) =>
    `<tr><th>${k}</th><td>${v === null || v === undefined || v === "" ? "—" :
      String(v)}</td></tr>`).join("");
  return `<h3>${title}</h3><table class="kv">${trs}</table>`;
}

// diff
$("btn-diff").onclick = async () => {
  const id = $("diff-scan-id").value.trim();
  const days = $("diff-days").value || 30;
  const r = await api(`/v1/scans/${id}/diff?days=${days}`);
  const body = await r.json();
  const tbody = $("diff-table tbody");
  tbody.innerHTML = "";
  for (const c of body.changes || []) {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td>${c.kind}</td><td>${c.field}</td>
      <td>${JSON.stringify(c.before)}</td><td>${JSON.stringify(c.after)}</td>`;
    tbody.appendChild(tr);
  }
  if (!(body.changes || []).length) {
    tbody.innerHTML = '<tr><td colspan="4">no changes detected in window</td></tr>';
  }
};
