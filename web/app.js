"use strict";

const $ = (id) => document.getElementById(id);
const API = "/functions/v1/app";

const state = { current: null, own: null, reqSeq: 0, controller: null, map: null, marker: null, lastQuery: null, queryStarted: false };

/* ================= Icons ================= */
const SIGNAL_ICONS = {
  proxy: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M4 7h11l-3-3M20 17H9l3 3"/><path d="M20 7h-2M4 17h2"/></svg>',
  vpn: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M12 3l8 4v5c0 5-3.5 8-8 9-4.5-1-8-4-8-9V7z"/><path d="M12 8v4M12 15h.01"/></svg>',
  tor: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="5"/><circle cx="12" cy="12" r="1.4" fill="currentColor"/></svg>',
  datacenter: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="3" y="4" width="18" height="6" rx="1.5"/><rect x="3" y="14" width="18" height="6" rx="1.5"/><path d="M7 7h.01M7 17h.01M12 7h4M12 17h4"/></svg>',
  mobile: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="7" y="2.5" width="10" height="19" rx="2.5"/><path d="M11 18.5h2"/></svg>',
  abuse: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M12 2c1 3-2 4-2 7 0 1.5 1 2.5 2 2.5S14 10.5 14 9c2 1.5 3 3.5 3 5.5a5 5 0 0 1-10 0C7 10 9.5 6.5 12 2z"/></svg>',
};
const TYPE_ICONS = {
  residential: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M3 11l9-8 9 8"/><path d="M5 9.5V21h14V9.5"/><path d="M9 21v-6h6v6"/></svg>',
  datacenter: SIGNAL_ICONS.datacenter, mobile: SIGNAL_ICONS.mobile,
  business: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="4" y="3" width="16" height="18" rx="1.5"/><path d="M9 7h2M13 7h2M9 11h2M13 11h2M9 15h2M13 15h2M10 21v-3h4v3"/></svg>',
};
const TYPE_TONES = { residential: "", datacenter: "tone-amber", mobile: "tone-blue", business: "tone-violet" };
const TYPE_BADGE_TONES = { residential: "tone-green", datacenter: "tone-amber", mobile: "tone-blue", business: "tone-violet" };
const RISK_TONES = { minimal: "tone-green", low: "tone-green", medium: "tone-amber", high: "tone-red", critical: "tone-red" };
const CHECK_OK = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9"/><path d="m8.5 12 2.5 2.5 4.5-5"/></svg>';
const CHECK_BAD = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9"/><path d="M12 8v4M12 16h.01"/></svg>';

/* ================= Utils ================= */
function toast(msg) { const el = $("toast"); el.textContent = msg; el.classList.add("show"); clearTimeout(toast._t); toast._t = setTimeout(() => el.classList.remove("show"), 2200); }
async function copyText(text, msg) {
  try { await navigator.clipboard.writeText(text); toast(msg); }
  catch { const ta = document.createElement("textarea"); ta.value = text; ta.style.position = "fixed"; ta.style.opacity = "0"; document.body.appendChild(ta); ta.select(); try { document.execCommand("copy"); toast(msg); } catch { toast("复制失败，请手动选择复制"); } ta.remove(); }
}
function renderFlag(cc) {
  const el = $("r-flag"); el.textContent = "";
  if (cc && /^[A-Z]{2}$/.test(cc)) { const img = document.createElement("img"); img.src = `https://flagcdn.com/w80/${cc.toLowerCase()}.png`; img.alt = ""; img.onerror = () => { el.textContent = "🌐"; }; el.appendChild(img); }
  else el.textContent = "🌐";
}
function flagImg(cc, size = 20) { return cc && /^[A-Z]{2}$/.test(cc) ? `<img src="https://flagcdn.com/w40/${cc.toLowerCase()}.png" width="${size}" alt="">` : ""; }
function fmtCoord(lat, lon) { if (lat == null || lon == null) return "—"; return `${Math.abs(lat).toFixed(4)}° ${lat >= 0 ? "N" : "S"}, ${Math.abs(lon).toFixed(4)}° ${lon >= 0 ? "E" : "W"}`; }
function fmtTime(iso) { if (!iso) return "—"; try { return new Date(iso).toLocaleString("zh-CN", { hour12: false }); } catch { return iso; } }
function isPrivateIp(ip) {
  if (ip.includes(":")) { const l = ip.toLowerCase(); return l === "::1" || l === "::" || /^f[cd]/.test(l) || /^fe[89ab]/.test(l); }
  const p = ip.split(".").map(Number); if (p.length !== 4) return true;
  return p[0] === 10 || p[0] === 127 || p[0] === 0 || (p[0] === 172 && p[1] >= 16 && p[1] <= 31) || (p[0] === 192 && p[1] === 168) || (p[0] === 169 && p[1] === 254) || (p[0] === 100 && p[1] >= 64 && p[1] <= 127) || p[0] >= 224;
}
function isIpFormat(ip) {
  if (ip.includes(":")) return /^[0-9a-fA-F:]{2,45}$/.test(ip) && (ip.match(/:/g) || []).length >= 2;
  const m = ip.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  return !!m && m.slice(1).every((n) => +n <= 255);
}
function fetchTimeout(url, ms, opts = {}) { const c = new AbortController(); const t = setTimeout(() => c.abort(), ms); return fetch(url, { ...opts, signal: c.signal }).finally(() => clearTimeout(t)); }

/* ================= History ================= */
const HISTORY_KEY = "iplens-history";
const OWN_KEY = "iplens-own-report";
function readOwnCache() { try { const r = JSON.parse(localStorage.getItem(OWN_KEY)); return r && r.ok === true && r.ip && r.scores && r.type && r.location && Array.isArray(r.signals) ? r : null; } catch { return null; } }
function writeOwnCache(r) { try { localStorage.setItem(OWN_KEY, JSON.stringify(r)); } catch {} }
function getHistory() { try { return JSON.parse(localStorage.getItem(HISTORY_KEY)) || []; } catch { return []; } }
function pushHistory(ip) { let list = getHistory().filter((x) => x !== ip); list.unshift(ip); list = list.slice(0, 6); try { localStorage.setItem(HISTORY_KEY, JSON.stringify(list)); } catch {} renderHistory(); }
function renderHistory() {
  const box = $("history"); box.textContent = ""; const list = getHistory(); if (!list.length) return;
  const label = document.createElement("span"); label.className = "history-label"; label.textContent = "最近查询"; box.appendChild(label);
  for (const ip of list) { const b = document.createElement("button"); b.type = "button"; b.className = "chip"; b.textContent = ip; b.addEventListener("click", () => { location.hash = `#ip=${ip}`; }); box.appendChild(b); }
}

/* ================= Reveal & nav ================= */
const revealObserver = new IntersectionObserver((es) => { for (const e of es) if (e.isIntersecting) { e.target.classList.add("in"); revealObserver.unobserve(e.target); } }, { threshold: 0.1 });
document.querySelectorAll(".reveal").forEach((el) => revealObserver.observe(el));
window.addEventListener("scroll", () => { $("nav").classList.toggle("scrolled", window.scrollY > 24); }, { passive: true });

/* ================= IP query ================= */
function animateScore(trust, fraud, riskCode) {
  const fill = $("gauge-fill"); const C = 527.8;
  fill.style.stroke = riskCode === "minimal" || riskCode === "low" ? "url(#gaugeGrad)" : riskCode === "medium" ? "#fbbf24" : "#fb4d6d";
  const numEl = $("r-trust"); const fraudEl = $("r-fraud");
  fill.style.strokeDashoffset = String(C * (1 - trust / 100)); numEl.textContent = String(trust); fraudEl.textContent = String(fraud);
  if (document.visibilityState === "visible") {
    const start = performance.now(); const dur = 1000;
    (function frame(now) { const t = Math.min(1, (now - start) / dur); const e = 1 - Math.pow(1 - t, 3); fill.style.strokeDashoffset = String(C * (1 - (trust / 100) * e)); numEl.textContent = String(Math.round(trust * e)); fraudEl.textContent = String(Math.round(fraud * e)); if (t < 1) requestAnimationFrame(frame); })(performance.now());
  }
  numEl.style.color = riskCode === "medium" ? "#fbbf24" : riskCode === "high" || riskCode === "critical" ? "#fb4d6d" : "";
}
function renderFraud(fraud, riskCode, riskLevel) {
  $("fraud-marker").style.left = `${fraud}%`; $("fraud-marker-tip").textContent = `${fraud}%`;
  const lvl = $("r-fraud-level"); lvl.textContent = riskLevel;
  lvl.className = "fraud-level " + (riskCode === "medium" ? "tone-amber" : (riskCode === "high" || riskCode === "critical") ? "tone-red" : "");
}
function renderSignals(signals) {
  $("signals-count").textContent = `${signals.length} 项检测`;
  const grid = $("signals-grid"); grid.textContent = "";
  for (const s of signals) {
    const cls = s.detected ? "hit" : "clean";
    const label = s.detected ? "检测到" : "未检测到";
    const el = document.createElement("div"); el.className = `signal ${cls}`;
    const icon = document.createElement("div"); icon.className = "signal-icon"; icon.innerHTML = SIGNAL_ICONS[s.key] || SIGNAL_ICONS.abuse;
    const body = document.createElement("div"); body.className = "signal-body";
    const top = document.createElement("div"); top.className = "signal-top";
    const name = document.createElement("span"); name.className = "signal-name"; name.textContent = s.label;
    const st = document.createElement("span"); st.className = "signal-state"; st.textContent = label;
    top.append(name, st);
    const desc = document.createElement("p"); desc.className = "signal-desc"; desc.textContent = s.desc;
    body.append(top, desc); el.append(icon, body); grid.appendChild(el);
  }
}
function renderMap(loc) {
  const has = loc.lat != null && loc.lon != null; const fb = $("map-fallback");
  const openBtn = $("map-open");
  if (has) {
    openBtn.hidden = false;
    openBtn.href = `https://uri.amap.com/marker?position=${loc.lon},${loc.lat}&name=${encodeURIComponent(state.current ? state.current.ip : "IP 位置")}&src=iplens&callnative=0`;
  } else openBtn.hidden = true;
  if (!has || typeof L === "undefined") { fb.hidden = false; $("map-fallback-text").textContent = has ? fmtCoord(loc.lat, loc.lon) : "该 IP 暂无可用坐标"; if (state.map) { state.map.remove(); state.map = null; state.marker = null; } return; }
  fb.hidden = true;
  if (!state.map) {
    state.map = L.map("map", { scrollWheelZoom: false }).setView([loc.lat, loc.lon], 11);
    L.tileLayer("https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Dark_Gray_Base/MapServer/tile/{z}/{y}/{x}", { attribution: "Tiles &copy; Esri &mdash; Esri, DeLorme, NAVTEQ", maxZoom: 16 }).addTo(state.map);
    L.tileLayer("https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Dark_Gray_Reference/MapServer/tile/{z}/{y}/{x}", { maxZoom: 16 }).addTo(state.map);
  } else state.map.setView([loc.lat, loc.lon], 11);
  if (state.marker) state.marker.remove();
  state.marker = L.marker([loc.lat, loc.lon], { icon: L.divIcon({ className: "map-pin", iconSize: [18, 18], iconAnchor: [9, 9] }) }).addTo(state.map);
  const tip = document.createElement("div"); tip.className = "map-tip-inner";
  const row = document.createElement("div"); row.className = "map-tip-row";
  if (loc.countryCode && /^[A-Z]{2}$/.test(loc.countryCode)) { const img = document.createElement("img"); img.src = `https://flagcdn.com/w40/${loc.countryCode.toLowerCase()}.png`; img.alt = ""; row.appendChild(img); }
  const ipEl = document.createElement("strong"); ipEl.textContent = state.current ? state.current.ip : ""; row.appendChild(ipEl);
  const place = document.createElement("span"); place.className = "map-tip-place"; place.textContent = [loc.city, loc.region, loc.country].filter(Boolean).join(" · ") || "目标位置";
  tip.append(row, place);
  state.marker.bindTooltip(tip, { permanent: true, direction: "top", offset: [0, -12], className: "map-tip", opacity: 1 }).openTooltip();
  setTimeout(() => { if (state.map) { state.map.invalidateSize(); if (state.marker) state.marker.setLatLng(state.marker.getLatLng()); } }, 350);
}
function verdictText(r) {
  const hits = r.signals.filter((s) => s.detected === true).map((s) => s.label);
  const typePart = r.type.code === "residential" ? `该 IP 属于${r.type.confidence === "high" ? "家庭宽带" : "疑似家庭宽带"}接入` : r.type.code === "datacenter" ? "该 IP 托管于数据中心，并非家庭网络" : r.type.code === "mobile" ? "该 IP 通过移动蜂窝网络接入" : "该 IP 属于企业网络接入";
  return `${typePart}；${hits.length ? `检测到${hits.join("、")}信号，建议谨慎对待该来源的流量` : "未检测到匿名网络或滥用信号，来源可信度较高"}。`;
}
function typeDesc(r) {
  const conf = { high: "高置信度", medium: "中置信度" }[r.type.confidence];
  if (r.type.code === "residential") return `住宅运营商网络 · ${conf} · 非机房 / 非移动出口`;
  if (r.type.code === "datacenter") return `云服务商或机房托管 · ${conf} · 非家宽`;
  if (r.type.code === "mobile") return `蜂窝移动网络出口 · ${conf} · 非家宽`;
  return `企业 / 组织专线 · ${conf} · 非家宽`;
}
function render(r) {
  state.current = r;
  $("report").hidden = false;
  renderFlag(r.location.countryCode);
  $("r-ip").textContent = r.ip;
  $("search-input").value = r.ip;
  $("r-geo").textContent = [r.location.city, r.location.region, r.location.country].filter(Boolean).join(" · ") || "未知地区";
  $("r-isp").textContent = r.network.isp || r.network.org || "未知运营商";
  $("r-version").textContent = `IPv${r.version}`;
  const tb = $("r-type"); tb.textContent = r.type.residential ? "家宽 IP" : `非家宽 · ${r.type.label}`; tb.className = `badge ${TYPE_BADGE_TONES[r.type.code] || ""}`;
  const rb = $("r-risk"); rb.textContent = r.scores.riskLevel; rb.className = `badge ${RISK_TONES[r.scores.riskCode] || ""}`;
  animateScore(r.scores.trust, r.scores.fraud, r.scores.riskCode);
  renderFraud(r.scores.fraud, r.scores.riskCode, r.scores.riskLevel);
  $("r-verdict").textContent = verdictText(r);
  renderSignals(r.signals);
  $("r-country").textContent = r.location.country ? `${r.location.country} (${r.location.countryCode})` : "—";
  $("r-region").textContent = r.location.region || "—"; $("r-city").textContent = r.location.city || "—";
  $("r-coords").textContent = fmtCoord(r.location.lat, r.location.lon); $("r-tz").textContent = r.location.timezone || "—";
  renderMap(r.location);
  $("type-verdict").className = `type-verdict ${TYPE_TONES[r.type.code] || ""}`;
  $("type-icon").innerHTML = TYPE_ICONS[r.type.code];
  $("type-label").textContent = r.type.label; $("type-desc").textContent = typeDesc(r);
  $("r-asn").textContent = r.network.asn || "—"; $("r-org").textContent = r.network.org || "—"; $("r-isp2").textContent = r.network.isp || "—";
  $("r-zip").textContent = r.location.zip || "—"; $("r-source").textContent = "ipquery.io · ip-api.com 双源";
  $("r-time").textContent = fmtTime(r.assessedAt);
  document.querySelectorAll("#report .reveal").forEach((el) => { el.classList.remove("in"); requestAnimationFrame(() => requestAnimationFrame(() => el.classList.add("in"))); });
}
function setLoading(on) { $("loading").hidden = !on; $("search-btn").disabled = on; if (on) $("error").hidden = true; }
function showError(msg) { $("loading").hidden = true; $("report").hidden = true; $("error").hidden = false; $("error-msg").textContent = msg; }
async function fetchReport(q) {
  const url = q ? `${API}?q=${encodeURIComponent(q)}` : API;
  const res = await fetch(url, state.controller ? { signal: state.controller.signal } : {});
  let data = null; try { data = await res.json(); } catch {}
  if (!res.ok || !data || data.ok !== true) { const e = new Error(data && data.message ? data.message : "检测服务暂时不可用，请稍后重试"); e.code = data && data.error; throw e; }
  return data;
}
async function browserIp() {
  const v4sources = [
    { url: "https://ipv4.icanhazip.com", text: true }, { url: "https://api.ipify.org?format=json", pick: (d) => d.ip },
  ];
  const attempt = async (s) => {
    const res = await fetchTimeout(s.url, 4000);
    const ip = (s.text ? await res.text() : s.pick(await res.json()) || "").trim();
    if (!isIpFormat(ip) || ip.includes(":")) throw new Error("invalid");
    return ip;
  };
  try { return await Promise.any(v4sources.map(attempt)); } catch {}
  try { const res = await fetchTimeout("https://api6.ipify.org?format=json", 4000); const ip = ((await res.json()).ip || "").trim(); if (isIpFormat(ip)) return ip; } catch {}
  return null;
}
async function detectOwnIp() {
  try { return await fetchReport(null); }
  catch (e) { if (e.code === "ip_unavailable") { const ip = await browserIp(); if (ip) return await fetchReport(ip); throw new Error("无法识别您的本机 IP，请在上方手动输入地址查询"); } throw e; }
}
async function ownReport() { if (!state.own) state.own = await detectOwnIp(); return state.own; }
async function query(ip, scroll) {
  const seq = ++state.reqSeq; state.queryStarted = true;
  if (state.controller) state.controller.abort(); state.controller = new AbortController(); state.lastQuery = ip || null;
  let showedCache = false;
  if (ip) { $("search-input").value = ip; setLoading(true); }
  else {
    const cached = readOwnCache();
    if (cached) { showedCache = true; state.own = cached; $("error").hidden = true; render(cached); }
    else setLoading(true);
  }
  try {
    const report = ip ? await fetchReport(ip) : await detectOwnIp();
    if (seq !== state.reqSeq) return;
    if (!ip) { state.own = report; writeOwnCache(report); }
    setLoading(false); render(report); pushHistory(report.ip);
    try {
      if (ip) history.replaceState(null, "", `#ip=${report.ip}`);
      else history.replaceState(null, "", location.pathname + location.search);
    } catch {}
    if (scroll) $("result").scrollIntoView({ behavior: "smooth", block: "start" });
  } catch (e) {
    if (seq !== state.reqSeq || e.name === "AbortError") return;
    setLoading(false);
    if (showedCache) { toast("刷新失败，正在显示上次评估结果"); return; }
    showError(e.message || "检测失败，请稍后重试");
    if (scroll) $("result").scrollIntoView({ behavior: "smooth", block: "start" });
  }
}

/* ================= ASN monitor ================= */
const asn = {
  ws: null, started: false, paused: true, stopped: false, initialDone: false,
  rows: [], cache: new Map(), pending: new Map(), queue: [], active: 0,
  renderTimer: null, pollTimer: null,
  start() {
    if (this.started) return;
    this.started = true; this.stopped = false; this.initialDone = false; this.rows = [];
    $("asn-body").innerHTML = '<tr class="empty-row"><td colspan="6">正在获取最近路由更新…</td></tr>';
    $("asn-count").textContent = "0"; $("asn-pause").textContent = "开启实时";
    this.setConn("", "获取中…");
    this.loadSnapshot();
  },
  setConn(cls, text) { const el = $("asn-conn"); el.className = `conn-state ${cls}`; $("asn-conn-text").textContent = text; },
  async loadSnapshot() {
    try {
      const res = await fetchTimeout(`${API}?feed=bgp`, 12000);
      const d = await res.json();
      if (!d || d.ok !== true || !Array.isArray(d.rows)) throw new Error("bad_feed");
      this.rows = d.rows.slice(-100);
      this.finishInitial();
    } catch {
      this.finishInitial();
    }
  },
  connect() {
    let ws; try { ws = new WebSocket("wss://ris-live.ripe.net/v1/ws/?client=iplens"); } catch { this.startPolling(); return; }
    this.ws = ws;
    ws.onopen = () => { ws.send(JSON.stringify({ type: "ris_subscribe", data: { type: "UPDATE" } })); this.stopPolling(); this.setConn("live", "实时连接"); };
    ws.onmessage = (e) => { if (this.paused) return; let msg; try { msg = JSON.parse(e.data); } catch { return; } this.handle(msg); };
    ws.onclose = () => { if (this.started && !this.stopped && !this.paused) { this.setConn("error", "直连断开，改用服务端快照…"); this.startPolling(); } };
    ws.onerror = () => { if (!this.paused) this.startPolling(); };
  },
  startPolling() {
    if (this.pollTimer || this.paused || this.stopped) return;
    this.setConn("live", "实时连接 · 服务端中转");
    this.pollTimer = setInterval(async () => {
      if (this.paused || this.stopped) return;
      try {
        const res = await fetchTimeout(`${API}?feed=bgp`, 12000);
        const d = await res.json();
        if (d && d.ok === true && Array.isArray(d.rows)) { this.rows = d.rows.slice(-100); this.scheduleRender(); }
      } catch {}
    }, 8000);
  },
  stopPolling() { if (this.pollTimer) { clearInterval(this.pollTimer); this.pollTimer = null; } },
  handle(msg) {
    if (this.paused) return;
    if (msg.type !== "ris_message") return; const d = msg.data; if (!d || d.type !== "UPDATE") return;
    const path = d.path || []; const origin = path.length ? path[path.length - 1] : null; const ts = (d.timestamp || Date.now() / 1000) * 1000;
    for (const ann of d.announcements || []) for (const pfx of ann.prefixes || []) this.pushRow(ts, pfx, origin, "announce");
    for (const pfx of d.withdrawals || []) this.pushRow(ts, pfx, null, "withdraw");
  },
  pushRow(ts, pfx, origin, type) {
    this.rows.push({ ts, pfx, origin, type });
    if (this.rows.length > 100) this.rows.splice(0, this.rows.length - 100);
    if (!this.paused) this.scheduleRender();
  },
  finishInitial() {
    if (this.initialDone) return; this.initialDone = true;
    this.paused = true;
    $("asn-pause").textContent = "开启实时";
    this.render();
    this.setConn("paused", this.rows.length ? "静态快照 · 已暂停" : "暂无数据");
  },
  scheduleRender() {
    if (this.renderTimer) return;
    this.renderTimer = setTimeout(() => { this.renderTimer = null; this.render(); }, 3000);
  },
  render() {
    const body = $("asn-body"); body.textContent = "";
    const sorted = [...this.rows].sort((a, b) => b.ts - a.ts);
    $("asn-count").textContent = String(sorted.length);
    if (!sorted.length) { body.innerHTML = '<tr class="empty-row"><td colspan="6">暂无路由更新，可开启实时或稍后重试</td></tr>'; return; }
    for (const r of sorted) {
      const tr = document.createElement("tr");
      const time = new Date(r.ts).toLocaleTimeString("zh-CN", { hour12: false });
      tr.innerHTML = `<td>${time}</td><td class="country-cell">—</td><td class="mono"></td><td class="mono asn-cell"></td><td class="name-cell">—</td><td><span class="tag ${r.type}">${r.type === "announce" ? "公告" : "撤销"}</span></td>`;
      tr.children[2].textContent = r.pfx; tr.children[3].textContent = r.origin ? `AS${r.origin}` : "—";
      body.appendChild(tr);
      if (r.origin) this.enrich(r.origin, r.pfx, tr);
    }
  },
  enrich(asnNum, pfx, tr) {
    if (this.cache.has(asnNum)) { this.fill(tr, this.cache.get(asnNum)); return; }
    if (this.pending.has(asnNum)) { this.pending.get(asnNum).push({ tr, pfx }); return; }
    this.pending.set(asnNum, [{ tr, pfx }]);
    if (this.queue.length > 60) { const old = this.queue.shift(); this.pending.delete(old); }
    this.queue.push(asnNum); this.pump();
  },
  pump() {
    while (this.active < 4 && this.queue.length) {
      const asnNum = this.queue.shift(); this.active++;
      const jobs = this.pending.get(asnNum) || []; const pfx = jobs[0] ? jobs[0].pfx : "";
      fetchTimeout(`${API}?asn=${asnNum}&pfx=${encodeURIComponent(pfx)}`, 12000).then((r) => r.json()).then((d) => {
        if (d && d.ok) { this.cache.set(asnNum, d); for (const j of jobs) if (j.tr.isConnected) this.fill(j.tr, d); }
      }).catch(() => {}).finally(() => { this.pending.delete(asnNum); this.active--; this.pump(); });
    }
  },
  fill(tr, d) {
    const cc = d.countryCode || ""; const name = d.country || "";
    tr.children[1].innerHTML = cc ? `<span class="flag-cell">${flagImg(cc)}${name}</span>` : (name || "—");
    tr.children[4].textContent = d.name || "—"; tr.children[4].title = d.name || "";
  },
  togglePause() {
    if (!this.initialDone) return;
    this.paused = !this.paused;
    $("asn-pause").textContent = this.paused ? "开启实时" : "暂停";
    if (this.paused) {
      this.stopPolling();
      if (this.ws) { try { this.ws.close(); } catch {} this.ws = null; }
      this.setConn("paused", "静态快照 · 已暂停");
    } else {
      this.setConn("", "连接中…");
      this.connect();
      this.render(); this.scheduleRender();
    }
  },
  clear() { this.rows = []; this.render(); },
};

/* ================= DNS leak ================= */
const dns = {
  started: false, running: false,
  countryFromGeo(geo) { return (geo || "").split(" - ")[0].trim(); },
  async run() {
    if (this.running) return; this.running = true; this.started = true;
    $("dns-loading").hidden = false; $("dns-verdict").hidden = true; $("dns-run").disabled = true;
    $("dns-body").innerHTML = '<tr class="empty-row"><td colspan="4">探测进行中…</td></tr>';
    let exitCountry; try { exitCountry = (await ownReport()).location.country; } catch { exitCountry = ""; }
    const N = 8; const map = new Map(); let done = 0;
    await Promise.all(Array.from({ length: N }, async () => {
      try { const res = await fetchTimeout("https://edns.ip-api.com/json", 12000, { cache: "no-store" }); const d = await res.json(); const ip = d && d.dns && d.dns.ip; const geo = (d && d.dns && d.dns.geo) || ""; if (ip) { const e = map.get(ip) || { ip, geo, count: 0 }; e.count++; if (geo) e.geo = geo; map.set(ip, e); } } catch {}
      done++; $("dns-summary").textContent = `正在探测…已完成 ${done}/${N} 次随机子域查询。`;
    }));
    const rows = [...map.values()].sort((a, b) => b.count - a.count);
    const body = $("dns-body"); body.textContent = "";
    if (!rows.length) body.innerHTML = '<tr class="empty-row"><td colspan="4">未获取到解析服务器，请稍后重试</td></tr>';
    rows.forEach((r, i) => { const tr = document.createElement("tr"); tr.innerHTML = `<td class="num">${i + 1}</td><td class="mono"></td><td class="geo-cell"></td><td class="num"><span class="hit-pill ${r.count > 1 ? "hot" : ""}">${r.count} 次</span></td>`; tr.children[1].textContent = r.ip; tr.children[2].textContent = r.geo || "未知"; body.appendChild(tr); });
    const countries = new Set(rows.map((r) => this.countryFromGeo(r.geo)).filter(Boolean));
    const banner = $("dns-verdict"); banner.hidden = false;
    if (!rows.length) { this.setVerdict("warn", "未获取到解析服务器", "本次探测未能捕获递归服务器地址，可能是网络拦截了检测端点，请稍后重试。"); }
    else if (!exitCountry) { this.setVerdict("warn", "已捕获解析服务器", `共 ${rows.length} 台递归服务器应答，但无法识别你的出口位置以进行泄露比对。`); }
    else { const foreign = [...countries].filter((c) => c.toLowerCase() !== exitCountry.toLowerCase()); if (!foreign.length) this.setVerdict("good", "未发现 DNS 泄露迹象", `所有解析请求均由 ${exitCountry} 境内的服务器完成，与你的出口位置一致。`); else this.setVerdict("bad", "发现 DNS 泄露迹象", `部分解析请求由 ${foreign.join("、")} 的服务器完成，与出口位置（${exitCountry}）不一致，可能暴露你的真实位置。`); }
    $("dns-summary").textContent = `共发起 ${N} 次查询，捕获到 ${rows.length} 台不同服务器。运营商 DNS 常以集群方式应答，多台属正常现象；结果基于 EDNS 技术推断，受运营商策略影响，仅供参考。`;
    $("dns-loading").hidden = true; $("dns-run").disabled = false; this.running = false;
  },
  setVerdict(tone, title, desc) { const b = $("dns-verdict"); b.className = `verdict-banner ${tone}`; $("dns-verdict-icon").innerHTML = tone === "good" ? CHECK_OK : CHECK_BAD; $("dns-verdict-title").textContent = title; $("dns-verdict-desc").textContent = desc; },
};

/* ================= WebRTC ================= */
const STUN_SERVERS = [
  { host: "stun.l.google.com:19302", region: "Global", org: "Google" },
  { host: "stun1.l.google.com:19302", region: "Global", org: "Google" },
  { host: "stun2.l.google.com:19302", region: "Global", org: "Google" },
  { host: "stun.cloudflare.com:3478", region: "Global", org: "Cloudflare" },
  { host: "stun.global.stun.twilio.com:3478", region: "Global", org: "Twilio" },
  { host: "stun.stunprotocol.org:3478", region: "Global", org: "StunProtocol" },
  { host: "stun.nextcloud.com:443", region: "Global", org: "Nextcloud" },
  { host: "stun.sip.us:3478", region: "Global", org: "SIP" },
];
const rtc = {
  started: false, running: false, httpIp: "",
  async ensureHttpIp() { if (this.httpIp) { $("rtc-http-ip").textContent = this.httpIp; return; } try { this.httpIp = (await ownReport()).ip; } catch { this.httpIp = ""; } $("rtc-http-ip").textContent = this.httpIp || "未知"; },
  gather(server, timeout = 6500) {
    return new Promise((resolve) => {
      let pc; try { pc = new RTCPeerConnection({ iceServers: [{ urls: `stun:${server.host}` }] }); } catch { resolve({ ips: [], mdns: false, status: "unsupported" }); return; }
      const ips = new Set(); let mdns = false; let done = false;
      const finish = (status) => { if (done) return; done = true; try { pc.close(); } catch {} resolve({ ips: [...ips], mdns, status }); };
      const parse = (line) => { const p = line.split(" "); const typ = p[7]; const ip = p[4]; if (typ === "srflx" && ip) ips.add(ip); if (typ === "host" && ip && ip.endsWith(".local")) mdns = true; };
      try { pc.createDataChannel("probe"); } catch {}
      pc.onicecandidate = (e) => { if (!e.candidate) { finish("complete"); return; } parse(e.candidate.candidate); };
      pc.onicegatheringstatechange = () => { if (pc.iceGatheringState === "complete") finish("complete"); };
      pc.createOffer().then((o) => pc.setLocalDescription(o)).catch(() => finish("error"));
      setTimeout(() => finish(pc.iceGatheringState === "complete" ? "complete" : "timeout"), timeout);
    });
  },
  renderList() {
    const box = $("stun-list"); box.textContent = "";
    STUN_SERVERS.forEach((s, i) => { const row = document.createElement("div"); row.className = "stun-row"; row.id = `stun-${i}`; row.innerHTML = `<div class="stun-info"><div class="stun-host">stun:${s.host}</div><div class="stun-tags"><span class="tag">${s.region}</span><span class="tag org">${s.org}</span></div></div><div class="stun-result pending" id="stun-res-${i}"><span class="spin"></span>等待检测</div>`; box.appendChild(row); });
  },
  async run() {
    if (this.running) return; this.running = true; this.started = true;
    $("rtc-run").disabled = true; $("rtc-verdict").hidden = true; $("rtc-loading").hidden = false; $("rtc-progress").textContent = "检测中…";
    this.renderList(); await this.ensureHttpIp();
    const allIps = new Set(); let completed = 0;
    await Promise.all(STUN_SERVERS.map(async (s, i) => {
      const r = await this.gather(s); const res = $(`stun-res-${i}`); const row = $(`stun-${i}`);
      const pub = r.ips.filter((ip) => !isPrivateIp(ip)); pub.forEach((ip) => allIps.add(ip));
      res.classList.remove("pending");
      if (r.status === "unsupported") { res.innerHTML = "浏览器不支持 WebRTC"; }
      else if (pub.length) { const leak = this.httpIp && pub.some((ip) => ip !== this.httpIp); res.classList.add(leak ? "leak" : "ok"); row.classList.add(leak ? "leak" : "ok"); res.innerHTML = `${leak ? CHECK_BAD : CHECK_OK}<span>${pub.join(", ")}${leak ? " · 与出口不一致" : " · 与出口一致"}</span>`; }
      else if (r.mdns) { res.classList.add("ok"); row.classList.add("ok"); res.innerHTML = `${CHECK_OK}<span>mDNS 已隐藏本地地址</span>`; }
      else if (r.ips.length) { res.classList.add("ok"); row.classList.add("ok"); res.innerHTML = `${CHECK_OK}<span>仅内网候选，无公网泄露</span>`; }
      else { res.innerHTML = `${CHECK_OK}<span>未检测到 WebRTC 泄露真实 IP</span>`; res.classList.add("ok"); row.classList.add("ok"); }
      completed++; $("rtc-progress").textContent = `${completed}/${STUN_SERVERS.length} 已完成`;
    }));
    const pub = [...allIps]; const banner = $("rtc-verdict"); banner.hidden = false;
    if (!pub.length) this.setVerdict("good", "没有收集到公网候选，没有泄露", "浏览器以 mDNS 隐藏了本地地址，或 WebRTC / STUN 请求被禁用与拦截——你的真实 IP 未被 WebRTC 暴露。");
    else if (!this.httpIp) this.setVerdict("warn", "已收集到 WebRTC 映射地址", `STUN 返回地址 ${pub.join(", ")}，但无法识别 HTTP 出口以进行比对。`);
    else { const leaked = pub.filter((ip) => ip !== this.httpIp); if (!leaked.length) this.setVerdict("good", "未发现 WebRTC 泄露", `WebRTC 映射地址与 HTTP 出口一致（${this.httpIp}），代理未被子进程绕过。`); else this.setVerdict("bad", "发现 WebRTC 泄露", `WebRTC 暴露了不同于 HTTP 出口（${this.httpIp}）的地址：${leaked.join(", ")}，建议禁用 WebRTC 或启用强制代理。`); }
    $("rtc-loading").hidden = true; $("rtc-run").disabled = false; $("rtc-progress").textContent = `${STUN_SERVERS.length}/${STUN_SERVERS.length} 已完成`; this.running = false;
  },
  setVerdict(tone, title, desc) { const b = $("rtc-verdict"); b.className = `verdict-banner ${tone}`; $("rtc-verdict-icon").innerHTML = tone === "good" ? CHECK_OK : CHECK_BAD; $("rtc-verdict-title").textContent = title; $("rtc-verdict-desc").textContent = desc; },
};

/* ================= Exit detection ================= */
const exit = {
  started: false, running: false,
  V4: [["https://ipv4.icanhazip.com", true], ["https://v4.ident.me", true], ["https://api.ipify.org?format=json", false]],
  V6: [["https://ipv6.icanhazip.com", true], ["https://v6.ident.me", true], ["https://api6.ipify.org?format=json", false]],
  async probe(list, wantV6) {
    for (const [url, text] of list) { try { const res = await fetchTimeout(url, 7000); let ip = text ? (await res.text()).trim() : (await res.json()).ip; ip = (ip || "").trim(); if (!ip || !isIpFormat(ip)) continue; const isV6 = ip.includes(":"); if (wantV6 !== isV6) continue; if (isPrivateIp(ip)) continue; return ip; } catch {} }
    return null;
  },
  async geo(ip) { try { const r = await (await fetchTimeout(`${API}?q=${encodeURIComponent(ip)}`, 12000)).json(); if (r.ok) return [r.location.city, r.location.country].filter(Boolean).join(", ") || r.location.country || ""; } catch {} return ""; },
  setCard(fam, ip, geo) {
    const stateEl = $(`exit-${fam}-state`); const ipEl = $(`exit-${fam}-ip`);
    if (ip) { stateEl.textContent = "可用"; stateEl.className = "badge tone-green"; ipEl.textContent = ip; if (ip.includes(":")) ipEl.innerHTML = ipEl.innerHTML.replace(/:/g, ":<wbr>"); ipEl.classList.remove("none"); $(`exit-${fam}-geo`).textContent = geo || "—"; }
    else { stateEl.textContent = "不可用"; stateEl.className = "badge"; ipEl.textContent = "无出口"; ipEl.classList.add("none"); $(`exit-${fam}-geo`).textContent = "当前网络未检测到该协议出口"; }
  },
  async run() {
    if (this.running) return; this.running = true; this.started = true; $("exit-run").disabled = true;
    $("exit-v4-state").textContent = "检测中"; $("exit-v4-state").className = "badge"; $("exit-v6-state").textContent = "检测中"; $("exit-v6-state").className = "badge";
    $("exit-v4-ip").textContent = "…"; $("exit-v6-ip").textContent = "…"; $("exit-summary").textContent = "正在探测双栈出口…";
    const [v4, v6] = await Promise.all([this.probe(this.V4, false), this.probe(this.V6, true)]);
    const [g4, g6] = await Promise.all([v4 ? this.geo(v4) : "", v6 ? this.geo(v6) : ""]);
    this.setCard("v4", v4, g4); this.setCard("v6", v6, g6);
    let s;
    if (v4 && v6) s = `你的网络为 <b>双栈网络</b>：IPv4 出口 <b>${v4}</b>，IPv6 出口 <b>${v6}</b>。两种协议均可独立访问互联网。`;
    else if (v4) s = `你的网络 <b>仅 IPv4 可用</b>，出口为 <b>${v4}</b>；未检测到 IPv6 出口，访问纯 IPv6 资源可能受限。`;
    else if (v6) s = `你的网络 <b>仅 IPv6 可用</b>，出口为 <b>${v6}</b>；未检测到 IPv4 出口，访问纯 IPv4 资源可能依赖 NAT64/DNS64 转换。`;
    else s = "未能检测到任何公网出口，可能处于受限网络或检测端点被拦截，请稍后重试。";
    $("exit-summary").innerHTML = s; $("exit-run").disabled = false; this.running = false;
  },
};

/* ================= API docs ================= */
const api = {
  init() {
    const base = `${location.origin}${API}`;
    $("api-ex-self").textContent = `curl ${base}`;
    $("api-ex-ip").textContent = `curl "${base}?q=1.1.1.1"`;
    $("api-ex-asn").textContent = `curl "${base}?asn=15169&pfx=8.8.8.0/24"`;
  },
  async tryIt(q) {
    const pre = $("api-response"); pre.hidden = false; pre.textContent = "请求中…";
    try { const url = q ? `${API}?q=${encodeURIComponent(q)}` : API; const res = await fetchTimeout(url, 15000); const data = await res.json(); pre.textContent = JSON.stringify(data, null, 2); }
    catch (e) { pre.textContent = `请求失败：${e.message || e}`; }
  },
};

/* ================= Router ================= */
const VIEWS = ["query", "asn", "dns", "webrtc", "api"];
function showView(view) {
  for (const v of VIEWS) $(`view-${v}`).hidden = v !== view;
  document.querySelectorAll("[data-nav]").forEach((a) => a.classList.toggle("active", a.dataset.route === view));
  const navLinks = document.querySelector(".nav-links"); const active = navLinks.querySelector("a.active");
  if (active) { const r = active.getBoundingClientRect(); const c = navLinks.getBoundingClientRect(); navLinks.scrollLeft += r.left - c.left - c.width / 2 + r.width / 2; }
  window.scrollTo({ top: 0, behavior: "auto" });
  if (view === "query" && state.map) setTimeout(() => state.map.invalidateSize(), 200);
}
function route() {
  const h = location.hash; let view = "query"; let ip = null;
  const m = h.match(/^#ip=(.+)$/);
  if (m) { view = "query"; ip = decodeURIComponent(m[1]); }
  else if (h === "#asn") view = "asn"; else if (h === "#dns") view = "dns"; else if (h === "#webrtc") view = "webrtc"; else if (h === "#api") view = "api";
  showView(view);
  if (view === "query") { if (ip) query(ip, false); else if (!state.queryStarted) query(null, false); if (!exit.started) exit.run(); }
  else if (view === "asn") asn.start();
  else if (view === "dns") { if (!dns.started) dns.run(); }
  else if (view === "webrtc") { if (!rtc.started) rtc.run(); else rtc.ensureHttpIp(); }
  else if (view === "api") api.init();
}

/* ================= Events ================= */
$("search-form").addEventListener("submit", (e) => { e.preventDefault(); const v = $("search-input").value.trim(); if (!v) { toast("请输入 IP 地址，或点击「重新识别本机 IP」"); return; } location.hash = `#ip=${v}`; if (location.hash === `#ip=${v}`) query(v, true); });
$("detect-me").addEventListener("click", () => { $("search-input").value = ""; query(null, true); });
document.querySelectorAll("[data-example]").forEach((b) => b.addEventListener("click", () => { location.hash = `#ip=${b.dataset.example}`; query(b.dataset.example, true); }));
$("error-retry").addEventListener("click", () => query(state.lastQuery, false));
$("copy-ip").addEventListener("click", () => state.current && copyText(state.current.ip, "IP 地址已复制"));
$("share-link").addEventListener("click", () => state.current && copyText(`${location.origin}${location.pathname}#ip=${state.current.ip}`, "查询链接已复制"));
$("asn-pause").addEventListener("click", () => asn.togglePause());
$("asn-clear").addEventListener("click", () => asn.clear());
$("dns-run").addEventListener("click", () => dns.run());
$("rtc-run").addEventListener("click", () => rtc.run());
$("exit-run").addEventListener("click", () => exit.run());
$("exit-v4-copy").addEventListener("click", () => { const t = $("exit-v4-ip").textContent; if (t && t !== "无出口") copyText(t, "IPv4 出口已复制"); });
$("exit-v6-copy").addEventListener("click", () => { const t = $("exit-v6-ip").textContent; if (t && t !== "无出口") copyText(t, "IPv6 出口已复制"); });
$("api-try-form").addEventListener("submit", (e) => { e.preventDefault(); api.tryIt($("api-try-input").value.trim()); });
document.querySelectorAll(".api-copy").forEach((b) => b.addEventListener("click", () => { const map = { self: "api-ex-self", ip: "api-ex-ip", asn: "api-ex-asn" }; copyText($(map[b.dataset.copy]).textContent, "示例命令已复制"); }));
window.addEventListener("hashchange", route);

/* ================= Init ================= */
renderHistory();
route();