"use strict";

const $ = (id) => document.getElementById(id);
const API = "/functions/v1/app";
const HISTORY_KEY = "ipspot-history";
const OWN_KEY = "ipspot-own-v6";
const THEME_KEY = "ipspot-theme";
const BASE_TITLE = "IPSpot · 免费 IP 纯净度检测 — 原生/家宽判定 · 欺诈评分 · 浏览器指纹 · 真实地理地址";

const state = {
  current: null,
  own: null,
  fp: null,
  clientEnv: null,
  geoAddr: null,
  aiLoadedForIp: null,
  reqSeq: 0,
  controller: null,
  map: null,
  marker: null,
  lastQuery: null,
  queryStarted: false,
  pingRan: false,
};

const SIGNAL_ORDER = ["proxy", "vpn", "tor", "datacenter", "mobile", "abuse"];
const SIGNAL_ICONS = {
  proxy: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M4 7h11l-3-3M20 17H9l3 3"/><path d="M20 7h-2M4 17h2"/></svg>',
  vpn: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M12 3l8 4v5c0 5-3.5 8-8 9-4.5-1-8-4-8-9V7z"/><path d="M12 8v4M12 15h.01"/></svg>',
  tor: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="5"/><circle cx="12" cy="12" r="1.4" fill="currentColor"/></svg>',
  datacenter: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="3" y="4" width="18" height="6" rx="1.5"/><rect x="3" y="14" width="18" height="6" rx="1.5"/><path d="M7 7h.01M7 17h.01M12 7h4M12 17h4"/></svg>',
  mobile: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="7" y="2.5" width="10" height="19" rx="2.5"/><path d="M11 18.5h2"/></svg>',
  abuse: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M12 2c1 3-2 4-2 7 0 1.5 1 2.5 2 2.5S14 10.5 14 9c2 1.5 3 3.5 3 5.5a5 5 0 0 1-10 0C7 10 9.5 6.5 12 2z"/></svg>',
};

const COUNTRY_ZH = {
  AE:"阿联酋", AR:"阿根廷", AT:"奥地利", AU:"澳大利亚", BE:"比利时", BG:"保加利亚", BR:"巴西",
  CA:"加拿大", CH:"瑞士", CL:"智利", CN:"中国", CO:"哥伦比亚", CZ:"捷克", DE:"德国", DK:"丹麦",
  EE:"爱沙尼亚", EG:"埃及", ES:"西班牙", FI:"芬兰", FR:"法国", GB:"英国", GR:"希腊", HK:"中国香港",
  HR:"克罗地亚", HU:"匈牙利", ID:"印度尼西亚", IE:"爱尔兰", IL:"以色列", IN:"印度", IS:"冰岛",
  IT:"意大利", JP:"日本", KH:"柬埔寨", KR:"韩国", KZ:"哈萨克斯坦", LT:"立陶宛", LU:"卢森堡",
  LV:"拉脱维亚", MO:"中国澳门", MX:"墨西哥", MY:"马来西亚", NG:"尼日利亚", NL:"荷兰", NO:"挪威",
  NZ:"新西兰", PH:"菲律宾", PK:"巴基斯坦", PL:"波兰", PT:"葡萄牙", RO:"罗马尼亚", RU:"俄罗斯",
  SA:"沙特阿拉伯", SE:"瑞典", SG:"新加坡", SK:"斯洛伐克", TH:"泰国", TR:"土耳其", TW:"中国台湾",
  UA:"乌克兰", US:"美国", VN:"越南", ZA:"南非",
};

const COUNTRY_LANG = {
  CN: ["zh"], HK: ["zh", "en"], TW: ["zh"], MO: ["zh", "pt"],
  US: ["en"], GB: ["en"], CA: ["en", "fr"], AU: ["en"], NZ: ["en"], SG: ["en", "zh"],
  JP: ["ja"], KR: ["ko"], DE: ["de"], FR: ["fr"], ES: ["es"], IT: ["it"], NL: ["nl"], RU: ["ru"],
};

/* ================= Utils ================= */
function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (m) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[m]));
}
function toast(msg) {
  const el = $("toast"); el.textContent = msg; el.classList.add("show");
  clearTimeout(toast._t); toast._t = setTimeout(() => el.classList.remove("show"), 2000);
}
async function copyText(text, msg) {
  try { await navigator.clipboard.writeText(text); toast(msg); }
  catch {
    const ta = document.createElement("textarea"); ta.value = text; ta.style.cssText = "position:fixed;opacity:0";
    document.body.appendChild(ta); ta.select();
    try { document.execCommand("copy"); toast(msg); } catch { toast("复制失败"); }
    ta.remove();
  }
}
function countryName(cc, fallback = "") {
  const c = (cc || "").toUpperCase();
  const zh = COUNTRY_ZH[c];
  if (zh && fallback && zh !== fallback) return `${zh} (${fallback})`;
  return zh || fallback || c || "—";
}
function countryShort(cc, fallback = "") {
  const c = (cc || "").toUpperCase();
  return COUNTRY_ZH[c] || fallback || c || "—";
}
function flagHtml(cc, w = 40) {
  return cc && /^[A-Z]{2}$/.test(cc)
    ? `<img src="https://flagcdn.com/w${w}/${cc.toLowerCase()}.png" alt="${esc(cc)}">`
    : "";
}
function fnv1a(str) {
  let h = 2166136261;
  for (let i = 0; i < str.length; i++) { h ^= str.charCodeAt(i); h = Math.imul(h, 16777619); }
  return (h >>> 0).toString(16).padStart(8, "0");
}
function hashHex32(str) {
  return fnv1a(str) + fnv1a(str + "#1") + fnv1a("#2" + str) + fnv1a(str.split("").reverse().join(""));
}
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
function fetchTimeout(url, ms, opts = {}) {
  const c = new AbortController(); const t = setTimeout(() => c.abort(), ms);
  return fetch(url, { ...opts, signal: c.signal }).finally(() => clearTimeout(t));
}
function randomAlphaNum(len = 32) {
  const chars = "abcdefghijklmnopqrstuvwxyz0123456789";
  const a = new Uint8Array(len);
  if (crypto?.getRandomValues) crypto.getRandomValues(a);
  else for (let i = 0; i < len; i++) a[i] = Math.floor(Math.random() * 256);
  let out = "";
  for (let i = 0; i < len; i++) out += chars[a[i] % chars.length];
  return out;
}

/* ================= Dynamic SEO Document Title ================= */
function updateSeoTitle(view, report) {
  if (view === "fp") { document.title = "浏览器指纹环境检测 — IPSpot"; return; }
  if (view === "asn") { document.title = "全球 ASN 与 BGP 路由实时监控 — IPSpot"; return; }
  if (view === "dns") { document.title = "DNS 泄露在线检测 — IPSpot"; return; }
  if (view === "webrtc") { document.title = "WebRTC 真实 IP 泄露在线检测 — IPSpot"; return; }
  if (view === "api") { document.title = "开放 IP 情报 JSON API 文档 — IPSpot"; return; }
  if (report && report.ip) {
    const loc = countryShort(report.location.countryCode, report.location.country);
    document.title = `${report.ip} · ${report.type.label} · ${loc}（风险 ${report.scores.fraud}%）— IPSpot`;
  } else {
    document.title = BASE_TITLE;
  }
}

/* ================= Theme ================= */
function currentTheme() {
  return document.documentElement.getAttribute("data-theme") === "light" ? "light" : "dark";
}
function syncThemeUI() {
  const t = currentTheme();
  $("theme-label").textContent = t === "dark" ? "浅色" : "深色";
  $("meta-theme-color").setAttribute("content", t === "light" ? "#F5F7FA" : "#070B14");
}
function toggleTheme() {
  const next = currentTheme() === "dark" ? "light" : "dark";
  document.documentElement.setAttribute("data-theme", next);
  try { localStorage.setItem(THEME_KEY, next); } catch {}
  syncThemeUI();
}

/* ================= Collapsible Helper ================= */
function bindToggle(btnId, boxId, onOpen) {
  const btn = $(btnId); const box = $(boxId);
  if (!btn || !box) return;
  btn.addEventListener("click", () => {
    const open = box.hidden;
    box.hidden = !open;
    btn.setAttribute("aria-expanded", String(open));
    if (open && onOpen) onOpen();
  });
}

/* ================= Cache & History ================= */
function readOwnCache() {
  try {
    const r = JSON.parse(localStorage.getItem(OWN_KEY));
    return r && r.ok && r.ip && r.humanRatio && r.exposure && Array.isArray(r.registryHistory) ? r : null;
  } catch { return null; }
}
function writeOwnCache(r) { try { localStorage.setItem(OWN_KEY, JSON.stringify(r)); } catch {} }
function getHistory() { try { return JSON.parse(localStorage.getItem(HISTORY_KEY)) || []; } catch { return []; } }
function pushHistory(val) {
  let list = getHistory().filter((x) => x !== val);
  list.unshift(val); list = list.slice(0, 6);
  try { localStorage.setItem(HISTORY_KEY, JSON.stringify(list)); } catch {}
  renderHistory();
}
function renderHistory() {
  const box = $("history"); box.textContent = "";
  const list = getHistory(); if (!list.length) return;
  const label = document.createElement("span");
  label.className = "history-label"; label.textContent = "最近查询";
  box.appendChild(label);
  for (const item of list) {
    const b = document.createElement("button");
    b.type = "button"; b.className = "chip"; b.textContent = item;
    b.addEventListener("click", () => { location.hash = `#ip=${encodeURIComponent(item)}`; });
    box.appendChild(b);
  }
}

/* ================= Accurate Fingerprint Engine (FPJS v4 + High-Entropy OS/Screen + Zero Broken Endpoints) ================= */
const fpEngine = {
  _collecting: null,
  getCanvas() {
    try {
      const c = document.createElement("canvas"); c.width = 240; c.height = 48;
      const ctx = c.getContext("2d"); if (!ctx) return "不支持";
      ctx.textBaseline = "top"; ctx.font = "14px Arial";
      ctx.fillStyle = "#0ea5e9"; ctx.fillRect(8, 6, 86, 20);
      ctx.fillStyle = "#0f172a"; ctx.fillText("IPSpot.org · FP2026", 12, 11);
      return fnv1a(c.toDataURL());
    } catch { return "已屏蔽"; }
  },
  getWebGL() {
    try {
      const c = document.createElement("canvas");
      const gl = c.getContext("webgl") || c.getContext("experimental-webgl");
      if (!gl) return { vendor: "不支持", renderer: "不支持", hash: "—" };
      const dbg = gl.getExtension("WEBGL_debug_renderer_info");
      const vendor = dbg ? String(gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL) || "—") : String(gl.getParameter(gl.VENDOR) || "—");
      const renderer = dbg ? String(gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL) || "—") : String(gl.getParameter(gl.RENDERER) || "—");
      const exts = (gl.getSupportedExtensions() || []).join(",");
      return { vendor, renderer, hash: fnv1a(`${vendor}|${renderer}|${exts}`) };
    } catch { return { vendor: "受限", renderer: "受限", hash: "—" }; }
  },
  async getAudio() {
    try {
      const AC = window.OfflineAudioContext || window.webkitOfflineAudioContext;
      if (!AC) return "不支持";
      const ctx = new AC(1, 44100, 44100);
      const osc = ctx.createOscillator(); osc.type = "triangle"; osc.frequency.value = 10000;
      const comp = ctx.createDynamicsCompressor();
      osc.connect(comp); comp.connect(ctx.destination); osc.start(0);
      const buf = await ctx.startRendering();
      const ch = buf.getChannelData(0);
      let acc = 0; for (let i = 4500; i < 5000; i++) acc += Math.abs(ch[i]);
      return fnv1a(acc.toFixed(6));
    } catch { return "受限"; }
  },
  detectFonts() {
    const candidates = [
      "Arial", "Helvetica", "Segoe UI", "PingFang SC", "Microsoft YaHei",
      "Hiragino Sans GB", "Noto Sans SC", "Roboto", "SF Pro Text",
      "Consolas", "Monaco", "Courier New", "Georgia", "Times New Roman", "Verdana", "Tahoma",
    ];
    try {
      const c = document.createElement("canvas");
      const ctx = c.getContext("2d");
      if (!ctx) return { count: 0, hash: "—", sample: "不支持" };
      const text = "mmmmmmmmmmlli123汉字";
      const baseFonts = ["monospace", "sans-serif", "serif"];
      const baseWidths = baseFonts.map((f) => { ctx.font = `48px ${f}`; return ctx.measureText(text).width; });
      const matched = [];
      for (const font of candidates) {
        let hit = false;
        for (let i = 0; i < baseFonts.length; i++) {
          ctx.font = `48px '${font}', ${baseFonts[i]}`;
          if (Math.abs(ctx.measureText(text).width - baseWidths[i]) > 0.2) { hit = true; break; }
        }
        if (hit) matched.push(font);
      }
      return {
        count: matched.length,
        hash: fnv1a(matched.join(",")),
        sample: matched.length ? `${matched.length} 项 (${matched.slice(0, 4).join(", ")}${matched.length > 4 ? "…" : ""})` : "0 项",
      };
    } catch {
      return { count: 0, hash: "—", sample: "受限" };
    }
  },
  async detectMediaDevices() {
    try {
      if (!navigator.mediaDevices || typeof navigator.mediaDevices.enumerateDevices !== "function") return "未开放";
      const list = await navigator.mediaDevices.enumerateDevices();
      let mic = 0; let spk = 0; let cam = 0;
      for (const d of list) {
        if (d.kind === "audioinput") mic++;
        else if (d.kind === "audiooutput") spk++;
        else if (d.kind === "videoinput") cam++;
      }
      return `麦克风 ${mic} · 扬声器 ${spk} · 摄像头 ${cam}`;
    } catch { return "已限制"; }
  },
  async detectOsAndBrowser() {
    const ua = navigator.userAgent || "";
    let os = navigator.platform || "未知";
    let browser = "";
    try {
      const uad = navigator.userAgentData;
      if (uad && typeof uad.getHighEntropyValues === "function") {
        const hi = await uad.getHighEntropyValues(["platform", "platformVersion", "architecture", "bitness", "fullVersionList", "model"]);
        const plat = hi.platform || uad.platform || "";
        const major = parseInt(String(hi.platformVersion || "0").split(".")[0], 10);
        const arch = [hi.architecture, hi.bitness ? `${hi.bitness}-bit` : ""].filter(Boolean).join(" ");
        if (plat === "Windows") {
          const winVer = Number.isFinite(major) && major >= 13 ? "Windows 11" : major >= 1 ? "Windows 10" : "Windows";
          os = arch ? `${winVer} (${arch})` : winVer;
        } else if (plat) {
          const ver = hi.platformVersion ? ` ${hi.platformVersion}` : "";
          os = `${plat}${ver}${arch ? ` (${arch})` : ""}${hi.model ? ` · ${hi.model}` : ""}`;
        }
        const list = Array.isArray(hi.fullVersionList) ? hi.fullVersionList : (Array.isArray(uad.brands) ? uad.brands : []);
        const cleanBrands = list.filter((b) => b.brand && !/not.?a/i.test(b.brand));
        const preferred = cleanBrands.find((b) => /Edge|Chrome|Opera|Brave|Vivaldi/i.test(b.brand)) || cleanBrands[0];
        if (preferred) browser = `${preferred.brand} ${preferred.version}`;
      }
    } catch { /* fallback below */ }

    if (os === "Win32" || os === "Win64") os = "Windows (64-bit)";
    else if (/MacIntel/i.test(os)) os = "macOS";
    if (!browser) {
      const m = ua.match(/(Edg|Chrome|Firefox|Safari)\/([\d.]+)/);
      browser = m ? `${m[1] === "Edg" ? "Edge" : m[1]} ${m[2]}` : "标准浏览器";
    }
    return { os, browser };
  },
  getScreenInfo() {
    const rawDpr = Number(window.devicePixelRatio || 1);
    const dpr = Math.round(rawDpr * 100) / 100;
    const sw = screen.width;
    const sh = screen.height;
    const estW = Math.round(sw * rawDpr);
    const estH = Math.round(sh * rawDpr);
    const vp = `${window.innerWidth}×${window.innerHeight}`;
    const main = `${sw}×${sh} (DPR ${dpr} · ${screen.colorDepth}bit)`;
    const detail = `逻辑 ${sw}×${sh} · 物理估算 ${estW}×${estH} · 视口 ${vp} · DPR ${dpr}`;
    return { main, detail };
  },
  getHardwareInfo() {
    const cores = navigator.hardwareConcurrency ? `${navigator.hardwareConcurrency} 逻辑核` : "未知";
    const dm = navigator.deviceMemory;
    // W3C 隐私规范：deviceMemory 最大只上报 8（16GB/32GB 均报 8）
    const mem = dm ? (dm >= 8 ? "≥ 8 GB" : `${dm} GB`) : "未公开";
    return `${cores} / ${mem}`;
  },
  async waitForFingerprintJs(timeoutMs = 2600) {
    const start = Date.now();
    while (Date.now() - start < timeoutMs) {
      if (window.FingerprintJS && typeof window.FingerprintJS.load === "function") return window.FingerprintJS;
      await new Promise((r) => setTimeout(r, 120));
    }
    return null;
  },
  async getFingerprintJsId(fallbackSeed) {
    try {
      const lib = await this.waitForFingerprintJs();
      if (lib) {
        const agent = await lib.load();
        const res = await agent.get();
        if (res && res.visitorId) return res.visitorId;
      }
    } catch { /* fallback */ }
    return hashHex32(fallbackSeed);
  },
  async collect(force = false) {
    if (state.fp && !force) return state.fp;
    if (this._collecting && !force) return this._collecting;

    this._collecting = (async () => {
      const canvas = this.getCanvas();
      const webgl = this.getWebGL();
      const fonts = this.detectFonts();
      const screenInfo = this.getScreenInfo();
      const hwStr = this.getHardwareInfo();
      const [audio, media, sys] = await Promise.all([
        this.getAudio(),
        this.detectMediaDevices(),
        this.detectOsAndBrowser(),
      ]);

      const tz = (() => { try { return Intl.DateTimeFormat().resolvedOptions().timeZone || "未知"; } catch { return "未知"; } })();
      const langs = (navigator.languages?.length ? [...navigator.languages] : [navigator.language || ""]).filter(Boolean);
      const ua = navigator.userAgent || "";
      const webdriver = navigator.webdriver === true;
      const headless = [];
      if (/HeadlessChrome|PhantomJS|Playwright|Puppeteer|Selenium/i.test(ua)) headless.push("UA 无头特征");
      if (webdriver) headless.push("webdriver=true");
      if (/SwiftShader|llvmpipe/i.test(webgl.renderer)) headless.push("软件渲染 GPU");

      const seed = [canvas, audio, webgl.hash, fonts.hash, screenInfo.main, sys.os, tz, langs.join(",")].join("|");
      const id = await this.getFingerprintJsId(seed);

      const fp = {
        id,
        canvas,
        audio,
        fonts,
        media,
        os: sys.os,
        browser: sys.browser,
        webglVendor: webgl.vendor,
        webglRenderer: webgl.renderer,
        webglHash: webgl.hash,
        tz,
        langs,
        screenMain: screenInfo.main,
        screenDetail: screenInfo.detail,
        hwStr,
        touch: navigator.maxTouchPoints ?? 0,
        cookies: navigator.cookieEnabled ? "开启" : "禁用",
        dnt: navigator.doNotTrack === "1" ? "开启" : "未开启",
        webdriver,
        headless,
        ua,
      };
      state.fp = fp;
      return fp;
    })().finally(() => { this._collecting = null; });

    return this._collecting;
  },
  async quickWebRtc(httpIp) {
    return new Promise((resolve) => {
      if (typeof RTCPeerConnection === "undefined") { resolve({ text: "未检测到 WebRTC 泄露", leak: false }); return; }
      let pc;
      try { pc = new RTCPeerConnection({ iceServers: [{ urls: "stun:stun.cloudflare.com:3478" }] }); }
      catch { resolve({ text: "未检测到 WebRTC 泄露", leak: false }); return; }
      const ips = new Set(); let done = false;
      const finish = () => {
        if (done) return; done = true;
        try { pc.close(); } catch {}
        const list = [...ips];
        if (!list.length) resolve({ text: "未检测到 WebRTC 泄露", leak: false });
        else if (httpIp && list.some((x) => x !== httpIp)) resolve({ text: `WebRTC 泄露：${list.join(", ")}`, leak: true });
        else resolve({ text: `与出口一致 (${list[0]})`, leak: false });
      };
      try { pc.createDataChannel("p"); } catch {}
      pc.onicecandidate = (e) => {
        if (!e.candidate) { finish(); return; }
        const p = e.candidate.candidate.split(" ");
        if (p[7] === "srflx" && p[4] && !isPrivateIp(p[4])) ips.add(p[4]);
      };
      pc.createOffer().then((o) => pc.setLocalDescription(o)).catch(finish);
      setTimeout(finish, 2400);
    });
  },
  async evaluateWithReport(r) {
    const [fp, rtcRes] = await Promise.all([
      this.collect(),
      this.quickWebRtc(r?.ip || ""),
    ]);

    $("r-webrtc-brief").innerHTML = rtcRes.leak
      ? `<span class="pill red">${esc(rtcRes.text)}</span>`
      : `<span class="pill green">${esc(rtcRes.text)}</span>`;

    $("r-fp-id").textContent = fp.id;
    $("r-fp-canvas").textContent = fp.canvas;
    $("r-fp-webgl").textContent = fp.webglRenderer;
    $("r-fp-audio").textContent = fp.audio;
    if ($("r-fp-os")) $("r-fp-os").textContent = `${fp.os} · ${fp.browser}`;
    $("r-fp-screen").textContent = fp.screenMain;
    $("r-fp-hw").textContent = fp.hwStr;
    $("r-fp-tz").textContent = `${fp.tz} · ${fp.langs[0] || "—"}`;
    $("r-fp-bot").innerHTML = fp.headless.length
      ? `<span class="pill red">${esc(fp.headless.join(" / "))}</span>`
      : `<span class="pill green">正常真人浏览器</span>`;

    const isRadar = r?.humanRatio?.source === "cloudflare-radar";
    const human = typeof r?.humanRatio?.human === "number" ? r.humanRatio.human : 50;
    const bot = typeof r?.humanRatio?.bot === "number" ? r.humanRatio.bot : Number((100 - human).toFixed(2));
    $("hb-human-bar").style.width = `${human}%`;
    $("hb-bot-bar").style.width = `${bot}%`;
    $("hb-human-pct").textContent = isRadar ? `${human.toFixed(2)}%` : `${Math.round(human)}%`;
    $("hb-bot-pct").textContent = isRadar ? `${bot.toFixed(2)}%` : `${Math.round(bot)}%`;
    const srcEl = $("hb-source");
    if (srcEl) {
      srcEl.hidden = false;
      srcEl.textContent = isRadar ? "Cloudflare Radar" : "估算";
    }

    const ipTz = r?.location?.timezone || "";
    const ipCC = (r?.location?.countryCode || "").toUpperCase();
    const tzOk = !ipTz || ipTz.toLowerCase() === fp.tz.toLowerCase();
    const langAllow = COUNTRY_LANG[ipCC] || [];
    const primaryLang = (fp.langs[0] || "").toLowerCase();
    const langOk = !langAllow.length || langAllow.some((p) => primaryLang.startsWith(p));

    const warnings = [];
    if (fp.webdriver) warnings.push("WebDriver 自动化");
    if (fp.headless.length && !fp.webdriver) warnings.push(fp.headless[0]);
    if (rtcRes.leak) warnings.push("WebRTC 泄露");
    if (!tzOk) warnings.push("时区偏差");
    if (!langOk) warnings.push("语言不符");

    const rows = [
      ["时区", ipTz || "—", fp.tz, tzOk ? ["green", "一致"] : ["amber", "偏差"]],
      ["语言", ipCC || "—", fp.langs[0] || "—", langOk ? ["green", "匹配"] : ["amber", "不符"]],
      ["WebRTC", r?.ip || "—", rtcRes.leak ? "泄露" : "无泄露", rtcRes.leak ? ["red", "泄露"] : ["green", "安全"]],
      ["自动化", r?.signals?.find((s) => s.key === "abuse")?.detected ? "风险" : "无记录", fp.headless.length ? fp.headless[0] : "正常", fp.headless.length ? ["red", "异常"] : ["green", "真人"]],
    ];
    $("hb-table-body").innerHTML = rows.map(([k, a, b, [cls, st]]) =>
      `<tr><td>${esc(k)}</td><td class="mono">${esc(a)}</td><td class="mono">${esc(b)}</td><td><span class="pill ${cls}">${esc(st)}</span></td></tr>`
    ).join("");

    state.clientEnv = { humanScore: human, warnings };
    this.renderPage();
  },
  async renderPage(force = false) {
    const fp = await this.collect(force);
    const score = fp.webdriver ? 35 : fp.headless.length ? 60 : (state.clientEnv?.warnings?.includes("WebRTC 泄露") ? 72 : 96);
    $("fp-page-id").textContent = fp.id;
    const pill = $("fp-page-score");
    pill.textContent = `环境健康度 ${score}%`;
    pill.className = `fp-score-pill ${score >= 85 ? "" : score >= 60 ? "warn" : "bad"}`;
    $("fp-page-verdict").textContent = fp.headless.length
      ? `检测到自动化特征：${fp.headless.join(" · ")}`
      : "未检测到自动化脚本特征，浏览器指纹环境自然一致。";

    const mkRows = (list) => list.map(([k, v]) =>
      `<div class="kv-row"><div class="kv-k">${esc(k)}</div><div class="kv-v mono">${esc(v)}</div></div>`
    ).join("");

    $("fp-page-core").innerHTML = mkRows([
      ["FingerprintJS ID", fp.id],
      ["Canvas 哈希", fp.canvas],
      ["WebGL 哈希", fp.webglHash],
      ["Audio 音频哈希", fp.audio],
      ["字体集合哈希", `${fp.fonts.hash} · ${fp.fonts.sample}`],
      ["WebDriver", fp.webdriver ? "true（检测到自动化）" : "false（正常）"],
      ["无头浏览器特征", fp.headless.length ? fp.headless.join(" / ") : "未检测到"],
    ]);

    $("fp-page-hardware").innerHTML = mkRows([
      ["操作系统", fp.os],
      ["浏览器版本", fp.browser],
      ["GPU 厂商", fp.webglVendor],
      ["GPU 渲染器", fp.webglRenderer],
      ["屏幕与缩放", fp.screenDetail],
      ["处理器 / 内存", fp.hwStr],
      ["触控支持", fp.touch > 0 ? `${fp.touch} 点触控` : "无触控屏"],
      ["媒体设备", fp.media],
    ]);

    const conn = state.current?.connection;
    const envRows = [
      ["系统时区", fp.tz],
      ["浏览器语言", fp.langs.join(", ") || "—"],
      ["Cookie / DNT", `${fp.cookies} / ${fp.dnt}`],
    ];
    if (conn && (conn.httpProtocol || conn.tlsVersion)) {
      envRows.push(["连接协议", `${conn.httpProtocol || "—"} · ${conn.tlsVersion || "—"}`]);
      if (conn.tlsCipher) envRows.push(["TLS 加密套件", conn.tlsCipher]);
      if (conn.colo) envRows.push(["接入边缘节点", conn.colo]);
    }
    envRows.push(["User-Agent", fp.ua]);
    $("fp-page-env").innerHTML = mkRows(envRows);
  },
};

/* ================= Real Geo Street Address ================= */
async function loadGeoAddress(loc, jitter = false) {
  if (!loc || loc.lat == null || loc.lon == null) {
    $("ga-source").textContent = "无坐标";
    $("ga-street").textContent = "—";
    $("ga-city").textContent = loc?.city || "—";
    $("ga-state").textContent = loc?.region || "—";
    $("ga-country").textContent = countryName(loc?.countryCode, loc?.country);
    $("ga-zip").textContent = loc?.zip || "—";
    $("ga-tz").textContent = loc?.timezone || "—";
    state.geoAddr = null;
    return;
  }

  $("ga-refresh").disabled = true;
  $("ga-street").textContent = "反查中…";

  try {
    const qs = new URLSearchParams({
      action: "geoaddr",
      lat: String(loc.lat),
      lon: String(loc.lon),
      tz: loc.timezone || "",
      jitter: jitter ? "1" : "0",
    });
    const res = await fetchTimeout(`${API}?${qs.toString()}`, 8000);
    const d = await res.json();
    if (!res.ok || !d.ok) throw new Error();

    const addr = {
      street: d.street && d.street !== "—" ? d.street : (loc.city ? `${loc.city} Center` : "—"),
      city: d.city && d.city !== "—" ? d.city : (loc.city || "—"),
      state: d.state && d.state !== "—" ? d.state : (loc.region || "—"),
      country: d.country && d.country !== "—" ? countryName(d.countryCode || loc.countryCode, d.country) : countryName(loc.countryCode, loc.country),
      zip: d.postcode && d.postcode !== "—" ? d.postcode : (loc.zip || "—"),
      tz: d.timezone && d.timezone !== "—" ? d.timezone : (loc.timezone || "—"),
      source: d.source || "OSM",
    };
    state.geoAddr = addr;
    $("ga-source").textContent = addr.source;
    $("ga-street").textContent = addr.street;
    $("ga-city").textContent = addr.city;
    $("ga-state").textContent = addr.state;
    $("ga-country").textContent = addr.country;
    $("ga-zip").textContent = addr.zip;
    $("ga-tz").textContent = addr.tz;
    if (jitter) toast("已切换同区真实街道地址");
  } catch {
    const fallback = {
      street: "暂未获取到具体街道",
      city: loc.city || "—",
      state: loc.region || "—",
      country: countryName(loc.countryCode, loc.country),
      zip: loc.zip || "—",
      tz: loc.timezone || "—",
      source: "IP 基础库",
    };
    state.geoAddr = fallback;
    $("ga-source").textContent = fallback.source;
    $("ga-street").textContent = fallback.street;
    $("ga-city").textContent = fallback.city;
    $("ga-state").textContent = fallback.state;
    $("ga-country").textContent = fallback.country;
    $("ga-zip").textContent = fallback.zip;
    $("ga-tz").textContent = fallback.tz;
  } finally {
    $("ga-refresh").disabled = false;
  }
}

/* ================= Colorful Map + Glowing Pin + Floating Tooltip ================= */
function renderMap(r) {
  const loc = r.location;
  const has = loc.lat != null && loc.lon != null;
  const openBtn = $("map-open");
  const fb = $("map-fallback");
  $("r-coords-pill").textContent = has ? `${loc.lat.toFixed(4)}, ${loc.lon.toFixed(4)}` : "—";

  if (has) {
    openBtn.hidden = false;
    openBtn.href = loc.countryCode === "CN"
      ? `https://uri.amap.com/marker?position=${loc.lon},${loc.lat}&name=${encodeURIComponent(r.ip)}&src=ipspot&callnative=0`
      : `https://www.google.com/maps?q=${loc.lat},${loc.lon}`;
  } else openBtn.hidden = true;

  if (!has || typeof L === "undefined") {
    fb.hidden = false;
    $("map-fallback-text").textContent = "暂无可用坐标";
    if (state.map) { state.map.remove(); state.map = null; state.marker = null; }
    return;
  }
  fb.hidden = true;

  if (!state.map) {
    state.map = L.map("map", { scrollWheelZoom: false }).setView([loc.lat, loc.lon], 11);
    L.tileLayer("https://server.arcgisonline.com/ArcGIS/rest/services/World_Street_Map/MapServer/tile/{z}/{y}/{x}", {
      attribution: "Tiles &copy; Esri",
      maxZoom: 17,
    }).addTo(state.map);
  } else {
    state.map.setView([loc.lat, loc.lon], 11);
  }

  if (state.marker) state.marker.remove();
  state.marker = L.marker([loc.lat, loc.lon], {
    icon: L.divIcon({ className: "map-pin", iconSize: [20, 20], iconAnchor: [10, 10] }),
  }).addTo(state.map);

  const tip = document.createElement("div"); tip.className = "map-tip-inner";
  const row = document.createElement("div"); row.className = "map-tip-row";
  if (loc.countryCode && /^[A-Z]{2}$/.test(loc.countryCode)) {
    const img = document.createElement("img");
    img.src = `https://flagcdn.com/w40/${loc.countryCode.toLowerCase()}.png`;
    img.alt = loc.countryCode;
    row.appendChild(img);
  }
  const ipEl = document.createElement("strong"); ipEl.textContent = r.ip;
  row.appendChild(ipEl);
  const place = document.createElement("span"); place.className = "map-tip-place";
  place.textContent = [loc.city, loc.region, countryName(loc.countryCode, loc.country)].filter(Boolean).join(" · ") || "目标位置";
  tip.append(row, place);

  state.marker.bindTooltip(tip, {
    permanent: true,
    direction: "top",
    offset: [0, -14],
    className: "map-tip",
    opacity: 1,
  }).openTooltip();

  setTimeout(() => { if (state.map) state.map.invalidateSize(); }, 250);
}

/* ================= Render Main Report ================= */
function renderSignals(signals) {
  const raw = Array.isArray(signals) ? signals : [];
  const byKey = new Map(raw.map((s) => [s.key, s]));
  const list = SIGNAL_ORDER.map((k) => byKey.get(k)).filter(Boolean);
  const finalList = list.length === 6 ? list : raw.slice(0, 6);

  $("signals-count").textContent = `${finalList.length} 项检测`;
  $("signals-grid").innerHTML = finalList.map((s) => `
    <div class="signal ${s.detected ? "hit" : "clean"}">
      <div class="signal-icon">${SIGNAL_ICONS[s.key] || SIGNAL_ICONS.abuse}</div>
      <div class="signal-body">
        <div class="signal-top">
          <span class="signal-name">${esc(s.label)}</span>
          <span class="signal-state">${s.detected ? "检测到" : "未检测到"}</span>
        </div>
        <p class="signal-desc">${esc(s.desc)}</p>
      </div>
    </div>
  `).join("");
}

function renderMultiGeo(r) {
  const list = r.location.multiSource || [];
  const box = $("r-geo-list");
  const moreBtn = $("btn-geo-more");
  const limit = 3;

  if (!list.length) {
    box.innerHTML = `<div class="geo-line"><span>${esc(countryName(r.location.countryCode, r.location.country))}</span></div>`;
    moreBtn.hidden = true;
    return;
  }

  box.innerHTML = list.map((g, idx) => {
    const place = [countryShort(g.countryCode, g.country), g.region, g.city].filter(Boolean).join(", ");
    const extraAttr = idx >= limit ? ' class="geo-line geo-extra" hidden' : ' class="geo-line"';
    return `<div${extraAttr}><span class="geo-src">${esc(g.source)}</span><span class="geo-place">${flagHtml(g.countryCode)}<span>${esc(place)}</span></span></div>`;
  }).join("");

  if (list.length > limit) {
    const extraCount = list.length - limit;
    moreBtn.hidden = false;
    moreBtn.dataset.expanded = "0";
    moreBtn.textContent = `展开更多 (${extraCount}) ▾`;
  } else {
    moreBtn.hidden = true;
  }
}

function renderReport(r) {
  state.current = r;
  state.aiLoadedForIp = null;
  $("report").hidden = false;
  updateSeoTitle("query", r);

  $("r-flag").innerHTML = flagHtml(r.location.countryCode, 80) || "🌐";
  $("r-ip").textContent = r.ip;
  $("search-input").value = r.queriedDomain || r.ip;
  if (r.queriedDomain) { $("r-domain").hidden = false; $("r-domain").textContent = r.queriedDomain; }
  else $("r-domain").hidden = true;

  const geoSummary = [r.location.city, r.location.region, countryName(r.location.countryCode, r.location.country), r.company.name || r.network.org]
    .filter((x) => x && x !== "—").join(" · ");
  $("r-geo-isp").textContent = geoSummary || "—";

  const tagBox = $("r-asset-tags");
  if (tagBox) {
    const tags = r.exposure?.tags || [];
    if (tags.length) {
      tagBox.hidden = false;
      tagBox.innerHTML = tags.map((t) => {
        const danger = /^(compromised|malware|botnet|tor|proxy|cve:)/i.test(t);
        return `<span class="asset-tag ${danger ? "warn" : ""}">${esc(t)}</span>`;
      }).join("");
    } else {
      tagBox.hidden = true;
      tagBox.innerHTML = "";
    }
  }

  $("r-version").textContent = `IPv${r.version}`;
  const nb = $("r-native-badge");
  nb.textContent = r.location.geoTypeLabel || "未知来源";
  nb.className = `badge ${r.location.isNative === true ? "green" : r.location.isNative === false ? "amber" : ""}`;

  const tb = $("r-type-badge");
  tb.textContent = r.type.residential ? "家宽 IP" : `非家宽 · ${r.type.label}`;
  tb.className = `badge ${r.type.residential ? "green" : r.type.code === "datacenter" ? "amber" : "blue"}`;

  const rb = $("r-risk-badge");
  rb.textContent = r.scores.riskLevel;
  rb.className = `badge ${(r.scores.riskCode === "minimal" || r.scores.riskCode === "low") ? "green" : r.scores.riskCode === "medium" ? "amber" : "red"}`;

  $("r-asn-org").textContent = [r.network.asn, r.company.name || r.network.org].filter(Boolean).join(" · ") || "—";
  $("r-company-brief").textContent = [r.company.domain, r.company.typeLabel, r.network.route].filter((x) => x && x !== "未标注").join(" · ") || "—";
  $("r-company-name").textContent = r.company.name || "—";
  $("r-company-type").textContent = r.company.typeLabel || "—";
  $("r-company-domain").innerHTML = r.company.domain
    ? `<a href="https://${esc(r.company.domain)}" target="_blank" rel="noopener noreferrer">${esc(r.company.domain)}</a>` : "—";
  $("r-route").textContent = r.network.route || "—";
  $("r-rdns").textContent = r.network.rdns || "—";
  $("r-netname").textContent = [r.company.netName, r.company.rir].filter(Boolean).join(" · ") || "—";
  $("r-abuse").textContent = [r.company.abuserScore, r.company.abuseEmail].filter(Boolean).join(" · ") || "—";
  if ($("r-ports")) {
    const ports = r.exposure?.ports || [];
    $("r-ports").textContent = ports.length ? ports.join(", ") : "无公开记录";
  }

  $("r-range").textContent = r.network.ipRange || r.network.route || "—";
  if (r.ipNumeric && r.ipNumeric !== "—") {
    $("r-numeric-wrap").hidden = false;
    $("r-numeric").textContent = r.ipNumeric;
  } else $("r-numeric-wrap").hidden = true;

  const srcPill = $("r-ip-source");
  srcPill.textContent = r.location.geoTypeLabel || "未知来源";
  srcPill.className = `pill ${r.location.isNative === true ? "green" : r.location.isNative === false ? "red" : ""}`;

  const attrPill = $("r-ip-attr");
  attrPill.textContent = r.type.label;
  attrPill.className = `pill ${r.type.residential ? "green" : r.type.code === "datacenter" ? "red" : "amber"}`;

  renderMultiGeo(r);

  const fraud = r.scores.fraud;
  const pin = $("fraud-marker");
  pin.style.left = `${Math.max(2, Math.min(98, fraud))}%`;
  pin.classList.toggle("edge-left", fraud <= 15);
  pin.classList.toggle("edge-right", fraud >= 85);

  const bubble = $("fraud-marker-tip");
  bubble.textContent = `${fraud}% ${r.scores.riskLevel}`;
  bubble.className = `risk-bubble ${fraud <= 30 ? "" : fraud <= 50 ? "amber" : "red"}`;
  if ($("r-ip-score")) {
    $("r-ip-score").innerHTML = `综合纯净分：<b>${r.scores.trust} / 100</b>`;
  }
  $("r-breakdown").innerHTML = (r.scores.breakdown || []).map((b) =>
    `<li><span>${esc(b.label)}（${esc(b.reason)}）</span><b>+${b.delta}%</b></li>`
  ).join("") || "<li><span>基线纯净</span><b>+0%</b></li>";

  $("ai-expand").hidden = true;
  $("ai-provider").hidden = true;
  $("ai-content").innerHTML = "";
  $("ai-run").disabled = false;
  $("ai-run").textContent = "✦ 生成 AI 诊断";

  renderSignals(r.signals);

  const regBody = $("r-reg-history");
  if (r.registryHistory?.length) {
    regBody.innerHTML = r.registryHistory.map((row, idx) => `
      <tr>
        <td class="mono"><i class="dot-ind ${idx > 0 ? "old" : ""}"></i>${esc(row.cidr)}</td>
        <td class="mono">${esc(row.rir)}</td>
        <td><span class="flag-cell">${flagHtml(row.countryCode)}${esc(countryShort(row.countryCode))}</span></td>
        <td class="mono">${esc(row.firstSeen)}</td>
        <td class="mono">${esc(row.lastSeen)}</td>
      </tr>
    `).join("");
  } else {
    regBody.innerHTML = `<tr><td colspan="5" class="empty-td">注册局暂无历史变更记录</td></tr>`;
  }

  const bgpBody = $("r-bgp-history");
  if (r.bgpHistory?.length) {
    bgpBody.innerHTML = r.bgpHistory.map((row) => `
      <tr>
        <td class="mono">${esc(row.cidr)}</td>
        <td class="mono">${esc(row.asn)}</td>
        <td class="mono">${esc(row.firstSeen)}</td>
        <td class="mono">${esc(row.lastSeen)}</td>
      </tr>
    `).join("");
  } else {
    bgpBody.innerHTML = `<tr><td colspan="4" class="empty-td">暂无 BGP 历史记录</td></tr>`;
  }

  renderMap(r);
  loadGeoAddress(r.location, false);
  fpEngine.evaluateWithReport(r);
}

/* ================= AI Analysis ================= */
function mdListToHtml(md) {
  const lines = esc(md).split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
  const bold = (s) => s.replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>");
  return `<ul>${lines.map((l) => `<li>${bold(l.replace(/^[-*•\d.]+\s*/, ""))}</li>`).join("")}</ul>`;
}
async function runAiDeep() {
  if (!state.current) return;
  if (state.aiLoadedForIp === state.current.ip && $("ai-content").innerHTML) {
    const nextHidden = !$("ai-expand").hidden;
    $("ai-expand").hidden = nextHidden;
    $("ai-run").textContent = nextHidden ? "✦ 查看 AI 诊断" : "收起 AI 诊断";
    return;
  }

  $("ai-expand").hidden = false;
  $("ai-loading").hidden = false;
  $("ai-content").innerHTML = "";
  $("ai-run").disabled = true;
  try {
    const res = await fetchTimeout(`${API}?action=ai`, 16000, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ ip: state.current.ip, clientEnv: state.clientEnv }),
    });
    const d = await res.json();
    if (!res.ok || !d.ok) throw new Error(d.message || "分析失败");
    state.aiLoadedForIp = state.current.ip;
    $("ai-provider").hidden = false;
    $("ai-provider").textContent = `${d.provider}${d.cached ? " · 缓存" : ""}`;
    $("ai-content").innerHTML = mdListToHtml(d.text || "");
    $("ai-run").textContent = "收起 AI 诊断";
  } catch (e) {
    $("ai-content").textContent = e.message || "AI 暂不可用";
    $("ai-run").textContent = "✦ 重试 AI 诊断";
  } finally {
    $("ai-loading").hidden = true;
    $("ai-run").disabled = false;
  }
}

/* ================= Dual Stack Exit & Site Latency ================= */
const PING_SITES = [
  { name: "百度", url: "https://www.baidu.com/favicon.ico" },
  { name: "Cloudflare", url: "https://www.cloudflare.com/favicon.ico" },
  { name: "GitHub", url: "https://github.com/favicon.ico" },
  { name: "Google", url: "https://www.google.com/favicon.ico" },
  { name: "ChatGPT", url: "https://chatgpt.com/favicon.ico" },
  { name: "YouTube", url: "https://www.youtube.com/favicon.ico" },
];
async function runLatency() {
  state.pingRan = true;
  $("latency-grid").innerHTML = PING_SITES.map((s, i) =>
    `<div class="ping-cell"><span>${esc(s.name)}</span><span class="ping-ms" id="pm-${i}">…</span></div>`
  ).join("");
  await Promise.all(PING_SITES.map(async (s, i) => {
    const t0 = performance.now();
    const el = $(`pm-${i}`);
    try {
      await fetchTimeout(`${s.url}?_=${Date.now()}`, 4000, { mode: "no-cors", cache: "no-store" });
      const ms = Math.round(performance.now() - t0);
      el.textContent = `${ms}ms`;
      el.className = `ping-ms ${ms < 250 ? "fast" : ms < 700 ? "mid" : "slow"}`;
    } catch {
      el.textContent = "超时";
      el.className = "ping-ms slow";
    }
  }));
}

const exit = {
  started: false, running: false, _own: null,
  V4: [["https://ipv4.icanhazip.com", true], ["https://v4.ident.me", true], ["https://api.ipify.org?format=json", false]],
  V6: [["https://ipv6.icanhazip.com", true], ["https://v6.ident.me", true], ["https://api6.ipify.org?format=json", false]],
  async probe(list, wantV6) {
    const one = async ([url, txt]) => {
      const res = await fetchTimeout(url, 3800);
      const ip = txt ? (await res.text()).trim() : ((await res.json()).ip || "").trim();
      if (!ip || !isIpFormat(ip) || wantV6 !== ip.includes(":") || isPrivateIp(ip)) throw new Error();
      return ip;
    };
    try { return await Promise.any(list.map(one)); } catch { return null; }
  },
  prefill(r) {
    if (!r?.ip) return;
    const fam = r.version === 6 ? "v6" : "v4";
    const sub = [countryShort(r.location.countryCode), r.location.city, r.network.asn].filter(Boolean).join(" · ");
    this._own = { fam, ip: r.ip, sub };
    this.set(fam, r.ip, sub);
  },
  set(fam, ip, sub) {
    const ipEl = $(`exit-${fam}-ip`);
    if (ip) { ipEl.textContent = ip; ipEl.classList.remove("none"); $(`exit-${fam}-geo`).textContent = sub || "—"; }
    else { ipEl.textContent = "无公网出口"; ipEl.classList.add("none"); $(`exit-${fam}-geo`).textContent = "未分配"; }
  },
  async geo(ip) {
    try {
      const r = await (await fetchTimeout(`${API}?q=${encodeURIComponent(ip)}`, 9000)).json();
      if (r.ok) return [countryShort(r.location.countryCode), r.location.city, r.network.asn].filter(Boolean).join(" · ");
    } catch {}
    return "";
  },
  async run() {
    if (this.running) return;
    this.running = true; this.started = true;
    const [p4, p6] = await Promise.all([this.probe(this.V4, false), this.probe(this.V6, true)]);
    const v4 = p4 || (this._own?.fam === "v4" ? this._own.ip : null);
    const v6 = p6 || (this._own?.fam === "v6" ? this._own.ip : null);
    this.set("v4", v4, this._own?.fam === "v4" ? this._own.sub : "");
    this.set("v6", v6, this._own?.fam === "v6" ? this._own.sub : "");
    const [g4, g6] = await Promise.all([v4 ? this.geo(v4) : "", v6 ? this.geo(v6) : ""]);
    this.set("v4", v4, g4 || (this._own?.fam === "v4" ? this._own.sub : ""));
    this.set("v6", v6, g6 || (this._own?.fam === "v6" ? this._own.sub : ""));
    this.running = false;
  },
};

/* ================= Core Query ================= */
async function fetchReport(q) {
  const url = q ? `${API}?q=${encodeURIComponent(q)}` : API;
  const res = await fetch(url, state.controller ? { signal: state.controller.signal } : {});
  let d = null; try { d = await res.json(); } catch {}
  if (!res.ok || !d || d.ok !== true) { const e = new Error(d?.message || "查询失败"); e.code = d?.error; throw e; }
  return d;
}
async function browserIp() {
  const v4 = [{ url: "https://ipv4.icanhazip.com", txt: true }, { url: "https://api.ipify.org?format=json", pick: (d) => d.ip }];
  try {
    return await Promise.any(v4.map(async (s) => {
      const res = await fetchTimeout(s.url, 3800);
      const ip = (s.txt ? await res.text() : s.pick(await res.json()) || "").trim();
      if (!isIpFormat(ip) || ip.includes(":")) throw new Error();
      return ip;
    }));
  } catch {}
  try {
    const ip = ((await (await fetchTimeout("https://api6.ipify.org?format=json", 3800)).json()).ip || "").trim();
    if (isIpFormat(ip)) return ip;
  } catch {}
  return null;
}
async function detectOwnIp() {
  try { return await fetchReport(null); }
  catch (e) {
    if (e.code === "ip_unavailable") {
      const ip = await browserIp();
      if (ip) return await fetchReport(ip);
      throw new Error("无法自动识别本机 IP，请手动输入查询");
    }
    throw e;
  }
}
async function ownReport() { if (!state.own) state.own = await detectOwnIp(); return state.own; }

async function query(target) {
  const seq = ++state.reqSeq; state.queryStarted = true;
  if (state.controller) state.controller.abort();
  state.controller = new AbortController();
  state.lastQuery = target || null;

  let showedCache = false;
  if (target) {
    $("search-input").value = target;
    $("loading").hidden = false; $("error").hidden = true;
  } else {
    const cached = readOwnCache();
    if (cached) { showedCache = true; state.own = cached; $("error").hidden = true; renderReport(cached); }
    else { $("loading").hidden = false; $("error").hidden = true; }
  }

  try {
    const report = target ? await fetchReport(target) : await detectOwnIp();
    if (seq !== state.reqSeq) return;
    if (!target) { state.own = report; writeOwnCache(report); exit.prefill(report); }
    $("loading").hidden = true;
    renderReport(report);
    pushHistory(report.queriedDomain || report.ip);
    try {
      if (target) history.replaceState(null, "", `#ip=${encodeURIComponent(report.queriedDomain || report.ip)}`);
      else history.replaceState(null, "", location.pathname + location.search);
    } catch {}
  } catch (e) {
    if (seq !== state.reqSeq || e.name === "AbortError") return;
    $("loading").hidden = true;
    if (showedCache) { toast("刷新失败，已显示缓存"); return; }
    $("report").hidden = true; $("error").hidden = false; $("error-msg").textContent = e.message || "检测失败";
  }
}

/* ================= Subviews: ASN / DNS / WebRTC / API ================= */
const asn = {
  ws: null, started: false, paused: true, initialDone: false,
  rows: [], cache: new Map(), pending: new Map(), queue: [], active: 0, timer: null, poll: null,
  start() {
    if (this.started) return;
    this.started = true; this.rows = [];
    this.setConn("", "加载中…");
    fetchTimeout(`${API}?feed=bgp`, 12000).then((r) => r.json()).then((d) => {
      if (d?.ok && Array.isArray(d.rows)) this.rows = d.rows.slice(-100);
    }).catch(() => {}).finally(() => {
      this.initialDone = true; this.paused = true; $("asn-pause").textContent = "开启实时";
      this.render(); this.setConn("paused", "静态快照");
    });
  },
  setConn(cls, txt) { $("asn-conn").className = `conn-state ${cls}`; $("asn-conn-text").textContent = txt; },
  connect() {
    let ws; try { ws = new WebSocket("wss://ris-live.ripe.net/v1/ws/?client=ipspot"); } catch { this.startPoll(); return; }
    this.ws = ws;
    ws.onopen = () => { ws.send(JSON.stringify({ type: "ris_subscribe", data: { type: "UPDATE" } })); this.stopPoll(); this.setConn("live", "实时连接"); };
    ws.onmessage = (e) => {
      if (this.paused) return;
      try {
        const m = JSON.parse(e.data);
        if (m.type !== "ris_message" || m.data?.type !== "UPDATE") return;
        const path = m.data.path || []; const origin = path.length ? path[path.length - 1] : null;
        const ts = (m.data.timestamp || Date.now() / 1000) * 1000;
        for (const a of m.data.announcements || []) for (const pfx of a.prefixes || []) this.push(ts, pfx, origin, "announce");
        for (const pfx of m.data.withdrawals || []) this.push(ts, pfx, null, "withdraw");
      } catch {}
    };
    ws.onclose = () => { if (!this.paused) this.startPoll(); };
  },
  startPoll() {
    if (this.poll || this.paused) return;
    this.setConn("live", "中转刷新");
    this.poll = setInterval(async () => {
      if (this.paused) return;
      try {
        const d = await (await fetchTimeout(`${API}?feed=bgp`, 10000)).json();
        if (d?.ok && Array.isArray(d.rows)) { this.rows = d.rows.slice(-100); this.sched(); }
      } catch {}
    }, 8000);
  },
  stopPoll() { if (this.poll) { clearInterval(this.poll); this.poll = null; } },
  push(ts, pfx, origin, type) {
    this.rows.push({ ts, pfx, origin, type });
    if (this.rows.length > 100) this.rows.splice(0, this.rows.length - 100);
    if (!this.paused) this.sched();
  },
  sched() { if (!this.timer) this.timer = setTimeout(() => { this.timer = null; this.render(); }, 2500); },
  render() {
    const body = $("asn-body"); body.textContent = "";
    const sorted = [...this.rows].sort((a, b) => b.ts - a.ts);
    $("asn-count").textContent = String(sorted.length);
    if (!sorted.length) { body.innerHTML = '<tr><td colspan="6" class="empty-td">暂无数据</td></tr>'; return; }
    for (const r of sorted) {
      const tr = document.createElement("tr");
      tr.innerHTML = `<td class="mono">${esc(new Date(r.ts).toLocaleTimeString("zh-CN", { hour12: false }))}</td><td>—</td><td class="mono">${esc(r.pfx)}</td><td class="mono">${r.origin ? `AS${r.origin}` : "—"}</td><td>—</td><td><span class="pill ${r.type === "announce" ? "green" : "amber"}">${r.type === "announce" ? "公告" : "撤销"}</span></td>`;
      body.appendChild(tr);
      if (r.origin) this.enrich(r.origin, r.pfx, tr);
    }
  },
  enrich(n, pfx, tr) {
    if (this.cache.has(n)) { this.fill(tr, this.cache.get(n)); return; }
    if (this.pending.has(n)) { this.pending.get(n).push({ tr, pfx }); return; }
    this.pending.set(n, [{ tr, pfx }]);
    if (this.queue.length > 60) { const old = this.queue.shift(); this.pending.delete(old); }
    this.queue.push(n); this.pump();
  },
  pump() {
    while (this.active < 4 && this.queue.length) {
      const n = this.queue.shift(); this.active++;
      const jobs = this.pending.get(n) || [];
      fetchTimeout(`${API}?asn=${n}&pfx=${encodeURIComponent(jobs[0]?.pfx || "")}`, 10000).then((r) => r.json()).then((d) => {
        if (d?.ok) { this.cache.set(n, d); for (const j of jobs) if (j.tr.isConnected) this.fill(j.tr, d); }
      }).catch(() => {}).finally(() => { this.pending.delete(n); this.active--; this.pump(); });
    }
  },
  fill(tr, d) {
    tr.children[1].innerHTML = d.countryCode ? `<span class="flag-cell">${flagHtml(d.countryCode)}${esc(countryShort(d.countryCode, d.country))}</span>` : (d.country || "—");
    tr.children[4].textContent = d.name || "—";
  },
  toggle() {
    if (!this.initialDone) return;
    this.paused = !this.paused; $("asn-pause").textContent = this.paused ? "开启实时" : "暂停";
    if (this.paused) { this.stopPoll(); try { this.ws?.close(); } catch {} this.ws = null; this.setConn("paused", "已暂停"); }
    else { this.setConn("", "连接中…"); this.connect(); }
  },
  clear() { this.rows = []; this.render(); },
};

/* ================= DNS Leak Test ================= */
const dns = {
  started: false, running: false,
  async probeEdnsSubdomains(map, count = 6) {
    await Promise.all(Array.from({ length: count }, async () => {
      try {
        const sub = randomAlphaNum(32);
        const res = await fetchTimeout(`https://${sub}.edns.ip-api.com/json`, 8000, { cache: "no-store" });
        const d = await res.json();
        const ip = d?.dns?.ip; const geo = d?.dns?.geo || "";
        if (ip) { const e = map.get(ip) || { ip, geo, n: 0 }; e.n++; if (geo) e.geo = geo; map.set(ip, e); }
      } catch {}
    }));
  },
  async probeEdnsDirect(map, count = 5) {
    await Promise.all(Array.from({ length: count }, async (_, i) => {
      try {
        const res = await fetchTimeout(`https://edns.ip-api.com/json?_=${Date.now()}_${i}`, 8000, { cache: "no-store" });
        const d = await res.json();
        const ip = d?.dns?.ip; const geo = d?.dns?.geo || "";
        if (ip) { const e = map.get(ip) || { ip, geo, n: 0 }; e.n++; if (geo) e.geo = geo; map.set(ip, e); }
      } catch {}
    }));
  },
  async probeBashWs(map) {
    try {
      const id = 1000000 + Math.floor(Math.random() * 8999999);
      await Promise.all(Array.from({ length: 5 }, (_, k) =>
        fetchTimeout(`https://${k + 1}.${id}.bash.ws`, 3500, { mode: "no-cors", cache: "no-store" }).catch(() => null)
      ));
      await new Promise((r) => setTimeout(r, 900));
      const res = await fetchTimeout(`https://bash.ws/dnsleak/test/${id}?json`, 8000, { cache: "no-store" });
      const list = await res.json();
      if (Array.isArray(list)) {
        for (const item of list) {
          if (item?.type === "dns" && item.ip) {
            const geo = [item.country_name, item.asn].filter(Boolean).join(" - ");
            const e = map.get(item.ip) || { ip: item.ip, geo, n: 0 };
            e.n++; if (geo) e.geo = geo;
            map.set(item.ip, e);
          }
        }
      }
    } catch {}
  },
  async run() {
    if (this.running) return;
    this.running = true; this.started = true;
    $("dns-loading").hidden = false; $("dns-verdict").hidden = true; $("dns-run").disabled = true;
    $("dns-body").innerHTML = '<tr><td colspan="4" class="empty-td">正在探测递归 DNS 服务器…</td></tr>';
    $("dns-summary").textContent = "正在通过 32 位随机子域探测…";

    let exitC = ""; try { exitC = (await ownReport()).location.country; } catch {}
    const map = new Map();
    let method = "edns 32位随机子域";

    await this.probeEdnsSubdomains(map, 6);
    if (!map.size) {
      method = "edns 主端点";
      $("dns-summary").textContent = "切换备用 DNS 探测通道…";
      await this.probeEdnsDirect(map, 5);
    }
    if (!map.size) {
      method = "bash.ws 通道";
      $("dns-summary").textContent = "切换第二备用 DNS 探测通道…";
      await this.probeBashWs(map);
    }

    const rows = [...map.values()].sort((a, b) => b.n - a.n);
    $("dns-body").innerHTML = rows.length
      ? rows.map((r, i) => `<tr><td>${i + 1}</td><td class="mono">${esc(r.ip)}</td><td>${esc(r.geo || "—")}</td><td class="mono">${r.n} 次</td></tr>`).join("")
      : '<tr><td colspan="4" class="empty-td">未捕获到递归 DNS，请检查是否开启了广告拦截插件或网络限制</td></tr>';

    const countries = new Set(rows.map((r) => (r.geo || "").split(" - ")[0].trim()).filter(Boolean));
    const v = $("dns-verdict"); v.hidden = false;
    if (!rows.length) {
      v.className = "verdict-bar warn";
      $("dns-verdict-title").textContent = "未获取到解析服务器";
      $("dns-verdict-desc").textContent = "三个探测通道均被当前网络或浏览器插件拦截，请关闭拦截后重试";
    } else if (exitC && [...countries].some((c) => c.toLowerCase() !== exitC.toLowerCase())) {
      v.className = "verdict-bar bad";
      $("dns-verdict-title").textContent = "发现 DNS 泄露迹象";
      $("dns-verdict-desc").textContent = `部分解析服务器归属地（${[...countries].join("、")}）与出口国家（${exitC}）不一致`;
    } else {
      v.className = "verdict-bar good";
      $("dns-verdict-title").textContent = "未发现 DNS 泄露";
      $("dns-verdict-desc").textContent = `共捕获 ${rows.length} 台解析服务器，归属地与出口一致`;
    }
    $("dns-summary").textContent = `探测完成（通道：${method}），共捕获 ${rows.length} 台递归解析服务器。`;
    $("dns-loading").hidden = true; $("dns-run").disabled = false; this.running = false;
  },
};

const STUNS = ["stun.cloudflare.com:3478", "stun.l.google.com:19302", "stun1.l.google.com:19302", "stun.global.stun.twilio.com:3478", "stun.stunprotocol.org:3478"];
const rtc = {
  started: false, running: false, httpIp: "",
  async ensureIp() { if (!this.httpIp) { try { this.httpIp = (await ownReport()).ip; } catch {} } $("rtc-http-ip").textContent = this.httpIp || "—"; },
  probe(host) {
    return new Promise((resolve) => {
      let pc; try { pc = new RTCPeerConnection({ iceServers: [{ urls: `stun:${host}` }] }); } catch { resolve([]); return; }
      const ips = new Set(); let done = false;
      const fin = () => { if (done) return; done = true; try { pc.close(); } catch {} resolve([...ips]); };
      try { pc.createDataChannel("p"); } catch {}
      pc.onicecandidate = (e) => {
        if (!e.candidate) { fin(); return; }
        const p = e.candidate.candidate.split(" ");
        if (p[7] === "srflx" && p[4] && !isPrivateIp(p[4])) ips.add(p[4]);
      };
      pc.createOffer().then((o) => pc.setLocalDescription(o)).catch(fin);
      setTimeout(fin, 5000);
    });
  },
  async run() {
    if (this.running) return;
    this.running = true; this.started = true;
    $("rtc-run").disabled = true; $("rtc-loading").hidden = false; $("rtc-verdict").hidden = true;
    await this.ensureIp();
    $("stun-list").innerHTML = STUNS.map((h, i) => `<div class="stun-row" id="sr-${i}"><span class="mono">stun:${esc(h)}</span><span id="sv-${i}">探测中…</span></div>`).join("");
    const all = new Set();
    await Promise.all(STUNS.map(async (h, i) => {
      const ips = await this.probe(h);
      ips.forEach((x) => all.add(x));
      const leak = this.httpIp && ips.some((x) => x !== this.httpIp);
      const row = $(`sr-${i}`); const val = $(`sv-${i}`);
      if (leak) { row.classList.add("leak"); val.innerHTML = `<span class="pill red">泄露 ${esc(ips.join(", "))}</span>`; }
      else if (ips.length) val.innerHTML = `<span class="pill green">${esc(ips.join(", "))}</span>`;
      else val.innerHTML = `<span class="pill green">无公网暴露</span>`;
    }));
    const pub = [...all]; const v = $("rtc-verdict"); v.hidden = false;
    if (this.httpIp && pub.some((x) => x !== this.httpIp)) { v.className = "verdict-bar bad"; $("rtc-verdict-title").textContent = "发现 WebRTC 泄露"; $("rtc-verdict-desc").textContent = `暴露地址：${pub.join(", ")}`; }
    else { v.className = "verdict-bar good"; $("rtc-verdict-title").textContent = "未发现 WebRTC 泄露"; $("rtc-verdict-desc").textContent = pub.length ? `与 HTTP 出口一致 (${pub.join(", ")})` : "浏览器未暴露公网地址"; }
    $("rtc-loading").hidden = true; $("rtc-run").disabled = false; this.running = false;
  },
};

const api = {
  init() {
    const base = `${location.origin}${API}`;
    $("api-ex-self").textContent = `curl ${base}`;
    $("api-ex-ip").textContent = `curl "${base}?q=openai.com"`;
    $("api-ex-asn").textContent = `curl "${base}?asn=15169&pfx=8.8.8.0/24"`;
  },
  async tryIt(q) {
    const pre = $("api-response"); pre.hidden = false; pre.textContent = "请求中…";
    try {
      const res = await fetchTimeout(q ? `${API}?q=${encodeURIComponent(q)}` : API, 14000);
      pre.textContent = JSON.stringify(await res.json(), null, 2);
    } catch (e) { pre.textContent = `错误：${e.message || e}`; }
  },
};

/* ================= Router & Mobile Nav Auto-Center ================= */
const VIEWS = ["query", "fp", "asn", "dns", "webrtc", "api"];
function showView(view) {
  for (const v of VIEWS) $(`view-${v}`).hidden = v !== view;
  document.querySelectorAll("[data-nav]").forEach((a) => a.classList.toggle("active", a.dataset.route === view));
  const navLinks = document.querySelector(".nav-links");
  const active = navLinks?.querySelector("a.active");
  if (navLinks && active) {
    const targetLeft = active.offsetLeft - navLinks.clientWidth / 2 + active.clientWidth / 2;
    navLinks.scrollTo({ left: Math.max(0, targetLeft), behavior: "smooth" });
  }
  updateSeoTitle(view, state.current);
  window.scrollTo({ top: 0, behavior: "auto" });
  if (view === "query" && state.map) setTimeout(() => state.map.invalidateSize(), 180);
}
function route() {
  const h = location.hash; let view = "query"; let target = null;
  const m = h.match(/^#ip=(.+)$/);
  if (m) { view = "query"; target = decodeURIComponent(m[1]); }
  else if (h === "#fp") view = "fp";
  else if (h === "#asn") view = "asn";
  else if (h === "#dns") view = "dns";
  else if (h === "#webrtc") view = "webrtc";
  else if (h === "#api") view = "api";

  showView(view);
  if (view === "query") {
    if (target) query(target);
    else if (!state.queryStarted) query(null);
    if (!exit.started) exit.run();
  } else if (view === "fp") fpEngine.renderPage();
  else if (view === "asn") asn.start();
  else if (view === "dns") { if (!dns.started) dns.run(); }
  else if (view === "webrtc") { if (!rtc.started) rtc.run(); else rtc.ensureIp(); }
  else if (view === "api") api.init();
}

/* ================= Event Bindings ================= */
$("theme-toggle").addEventListener("click", toggleTheme);
bindToggle("btn-asn-more", "asn-more");
bindToggle("btn-hb-more", "hb-more");
bindToggle("btn-score-more", "score-more");
bindToggle("btn-fp-more", "fp-more");
bindToggle("btn-bgp-more", "bgp-more");
bindToggle("btn-ping-toggle", "ping-panel", () => { if (!state.pingRan) runLatency(); });

$("btn-geo-more").addEventListener("click", () => {
  const btn = $("btn-geo-more");
  const extras = $("r-geo-list").querySelectorAll(".geo-extra");
  const open = btn.dataset.expanded !== "1";
  extras.forEach((el) => { el.hidden = !open; });
  btn.dataset.expanded = open ? "1" : "0";
  btn.textContent = open ? "收起 ▴" : `展开更多 (${extras.length}) ▾`;
});

$("search-form").addEventListener("submit", (e) => {
  e.preventDefault();
  const v = $("search-input").value.trim();
  if (!v) { query(null); return; }
  const next = `#ip=${encodeURIComponent(v)}`;
  if (location.hash === next) query(v);
  else location.hash = next;
});
$("detect-me").addEventListener("click", () => { $("search-input").value = ""; query(null); });
document.querySelectorAll("[data-example]").forEach((b) => b.addEventListener("click", () => {
  const v = b.dataset.example;
  location.hash = `#ip=${encodeURIComponent(v)}`;
  query(v);
}));
$("error-retry").addEventListener("click", () => query(state.lastQuery));
$("copy-ip").addEventListener("click", () => state.current && copyText(state.current.ip, "已复制 IP"));
$("share-link").addEventListener("click", () => state.current && copyText(`${location.origin}${location.pathname}#ip=${encodeURIComponent(state.current.ip)}`, "已复制链接"));
$("ai-run").addEventListener("click", runAiDeep);

$("ga-refresh").addEventListener("click", () => state.current && loadGeoAddress(state.current.location, true));
$("ga-copy-all").addEventListener("click", () => {
  const g = state.geoAddr;
  if (!g) return;
  const text = `街道: ${g.street}\n城市: ${g.city}\n州/省: ${g.state}\n国家: ${g.country}\n邮编: ${g.zip}\n时区: ${g.tz}`;
  copyText(text, "已复制完整真实地址");
});
document.querySelectorAll(".ga-item").forEach((btn) => {
  btn.addEventListener("click", () => {
    const val = btn.querySelector(".ga-v")?.textContent?.trim();
    const label = btn.querySelector(".ga-k")?.textContent?.trim();
    if (val && val !== "—" && val !== "获取中…" && val !== "反查中…") copyText(val, `已复制${label}`);
  });
});

$("exit-run").addEventListener("click", () => { exit.run(); if (!$("ping-panel").hidden) runLatency(); });
$("exit-v4-copy").addEventListener("click", () => { const t = $("exit-v4-ip").textContent; if (t && t !== "无公网出口") copyText(t, "已复制 IPv4"); });
$("exit-v6-copy").addEventListener("click", () => { const t = $("exit-v6-ip").textContent; if (t && t !== "无公网出口") copyText(t, "已复制 IPv6"); });
$("fp-page-run").addEventListener("click", async () => {
  state.fp = null;
  await fpEngine.renderPage(true);
  if (state.current) await fpEngine.evaluateWithReport(state.current);
  toast("已重新采集浏览器指纹");
});
$("asn-pause").addEventListener("click", () => asn.toggle());
$("asn-clear").addEventListener("click", () => asn.clear());
$("dns-run").addEventListener("click", () => dns.run());
$("rtc-run").addEventListener("click", () => rtc.run());
$("api-try-form").addEventListener("submit", (e) => { e.preventDefault(); api.tryIt($("api-try-input").value.trim()); });
document.querySelectorAll(".api-copy").forEach((b) => b.addEventListener("click", () => {
  const m = { self: "api-ex-self", ip: "api-ex-ip", asn: "api-ex-asn" };
  copyText($(m[b.dataset.copy]).textContent, "已复制命令");
}));
$("open-privacy").addEventListener("click", () => $("privacy-dialog").showModal());
$("close-privacy").addEventListener("click", () => $("privacy-dialog").close());
$("privacy-dialog").addEventListener("click", (e) => { if (e.target === $("privacy-dialog")) $("privacy-dialog").close(); });
window.addEventListener("hashchange", route);

/* Init */
syncThemeUI();
renderHistory();
route();