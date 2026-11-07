type Signal = {
  key: string;
  label: string;
  detected: boolean;
  desc: string;
};

type Report = {
  ok: true;
  ip: string;
  version: 4 | 6;
  source: "ipquery";
  location: {
    country: string;
    countryCode: string;
    region: string;
    city: string;
    zip: string;
    lat: number | null;
    lon: number | null;
    timezone: string;
    localtime: string;
  };
  network: { asn: string; org: string; isp: string };
  type: {
    code: "residential" | "datacenter" | "mobile" | "business";
    label: string;
    residential: boolean;
    confidence: "high" | "medium";
  };
  scores: { trust: number; fraud: number; riskLevel: string; riskCode: string };
  signals: Signal[];
  assessedAt: string;
};

const CACHE_TTL = 15 * 60 * 1000;
const CACHE_MAX = 800;
const cache = new Map<string, { at: number; report: Report }>();

const IPV4_RE =
  /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
const IPV6_RE =
  /^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]+|::(ffff(:0{1,4})?:)?((25[0-5]|(2[0-4]|1?[0-9])?[0-9])\.){3}(25[0-5]|(2[0-4]|1?[0-9])?[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1?[0-9])?[0-9])\.){3}(25[0-5]|(2[0-4]|1?[0-9])?[0-9]))$/;

const BUSINESS_WORDS = ["business", "enterprise", "专线"];
const RESIDENTIAL_WORDS = [
  "telecom", "broadband", "cable", "comcast", "charter", "spectrum",
  "verizon", "at&t", "bell ", "rogers", "telus", "telefonica",
  "orange", "deutsche telekom", "british telecom", "kpn", "proximus",
  "swisscom", "singtel", "starhub", "kddi", "softbank", "sk broadband",
  "lg uplus", "telstra", "optus", "pldt", "telekom", "china telecom",
  "china unicom", "china mobile", "chinanet", "unicom", "cnc group",
  "电信", "联通", "移动", "铁通", "广电", "长城宽带",
];
const RESIDENTIAL_ASNS = new Set([
  4134, 4812, 4837, 9808, 9394, 4538, 17964, 17621, 17622, 17816,
  17962, 18245, 24138, 24444, 24400, 24547, 38019, 56040, 56041,
  56042, 56044, 56046, 56047, 56048, 58453, 9809, 9810, 9811,
  7922, 20115, 7018, 701, 22773, 3320, 3215, 12322, 5410, 2856,
  5089, 3301, 29518, 2119, 4766, 9318, 17858, 2516, 4713, 17676,
  9500, 1221, 4804, 4775, 9299, 17552, 45758, 131090, 7545, 6327,
  577, 852, 680, 6830, 1273, 5511, 1267, 3269, 12874, 8374,
]);

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
    },
  });
}

function isPrivateV4(ip: string): boolean {
  const p = ip.split(".").map(Number);
  if (p[0] === 0 || p[0] === 10 || p[0] === 127) return true;
  if (p[0] === 169 && p[1] === 254) return true;
  if (p[0] === 172 && p[1] >= 16 && p[1] <= 31) return true;
  if (p[0] === 192 && p[1] === 168) return true;
  if (p[0] === 100 && p[1] >= 64 && p[1] <= 127) return true;
  if (p[0] >= 224) return true;
  return false;
}

function isPrivateV6(ip: string): boolean {
  const lower = ip.toLowerCase();
  if (lower === "::" || lower === "::1") return true;
  if (/^f[cd]/.test(lower)) return true;
  if (/^fe[89ab]/.test(lower)) return true;
  if (lower.startsWith("::ffff:")) {
    const v4 = lower.slice(7);
    if (IPV4_RE.test(v4)) return isPrivateV4(v4);
  }
  return false;
}

function publicIp(candidate: string | null): string | null {
  if (!candidate) return null;
  const ip = candidate.trim().replace(/^::ffff:/i, "");
  if (IPV4_RE.test(ip)) return isPrivateV4(ip) ? null : ip;
  if (IPV6_RE.test(ip)) return isPrivateV6(ip) ? null : ip;
  return null;
}

function clientIpFromHeaders(req: Request): string | null {
  const direct = ["cf-connecting-ip", "x-real-ip", "x-client-ip"];
  for (const h of direct) {
    const ip = publicIp(req.headers.get(h));
    if (ip) return ip;
  }
  const forwarded = req.headers.get("x-forwarded-for");
  if (forwarded) {
    for (const part of forwarded.split(",")) {
      const ip = publicIp(part);
      if (ip) return ip;
    }
  }
  return null;
}

async function fetchJson(url: string, timeoutMs: number): Promise<any> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      signal: controller.signal,
      headers: { accept: "application/json" },
    });
    if (!res.ok) throw new Error(`upstream ${res.status}`);
    return await res.json();
  } finally {
    clearTimeout(timer);
  }
}

function containsAny(text: string, words: string[]): boolean {
  const lower = text.toLowerCase();
  return words.some((w) => lower.includes(w));
}

function asnNumber(asn: string): number {
  const m = asn.match(/(\d+)/);
  return m ? Number(m[1]) : 0;
}

function riskLabel(fraud: number): { riskLevel: string; riskCode: string } {
  if (fraud < 20) return { riskLevel: "极低风险", riskCode: "minimal" };
  if (fraud < 40) return { riskLevel: "低风险", riskCode: "low" };
  if (fraud < 60) return { riskLevel: "中等风险", riskCode: "medium" };
  if (fraud < 80) return { riskLevel: "高风险", riskCode: "high" };
  return { riskLevel: "极高风险", riskCode: "critical" };
}

function boolFlag(v: unknown): boolean | null {
  return typeof v === "boolean" ? v : null;
}

function orFlag(a: boolean | null, b: boolean | null): boolean | null {
  if (a === true || b === true) return true;
  if (a === false || b === false) return false;
  return null;
}

function buildReport(ip: string, raw: any, sec: any): Report {
  const version: 4 | 6 = IPV4_RE.test(ip) ? 4 : 6;
  const loc = raw.location ?? {};
  const isp = raw.isp ?? {};
  const risk = raw.risk ?? {};
  const assessment = risk.assessment ?? {};
  const secOk = sec && sec.status === "success";

  const location: Report["location"] = {
    country: loc.country ?? "",
    countryCode: (loc.country_code ?? "").toUpperCase(),
    region: loc.state ?? "",
    city: loc.city ?? "",
    zip: loc.zipcode ?? "",
    lat: typeof loc.latitude === "number" ? loc.latitude : null,
    lon: typeof loc.longitude === "number" ? loc.longitude : null,
    timezone: loc.timezone ?? "",
    localtime: loc.localtime ?? "",
  };
  const network: Report["network"] = {
    asn: isp.asn ?? "",
    org: isp.org ?? "",
    isp: isp.isp ?? "",
  };

  const flags = {
    proxy: orFlag(boolFlag(risk.is_proxy), secOk ? sec.proxy === true : null),
    vpn: boolFlag(risk.is_vpn),
    tor: boolFlag(risk.is_tor),
    datacenter: orFlag(boolFlag(risk.is_datacenter), secOk ? sec.hosting === true : null),
    mobile: orFlag(boolFlag(risk.is_mobile), secOk ? sec.mobile === true : null),
  };
  const threat = Number(assessment.threat_score) || 0;
  const riskScore = Number(risk.risk_score) || 0;
  const anonymity = Number(assessment.anonymity_score) || 0;
  const hasThreatData =
    typeof assessment.threat_score === "number" || typeof risk.risk_score === "number";

  const orgText = `${network.org} ${network.isp}`;
  const asn = asnNumber(network.asn);

  let type: Report["type"];
  if (flags.datacenter) {
    type = { code: "datacenter", label: "数据中心", residential: false, confidence: "high" };
  } else if (flags.mobile) {
    type = { code: "mobile", label: "移动网络", residential: false, confidence: "high" };
  } else if (containsAny(orgText, BUSINESS_WORDS)) {
    type = { code: "business", label: "企业专线", residential: false, confidence: "medium" };
  } else if (RESIDENTIAL_ASNS.has(asn) || containsAny(orgText, RESIDENTIAL_WORDS)) {
    type = { code: "residential", label: "家庭宽带", residential: true, confidence: "high" };
  } else {
    type = { code: "residential", label: "家庭宽带", residential: true, confidence: "medium" };
  }

  let fraud = 0;
  if (flags.tor) fraud += 45;
  if (flags.vpn) fraud += 28;
  if (flags.proxy) fraud += 28;
  if (flags.datacenter) fraud += 25;
  if (flags.mobile) fraud += 4;
  if (flags.datacenter && (flags.proxy || flags.vpn || flags.tor)) fraud += 12;
  fraud += Math.min(100, threat) * 0.3;
  fraud += Math.min(100, riskScore) * 0.2;
  fraud += Math.min(100, anonymity) * 0.15;
  fraud = Math.max(0, Math.min(100, Math.round(fraud)));
  const trust = 100 - fraud;

  const signals: Signal[] = [];
  const defs = [
    { key: "proxy", label: "代理服务器", flag: flags.proxy, desc: "流量是否经过公开代理或匿名代理转发" },
    { key: "vpn", label: "VPN 出口", flag: flags.vpn, desc: "是否为已知 VPN 服务的出口节点" },
    { key: "tor", label: "Tor 网络", flag: flags.tor, desc: "是否为 Tor 匿名网络的出口节点" },
    { key: "datacenter", label: "数据中心", flag: flags.datacenter, desc: "是否托管于云服务商或机房，而非家庭网络" },
    { key: "mobile", label: "移动网络", flag: flags.mobile, desc: "是否通过蜂窝移动网络接入互联网" },
  ];
  for (const d of defs) {
    if (typeof d.flag === "boolean") {
      signals.push({ key: d.key, label: d.label, detected: d.flag, desc: d.desc });
    }
  }
  if (hasThreatData) {
    signals.push({
      key: "abuse",
      label: "滥用威胁",
      detected: threat > 0 || riskScore > 0,
      desc: "是否出现在 Spamhaus 等滥用与劫持情报源中",
    });
  }

  return {
    ok: true,
    ip,
    version,
    source: "ipquery",
    location,
    network,
    type,
    scores: { trust, fraud, ...riskLabel(fraud) },
    signals,
    assessedAt: new Date().toISOString(),
  };
}

async function fetchFresh(ip: string): Promise<Report> {
  const geoPromise = fetchJson(`https://ipwho.is/${encodeURIComponent(ip)}`, 3500).catch(() => null);
  const secPromise = fetchJson(`http://ip-api.com/json/${encodeURIComponent(ip)}?fields=status,mobile,proxy,hosting,zip`, 3500).catch(() => null);
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      const raw = await fetchJson(`https://api.ipquery.io/${encodeURIComponent(ip)}`, 8000);
      if (raw && raw.ip && raw.location && raw.risk) {
        const [geo, sec] = await Promise.all([geoPromise, secPromise]);
        const report = buildReport(ip, raw, sec);
        if (!report.location.zip) {
          if (geo && geo.success === true && geo.postal) report.location.zip = String(geo.postal);
          else if (sec && sec.status === "success" && sec.zip) report.location.zip = String(sec.zip);
        }
        return report;
      }
    } catch { /* retry once, then fail honestly */ }
  }
  throw new Error("upstream_unavailable");
}

function cacheReport(ip: string, report: Report) {
  if (cache.size >= CACHE_MAX) {
    const oldest = cache.keys().next().value;
    if (oldest !== undefined) cache.delete(oldest);
  }
  cache.set(ip, { at: Date.now(), report });
}

async function lookup(ip: string): Promise<Report> {
  const hit = cache.get(ip);
  if (hit && Date.now() - hit.at < CACHE_TTL) return hit.report;
  if (hit) {
    const prevZip = hit.report.location.zip;
    fetchFresh(ip).then((r) => { if (!r.location.zip && prevZip) r.location.zip = prevZip; cacheReport(ip, r); }).catch(() => {});
    return hit.report;
  }
  const report = await fetchFresh(ip);
  cacheReport(ip, report);
  return report;
}

const asnCache = new Map<number, { at: number; data: Record<string, unknown> }>();
const ASN_TTL = 60 * 60 * 1000;

type BgpRow = { ts: number; pfx: string; origin: number | null; type: "announce" | "withdraw" };
type BgpSnapshot = { ok: true; source: "ris-live"; collectedAt: string; rows: BgpRow[] };
const BGP_TTL = 25 * 1000;
let bgpSnapshot: { at: number; data: BgpSnapshot } | null = null;
let bgpPending: Promise<BgpSnapshot> | null = null;

function parseBgpMessage(msg: any, rows: BgpRow[]) {
  if (msg?.type !== "ris_message") return;
  const d = msg.data;
  if (!d || d.type !== "UPDATE") return;
  const path = Array.isArray(d.path) ? d.path : [];
  const origin = path.length && Number.isInteger(path[path.length - 1]) ? path[path.length - 1] : null;
  const ts = (typeof d.timestamp === "number" ? d.timestamp : Date.now() / 1000) * 1000;
  for (const ann of d.announcements || []) {
    for (const pfx of ann?.prefixes || []) {
      if (typeof pfx === "string" && pfx.includes("/")) rows.push({ ts, pfx, origin, type: "announce" });
    }
  }
  for (const pfx of d.withdrawals || []) {
    if (typeof pfx === "string" && pfx.includes("/")) rows.push({ ts, pfx, origin: null, type: "withdraw" });
  }
}

async function collectBgpSnapshot(): Promise<BgpSnapshot> {
  const rows: BgpRow[] = [];
  return await new Promise<BgpSnapshot>((resolve, reject) => {
    let settled = false;
    let ws: any;
    const finish = (err?: Error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try { ws?.close(); } catch {}
      if (err) reject(err);
      else resolve({ ok: true, source: "ris-live", collectedAt: new Date().toISOString(), rows: rows.slice(-100) });
    };
    const timer = setTimeout(() => finish(rows.length ? undefined : new Error("no_updates")), 6000);
    const onMessage = (e: any) => {
      let msg: any;
      try { msg = JSON.parse(typeof e.data === "string" ? e.data : ""); } catch { return; }
      parseBgpMessage(msg, rows);
      if (rows.length >= 100) finish();
    };
    const subscribe = () => {
      try { ws.send(JSON.stringify({ type: "ris_subscribe", data: { type: "UPDATE" } })); }
      catch { finish(new Error("subscribe_failed")); }
    };
    const attach = (sock: any) => {
      ws = sock;
      if (typeof ws.addEventListener === "function") {
        ws.addEventListener("message", onMessage);
        ws.addEventListener("close", () => finish(rows.length ? undefined : new Error("closed_early")));
        ws.addEventListener("error", () => finish(new Error("websocket_error")));
      } else {
        ws.onmessage = onMessage;
        ws.onclose = () => finish(rows.length ? undefined : new Error("closed_early"));
        ws.onerror = () => finish(new Error("websocket_error"));
      }
    };
    const url = "https://ris-live.ripe.net/v1/ws/?client=iplens-pages";
    if (typeof WebSocket !== "undefined") {
      const sock = new WebSocket(url.replace(/^https:/, "wss:"));
      attach(sock);
      sock.addEventListener("open", subscribe);
      sock.addEventListener("error", () => finish(new Error("connect_failed")));
    } else {
      fetch(url, { headers: { Upgrade: "websocket" } }).then((res) => {
        const sock = (res as any).webSocket;
        if (!sock || res.status !== 101) { finish(new Error("websocket_upgrade_failed")); return; }
        sock.accept();
        attach(sock);
        subscribe();
      }).catch(() => finish(new Error("connect_failed")));
    }
  });
}

async function lookupBgpFeed(): Promise<BgpSnapshot> {
  if (bgpSnapshot && Date.now() - bgpSnapshot.at < BGP_TTL) return bgpSnapshot.data;
  if (!bgpPending) {
    bgpPending = collectBgpSnapshot()
      .then((data) => { bgpSnapshot = { at: Date.now(), data }; return data; })
      .finally(() => { bgpPending = null; });
  }
  return bgpPending;
}

async function lookupAsn(asn: number, prefix: string | null): Promise<Record<string, unknown>> {
  const hit = asnCache.get(asn);
  if (hit && Date.now() - hit.at < ASN_TTL) return hit.data;

  let name = "";
  let country = "";
  let countryCode = "";
  try {
    const raw = await fetchJson(`https://stat.ripe.net/data/as-names/data.json?resource=AS${asn}`, 8000);
    name = raw?.data?.names?.[String(asn)] ?? "";
  } catch { /* name optional */ }

  if (prefix) {
    const base = prefix.split("/")[0];
    const ip = publicIp(base);
    if (ip) {
      try {
        const raw = await fetchJson(`https://api.ipquery.io/${encodeURIComponent(ip)}`, 8000);
        if (raw && raw.location) {
          country = raw.location.country ?? "";
          countryCode = (raw.location.country_code ?? "").toUpperCase();
          if (!name) name = raw.isp?.org ?? raw.isp?.isp ?? "";
        }
      } catch { /* country optional */ }
    }
  }

  const data = { ok: true, asn: `AS${asn}`, name, country, countryCode };
  if (asnCache.size >= 2000) {
    const oldest = asnCache.keys().next().value;
    if (oldest !== undefined) asnCache.delete(oldest);
  }
  asnCache.set(asn, { at: Date.now(), data });
  return data;
}

export async function handler(req: Request): Promise<Response> {
  if (req.method !== "GET") {
    return json({ ok: false, error: "method_not_allowed", message: "仅支持 GET 请求" }, 405);
  }

  const url = new URL(req.url);

  if (url.searchParams.get("feed") === "bgp") {
    try {
      return json(await lookupBgpFeed());
    } catch {
      return json({ ok: false, error: "upstream_unavailable", message: "BGP 路由流暂时不可用，请稍后重试" }, 502);
    }
  }

  const asnParam = url.searchParams.get("asn");
  if (asnParam !== null) {
    const asn = Number(String(asnParam).replace(/^AS/i, ""));
    if (!Number.isInteger(asn) || asn < 1 || asn > 4294967295) {
      return json({ ok: false, error: "invalid_asn", message: "请输入合法的 ASN 编号" }, 400);
    }
    try {
      return json(await lookupAsn(asn, url.searchParams.get("pfx")));
    } catch {
      return json({ ok: false, error: "upstream_unavailable", message: "ASN 数据源暂时不可用" }, 502);
    }
  }

  const q = url.searchParams.get("q");

  let ip: string | null;
  if (q !== null && q.trim() !== "") {
    ip = publicIp(q);
    if (!ip) {
      const trimmed = q.trim();
      const validFormat = IPV4_RE.test(trimmed) || IPV6_RE.test(trimmed);
      return json(
        {
          ok: false,
          error: validFormat ? "private_ip" : "invalid_ip",
          message: validFormat ? "该地址为内网或保留地址，无法检测" : "请输入合法的 IPv4 或 IPv6 地址",
        },
        400,
      );
    }
  } else {
    ip = clientIpFromHeaders(req);
    if (!ip) {
      return json({ ok: false, error: "ip_unavailable", message: "无法从连接中识别您的 IP，请手动查询" }, 422);
    }
  }

  try {
    const report = await lookup(ip);
    return json(report);
  } catch {
    return json({ ok: false, error: "upstream_unavailable", message: "IP 数据源暂时不可用，请稍后重试" }, 502);
  }
}