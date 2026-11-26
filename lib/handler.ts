type Lang = "en" | "zh-CN" | "zh-TW" | "ja";

type Signal = {
  key: string;
  label: string;
  detected: boolean;
  desc: string;
  checked?: string[];
  hits?: string[];
  detail?: string;
  meta?: Record<string, number>;
};

type ScoreBreakdownItem = {
  key: string;
  label: string;
  delta: number;
  reason: string;
  meta?: Record<string, string | number>;
};

type GeoCompareItem = {
  source: string;
  countryCode: string;
  country: string;
  region: string;
  city: string;
};

type RegistryHistoryRow = {
  cidr: string;
  rir: string;
  countryCode: string;
  firstSeen: string;
  lastSeen: string;
};

type BgpHistoryRow = {
  cidr: string;
  asn: string;
  firstSeen: string;
  lastSeen: string;
};

type RadarBotData = {
  human: number;
  bot: number;
  source: "cloudflare-radar" | "estimated";
};

type RadarAsnEntity = {
  countryCode: string;
  orgName: string;
  website: string;
  rir: string;
};

type Report = {
  ok: true;
  ip: string;
  ipNumeric: string;
  queriedDomain?: string;
  version: 4 | 6;
  sources: string[];
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
    registeredCountryCode: string;
    isNative: boolean | null;
    geoTypeLabel: string;
    multiSource: GeoCompareItem[];
  };
  network: {
    asn: string;
    asnType: string;
    org: string;
    isp: string;
    route: string;
    ipRange: string;
    rdns: string;
  };
  company: {
    name: string;
    type: string;
    typeLabel: string;
    domain: string;
    netName: string;
    abuseEmail: string;
    abuserScore: string;
    rir: string;
  };
  type: {
    code: "residential" | "dual_isp" | "datacenter" | "mobile" | "business" | "unknown";
    label: string;
    residential: boolean;
    confidence: "high" | "medium" | "low";
    reason: string;
  };
  scores: {
    trust: number;
    fraud: number;
    riskLevel: string;
    riskCode: string;
    breakdown: ScoreBreakdownItem[];
  };
  humanRatio: RadarBotData;
  exposure: {
    ports: number[];
    tags: string[];
    vulnsCount: number;
  };
  abuse?: {
    confidence: number;
    reports: number;
    lastReportedAt: string;
  };
  signals: Signal[];
  registryHistory: RegistryHistoryRow[];
  bgpHistory: BgpHistoryRow[];
  connection?: {
    httpProtocol: string;
    tlsVersion: string;
    tlsCipher: string;
    colo: string;
  };
  assessedAt: string;
};

const CACHE_TTL = 15 * 60 * 1000;
const CACHE_MAX = 800;
const cache = new Map<string, { at: number; report: Report }>();

const RADAR_TTL = 6 * 60 * 60 * 1000;
const radarCache = new Map<number, { at: number; data: { human: number; bot: number } | null }>();
const radarEntityCache = new Map<number, { at: number; data: RadarAsnEntity | null }>();

const AI_CACHE_TTL = 12 * 60 * 60 * 1000;
const aiCache = new Map<string, { at: number; data: Record<string, unknown> }>();

const GEOADDR_TTL = 6 * 60 * 60 * 1000;
const geoAddrCache = new Map<string, { at: number; data: Record<string, unknown> }>();

const IPV4_RE =
  /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
const IPV6_RE =
  /^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]+|::(ffff(:0{1,4})?:)?((25[0-5]|(2[0-4]|1?[0-9])?[0-9])\.){3}(25[0-5]|(2[0-4]|1?[0-9])?[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1?[0-9])?[0-9])\.){3}(25[0-5]|(2[0-4]|1?[0-9])?[0-9]))$/;
const DOMAIN_RE = /^(?=.{3,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$/;

const COUNTRY_NAME_TO_CODE: Record<string, string> = {
  "united states": "US", "usa": "US", "u.s.a.": "US", "united states of america": "US",
  "china": "CN", "hong kong": "HK", "taiwan": "TW", "macao": "MO", "macau": "MO",
  "japan": "JP", "south korea": "KR", "korea": "KR", "republic of korea": "KR",
  "singapore": "SG", "united kingdom": "GB", "uk": "GB", "great britain": "GB",
  "germany": "DE", "france": "FR", "netherlands": "NL", "canada": "CA",
  "australia": "AU", "switzerland": "CH", "sweden": "SE", "norway": "NO",
  "finland": "FI", "italy": "IT", "spain": "ES", "russia": "RU", "india": "IN",
  "brazil": "BR", "ireland": "IE", "poland": "PL", "vietnam": "VN", "thailand": "TH",
  "malaysia": "MY", "indonesia": "ID", "philippines": "PH", "turkey": "TR",
  "united arab emirates": "AE", "south africa": "ZA", "mexico": "MX", "new zealand": "NZ",
};

const DATACENTER_WORDS = [
  "amazon", "aws", "ec2", "googleusercontent", "google cloud", "google llc",
  "microsoft", "azure", "oracle", "alibaba", "aliyun", "alicloud", "tencent",
  "huawei cloud", "huaweicloud", "digitalocean", "vultr", "choopa", "constant company",
  "linode", "akamai", "hetzner", "ovh", "cloudflare", "fastly", "leaseweb",
  "m247", "colocrossing", "datacamp", "cdn77", "psychz", "zenlayer", "racknerd",
  "buyvm", "frantech", "it7", "bandwagon", "dmit", "contabo", "ionos", "1&1",
  "scaleway", "online s.a.s", "kamatera", "upcloud", "gcore", "g-core", "claw",
  "hytron", "back waves", "hostinger", "godaddy", "namecheap", "bluehost",
  "hostwinds", "interserver", "quadranet", "multacom", "sharktech", "nexeon",
  "datacenter", "data center", "hosting", "cloud", "vps", "server", "colo",
  "colocation", "dedicated", "dedi", "idc", "compute", "cdn", "proxy", "vpn",
  "rackspace", "softlayer", "ibm cloud", "ucloud", "qcloud", "ksyun", "jdcloud",
  "baiduyun", "volcengine", "bytedance", "xserver", "sakura internet", "conoha",
  "gmo internet", "kagoya", "crunchbits", "spartan host", "hosthatch", "greencloud",
  "melbicom", "aeza", "stark industries", "pq hosting", "hostkey", "terrahost",
  "xneelo", "servers.com", "packet", "equinix", "cogent", "he.net", "hurricane electric",
  "bgp.net", "virtual", "hypervisor", "kubernetes", "fly.io", "render", "vercel",
  "netlify", "railway", "heroku", "deno", "supabase", "github", "gitlab",
];

const VPN_RDNS_WORDS = [
  "nordvpn", "mullvad", "expressvpn", "protonvpn", "surfshark", "cyberghost",
  "privateinternetaccess", "windscribe", "ipvanish", "torguard", "perfect-privacy",
  "openvpn", "wireguard",
];

const RDNS_DC_WORDS = [
  "vps", "vm-", "srv", "server", "cloud", "host", "node", "dedi", "colo", "idc",
  "amazonaws", "googleusercontent", "vultr", "digitalocean", "linode", "hetzner",
  "ovh", "contabo", "scaleway", "leaseweb", "m247", "racknerd", "cloudflare", "compute",
];

const BUSINESS_WORDS = ["business", "enterprise", "corp", "corporate", "university", "college", "edu", "gov", "bank", "专线", "政企"];

const RESIDENTIAL_WORDS = [
  "telecom", "broadband", "cable", "fiber", "fibre", "dsl", "ftth",
  "comcast", "xfinity", "charter", "spectrum", "cox communications",
  "verizon fios", "at&t services", "bell canada", "rogers", "telus", "shaw",
  "telefonica", "orange", "deutsche telekom", "british telecom", "bt group",
  "virgin media", "sky broadband", "kpn", "ziggo", "proximus", "swisscom",
  "free sas", "sfr", "bouygues", "singtel", "starhub", "m1 limited", "myrepublic",
  "kddi", "softbank bb", "ntt communications", "ocn", "so-net", "big-lobe",
  "sk broadband", "kt corporation", "lg uplus", "telstra", "optus", "tpg",
  "pldt", "globe telecom", "cht", "hinet", "chunghwa", "pccw", "hkt", "hkbn",
  "china telecom", "china unicom", "china mobile", "chinanet", "cnc group",
  "电信", "联通", "移动", "铁通", "广电", "长城宽带", "有线宽带",
];

const RESIDENTIAL_ASNS = new Set([
  4134, 4812, 4837, 9808, 9394, 4538, 17964, 17621, 17622, 17816,
  17962, 18245, 24138, 24444, 24400, 24547, 38019, 56040, 56041,
  56042, 56044, 56046, 56047, 56048, 58453, 9809, 9810, 9811,
  7922, 20115, 7018, 701, 22773, 3320, 3215, 12322, 5410, 2856,
  5089, 3301, 29518, 2119, 4766, 9318, 17858, 2516, 4713, 17676,
  9500, 1221, 4804, 4775, 9299, 17552, 45758, 131090, 7545, 6327,
  577, 852, 680, 6830, 1273, 5511, 1267, 3269, 12874, 8374, 3462,
  4760, 9269, 3758, 4657,
]);

function normalizeLang(raw: unknown): Lang {
  const s = String(raw || "").trim().toLowerCase();
  if (s === "zh-tw" || s === "zh-hk" || s === "zh-hant") return "zh-TW";
  if (s === "zh-cn" || s === "zh" || s === "zh-hans") return "zh-CN";
  if (s === "ja" || s === "jp") return "ja";
  return "en";
}

function getEnv(env: Record<string, unknown> | undefined, key: string): string {
  if (env && typeof env[key] === "string" && (env[key] as string).trim()) {
    return (env[key] as string).trim();
  }
  const g = globalThis as any;
  if (g.process?.env && typeof g.process.env[key] === "string" && g.process.env[key].trim()) {
    return g.process.env[key].trim();
  }
  if (g.Deno?.env?.get) {
    try { return (g.Deno.env.get(key) || "").trim(); } catch { return ""; }
  }
  return "";
}

function getEnvAny(env: Record<string, unknown> | undefined, keys: string[]): string {
  for (const k of keys) {
    const v = getEnv(env, k);
    if (v) return v;
  }
  return "";
}

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
    },
  });
}

function ipv4ToInt(ip: string): number {
  const p = ip.split(".").map(Number);
  return (((p[0] * 256 + p[1]) * 256 + p[2]) * 256 + p[3]) >>> 0;
}

function intToIpv4(n: number): string {
  return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join(".");
}

function cidrToRange(cidr: string): string {
  if (!cidr || !cidr.includes("/")) return "";
  const [base, lenStr] = cidr.split("/");
  const len = Number(lenStr);
  if (!IPV4_RE.test(base) || !Number.isInteger(len) || len < 0 || len > 32) return "";
  const mask = len === 0 ? 0 : (0xffffffff << (32 - len)) >>> 0;
  const start = (ipv4ToInt(base) & mask) >>> 0;
  const end = (start | (~mask >>> 0)) >>> 0;
  return `${intToIpv4(start)} - ${intToIpv4(end)}`;
}

function normalizeCountryCode(raw: unknown): string {
  const s = String(raw || "").trim();
  if (!s) return "";
  if (/^[A-Za-z]{2}$/.test(s)) {
    const up = s.toUpperCase();
    return up === "EU" || up === "ZZ" || up === "AP" ? "" : up;
  }
  const lower = s.toLowerCase();
  if (COUNTRY_NAME_TO_CODE[lower]) return COUNTRY_NAME_TO_CODE[lower];
  for (const [k, v] of Object.entries(COUNTRY_NAME_TO_CODE)) {
    if (lower.includes(k)) return v;
  }
  return "";
}

function parseNum(v: unknown): number | null {
  if (typeof v === "number" && Number.isFinite(v)) return v;
  if (typeof v === "string" && v.trim() !== "") {
    const n = Number(v);
    if (Number.isFinite(n)) return n;
  }
  return null;
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

function connectionMetaFromReq(req: Request): Report["connection"] {
  const cf = (req as any).cf;
  if (!cf || typeof cf !== "object") return undefined;
  return {
    httpProtocol: String(cf.httpProtocol || ""),
    tlsVersion: String(cf.tlsVersion || ""),
    tlsCipher: String(cf.tlsCipher || ""),
    colo: String(cf.colo || ""),
  };
}

async function fetchJson(url: string, timeoutMs: number, headers?: Record<string, string>): Promise<any> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      signal: controller.signal,
      headers: {
        accept: "application/json",
        "user-agent": "IPSpot/1.0 (+https://ipspot.org)",
        ...headers,
      },
    });
    if (!res.ok) throw new Error(`upstream ${res.status}`);
    return await res.json();
  } finally {
    clearTimeout(timer);
  }
}

async function resolveDomain(domain: string): Promise<string | null> {
  try {
    const data = await fetchJson(
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=A`,
      3000,
      { accept: "application/dns-json" },
    );
    for (const a of Array.isArray(data?.Answer) ? data.Answer : []) {
      if (a.type === 1 && typeof a.data === "string") {
        const ip = publicIp(a.data);
        if (ip) return ip;
      }
    }
    const data6 = await fetchJson(
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=AAAA`,
      3000,
      { accept: "application/dns-json" },
    );
    for (const a of Array.isArray(data6?.Answer) ? data6.Answer : []) {
      if (a.type === 28 && typeof a.data === "string") {
        const ip = publicIp(a.data);
        if (ip) return ip;
      }
    }
  } catch { /* ignore */ }
  return null;
}

function containsAny(text: string, words: string[]): boolean {
  const lower = text.toLowerCase();
  return words.some((w) => lower.includes(w));
}

function asnNumber(asn: string | number | undefined): number {
  if (typeof asn === "number") return asn;
  const m = String(asn || "").match(/(\d+)/);
  return m ? Number(m[1]) : 0;
}

function riskLabel(fraud: number): { riskLevel: string; riskCode: string } {
  if (fraud <= 15) return { riskLevel: "极度纯净", riskCode: "minimal" };
  if (fraud <= 30) return { riskLevel: "低风险", riskCode: "low" };
  if (fraud <= 50) return { riskLevel: "轻度风险", riskCode: "medium" };
  if (fraud <= 70) return { riskLevel: "高风险", riskCode: "high" };
  return { riskLevel: "极度风险", riskCode: "critical" };
}

function companyTypeLabel(t: string): string {
  const map: Record<string, string> = {
    isp: "运营商 (ISP)",
    hosting: "数据中心 / 托管商",
    business: "商业企业",
    education: "教育科研",
    government: "政府机构",
    banking: "金融机构",
  };
  return map[(t || "").toLowerCase()] || (t ? t : "未标注");
}

function parseAbuserRatio(raw: unknown): number {
  if (typeof raw === "number") return raw;
  if (typeof raw === "string") {
    const m = raw.match(/([\d.]+)/);
    if (m) return parseFloat(m[1]);
  }
  return 0;
}

function fmtShortDate(raw: unknown): string {
  const s = String(raw || "");
  return s.length >= 10 ? s.slice(0, 10) : s || "—";
}

function cleanDomain(raw: unknown): string {
  return String(raw || "")
    .trim()
    .replace(/^https?:\/\//i, "")
    .replace(/^www\./i, "")
    .split("/")[0]
    .trim();
}

/* ================= Cloudflare Radar ================= */
async function fetchRadarBotClass(
  asnNum: number,
  env?: Record<string, unknown>,
): Promise<{ human: number; bot: number } | null> {
  if (!asnNum) return null;
  const token = getEnvAny(env, ["key", "CF_RADAR_TOKEN"]);
  if (!token) return null;

  const hit = radarCache.get(asnNum);
  if (hit && Date.now() - hit.at < RADAR_TTL) return hit.data;

  try {
    const raw = await fetchJson(
      `https://api.cloudflare.com/client/v4/radar/http/summary/bot_class?asn=${asnNum}&dateRange=7d&format=json`,
      3200,
      { authorization: `Bearer ${token}` },
    );
    const summary = raw?.result?.summary_0;
    if (raw?.success && summary && typeof summary === "object") {
      let humanVal: number | null = null;
      let botVal: number | null = null;
      for (const [k, v] of Object.entries(summary)) {
        const lk = k.toLowerCase();
        const num = parseFloat(String(v));
        if (!Number.isFinite(num)) continue;
        if (lk === "human") humanVal = num;
        else if (lk === "bot") botVal = num;
      }
      if (humanVal !== null || botVal !== null) {
        const h = humanVal !== null ? humanVal : Math.max(0, 100 - (botVal || 0));
        const human = Number(Math.max(0, Math.min(100, h)).toFixed(2));
        const bot = Number(Math.max(0, Math.min(100, 100 - human)).toFixed(2));
        const data = { human, bot };
        if (radarCache.size >= 1500) {
          const oldest = radarCache.keys().next().value;
          if (oldest !== undefined) radarCache.delete(oldest);
        }
        radarCache.set(asnNum, { at: Date.now(), data });
        return data;
      }
    }
  } catch { /* fallback */ }

  radarCache.set(asnNum, { at: Date.now(), data: null });
  return null;
}

async function fetchRadarAsnEntity(
  asnNum: number,
  env?: Record<string, unknown>,
): Promise<RadarAsnEntity | null> {
  if (!asnNum) return null;
  const token = getEnvAny(env, ["key", "CF_RADAR_TOKEN"]);
  if (!token) return null;

  const hit = radarEntityCache.get(asnNum);
  if (hit && Date.now() - hit.at < RADAR_TTL) return hit.data;

  try {
    const raw = await fetchJson(
      `https://api.cloudflare.com/client/v4/radar/entities/asns/${asnNum}?format=json`,
      3200,
      { authorization: `Bearer ${token}` },
    );
    const a = raw?.result?.asn;
    if (raw?.success && a && typeof a === "object") {
      const data: RadarAsnEntity = {
        countryCode: normalizeCountryCode(a.country),
        orgName: String(a.orgName || a.name || "").trim(),
        website: cleanDomain(a.website),
        rir: String(a.source || "").toUpperCase(),
      };
      if (radarEntityCache.size >= 1500) {
        const oldest = radarEntityCache.keys().next().value;
        if (oldest !== undefined) radarEntityCache.delete(oldest);
      }
      radarEntityCache.set(asnNum, { at: Date.now(), data });
      return data;
    }
  } catch { /* optional */ }

  radarEntityCache.set(asnNum, { at: Date.now(), data: null });
  return null;
}

/* ================= Shodan InternetDB ================= */
function extractShodanExposure(shodan: any): Report["exposure"] {
  if (!shodan || typeof shodan !== "object" || shodan.detail) {
    return { ports: [], tags: [], vulnsCount: 0 };
  }
  const ports: number[] = Array.isArray(shodan.ports)
    ? shodan.ports.filter((p: unknown) => typeof p === "number").slice(0, 24)
    : [];
  const vulnsCount = Array.isArray(shodan.vulns) ? shodan.vulns.length : 0;

  const tagSet = new Set<string>();
  if (Array.isArray(shodan.tags)) {
    for (const t of shodan.tags) {
      if (typeof t === "string" && t.trim()) tagSet.add(t.trim().toLowerCase());
    }
  }
  const portSet = new Set(ports);
  if (portSet.has(22)) tagSet.add("ssh");
  if (portSet.has(80) || portSet.has(443) || portSet.has(8080) || portSet.has(8443)) tagSet.add("webserver");
  if (portSet.has(53)) tagSet.add("dns");
  if (portSet.has(3389)) tagSet.add("rdp");
  if (portSet.has(1080) || portSet.has(3128) || portSet.has(8118)) tagSet.add("proxy-port");
  if (portSet.has(25) || portSet.has(465) || portSet.has(587)) tagSet.add("mail");
  if (portSet.has(3306) || portSet.has(5432) || portSet.has(6379) || portSet.has(27017)) tagSet.add("database");
  if (vulnsCount > 0) tagSet.add(`cve:${vulnsCount}`);

  return {
    ports,
    tags: [...tagSet].slice(0, 7),
    vulnsCount,
  };
}

/* ================= RDAP & History ================= */
function extractRdapInfo(rdap: any) {
  const out = {
    countryCode: "",
    netName: "",
    cidr: "",
    ipRange: "",
    orgName: "",
    abuseEmail: "",
    rir: "",
    regDate: "",
    lastChanged: "",
  };
  if (!rdap || typeof rdap !== "object") return out;

  out.countryCode = normalizeCountryCode(rdap.country);
  if (typeof rdap.name === "string") out.netName = rdap.name;
  if (Array.isArray(rdap.cidr0_cidrs) && rdap.cidr0_cidrs.length) {
    const c = rdap.cidr0_cidrs[0];
    const prefix = c.v4prefix || c.v6prefix;
    if (prefix && c.length) out.cidr = `${prefix}/${c.length}`;
  }
  if (typeof rdap.startAddress === "string" && typeof rdap.endAddress === "string") {
    out.ipRange = `${rdap.startAddress} - ${rdap.endAddress}`;
  }

  const rirHints = [
    String(rdap.port43 || ""),
    ...(Array.isArray(rdap.links) ? rdap.links.map((l: any) => String(l?.href || "")) : []),
  ].join(" ").toLowerCase();
  if (rirHints.includes("arin")) out.rir = "ARIN";
  else if (rirHints.includes("ripe")) out.rir = "RIPE NCC";
  else if (rirHints.includes("apnic")) out.rir = "APNIC";
  else if (rirHints.includes("lacnic")) out.rir = "LACNIC";
  else if (rirHints.includes("afrinic")) out.rir = "AFRINIC";

  if (Array.isArray(rdap.events)) {
    for (const ev of rdap.events) {
      if (ev?.eventAction === "registration" && ev.eventDate) out.regDate = fmtShortDate(ev.eventDate);
      if (ev?.eventAction === "last changed" && ev.eventDate) out.lastChanged = fmtShortDate(ev.eventDate);
    }
  }

  const scanEntities = (entities: any[]) => {
    if (!Array.isArray(entities)) return;
    for (const ent of entities) {
      const roles: string[] = Array.isArray(ent.roles) ? ent.roles : [];
      const vcard = Array.isArray(ent.vcardArray?.[1]) ? ent.vcardArray[1] : [];
      for (const item of vcard) {
        if (!Array.isArray(item) || item.length < 4) continue;
        if (item[0] === "fn" && typeof item[3] === "string" && !out.orgName) {
          if (roles.includes("registrant") || roles.includes("administrative") || !roles.includes("abuse")) {
            out.orgName = item[3];
          }
        }
        if (item[0] === "email" && typeof item[3] === "string") {
          if (roles.includes("abuse") || !out.abuseEmail) out.abuseEmail = item[3];
        }
        if (item[0] === "adr" && !out.countryCode) {
          const ccParam = normalizeCountryCode(item[1]?.cc);
          if (ccParam) { out.countryCode = ccParam; continue; }
          if (Array.isArray(item[3]) && item[3][6]) {
            const ccArr = normalizeCountryCode(item[3][6]);
            if (ccArr) { out.countryCode = ccArr; continue; }
          }
          if (typeof item[1]?.label === "string") {
            const lines = item[1].label.split(/\r?\n/).map((s: string) => s.trim()).filter(Boolean);
            const lastLine = lines[lines.length - 1] || "";
            const ccLine = normalizeCountryCode(lastLine);
            if (ccLine) out.countryCode = ccLine;
          }
        }
      }
      if (Array.isArray(ent.entities)) scanEntities(ent.entities);
    }
  };
  scanEntities(rdap.entities);
  return out;
}

function extractRirHistory(
  ripeRir: any,
  fallbackCC: string,
  rdapInfo: ReturnType<typeof extractRdapInfo>,
  routeFallback: string,
): RegistryHistoryRow[] {
  const list = Array.isArray(ripeRir?.data?.rirs) ? ripeRir.data.rirs : [];
  const rows: RegistryHistoryRow[] = [];
  for (const r of list) {
    if (!r) continue;
    rows.push({
      cidr: String(r.resource || "—"),
      rir: String(r.rir || "—"),
      countryCode: normalizeCountryCode(r.country),
      firstSeen: fmtShortDate(r.first_time),
      lastSeen: fmtShortDate(r.last_time),
    });
  }
  rows.sort((a, b) => (b.lastSeen || "").localeCompare(a.lastSeen || ""));
  if (rows.length && !rows[0].countryCode && fallbackCC) {
    rows[0].countryCode = fallbackCC;
  }
  if (!rows.length && (rdapInfo.cidr || routeFallback) && (rdapInfo.rir || fallbackCC)) {
    rows.push({
      cidr: rdapInfo.cidr || routeFallback,
      rir: rdapInfo.rir || "RIR",
      countryCode: fallbackCC,
      firstSeen: rdapInfo.regDate || "—",
      lastSeen: rdapInfo.lastChanged || fmtShortDate(new Date().toISOString()),
    });
  }
  return rows.slice(0, 8);
}

function extractBgpHistory(ripeHist: any): BgpHistoryRow[] {
  const byOrigin = Array.isArray(ripeHist?.data?.by_origin) ? ripeHist.data.by_origin : [];
  const rows: BgpHistoryRow[] = [];
  for (const item of byOrigin.slice(0, 8)) {
    const asn = item.origin ? `AS${item.origin}` : "—";
    for (const p of (Array.isArray(item.prefixes) ? item.prefixes : []).slice(0, 2)) {
      const tls = Array.isArray(p.timelines) ? p.timelines : [];
      if (!tls.length) continue;
      rows.push({
        cidr: String(p.prefix || "—"),
        asn,
        firstSeen: fmtShortDate(tls[0].starttime),
        lastSeen: fmtShortDate(tls[tls.length - 1].endtime),
      });
    }
  }
  rows.sort((a, b) => (b.lastSeen || "").localeCompare(a.lastSeen || ""));
  return rows.slice(0, 10);
}

function consensusCode(codes: string[]): string {
  const tally = new Map<string, number>();
  for (const c of codes) if (c) tally.set(c, (tally.get(c) || 0) + 1);
  let best = "";
  let bestN = 0;
  for (const c of codes) {
    if (!c) continue;
    const n = tally.get(c)!;
    if (n > bestN) { best = c; bestN = n; }
  }
  return best;
}

function buildReport(
  ip: string,
  d: {
    ipapi: any;
    ipquery: any;
    ipapiCom: any;
    ipwho: any;
    geojs: any;
    freeip: any;
    ipinfo: any;
    ip2loc: any;
    ipsb: any;
    ipguide: any;
    ipapico: any;
    proxycheck: any;
    onionoo: any;
    sfs: any;
    rdap: any;
    rirCountry: any;
    ripeRir: any;
    ripeGeo: any;
    ripeHist: any;
    shodan: any;
    radar: { human: number; bot: number } | null;
    radarEntity: RadarAsnEntity | null;
    abuseDb: any;
  },
  queriedDomain?: string,
): Report {
  const {
    ipapi, ipquery, ipapiCom, ipwho, geojs, freeip,
    ipinfo, ip2loc, ipsb, ipguide, ipapico,
    proxycheck, onionoo, sfs,
    rdap, rirCountry, ripeRir, ripeGeo, ripeHist, shodan, radar, radarEntity, abuseDb,
  } = d;
  const version: 4 | 6 = IPV4_RE.test(ip) ? 4 : 6;
  const ipNumeric = version === 4 ? String(ipv4ToInt(ip)) : "—";

  const ipapiOk = !!(ipapi && ipapi.ip && !ipapi.error);
  const ipapiLoc = ipapiOk
    ? (ipapi.location && typeof ipapi.location === "object"
      ? ipapi.location
      : (ipapi.country || ipapi.city || ipapi.region)
        ? {
            country_code: normalizeCountryCode(ipapi.country_code || ipapi.country),
            country: ipapi.country || "",
            state: ipapi.region || "",
            city: ipapi.city || "",
            zip: ipapi.zip || "",
            latitude: ipapi.lat,
            longitude: ipapi.lon,
            timezone: ipapi.timezone || "",
            local_time: "",
          }
        : null)
    : null;
  const ipapiHasRisk = !!(ipapiOk && (
    "is_proxy" in ipapi || "is_vpn" in ipapi || "is_tor" in ipapi ||
    "is_datacenter" in ipapi || "is_mobile" in ipapi || "is_abuser" in ipapi
  ));
  const ipqueryOk = !!(ipquery && ipquery.ip && ipquery.location);
  const ipapiComOk = !!(ipapiCom && ipapiCom.status === "success");
  const ipwhoOk = !!(ipwho && ipwho.success === true);
  const geojsOk = !!(geojs && geojs.country_code);
  const freeipOk = !!(freeip && freeip.countryCode);
  const ipinfoOk = !!(ipinfo && ipinfo.country && !ipinfo.error);
  const ip2locOk = !!(ip2loc && ip2loc.country_code && !ip2loc.error);
  const ipsbOk = !!(ipsb && ipsb.country_code);
  const ipguideOk = !!(ipguide && ipguide.location && (ipguide.location.country || ipguide.network?.autonomous_system?.country));
  const ipapicoOk = !!(ipapico && ipapico.country_code && !ipapico.error);
  const maxmindLoc = ripeGeo?.data?.located_resources?.[0]?.locations?.[0] || null;

  const pcData = proxycheck?.status === "ok" && proxycheck?.[ip] && typeof proxycheck[ip] === "object"
    ? proxycheck[ip]
    : null;
  const onionooOk = !!(onionoo && Array.isArray(onionoo.relays));
  const sfsOk = !!(sfs && sfs.success === 1 && sfs.ip && typeof sfs.ip === "object");

  const shodanOk = !!(shodan && typeof shodan === "object" && !shodan.detail);
  const exposure = extractShodanExposure(shodan);
  const abuseData = abuseDb?.data && typeof abuseDb.data === "object" ? abuseDb.data : null;

  const activeSources: string[] = [];
  if (maxmindLoc) activeSources.push("MaxMind");
  if (ipapiOk) activeSources.push("ipapi.is");
  if (ip2locOk) activeSources.push("IP2Location.io");
  if (ipinfoOk) activeSources.push("IPInfo.io");
  if (ipsbOk) activeSources.push("IP.SB");
  if (ipguideOk) activeSources.push("IP.Guide");
  if (ipwhoOk) activeSources.push("ipwho.is");
  if (ipapiComOk) activeSources.push("ip-api.com");
  if (ipqueryOk) activeSources.push("ipquery.io");
  if (geojsOk) activeSources.push("GeoJS");
  if (freeipOk) activeSources.push("FreeIPAPI");
  if (ipapicoOk) activeSources.push("ipapi.co");
  if (pcData) activeSources.push("proxycheck.io");
  if (onionooOk) activeSources.push("Tor Onionoo");
  if (sfsOk) activeSources.push("StopForumSpam");
  if (radar) activeSources.push("Cloudflare Radar");
  if (shodanOk) activeSources.push("Shodan");
  if (abuseData) activeSources.push("AbuseIPDB");

  const rdapInfo = extractRdapInfo(rdap);
  const rirStatsEntry = rirCountry?.data?.located_resources?.[0] || null;
  const rirStatsCC = normalizeCountryCode(rirStatsEntry?.location);
  const rirStatsCidr = typeof rirStatsEntry?.resource === "string" ? rirStatsEntry.resource : "";
  const ripeRirCC = normalizeCountryCode(ripeRir?.data?.rirs?.[0]?.country);

  const prefixRegisteredCC = rirStatsCC || rdapInfo.countryCode || ripeRirCC || "";
  const asnRegisteredCC =
    radarEntity?.countryCode ||
    normalizeCountryCode(ipapi?.asn?.country) ||
    normalizeCountryCode(ipguide?.network?.autonomous_system?.country) ||
    "";
  const registeredCC = prefixRegisteredCC || asnRegisteredCC || "";

  const multiSource: GeoCompareItem[] = [];
  if (maxmindLoc && maxmindLoc.country) {
    const [cc, region] = String(maxmindLoc.country).split("-");
    multiSource.push({
      source: "MaxMind",
      countryCode: (cc || "").toUpperCase(),
      country: "",
      region: region || "",
      city: String(maxmindLoc.city || ""),
    });
  }
  if (ip2locOk) {
    multiSource.push({
      source: "IP2Location",
      countryCode: String(ip2loc.country_code || "").toUpperCase(),
      country: ip2loc.country_name || "",
      region: ip2loc.region_name || "",
      city: ip2loc.city_name || "",
    });
  }
  if (ipinfoOk) {
    multiSource.push({
      source: "IPInfo.io",
      countryCode: String(ipinfo.country || "").toUpperCase(),
      country: "",
      region: ipinfo.region || "",
      city: ipinfo.city || "",
    });
  }
  if (ipapiLoc && (ipapiLoc.country_code || ipapiLoc.country)) {
    multiSource.push({
      source: "ipapi.is",
      countryCode: String(ipapiLoc.country_code || "").toUpperCase(),
      country: ipapiLoc.country || "",
      region: ipapiLoc.state || "",
      city: ipapiLoc.city || "",
    });
  }
  if (ipwhoOk) {
    multiSource.push({
      source: "ipwho.is",
      countryCode: String(ipwho.country_code || "").toUpperCase(),
      country: ipwho.country || "",
      region: ipwho.region || "",
      city: ipwho.city || "",
    });
  }
  if (ipqueryOk && ipquery.location) {
    multiSource.push({
      source: "ipquery.io",
      countryCode: String(ipquery.location.country_code || "").toUpperCase(),
      country: ipquery.location.country || "",
      region: ipquery.location.state || "",
      city: ipquery.location.city || "",
    });
  }
  if (ipapiComOk) {
    multiSource.push({
      source: "ip-api.com",
      countryCode: String(ipapiCom.countryCode || "").toUpperCase(),
      country: ipapiCom.country || "",
      region: ipapiCom.regionName || "",
      city: ipapiCom.city || "",
    });
  }
  if (ipsbOk) {
    multiSource.push({
      source: "IP.SB",
      countryCode: String(ipsb.country_code || "").toUpperCase(),
      country: ipsb.country || "",
      region: ipsb.region || "",
      city: ipsb.city || "",
    });
  }
  if (ipguideOk) {
    const gCC = normalizeCountryCode(ipguide.location.country) || normalizeCountryCode(ipguide.network?.autonomous_system?.country);
    if (gCC) {
      multiSource.push({
        source: "IP.Guide",
        countryCode: gCC,
        country: ipguide.location.country || "",
        region: "",
        city: ipguide.location.city || "",
      });
    }
  }
  if (geojsOk) {
    multiSource.push({
      source: "GeoJS",
      countryCode: String(geojs.country_code || "").toUpperCase(),
      country: geojs.country || "",
      region: geojs.region || "",
      city: geojs.city || "",
    });
  }
  if (freeipOk) {
    multiSource.push({
      source: "FreeIPAPI",
      countryCode: String(freeip.countryCode || "").toUpperCase(),
      country: freeip.countryName || "",
      region: freeip.regionName || "",
      city: freeip.cityName || "",
    });
  }
  if (ipapicoOk) {
    multiSource.push({
      source: "ipapi.co",
      countryCode: String(ipapico.country_code || "").toUpperCase(),
      country: ipapico.country_name || "",
      region: ipapico.region || "",
      city: ipapico.city || "",
    });
  }

  const consensusCC = consensusCode(multiSource.map((m) => m.countryCode));
  const pickLoc = () => {
    const ipinfoParts = typeof ipinfo?.loc === "string" ? ipinfo.loc.split(",") : [];
    const candidates = [
      ipapiLoc ? {
        cc: String(ipapiLoc.country_code || "").toUpperCase(),
        country: ipapiLoc.country || "",
        region: ipapiLoc.state || "",
        city: ipapiLoc.city || "",
        zip: ipapiLoc.zip ? String(ipapiLoc.zip) : "",
        lat: parseNum(ipapiLoc.latitude),
        lon: parseNum(ipapiLoc.longitude),
        timezone: ipapiLoc.timezone || "",
        localtime: ipapiLoc.local_time || "",
      } : null,
      ip2locOk ? {
        cc: String(ip2loc.country_code || "").toUpperCase(),
        country: ip2loc.country_name || "",
        region: ip2loc.region_name || "",
        city: ip2loc.city_name || "",
        zip: ip2loc.zip_code ? String(ip2loc.zip_code) : "",
        lat: parseNum(ip2loc.latitude),
        lon: parseNum(ip2loc.longitude),
        timezone: "",
        localtime: "",
      } : null,
      ipqueryOk && ipquery.location ? {
        cc: String(ipquery.location.country_code || "").toUpperCase(),
        country: ipquery.location.country || "",
        region: ipquery.location.state || "",
        city: ipquery.location.city || "",
        zip: ipquery.location.zipcode ? String(ipquery.location.zipcode) : "",
        lat: parseNum(ipquery.location.latitude),
        lon: parseNum(ipquery.location.longitude),
        timezone: ipquery.location.timezone || "",
        localtime: ipquery.location.localtime || "",
      } : null,
      ipapiComOk ? {
        cc: String(ipapiCom.countryCode || "").toUpperCase(),
        country: ipapiCom.country || "",
        region: ipapiCom.regionName || "",
        city: ipapiCom.city || "",
        zip: ipapiCom.zip ? String(ipapiCom.zip) : "",
        lat: parseNum(ipapiCom.lat),
        lon: parseNum(ipapiCom.lon),
        timezone: ipapiCom.timezone || "",
        localtime: "",
      } : null,
      ipinfoOk ? {
        cc: String(ipinfo.country || "").toUpperCase(),
        country: "",
        region: ipinfo.region || "",
        city: ipinfo.city || "",
        zip: ipinfo.postal ? String(ipinfo.postal) : "",
        lat: parseNum(ipinfoParts[0]),
        lon: parseNum(ipinfoParts[1]),
        timezone: ipinfo.timezone || "",
        localtime: "",
      } : null,
      ipsbOk ? {
        cc: String(ipsb.country_code || "").toUpperCase(),
        country: ipsb.country || "",
        region: ipsb.region || "",
        city: ipsb.city || "",
        zip: ipsb.postal_code ? String(ipsb.postal_code) : "",
        lat: parseNum(ipsb.latitude),
        lon: parseNum(ipsb.longitude),
        timezone: ipsb.timezone || "",
        localtime: "",
      } : null,
      ipwhoOk ? {
        cc: String(ipwho.country_code || "").toUpperCase(),
        country: ipwho.country || "",
        region: ipwho.region || "",
        city: ipwho.city || "",
        zip: ipwho.postal ? String(ipwho.postal) : "",
        lat: parseNum(ipwho.latitude),
        lon: parseNum(ipwho.longitude),
        timezone: ipwho.timezone?.id || "",
        localtime: ipwho.timezone?.current_time || "",
      } : null,
      geojsOk ? {
        cc: String(geojs.country_code || "").toUpperCase(),
        country: geojs.country || "",
        region: geojs.region || "",
        city: geojs.city || "",
        zip: "",
        lat: parseNum(geojs.latitude),
        lon: parseNum(geojs.longitude),
        timezone: geojs.timezone || "",
        localtime: "",
      } : null,
      freeipOk ? {
        cc: String(freeip.countryCode || "").toUpperCase(),
        country: freeip.countryName || "",
        region: freeip.regionName || "",
        city: freeip.cityName || "",
        zip: freeip.zipCode ? String(freeip.zipCode) : "",
        lat: parseNum(freeip.latitude),
        lon: parseNum(freeip.longitude),
        timezone: Array.isArray(freeip.timeZones) && freeip.timeZones.length === 1 ? (freeip.timeZones[0] || "") : "",
        localtime: "",
      } : null,
      ipapicoOk ? {
        cc: String(ipapico.country_code || "").toUpperCase(),
        country: ipapico.country_name || "",
        region: ipapico.region || "",
        city: ipapico.city || "",
        zip: ipapico.postal ? String(ipapico.postal) : "",
        lat: parseNum(ipapico.latitude),
        lon: parseNum(ipapico.longitude),
        timezone: ipapico.timezone || "",
        localtime: "",
      } : null,
    ].filter(Boolean) as any[];

    const primary = candidates.find((c) => c.cc === consensusCC && c.lat !== null) ||
      candidates.find((c) => c.cc === consensusCC) ||
      candidates[0] || {
        cc: "", country: "", region: "", city: "", zip: "", lat: null, lon: null, timezone: "", localtime: "",
      };
    if (!primary.zip) {
      const z = candidates.find((c) => c.cc === primary.cc && c.zip);
      if (z) primary.zip = z.zip;
    }
    if (!primary.timezone) {
      const tz = candidates.find((c) => c.cc === primary.cc && c.timezone) || candidates.find((c) => c.timezone);
      if (tz) primary.timezone = tz.timezone;
    }
    return primary;
  };
  const loc = pickLoc();

  let isNative: boolean | null = null;
  let geoTypeLabel = "未知来源";
  if (prefixRegisteredCC && loc.cc) {
    isNative = prefixRegisteredCC === loc.cc;
    geoTypeLabel = isNative ? `原生 IP (${prefixRegisteredCC})` : `广播 IP (${prefixRegisteredCC}→${loc.cc})`;
  } else if (asnRegisteredCC && loc.cc && asnRegisteredCC === loc.cc) {
    // When prefix RIR records time out, only treat same-country ASN entity as native; never misclassify cross-border ASN ownership as broadcast.
    isNative = true;
    geoTypeLabel = `原生 IP (${asnRegisteredCC})`;
  }

  const ipapiCompanyStr = typeof ipapi?.company === "string" ? ipapi.company : (ipapi?.company?.name || "");
  const ipapiAsnOrg = typeof ipapi?.asn === "string" ? ipapi.asn.replace(/^AS\d+\s*/i, "").trim() : (ipapi?.asn?.org || "");
  const asnNum =
    asnNumber(typeof ipapi?.asn === "string" ? ipapi.asn : ipapi?.asn?.asn) ||
    asnNumber(ipquery?.isp?.asn) ||
    asnNumber(ipapiCom?.as) ||
    asnNumber(ipwho?.connection?.asn) ||
    asnNumber(ip2loc?.asn) ||
    asnNumber(ipsb?.asn) ||
    asnNumber(ipguide?.network?.autonomous_system?.asn) ||
    asnNumber(geojs?.asn);
  const asnStr = asnNum ? `AS${asnNum}` : "";
  const orgStr =
    ipapiAsnOrg ||
    ipapiCompanyStr ||
    radarEntity?.orgName ||
    ipquery?.isp?.org ||
    ipapiCom?.org ||
    ipwho?.connection?.org ||
    ipsb?.asn_organization ||
    ip2loc?.as ||
    ipguide?.network?.autonomous_system?.organization ||
    rdapInfo.orgName ||
    geojs?.organization_name ||
    "";
  const ispStr =
    ipapiCompanyStr ||
    ipquery?.isp?.isp ||
    ipapiCom?.isp ||
    ipwho?.connection?.isp ||
    ipsb?.isp ||
    pcData?.provider ||
    abuseData?.isp ||
    orgStr;
  const rdns = (ipapiComOk && typeof ipapiCom.reverse === "string" ? ipapiCom.reverse : "") ||
    (Array.isArray(shodan?.hostnames) && shodan.hostnames[0] ? String(shodan.hostnames[0]) : "");

  const route =
    ipapi?.asn?.route ||
    ipapi?.company?.network ||
    ipguide?.network?.cidr ||
    pcData?.range ||
    rdapInfo.cidr ||
    rirStatsCidr ||
    (ripeRir?.data?.rirs?.[0]?.resource ? String(ripeRir.data.rirs[0].resource) : "") ||
    "";
  const ipRange = (version === 4 ? cidrToRange(route) : "") || rdapInfo.ipRange || "";
  const registryHistory = extractRirHistory(ripeRir, registeredCC, rdapInfo, route);
  const bgpHistory = extractBgpHistory(ripeHist);

  const asnType = String(ipapi?.asn?.type || "").toLowerCase();
  const compType = String(ipapi?.company?.type || "").toLowerCase();

  const company: Report["company"] = {
    name: ipapiCompanyStr || radarEntity?.orgName || rdapInfo.orgName || orgStr || "—",
    type: compType || asnType || "",
    typeLabel: companyTypeLabel(compType || asnType),
    domain: ipapi?.company?.domain || ipapi?.asn?.domain || ipwho?.connection?.domain || abuseData?.domain || radarEntity?.website || "",
    netName: rdapInfo.netName || "",
    abuseEmail: ipapi?.abuse?.email || rdapInfo.abuseEmail || "",
    abuserScore: String(ipapi?.company?.abuser_score || ipapi?.asn?.abuser_score || ""),
    rir: registryHistory[0]?.rir || rdapInfo.rir || radarEntity?.rir || ipguide?.network?.autonomous_system?.rir || "",
  };

  const shodanTagsLower = exposure.tags.map((t) => t.toLowerCase());
  const shodanPortSet = new Set(exposure.ports);
  const shodanHasCloud = shodanTagsLower.includes("cloud");
  const shodanHasProxy = shodanTagsLower.some((t) => t === "proxy" || t === "open-proxy" || t === "proxy-port");
  const shodanProxyPort = shodanPortSet.has(1080) || shodanPortSet.has(3128) || shodanPortSet.has(8118);
  const shodanHasVpn = shodanTagsLower.includes("vpn");
  const shodanVpnPort = shodanPortSet.has(1194) || shodanPortSet.has(51820) || shodanPortSet.has(1723) || (shodanPortSet.has(500) && shodanPortSet.has(4500));
  const shodanHasTor = shodanTagsLower.includes("tor");
  const shodanCompromised = shodanTagsLower.some((t) => t === "compromised" || t === "malware" || t === "botnet");

  const pcFlag = pcData?.proxy === "yes";
  const pcType = String(pcData?.type || "").toLowerCase();
  const pcIsTor = pcFlag && pcType === "tor";
  const pcIsVpn = pcFlag && pcType === "vpn";
  const pcIsCompromised = pcFlag && pcType.includes("compromised");
  const pcIsProxy = pcFlag && !pcIsTor && !pcIsVpn;

  const onionooTor = onionooOk && onionoo.relays.some((rel: any) => {
    if (!rel || rel.running === false) return false;
    const addrs = [
      ...(Array.isArray(rel.or_addresses) ? rel.or_addresses : []),
      ...(Array.isArray(rel.exit_addresses) ? rel.exit_addresses : []),
    ];
    return addrs.some((a: unknown) => typeof a === "string" && (a === ip || a.startsWith(`${ip}:`) || a.startsWith(`[${ip}]`)));
  });

  const sfsHit = sfsOk && sfs.ip.appears === 1;
  const sfsFreq = Number(sfs?.ip?.frequency) || 0;
  const sfsConf = Number(sfs?.ip?.confidence) || 0;

  const abuseUsage = String(abuseData?.usageType || "").toLowerCase();
  const abuseDc = abuseUsage.includes("data center") || abuseUsage.includes("web hosting") || abuseUsage.includes("transit");
  const abuseProxy = abuseUsage.includes("public proxy") || abuseUsage.includes("web proxy");

  const combinedText = `${orgStr} ${ispStr} ${company.name} ${company.domain} ${company.netName} ${ipapiCom?.asname || ""}`;
  const hostText = `${rdns} ${Array.isArray(shodan?.hostnames) ? shodan.hostnames.join(" ") : ""}`;
  const vpnByRdns = hostText.trim() ? containsAny(hostText, VPN_RDNS_WORDS) : false;

  const dcHits: string[] = [];
  if (ipapi?.is_datacenter === true || compType === "hosting" || asnType === "hosting") dcHits.push("ipapi.is");
  if (ipquery?.risk?.is_datacenter === true) dcHits.push("ipquery.io");
  if (ipapiComOk && ipapiCom.hosting === true) dcHits.push("ip-api.com");
  if (shodanHasCloud) dcHits.push("Shodan");
  if (abuseDc) dcHits.push("AbuseIPDB");
  const dcByApi = dcHits.length > 0;
  const dcByKeyword = containsAny(combinedText, DATACENTER_WORDS) || (rdns ? containsAny(rdns, RDNS_DC_WORDS) : false);
  if (dcByKeyword && !dcHits.includes("ASN/rDNS")) dcHits.push("ASN/rDNS");
  const isDc = dcByApi || dcByKeyword;

  const proxyHits: string[] = [];
  if (ipapi?.is_proxy === true) proxyHits.push("ipapi.is");
  if (ipquery?.risk?.is_proxy === true) proxyHits.push("ipquery.io");
  if (ipapiComOk && ipapiCom.proxy === true) proxyHits.push("ip-api.com");
  if (ip2locOk && ip2loc.is_proxy === true) proxyHits.push("IP2Location");
  if (freeipOk && freeip.isProxy === true) proxyHits.push("FreeIPAPI");
  if (pcIsProxy) proxyHits.push(`proxycheck (${pcData.type || "Proxy"})`);
  if (shodanHasProxy || shodanProxyPort) proxyHits.push(shodanProxyPort ? "Shodan (Proxy Port)" : "Shodan");
  if (abuseProxy) proxyHits.push("AbuseIPDB");
  const isProxy = proxyHits.length > 0;

  const vpnHits: string[] = [];
  if (pcIsVpn) vpnHits.push("proxycheck.io (VPN)");
  if (ipapi?.is_vpn === true) vpnHits.push("ipapi.is");
  if (ipquery?.risk?.is_vpn === true) vpnHits.push("ipquery.io");
  if (shodanHasVpn || shodanVpnPort) vpnHits.push(shodanVpnPort ? "Shodan (VPN Port)" : "Shodan");
  if (vpnByRdns) vpnHits.push("rDNS");
  const isVpn = vpnHits.length > 0;

  const torHits: string[] = [];
  if (onionooTor) torHits.push("Tor Onionoo");
  if (pcIsTor) torHits.push("proxycheck.io");
  if (ipapi?.is_tor === true) torHits.push("ipapi.is");
  if (ipquery?.risk?.is_tor === true) torHits.push("ipquery.io");
  if (shodanHasTor) torHits.push("Shodan");
  if (abuseData?.isTor === true) torHits.push("AbuseIPDB");
  const isTor = torHits.length > 0;

  const mobileHits: string[] = [];
  if (ipapi?.is_mobile === true) mobileHits.push("ipapi.is");
  if (ipquery?.risk?.is_mobile === true) mobileHits.push("ipquery.io");
  if (ipapiComOk && ipapiCom.mobile === true) mobileHits.push("ip-api.com");
  if (abuseUsage.includes("mobile")) mobileHits.push("AbuseIPDB");
  const isMobile = mobileHits.length > 0;

  const isCrawler = ipapi?.is_crawler === true || abuseUsage.includes("search engine spider");

  const ipqThreat = Number(ipquery?.risk?.assessment?.threat_score) || 0;
  const ipqRisk = Number(ipquery?.risk?.risk_score) || 0;
  const abuseDbConf = Number(abuseData?.abuseConfidenceScore) || 0;
  const abuseDbReports = Number(abuseData?.totalReports) || 0;
  const abuserRatio = Math.max(
    parseAbuserRatio(ipapi?.company?.abuser_score),
    parseAbuserRatio(ipapi?.asn?.abuser_score),
  );

  const abuseHits: string[] = [];
  if (abuseData && abuseDbConf >= 20) abuseHits.push(`AbuseIPDB (${abuseDbReports} / ${abuseDbConf}%)`);
  if (sfsHit) abuseHits.push(`StopForumSpam (${sfsFreq})`);
  if (ipapi?.is_abuser === true || abuserRatio >= 0.05) abuseHits.push("ipapi.is");
  if (ipqThreat > 0 || ipqRisk >= 50) abuseHits.push("ipquery.io");
  if (pcIsCompromised) abuseHits.push("proxycheck (Compromised)");
  if (shodanCompromised) abuseHits.push("Shodan (malware/botnet)");
  if (exposure.vulnsCount >= 3) abuseHits.push(`Shodan CVE:${exposure.vulnsCount}`);
  if (isCrawler) abuseHits.push("Crawler");
  const isAbuser = abuseHits.length > 0;

  const isKnownResAsn = RESIDENTIAL_ASNS.has(asnNum);
  const hasResWords = containsAny(combinedText, RESIDENTIAL_WORDS);
  const hasBizWords =
    containsAny(combinedText, BUSINESS_WORDS) ||
    compType === "business" ||
    compType === "education" ||
    compType === "government";

  const proxyChecked = [
    pcData ? "proxycheck.io" : "",
    ip2locOk && "is_proxy" in ip2loc ? "IP2Location" : "",
    ipqueryOk && ipquery.risk ? "ipquery.io" : "",
    ipapiComOk ? "ip-api.com" : "",
    freeipOk && "isProxy" in freeip ? "FreeIPAPI" : "",
    ipapiHasRisk ? "ipapi.is" : "",
    shodanOk ? "Shodan" : "",
  ].filter(Boolean);

  const isSingleHeuristicProxy =
    proxyHits.length === 1 &&
    (proxyHits[0] === "ip-api.com" || proxyHits[0] === "FreeIPAPI") &&
    proxyChecked.length >= 3;
  const strongProxyOrAnon = isTor || vpnHits.length > 0 || (proxyHits.length > 0 && !isSingleHeuristicProxy);
  const strongResEvidence =
    (compType === "isp" && asnType === "isp") ||
    isKnownResAsn ||
    (compType === "isp" && !asnType) ||
    (!compType && asnType === "isp");
  const isDualRoleIsp =
    ((asnType === "isp" || isKnownResAsn) && isDc) ||
    (compType === "isp" && (isDc || asnType === "hosting"));

  let type: Report["type"];
  if (isMobile && !isDc) {
    type = { code: "mobile", label: "移动网络", residential: false, confidence: "high", reason: "蜂窝移动运营商出口" };
  } else if (isDualRoleIsp && !dcByKeyword) {
    type = { code: "dual_isp", label: "双 ISP 托管", residential: false, confidence: "high", reason: "ISP 段但命中机房/托管特征" };
  } else if (isDc) {
    type = { code: "datacenter", label: "机房 IP", residential: false, confidence: dcByApi ? "high" : "medium", reason: dcByApi ? "命中数据中心/云主机库" : "组织或 rDNS 命中机房特征" };
  } else if (hasBizWords) {
    type = { code: "business", label: "商业宽带", residential: false, confidence: "medium", reason: "企业/高校/政企专线" };
  } else if ((compType === "isp" || asnType === "isp" || isKnownResAsn || hasResWords) && !strongProxyOrAnon) {
    if (isNative === false) {
      if (strongResEvidence) {
        type = { code: "residential", label: "家宽 IP", residential: true, confidence: "medium", reason: "住宅运营商宽带但跨区广播（非原生）" };
      } else {
        type = { code: "dual_isp", label: "广播 ISP", residential: false, confidence: "medium", reason: "ISP 特征但跨区广播" };
      }
    } else {
      type = {
        code: "residential",
        label: "家宽 IP",
        residential: true,
        confidence: strongResEvidence ? "high" : "medium",
        reason: isNative === true ? "原生住宅运营商宽带" : "住宅运营商宽带",
      };
    }
  } else if (compType === "isp" || isKnownResAsn || hasResWords) {
    type = { code: "dual_isp", label: "住宅代理", residential: false, confidence: "medium", reason: "ISP 段但命中代理/VPN" };
  } else {
    type = { code: "unknown", label: "商业/未分类", residential: false, confidence: "low", reason: "缺乏家宽证据，审慎归类" };
  }

  let humanRatio: RadarBotData;
  if (radar) {
    humanRatio = { human: radar.human, bot: radar.bot, source: "cloudflare-radar" };
  } else {
    let humanEst =
      type.code === "residential" ? (type.confidence === "high" ? 95 : 90) :
      type.code === "mobile" ? 88 :
      type.code === "business" ? 76 :
      type.code === "dual_isp" ? 58 :
      type.code === "datacenter" ? 32 : 68;
    if (isNative === false) humanEst -= 10;
    if (isProxy) humanEst -= 20;
    if (isVpn) humanEst -= 15;
    if (isTor) humanEst -= 28;
    if (isAbuser) humanEst -= 20;
    const h = Math.max(3, Math.min(98, Math.round(humanEst)));
    humanRatio = { human: h, bot: 100 - h, source: "estimated" };
  }

  const breakdown: ScoreBreakdownItem[] = [];
  const addScore = (
    key: string,
    label: string,
    delta: number,
    reason: string,
    meta?: Record<string, string | number>,
  ) => {
    if (delta > 0) breakdown.push({ key, label, delta, reason, ...(meta ? { meta } : {}) });
  };

  if (type.code === "residential") {
    addScore("baseline_residential", "网络基线", type.confidence === "high" ? 5 : 9, isNative === false ? "非原生住宅宽带基线" : "原生住宅宽带基线");
  } else if (type.code === "mobile") addScore("baseline_mobile", "网络基线", 14, "移动蜂窝 CGNAT 共享出口");
  else if (type.code === "business") addScore("baseline_business", "网络基线", 18, "企业/机构商用网络");
  else if (type.code === "dual_isp") addScore("baseline_dual_isp", "网络基线", 26, "双 ISP / 广播托管段");
  else if (type.code === "datacenter") addScore("baseline_datacenter", "网络基线", 33, "数据中心 / 云主机网络");
  else addScore("baseline_unknown", "网络基线", 22, "归属证据不足审慎基线");

  if (radar) {
    if (type.code === "residential") {
      if (radar.bot >= 85) addScore("radar_bot", "ASN 机器流量", 8, `Radar 实测该 ASN 机器流量占比 ${radar.bot}%`, { bot: radar.bot });
      else if (radar.bot >= 70) addScore("radar_bot", "ASN 机器流量", 4, `Radar 实测该 ASN 机器流量占比 ${radar.bot}%`, { bot: radar.bot });
    } else if (radar.bot >= 20) {
      const botDelta = Math.min(12, Math.max(1, Math.round((radar.bot - 15) * 0.16)));
      addScore("radar_bot", "ASN 机器流量", botDelta, `Radar 实测该 ASN 机器流量占比 ${radar.bot}%`, { bot: radar.bot });
    }
  }

  const broadcastRegCC = prefixRegisteredCC || registeredCC;
  if (isNative === false) {
    addScore("broadcast", "跨区广播", 14, `注册国 ${broadcastRegCC} ≠ 定位国 ${loc.cc}`, { reg: broadcastRegCC, loc: loc.cc });
  }
  if (isTor) addScore("tor", "Tor 节点", 45, "命中 Tor 匿名出口");
  if (isVpn) {
    const vpnDelta = vpnHits.length >= 2 ? 20 : 9;
    addScore("vpn", "VPN 出口", vpnDelta, vpnHits.length >= 2 ? "多源命中 VPN 出口节点" : "单一情报源标记 VPN 出口");
  }
  if (isProxy) {
    const proxyDelta = proxyHits.length >= 2 ? 22 : isSingleHeuristicProxy ? 7 : 12;
    const proxyReason = proxyHits.length >= 2
      ? "多源命中公开代理或转发节点"
      : isSingleHeuristicProxy
        ? "单一来源存在代理疑点（多数源未命中）"
        : "单一情报源标记代理节点";
    addScore("proxy", "代理节点", proxyDelta, proxyReason);
  }
  if (isDc && (isTor || (isProxy && isVpn) || proxyHits.length >= 2 || vpnHits.length >= 2)) {
    addScore("dc_proxy", "机房代理叠加", 7, "机房 + 多源代理/VPN 复合高危特征");
  }

  const directAbuseHits = abuseHits.filter((h) => !h.startsWith("AbuseIPDB") && h !== "Crawler" && !h.startsWith("Shodan CVE"));
  if (abuseData && abuseDbConf > 0) {
    const scaled = abuseDbConf >= 20
      ? Math.min(38, Math.max(16, Math.round(10 + abuseDbConf * 0.3)))
      : Math.max(5, Math.round(abuseDbConf * 0.6));
    addScore("abuseipdb", "AbuseIPDB 举报", scaled, `近 90 天被举报 ${abuseDbReports} 次（置信度 ${abuseDbConf}%）`, { reports: abuseDbReports, conf: abuseDbConf });
    if (directAbuseHits.length > 0) {
      const extraAbuse = abuserRatio >= 0.1 || ipqThreat >= 60 || shodanCompromised || sfsConf >= 50 ? 12 : 8;
      addScore("abuse_generic", "滥用与威胁", extraAbuse, "多源交叉命中滥用或威胁情报");
    }
  } else {
    if (abuseData && abuseDbReports > 0) {
      const histDelta = abuseDbReports >= 5 ? 4 : 2;
      addScore("abuse_history", "历史举报记录", histDelta, `AbuseIPDB 近 90 天存在 ${abuseDbReports} 次历史举报`, { reports: abuseDbReports });
    }
    if (directAbuseHits.length > 0) {
      const abuseDelta = abuserRatio >= 0.1 || ipqThreat >= 60 || shodanCompromised || sfsConf >= 50 ? 24 : 16;
      addScore("abuse_generic", "滥用与威胁", abuseDelta, "命中滥用或威胁情报源");
    }
  }

  if (isCrawler) addScore("crawler", "爬虫来源", 10, "命中商业/抓取爬虫库");
  if (exposure.vulnsCount >= 3) addScore("vulns", "暴露面漏洞", 6, `Shodan 发现 ${exposure.vulnsCount} 个已知漏洞特征`, { count: exposure.vulnsCount });

  const riskPorts = exposure.ports.filter((p) => p !== 53 && p !== 80 && p !== 443);
  if (type.code !== "residential" && riskPorts.length > 0) {
    const portDelta = riskPorts.length >= 3 ? 4 : 2;
    addScore("open_ports", "管理/代理端口暴露", portDelta, `开放端口 ${riskPorts.slice(0, 4).join(", ")}`, { ports: riskPorts.slice(0, 4).join(", ") });
  }

  const fraud = Math.max(0, Math.min(100, Math.round(breakdown.reduce((s, x) => s + x.delta, 0))));
  const trust = 100 - fraud;

  const vpnChecked = [
    pcData ? "proxycheck.io" : "",
    ipqueryOk && ipquery.risk ? "ipquery.io" : "",
    ipapiHasRisk ? "ipapi.is" : "",
    shodanOk ? "Shodan端口" : "",
    rdns ? "rDNS" : "",
  ].filter(Boolean);

  const torChecked = [
    onionooOk ? "Tor Onionoo" : "",
    pcData ? "proxycheck.io" : "",
    ipqueryOk && ipquery.risk ? "ipquery.io" : "",
    ipapiHasRisk ? "ipapi.is" : "",
    shodanOk ? "Shodan" : "",
    abuseData ? "AbuseIPDB" : "",
  ].filter(Boolean);

  const dcChecked = [
    ipqueryOk && ipquery.risk ? "ipquery.io" : "",
    ipapiComOk ? "ip-api.com" : "",
    ipapiHasRisk ? "ipapi.is" : "",
    shodanOk ? "Shodan" : "",
    combinedText.trim() ? "ASN/rDNS" : "",
  ].filter(Boolean);

  const mobileChecked = [
    ipapiComOk ? "ip-api.com" : "",
    ipqueryOk && ipquery.risk ? "ipquery.io" : "",
    ipapiHasRisk ? "ipapi.is" : "",
    abuseData ? "AbuseIPDB" : "",
  ].filter(Boolean);

  const abuseChecked = [
    sfsOk ? "StopForumSpam" : "",
    abuseData ? "AbuseIPDB" : "",
    shodanOk ? "Shodan" : "",
    ipqueryOk && ipquery.risk ? "ipquery.io" : "",
    pcData ? "proxycheck.io" : "",
    ipapiHasRisk ? "ipapi.is" : "",
  ].filter(Boolean);

  const abuseCleanParts: string[] = [];
  if (abuseData) abuseCleanParts.push(`AbuseIPDB ${abuseDbReports}次(${abuseDbConf}%)`);
  if (sfsOk) abuseCleanParts.push(`StopForumSpam ${sfsFreq}次`);
  if (shodanOk) abuseCleanParts.push(`Shodan ${exposure.vulnsCount}漏洞`);
  if (ipqueryOk && ipquery.risk) abuseCleanParts.push(`ipquery 风险 ${ipqRisk}`);
  const abuseDetailStr = abuseHits.length
    ? abuseHits.join(" · ")
    : (abuseCleanParts.length ? abuseCleanParts.join(" · ") : "");

  const signals: Signal[] = [
    {
      key: "proxy",
      label: "代理服务器",
      detected: isProxy,
      checked: proxyChecked,
      hits: proxyHits,
      desc: isProxy
        ? `命中：${proxyHits.join("、")}`
        : (proxyChecked.length ? `已核验 ${proxyChecked.join(" · ")}，未见代理特征` : "流量是否经过公开代理或匿名代理转发"),
    },
    {
      key: "vpn",
      label: "VPN 出口",
      detected: isVpn,
      checked: vpnChecked,
      hits: vpnHits,
      desc: isVpn
        ? `命中：${vpnHits.join("、")}`
        : (vpnChecked.length ? `已核验 ${vpnChecked.join(" · ")}，未见 VPN 特征` : "是否为已知 VPN 服务的出口节点"),
    },
    {
      key: "tor",
      label: "Tor 网络",
      detected: isTor,
      checked: torChecked,
      hits: torHits,
      desc: isTor
        ? `命中：${torHits.join("、")}`
        : (torChecked.length ? `已核验 ${torChecked.join(" · ")}，非 Tor 出口` : "是否为 Tor 匿名网络的出口节点"),
    },
    {
      key: "datacenter",
      label: "数据中心",
      detected: isDc,
      checked: dcChecked,
      hits: dcHits,
      desc: isDc
        ? `命中：${dcHits.join("、")}`
        : (dcChecked.length ? `已核验 ${dcChecked.join(" · ")}，非云机房/IDC` : "是否托管于云服务商或机房，而非家庭网络"),
    },
    {
      key: "mobile",
      label: "移动网络",
      detected: isMobile,
      checked: mobileChecked,
      hits: mobileHits,
      desc: isMobile
        ? `命中：${mobileHits.join("、")}`
        : (mobileChecked.length ? `已核验 ${mobileChecked.join(" · ")}，非蜂窝移动网络` : "是否通过蜂窝移动网络接入互联网"),
    },
    {
      key: "abuse",
      label: "滥用威胁",
      detected: isAbuser,
      checked: abuseChecked,
      hits: abuseHits,
      meta: {
        ...(abuseData ? { abuseReports: abuseDbReports, abuseConf: abuseDbConf } : {}),
        ...(sfsOk ? { sfsFreq } : {}),
        ...(shodanOk ? { vulns: exposure.vulnsCount } : {}),
        ...(ipqueryOk && ipquery.risk ? { ipqRisk } : {}),
      },
      ...(abuseDetailStr ? { detail: abuseDetailStr } : {}),
      desc: isAbuser
        ? `命中：${abuseHits.join(" · ")}`
        : (abuseDetailStr || "是否出现在滥用、黑名单或自动化爬虫情报源中"),
    },
  ];

  return {
    ok: true,
    ip,
    ipNumeric,
    ...(queriedDomain ? { queriedDomain } : {}),
    version,
    sources: activeSources,
    location: {
      country: loc.country,
      countryCode: loc.cc,
      region: loc.region,
      city: loc.city,
      zip: loc.zip,
      lat: loc.lat,
      lon: loc.lon,
      timezone: loc.timezone,
      localtime: loc.localtime,
      registeredCountryCode: registeredCC,
      isNative,
      geoTypeLabel,
      multiSource,
    },
    network: {
      asn: asnStr,
      asnType: asnType ? companyTypeLabel(asnType) : "—",
      org: orgStr,
      isp: ispStr,
      route,
      ipRange,
      rdns,
    },
    company,
    type,
    scores: {
      trust,
      fraud,
      ...riskLabel(fraud),
      breakdown,
    },
    humanRatio,
    exposure,
    ...(abuseData ? {
      abuse: {
        confidence: abuseDbConf,
        reports: abuseDbReports,
        lastReportedAt: fmtShortDate(abuseData.lastReportedAt),
      },
    } : {}),
    signals,
    registryHistory,
    bgpHistory,
    assessedAt: new Date().toISOString(),
  };
}

async function withSoftDeadline<T>(promise: Promise<T>, ms: number, fallback: T): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  return await Promise.race([
    promise,
    new Promise<T>((resolve) => {
      timer = setTimeout(() => resolve(fallback), Math.max(0, ms));
    }),
  ]).finally(() => {
    if (timer !== undefined) clearTimeout(timer);
  });
}

function resolveWhenPrimaryReady(checks: Array<Promise<boolean>>): Promise<void> {
  return new Promise((resolve) => {
    let pending = checks.length;
    let settled = false;
    for (const p of checks) {
      p.then((ok) => {
        pending--;
        if (!settled && (ok || pending <= 0)) {
          settled = true;
          resolve();
        }
      }).catch(() => {
        pending--;
        if (!settled && pending <= 0) {
          settled = true;
          resolve();
        }
      });
    }
  });
}

async function fetchFresh(
  ip: string,
  queriedDomain?: string,
  env?: Record<string, unknown>,
): Promise<Report> {
  const startedAt = Date.now();
  const encoded = encodeURIComponent(ip);
  const abuseKey = getEnvAny(env, ["ABUSEIPDB_KEY", "ABUSEIPDB_API_KEY", "ABUSE_KEY"]);
  const ipapiKey = getEnvAny(env, ["IPAPI_IS_KEY"]);
  const ipinfoToken = getEnvAny(env, ["IPINFO_TOKEN"]);
  const ip2locKey = getEnvAny(env, ["IP2LOCATION_KEY"]);
  const pcKey = getEnvAny(env, ["PROXYCHECK_KEY"]);

  // Edge-triggered early ASN resolution so Cloudflare Radar starts immediately instead of waiting for slow tails.
  let earlyAsnResolved = false;
  let resolveEarlyAsn!: (asn: number) => void;
  const earlyAsnPromise = new Promise<number>((resolve) => {
    resolveEarlyAsn = resolve;
  });
  const watchAsn = <T>(p: Promise<T>, extract: (val: T) => number): Promise<T> =>
    p.then((val) => {
      if (!earlyAsnResolved) {
        const n = extract(val);
        if (n > 0) {
          earlyAsnResolved = true;
          resolveEarlyAsn(n);
        }
      }
      return val;
    });

  const ipapiP = watchAsn(
    fetchJson(`https://api.ipapi.is/?q=${encoded}${ipapiKey ? `&key=${encodeURIComponent(ipapiKey)}` : ""}`, 3400).catch(() => null),
    (x) => asnNumber(typeof x?.asn === "string" ? x.asn : x?.asn?.asn),
  );
  const ipqueryP = watchAsn(
    fetchJson(`https://api.ipquery.io/${encoded}`, 3400).catch(() => null),
    (x) => asnNumber(x?.isp?.asn),
  );
  const ipapiComP = watchAsn(
    fetchJson(
      `http://ip-api.com/json/${encoded}?fields=status,country,countryCode,regionName,city,lat,lon,timezone,zip,isp,org,as,asname,reverse,mobile,proxy,hosting`,
      3200,
    ).catch(() => null),
    (x) => asnNumber(x?.as),
  );
  const ipwhoP = watchAsn(
    fetchJson(`https://ipwho.is/${encoded}`, 3200).catch(() => null),
    (x) => asnNumber(x?.connection?.asn),
  );
  const geojsP = watchAsn(
    fetchJson(`https://get.geojs.io/v1/ip/geo/${encoded}.json`, 3000).catch(() => null),
    (x) => asnNumber(x?.asn),
  );
  const freeipP = fetchJson(`https://freeipapi.com/api/json/${encoded}`, 3000).catch(() => null);
  const ipinfoP = fetchJson(`https://ipinfo.io/${encoded}/json${ipinfoToken ? `?token=${encodeURIComponent(ipinfoToken)}` : ""}`, 3200).catch(() => null);
  const ip2locP = watchAsn(
    fetchJson(`https://api.ip2location.io/?ip=${encoded}${ip2locKey ? `&key=${encodeURIComponent(ip2locKey)}` : ""}`, 3400).catch(() => null),
    (x) => asnNumber(x?.asn),
  );
  const ipsbP = watchAsn(
    fetchJson(`https://api.ip.sb/geoip/${encoded}`, 3000).catch(() => null),
    (x) => asnNumber(x?.asn),
  );
  const ipguideP = watchAsn(
    fetchJson(`https://ip.guide/${encoded}`, 3200).catch(() => null),
    (x) => asnNumber(x?.network?.autonomous_system?.asn),
  );
  const ipapicoP = fetchJson(`https://ipapi.co/${encoded}/json/`, 3000).catch(() => null);

  const proxycheckP = fetchJson(`https://proxycheck.io/v2/${encoded}?vpn=1&asn=1${pcKey ? `&key=${encodeURIComponent(pcKey)}` : ""}`, 3400).catch(() => null);
  const onionooP = fetchJson(`https://onionoo.torproject.org/details?search=${encoded}&limit=1`, 3400).catch(() => null);
  const sfsP = fetchJson(`https://api.stopforumspam.org/api?ip=${encoded}&json`, 3000).catch(() => null);
  const rdapP = fetchJson(`https://rdap.org/ip/${encoded}`, 3500).catch(() => null);
  const ripeRirP = fetchJson(`https://stat.ripe.net/data/rir/data.json?resource=${encoded}`, 3500).catch(() => null);
  const ripeGeoP = fetchJson(`https://stat.ripe.net/data/maxmind-geo-lite/data.json?resource=${encoded}`, 3500).catch(() => null);
  // All IP-only RIR/history lookups run concurrently in wave 1; Radar starts early on first resolved ASN.
  const ripeHistP = fetchJson(`https://stat.ripe.net/data/routing-history/data.json?resource=${encoded}&min_peers=10`, 3000).catch(() => null);
  const rirCountryP = fetchJson(`https://stat.ripe.net/data/rir-stats-country/data.json?resource=${encoded}`, 3000).catch(() => null);
  const shodanP = IPV4_RE.test(ip) ? fetchJson(`https://internetdb.shodan.io/${encoded}`, 3000).catch(() => null) : Promise.resolve(null);
  const abuseDbP = abuseKey
    ? fetchJson(`https://api.abuseipdb.com/api/v2/check?ipAddress=${encoded}&maxAgeInDays=90`, 3000, { key: abuseKey }).catch(() => null)
    : Promise.resolve(null);

  const radarP = earlyAsnPromise.then((asn) => (asn ? fetchRadarBotClass(asn, env) : null));
  const radarEntityP = earlyAsnPromise.then((asn) => (asn ? fetchRadarAsnEntity(asn, env) : null));

  const primaryChecks: Array<Promise<boolean>> = [
    ipapiP.then((d) => !!(d && d.ip && !d.error)),
    ipqueryP.then((d) => !!(d && d.ip && d.location)),
    ipapiComP.then((d) => !!(d && d.status === "success")),
    ipwhoP.then((d) => !!(d && d.success === true)),
    geojsP.then((d) => !!(d && d.country_code)),
    freeipP.then((d) => !!(d && d.countryCode)),
    ipinfoP.then((d) => !!(d && d.country && !d.error)),
    ip2locP.then((d) => !!(d && d.country_code && !d.error)),
    ipsbP.then((d) => !!(d && d.country_code)),
    ipguideP.then((d) => !!d?.location),
    ipapicoP.then((d) => !!(d && d.country_code && !d.error)),
  ];

  // Guarantee earlyAsnPromise settles once primary feeds finish if none yielded an ASN.
  Promise.all(primaryChecks).then(() => {
    if (!earlyAsnResolved) {
      earlyAsnResolved = true;
      resolveEarlyAsn(0);
    }
  });

  // Wait until at least one primary GeoIP source succeeds (or all primary sources fail).
  await resolveWhenPrimaryReady(primaryChecks);

  // Single bounded budget (~3.0s total) for remaining feeds & Radar; never serialize extra waterfalls.
  const totalBudgetMs = 3000;
  const remaining = Math.max(400, totalBudgetMs - (Date.now() - startedAt));

  const [
    ipapi, ipquery, ipapiCom, ipwho, geojs, freeip,
    ipinfo, ip2loc, ipsb, ipguide, ipapico,
    proxycheck, onionoo, sfs,
    rdap, ripeRir, ripeGeo, ripeHist, rirCountryRaw, shodan, abuseDb,
    radar, radarEntity,
  ] = await Promise.all([
    withSoftDeadline(ipapiP, remaining, null),
    withSoftDeadline(ipqueryP, remaining, null),
    withSoftDeadline(ipapiComP, remaining, null),
    withSoftDeadline(ipwhoP, remaining, null),
    withSoftDeadline(geojsP, remaining, null),
    withSoftDeadline(freeipP, remaining, null),
    withSoftDeadline(ipinfoP, remaining, null),
    withSoftDeadline(ip2locP, remaining, null),
    withSoftDeadline(ipsbP, remaining, null),
    withSoftDeadline(ipguideP, remaining, null),
    withSoftDeadline(ipapicoP, remaining, null),
    withSoftDeadline(proxycheckP, remaining, null),
    withSoftDeadline(onionooP, remaining, null),
    withSoftDeadline(sfsP, remaining, null),
    withSoftDeadline(rdapP, remaining, null),
    withSoftDeadline(ripeRirP, remaining, null),
    withSoftDeadline(ripeGeoP, remaining, null),
    withSoftDeadline(ripeHistP, remaining, null),
    withSoftDeadline(rirCountryP, remaining, null),
    withSoftDeadline(shodanP, remaining, null),
    withSoftDeadline(abuseDbP, remaining, null),
    withSoftDeadline(radarP, remaining, null),
    withSoftDeadline(radarEntityP, remaining, null),
  ]);

  const anyPrimaryOk =
    (ipapi && ipapi.ip && !ipapi.error) ||
    (ipquery && ipquery.ip && ipquery.location) ||
    (ipapiCom && ipapiCom.status === "success") ||
    (ipwho && ipwho.success === true) ||
    (geojs && geojs.country_code) ||
    (freeip && freeip.countryCode) ||
    (ipinfo && ipinfo.country && !ipinfo.error) ||
    (ip2loc && ip2loc.country_code && !ip2loc.error) ||
    (ipsb && ipsb.country_code) ||
    (ipguide && ipguide.location) ||
    (ipapico && ipapico.country_code && !ipapico.error);

  if (!anyPrimaryOk) throw new Error("upstream_unavailable");

  const rdapQuickCC = extractRdapInfo(rdap).countryCode;
  const needRirCountry = !rdapQuickCC && !normalizeCountryCode(ripeRir?.data?.rirs?.[0]?.country);
  const rirCountry = needRirCountry ? rirCountryRaw : null;

  return buildReport(
    ip,
    {
      ipapi, ipquery, ipapiCom, ipwho, geojs, freeip,
      ipinfo, ip2loc, ipsb, ipguide, ipapico,
      proxycheck, onionoo, sfs,
      rdap, rirCountry, ripeRir, ripeGeo, ripeHist, shodan, radar, radarEntity, abuseDb,
    },
    queriedDomain,
  );
}

function cacheReport(ip: string, report: Report) {
  if (cache.size >= CACHE_MAX) {
    const oldest = cache.keys().next().value;
    if (oldest !== undefined) cache.delete(oldest);
  }
  cache.set(ip, { at: Date.now(), report });
}

async function lookup(ip: string, queriedDomain?: string, env?: Record<string, unknown>): Promise<Report> {
  const hit = cache.get(ip);
  if (hit && Date.now() - hit.at < CACHE_TTL) {
    return queriedDomain ? { ...hit.report, queriedDomain } : hit.report;
  }
  const report = await fetchFresh(ip, queriedDomain, env);
  cacheReport(ip, report);
  return report;
}

function setBoundedCache<K, V>(map: Map<K, V>, max: number, key: K, value: V) {
  if (map.size >= max) {
    const oldest = map.keys().next().value;
    if (oldest !== undefined) map.delete(oldest);
  }
  map.set(key, value);
}

/* ================= 免费真实街道地址反查 ================= */
async function lookupGeoAddress(
  lat: number,
  lon: number,
  timezone: string,
  jitter: boolean,
): Promise<Record<string, unknown>> {
  let qLat = lat;
  let qLon = lon;
  if (jitter) {
    const angle = Math.random() * Math.PI * 2;
    const radius = 0.004 + Math.random() * 0.012;
    qLat = Number((lat + Math.sin(angle) * radius).toFixed(5));
    qLon = Number((lon + Math.cos(angle) * radius).toFixed(5));
  }

  const cacheKey = `${qLat.toFixed(3)},${qLon.toFixed(3)}`;
  if (!jitter) {
    const hit = geoAddrCache.get(cacheKey);
    if (hit && Date.now() - hit.at < GEOADDR_TTL) {
      return { ...hit.data, timezone: timezone || hit.data.timezone || "—" };
    }
  }

  try {
    const nom = await fetchJson(
      `https://nominatim.openstreetmap.org/reverse?format=jsonv2&lat=${qLat}&lon=${qLon}&zoom=18&addressdetails=1`,
      3200,
      { "user-agent": "IPSpot/1.0 (https://ipspot.org; hezhanleiok@gmail.com)", "accept-language": "en" },
    );
    const a = nom?.address;
    if (a && typeof a === "object") {
      const streetParts = [a.house_number, a.road || a.pedestrian || a.footway || a.neighbourhood || a.suburb].filter(Boolean);
      const data = {
        ok: true,
        source: "OpenStreetMap",
        lat: qLat,
        lon: qLon,
        street: streetParts.join(" ") || a.quarter || a.city_district || "—",
        city: a.city || a.town || a.village || a.municipality || a.county || "—",
        state: a.state || a.province || a.region || "—",
        country: a.country || "—",
        countryCode: String(a.country_code || "").toUpperCase(),
        postcode: a.postcode || "—",
        timezone: timezone || "—",
      };
      if (!jitter) setBoundedCache(geoAddrCache, 1500, cacheKey, { at: Date.now(), data });
      return data;
    }
  } catch { /* fallback */ }

  try {
    const ph = await fetchJson(`https://photon.komoot.io/reverse?lat=${qLat}&lon=${qLon}`, 3200);
    const p = ph?.features?.[0]?.properties;
    if (p && typeof p === "object") {
      const streetParts = [p.housenumber, p.street || p.name || p.district].filter(Boolean);
      const data = {
        ok: true,
        source: "Photon (OSM)",
        lat: qLat,
        lon: qLon,
        street: streetParts.join(" ") || "—",
        city: p.city || p.county || p.locality || "—",
        state: p.state || "—",
        country: p.country || "—",
        countryCode: String(p.countrycode || "").toUpperCase(),
        postcode: p.postcode || "—",
        timezone: timezone || "—",
      };
      if (!jitter) setBoundedCache(geoAddrCache, 1500, cacheKey, { at: Date.now(), data });
      return data;
    }
  } catch { /* fallback */ }

  try {
    const bdc = await fetchJson(
      `https://api.bigdatacloud.net/data/reverse-geocode-client?latitude=${qLat}&longitude=${qLon}&localityLanguage=en`,
      5000,
    );
    if (bdc && bdc.countryName) {
      const data = {
        ok: true,
        source: "BigDataCloud",
        lat: qLat,
        lon: qLon,
        street: bdc.locality || "—",
        city: bdc.city || bdc.locality || "—",
        state: bdc.principalSubdivision || "—",
        country: bdc.countryName || "—",
        countryCode: String(bdc.countryCode || "").toUpperCase(),
        postcode: bdc.postcode || "—",
        timezone: timezone || "—",
      };
      if (!jitter) setBoundedCache(geoAddrCache, 1500, cacheKey, { at: Date.now(), data });
      return data;
    }
  } catch { /* ignore */ }

  return { ok: false, error: "geoaddr_unavailable", message: "Reverse geocoding unavailable" };
}

/* ================= 5 层免费多语言 AI 自动容灾引擎 ================= */
type IpProfileCategory =
  | "native_residential_clean"
  | "native_residential_risky"
  | "broadcast_residential"
  | "dual_isp"
  | "datacenter_clean"
  | "datacenter_risky"
  | "mobile"
  | "business";

function classifyIpProfile(report: Report): IpProfileCategory {
  const fraud = report.scores.fraud;
  const hasAnon = report.signals.some((s) => (s.key === "tor" || s.key === "vpn" || s.key === "proxy") && s.detected);
  const hasAbuse = report.signals.some((s) => s.key === "abuse" && s.detected) || (report.abuse?.confidence ?? 0) >= 20;
  const isBroadcast = report.location.isNative === false;
  const reports = report.abuse?.reports ?? 0;

  if (report.type.code === "residential") {
    if (isBroadcast) return "broadcast_residential";
    if (hasAbuse || fraud > 20 || reports >= 3) return "native_residential_risky";
    return "native_residential_clean";
  }
  if (report.type.code === "dual_isp") return "dual_isp";
  if (report.type.code === "mobile") return "mobile";
  if (report.type.code === "business") return "business";
  if (report.type.code === "datacenter") {
    return !hasAnon && !hasAbuse && !isBroadcast && fraud <= 42 ? "datacenter_clean" : "datacenter_risky";
  }
  return hasAnon || hasAbuse || isBroadcast || fraud > 42 ? "datacenter_risky" : "business";
}

function buildRuleBasedAnalysis(report: Report, clientEnv: any, lang: Lang): string {
  const fraud = report.scores.fraud;
  const trust = report.scores.trust;
  const bot = report.humanRatio.bot;
  const profile = classifyIpProfile(report);
  const asnLabel = report.network.asn || report.company.name || "ISP";
  const regCC = report.location.registeredCountryCode || "—";
  const locCC = report.location.countryCode || "—";
  const isBroadcast = report.location.isNative === false;
  const routeTagEn = isBroadcast ? `${regCC}→${locCC}` : (report.location.isNative === true ? `native ${locCC}` : locCC);
  const routeTagZh = isBroadcast ? `${regCC}→${locCC}` : (report.location.isNative === true ? `原生 ${locCC}` : locCC);
  const routeTagJa = isBroadcast ? `${regCC}→${locCC}` : (report.location.isNative === true ? `ネイティブ ${locCC}` : locCC);
  const reports = report.abuse?.reports ?? 0;
  const conf = report.abuse?.confidence ?? 0;
  const riskPorts = report.exposure.ports.filter((p) => p !== 53 && p !== 80 && p !== 443);
  const hitNames = report.signals.filter((s) => s.detected).map((s) => s.key);
  const envWarn = clientEnv && Array.isArray(clientEnv.warnings) ? clientEnv.warnings : [];

  if (lang === "en") {
    const map: Record<IpProfileCategory, [string, string, string, string]> = {
      native_residential_clean: [
        `Clean native residential IP (${asnLabel}, ${locCC}); risk ${fraud}% / purity ${trust}/100 (ASN 7d bot avg ${bot}% is macro carrier traffic, not single-IP behavior).`,
        "Highly recommended — matches real consumer broadband with minimal Cloudflare, ChatGPT, or Claude verification friction.",
        "Recommended — well suited for social account warm-up, regional e-commerce stores, and payment checkout.",
        envWarn.length ? `IP is clean; fix local browser mismatches (${envWarn.join(", ")}) to stay consistent.` : "Clean network baseline; keep system timezone and language aligned with exit country.",
      ],
      native_residential_risky: [
        `Polluted native residential IP (${asnLabel}, ${locCC}); risk ${fraud}% / purity ${trust}/100 due to abuse history (${reports} reports, ${conf}% conf${hitNames.length ? `; signals: ${hitNames.join(", ")}` : ""}).`,
        "Use with caution — residential ASN helps, but existing abuse flags can trigger Cloudflare challenges or secondary login checks.",
        "Not ideal for high-value sign-ups or payments; limit to low-sensitivity browsing unless replaced with a cleaner IP.",
        envWarn.length ? `Also resolve local warnings (${envWarn.join(", ")}) and rotate to a clean unflagged residential IP for sensitive tasks.` : "Rotate to a clean residential IP without AbuseIPDB/spam flags before creating key accounts.",
      ],
      broadcast_residential: [
        `Non-native broadcast residential IP (${regCC} prefix → ${locCC} geo, ${asnLabel}); risk ${fraud}% / purity ${trust}/100.`,
        "Usable — recognized as residential carrier traffic for standard ChatGPT/Claude chats, though strict region-locked services may verify IP registration.",
        "Caution for local e-commerce/payments — RIR registration mismatch may trigger billing or KYC country reviews.",
        envWarn.length ? `Fix local mismatches (${envWarn.join(", ")}) and switch to true ${locCC} native residential if strict geo verification applies.` : `Use a true native ${locCC} residential IP for local banking or merchant accounts.`,
      ],
      dual_isp: [
        `Dual-ISP / residential-proxy or hosted ISP range (${report.type.reason}, ${asnLabel}); risk ${fraud}% / purity ${trust}/100.`,
        `Mixed reputation — higher CAPTCHA risk on ChatGPT/Claude (${hitNames.length ? `flagged: ${hitNames.join(", ")}` : `ASN bot ${bot}%`}).`,
        "Not recommended for social account creation, ad accounts, or payment gateways due to hybrid ISP/hosting detection.",
        envWarn.length ? `Resolve client warnings (${envWarn.join(", ")}) and migrate sensitive accounts to pure native residential.` : "Suitable for general research/scraping; use native home broadband for core accounts.",
      ],
      datacenter_clean: [
        `Native low-noise datacenter IP (${asnLabel}, ${locCC}); risk ${fraud}% / purity ${trust}/100 (ASN bot ${bot}%, ${reports} AbuseIPDB reports${riskPorts.length ? `, open ports: ${riskPorts.slice(0, 3).join("/")}` : ""}).`,
        "Light use / CAPTCHA expected — clean IP reputation avoids instant blocks, but hosting ASN lowers trust on strict AI anti-bot checks.",
        "Not recommended — non-residential cloud signature triggers risk controls on TikTok, Amazon, Stripe, or PayPal.",
        envWarn.length ? `Address browser warnings (${envWarn.join(", ")}) and reserve this VPS node for dev/API traffic.` : "Best suited for server workloads, APIs, or general browsing; switch to native residential for accounts.",
      ],
      datacenter_risky: [
        `High-risk / proxy-flagged or broadcast datacenter IP (${routeTagEn}, ${asnLabel}); risk ${fraud}% / purity ${trust}/100 (${hitNames.length ? `hits: ${hitNames.join(", ")}` : `ASN bot ${bot}%`}${reports ? `, ${reports} reports` : ""}).`,
        "Not recommended — datacenter + anonymizer/broadcast signals frequently cause Cloudflare blocks, Arkose loops, or AI model throttling.",
        "Avoid strictly — high probability of instant rejection or account suspension on e-commerce, social, and payment platforms.",
        envWarn.length ? `Multiple risks detected (${hitNames.join(", ") || "hosting"}) plus client mismatches (${envWarn.join(", ")}); switch to clean residential.` : "Do not use for accounts or payments; switch to a clean native residential IP.",
      ],
      mobile: [
        `Cellular mobile CGNAT exit (${asnLabel}, ${locCC}); risk ${fraud}% / purity ${trust}/100.`,
        "Usable — mobile carrier ASN generally clears AI checks cleanly, with occasional CAPTCHAs from shared CGNAT concurrency.",
        "Good for mobile social apps and light commerce; use fixed native residential for high-value long-term stores.",
        envWarn.length ? `Align local fingerprint (${envWarn.join(", ")}) with mobile region settings.` : "Keep device timezone and language matched to carrier region.",
      ],
      business: [
        `Enterprise / institutional commercial line (${asnLabel}, ${locCC}); risk ${fraud}% / purity ${trust}/100.`,
        "Recommended for office/work use — stable corporate ASN passes standard ChatGPT/Claude access reliably.",
        "Caution on consumer social sign-ups — commercial lines differ from home ISPs on consumer anti-fraud models.",
        envWarn.length ? `Check local warnings (${envWarn.join(", ")}); use consumer home broadband if onboarding retail social accounts.` : "Ideal for business workflows; pair with residential IP only if targeting consumer social growth.",
      ],
    };
    const [verdict, aiPlat, biz, tip] = map[profile];
    return [
      `- **Verdict**: ${verdict}`,
      `- **AI Platforms (ChatGPT/Claude)**: ${aiPlat}`,
      `- **Commerce / Social / Payments**: ${biz}`,
      `- **Recommendation**: ${tip}`,
    ].join("\n");
  }

  if (lang === "zh-TW") {
    const map: Record<IpProfileCategory, [string, string, string, string]> = {
      native_residential_clean: [
        `純淨原生家寬 IP（${asnLabel} · ${locCC}，風險 ${fraud}% / 純淨分 ${trust}）；所屬 ASN 機器流量均值 ${bot}% 屬大網宏觀統計，非單 IP 異常。`,
        "高度推薦 — 具備真實家庭寬頻信譽，存取 ChatGPT / Claude / Gemini 幾乎無驗證阻力。",
        "推薦使用 — 適合社群養號、跨境電商店鋪登入及合規支付結帳等高敏業務。",
        envWarn.length ? `IP 本身純淨，請對齊本機環境差異（${envWarn.join("、")}）。` : "目前網路基線極佳，保持時區、語言與出口地區一致即可。",
      ],
      native_residential_risky: [
        `原生家寬 IP 但存在污染記錄（${asnLabel} · ${locCC}，風險 ${fraud}% / 純淨分 ${trust}；近90天舉報 ${reports} 次 / 置信度 ${conf}%${hitNames.length ? `，命中：${hitNames.join("、")}` : ""}）。`,
        "謹慎可用 — 雖屬原生家寬，但歷史濫用權重仍可能觸發 Cloudflare 驗證或二次登入檢查。",
        "不建議用於新起號或大額支付，僅限低敏瀏覽，敏感業務建議更換無舉報家寬。",
        envWarn.length ? `請一併修正本機偏差（${envWarn.join("、")}），敏感帳號建議改用未受污染的家寬。` : "敏感業務建議重新撥號換取無舉報記錄的新鮮家寬段。",
      ],
      broadcast_residential: [
        `非原生 / 廣播家寬 IP（前綴註冊於 ${regCC} → 定位於 ${locCC}，${asnLabel}，風險 ${fraud}% / 純淨分 ${trust}）。`,
        "基本可用 — 住宅電信屬性使一般 ChatGPT / Claude 對話多可通行，但嚴格校驗註冊地的 AI 服務偶發鎖區或驗證。",
        "跨境與支付需謹慎 — RIR 註冊國與定位國不一致，易引發 PayPal、Stripe 或本土電商審核復查。",
        envWarn.length ? `請處理本機環境差異（${envWarn.join("、")}）；對原生歸屬要求嚴格的業務請換 ${locCC} 原生家寬。` : `日常存取穩定；註冊本土高敏金融或電商號建議改用真實 ${locCC} 原生家寬。`,
      ],
      dual_isp: [
        `雙 ISP / 住宅代理或混合託管段（${report.type.reason} · ${asnLabel}，風險 ${fraud}% / 純淨分 ${trust}）。`,
        `易遇風控 — 混合託管或代理特徵（${hitNames.length ? `命中 ${hitNames.join("、")}` : `ASN 機器流量 ${bot}%`}）常在 AI 平台觸發人機驗證。`,
        "不推薦用於養號、廣告戶或支付結帳，極易被電商與社群風控庫標記。",
        envWarn.length ? `修正本機環境問題（${envWarn.join("、")}），核心業務請遷移至無代理命中的純淨原生家寬。` : "適合一般資料檢索或測試，重要帳號務必切換純淨原生家寬。",
      ],
      datacenter_clean: [
        `原生普通機房 IP（${asnLabel} · ${locCC}，風險 ${fraud}% / 純淨分 ${trust}；ASN 機器流量 ${bot}%、歷史舉報 ${reports} 次${riskPorts.length ? `、開放管理/服務端口 ${riskPorts.slice(0, 3).join("/")}` : ""}）。`,
        "輕量可用但易降智/驗證 — 暫無惡意黑名單實錘，但公有雲/機房屬性存取 ChatGPT / Claude 仍易觸發驗證或配額收緊。",
        "不推薦用於跨境起號或支付 — 數據中心網段顯著偏離個人消費寬頻畫像。",
        envWarn.length ? `請修正本機偏差（${envWarn.join("、")}）；該節點更適合研發/API，敏感業務請換家寬。` : "適合開發測試、API 呼叫與普通瀏覽；社群起號或收付款請更換原生家寬 IP。",
      ],
      datacenter_risky: [
        `高風險 / 代理或廣播機房 IP（${routeTagZh} · ${asnLabel}，風險 ${fraud}% / 純淨分 ${trust}；${hitNames.length ? `命中：${hitNames.join("、")}` : `ASN 機器流量 ${bot}%`}${reports ? `、舉報 ${reports} 次` : ""}）。`,
        "不推薦 — 機房疊加代理/VPN 或高濫用特徵極易遭 Cloudflare 與 AI 平台直接攔截或降智。",
        "嚴禁使用 — 用於跨境店鋪、社群註冊與支付將大機率觸發風控拒付或關聯封號。",
        envWarn.length ? `當前風險高且存在本機偏差（${envWarn.join("、")}），請勿用於任何真實帳號，立即切換原生家寬。` : "僅限非敏感實驗查詢，重要帳號與支付請立即更換純淨原生家寬 IP。",
      ],
      mobile: [
        `蜂窩行動網路 IP（${asnLabel} · ${locCC}，風險 ${fraud}% / 純淨分 ${trust}，屬電信 CGNAT 共享出口）。`,
        "可用 — 行動營運商信譽優於一般機房，日常存取 ChatGPT / Claude 較穩，偶發驗證屬共享出口併發所致。",
        "適合行動端社群瀏覽與輕量營運；大額支付與核心長週期店鋪仍建議搭配固定原生家寬。",
        envWarn.length ? `請對齊本機指紋與行動環境差異（${envWarn.join("、")}）。` : "建議保持裝置時區語言一致，避免短時間頻繁跨越不同省份或國家。",
      ],
      business: [
        `企業 / 高校商用專線 IP（${asnLabel} · ${locCC}，風險 ${fraud}% / 純淨分 ${trust}）。`,
        "辦公推薦 — 商企專線低噪穩定，存取 ChatGPT / Claude 與開發服務表現可靠。",
        "謹慎用於 C 端社群起號 — 商業固定段落特徵有別於家庭動態寬頻，支付過濾視商家規則而定。",
        envWarn.length ? `請處理本機環境差異（${envWarn.join("、")}），日常辦公可繼續沿用。` : "日常開發與企業合規存取建議保留；若做 C 端消費社群孵化建議改用原生家寬。",
      ],
    };
    const [verdict, aiPlat, biz, tip] = map[profile];
    return [
      `- **綜合定性**：${verdict}`,
      `- **AI 平台 (ChatGPT/Claude)**：${aiPlat}`,
      `- **跨境 / 社群 / 支付**：${biz}`,
      `- **實操建議**：${tip}`,
    ].join("\n");
  }

  if (lang === "ja") {
    const map: Record<IpProfileCategory, [string, string, string, string]> = {
      native_residential_clean: [
        `クリーンなネイティブ住宅IP（${asnLabel}・${locCC}、リスク ${fraud}% / 純度 ${trust}/100）。ASN全体のBot比率 ${bot}% はキャリア網平均であり単一IPの異常ではありません。`,
        "強く推奨 — 実利用の住宅回線評価により ChatGPT / Claude での認証要求は極めて低頻度です。",
        "推奨 — SNS運用・越境ECログイン・オンライン決済まで幅広く適しています。",
        envWarn.length ? `IP自体は良好です。ローカル環境の差異（${envWarn.join("・")}）を整えてください。` : "環境は良好です。端末のタイムゾーンと言語を接続国と一致させて維持してください。",
      ],
      native_residential_risky: [
        `汚染履歴のあるネイティブ住宅IP（${asnLabel}・${locCC}、リスク ${fraud}% / 純度 ${trust}/100；報告 ${reports}件 / 信頼度 ${conf}%）。`,
        "注意が必要 — 住宅回線ではあるものの、過去の不正報告により検証要求が出やすい状態です。",
        "新規アカウント作成や決済には不向きです。低リスクな閲覧に留めてください。",
        envWarn.length ? `端末の差異（${envWarn.join("・")}）も解消し、重要用途は未汚染の住宅IPへ変更を推奨します。` : "重要アカウント用途では再接続等で別のクリーンな住宅IPに切り替えてください。",
      ],
      broadcast_residential: [
        `非ネイティブ（ブロードキャスト）住宅IP（登録国 ${regCC} → 利用地域 ${locCC}・${asnLabel}、リスク ${fraud}% / 純度 ${trust}/100）。`,
        "利用可能 — 通常の AI チャットは概ね利用できますが、RIR登録国を厳格に見るサービスでは認証が出ることがあります。",
        "決済・地域限定ECでは注意 — IP登録国と利用地の不一致が審査トリガーとなる場合があります。",
        envWarn.length ? `ローカル差異（${envWarn.join("・")}）を修正し、厳格な決済には ${locCC} ネイティブ住宅IPをご利用ください。` : `厳格な本人確認や決済には ${locCC} のネイティブ住宅回線への変更を推奨します。`,
      ],
      dual_isp: [
        `デュアルISP / 住宅プロキシ混在帯（${report.type.reason}・${asnLabel}、リスク ${fraud}% / 純度 ${trust}/100）。`,
        "認証頻発の可能性 — 商用・プロキシ混在特性により ChatGPT/Claude で制限対象になりやすい傾向です。",
        "非推奨 — SNS育成・広告アカウント・決済用途での利用は控えてください。",
        envWarn.length ? `端末設定の差異（${envWarn.join("・")}）を直し、重要業務は純粋なネイティブ住宅IPへ移行してください。` : "情報収集用途に留め、重要アカウントには通常の住宅回線を使用してください。",
      ],
      datacenter_clean: [
        `ネイティブ標準データセンターIP（${asnLabel}・${locCC}、リスク ${fraud}% / 純度 ${trust}/100；ASN Bot ${bot}%・報告 ${reports}件）。`,
        "軽量利用向け — 重大なブラックリストはありませんが、クラウド帯特有の厳格チェックでCAPTCHAや制限がかかりやすいです。",
        "非推奨 — 個人向けSNS新規登録・EC運用・決済チェックアウトでは不正検知されやすい帯域です。",
        envWarn.length ? `端末環境（${envWarn.join("・")}）を調整しつつ、サーバー/API用途に限定することを推奨します。` : "開発・API利用向きです。一般ユーザー向けのアカウント運用には住宅IPをご利用ください。",
      ],
      datacenter_risky: [
        `高リスク / プロキシ・ブロードキャスト該当データセンターIP（${routeTagJa}、リスク ${fraud}% / 純度 ${trust}/100${hitNames.length ? `・検知: ${hitNames.join(",")}` : ""}）。`,
        "非推奨 — 匿名化・高リスク帯のため Cloudflare や OpenAI / Anthropic で即座にブロック・制限される確率が高いです。",
        "使用禁止 — 決済エラーやアカウント凍結の原因となるため使用しないでください。",
        envWarn.length ? `端末差異（${envWarn.join("・")}）も含め高リスク状態のため、重要用途は必ずクリーンな住宅IPへ切り替えてください。` : "調査用途に留め、アカウントや決済では即座にクリーンなネイティブ住宅IPへ変更してください。",
      ],
      mobile: [
        `モバイルキャリア CGNAT 回線（${asnLabel}・${locCC}、リスク ${fraud}% / 純度 ${trust}/100）。`,
        "利用可能 — 携帯回線の評価は高く安定していますが、共有出口のため混雑時にCAPTCHAが出ることがあります。",
        "モバイルSNSや軽量ECに適しています。高額決済や主軸ショップには固定住宅IPが安心です。",
        envWarn.length ? `ローカル環境のズレ（${envWarn.join("・")}）をキャリア国に合わせて調整してください。` : "端末の時刻・言語設定を接続地域と一致させてご利用ください。",
      ],
      business: [
        `法人・教育機関向け商用回線（${asnLabel}・${locCC}、リスク ${fraud}% / 純度 ${trust}/100）。`,
        "業務利用に推奨 — 安定した企業帯域により標準的なAIチャットやAPI利用は快適です。",
        "個人SNSの新規育成には注意 — 家庭回線とは特性が異なるため、一部一般向けサービスで識別される場合があります。",
        envWarn.length ? `端末差異（${envWarn.join("・")}）のみ確認すれば、法人業務用途ではそのまま利用可能です。` : "ビジネス用途には適しています。個人向けSNS用途では住宅回線をご検討ください。",
      ],
    };
    const [verdict, aiPlat, biz, tip] = map[profile];
    return [
      `- **総合判定**：${verdict}`,
      `- **AI プラットフォーム**：${aiPlat}`,
      `- **EC / SNS / 決済**：${biz}`,
      `- **推奨アクション**：${tip}`,
    ].join("\n");
  }

  const map: Record<IpProfileCategory, [string, string, string, string]> = {
    native_residential_clean: [
      `纯净原生家宽 IP（${asnLabel} · ${locCC}，风险 ${fraud}% / 纯净分 ${trust}）；ASN 机器流量 ${bot}% 为整网 7 天均值，不代表当前单 IP 异常。`,
      "高度推荐 — 具备真实消费级宽带信誉，使用 ChatGPT / Claude / Gemini 极少触发验证码或降智。",
      "推荐使用 — 贴合本土家庭环境，适合 TikTok/社媒养号、跨境店铺后台登录及合规支付结账。",
      envWarn.length ? `IP 本身质量极佳，建议修正本机环境偏差（${envWarn.join("、")}）以防浏览器指纹关联。` : "当前出口与纯洁度状态极佳，保持本机时区、语言与出口国一致即可长期使用。",
    ],
    native_residential_risky: [
      `原生家宽但存在污染记录（${asnLabel} · ${locCC}，风险 ${fraud}% / 纯净分 ${trust}；近 90 天举报 ${reports} 次 / 置信度 ${conf}%${hitNames.length ? `，命中：${hitNames.join("、")}` : ""}）。`,
      "谨慎可用 — 原生家宽有一定容错，但已有滥用记录在高峰期易触发 Cloudflare 或二次人机校验。",
      "不建议高价值操作 — 可用于普通信息检索，涉及新号冷启动、广告户或大额支付建议先行更换纯净家宽。",
      envWarn.length ? `请同步处理本机偏差（${envWarn.join("、")}）；核心业务建议重新拨号获取无举报记录的家宽段。` : "如条件允许建议重拨换取 0 举报/0 威胁命中的干净原生家宽段。",
    ],
    broadcast_residential: [
      `非原生 / 广播家宽 IP（IP 段注册国 ${regCC} → 物理定位 ${locCC}，${asnLabel}，风险 ${fraud}% / 纯净分 ${trust}）。`,
      "基本可用 — 住宅运营商性质使常规 ChatGPT / Claude 对话顺畅，少数强校验 RIR 属地的 AI 服务偶发锁区提示。",
      "跨境 / 支付慎用 — 跨区广播导致 RIR 账单地与物理地偏差，易在 PayPal、Stripe 或本土电商触发风控核验。",
      envWarn.length ? `建议对齐本机环境（${envWarn.join("、")}）；若注册本土高敏金融或店铺号，请切换真正原生 ${locCC} 家宽。` : `普通浏览稳定；若做精准本土合规起号或收款，建议换成 ${locCC} 原生家宽。`,
    ],
    dual_isp: [
      `双 ISP / 混合托管或住宅代理段（${report.type.reason} · ${asnLabel}，风险 ${fraud}% / 纯净分 ${trust}）。`,
      `风控偏高 — 兼有托管或代理命中特征（${hitNames.length ? `命中 ${hitNames.join("、")}` : `ASN 机器流量 ${bot}%`}），访问 AI 平台易触发验证或降智。`,
      "不推荐 — 双 ISP/住宅代理是跨境店铺、社媒矩阵与支付网关重点拦截对象，不宜用于起号或结账。",
      envWarn.length ? `请先修正本机警告（${envWarn.join("、")}），敏感账号务必切换无代理特征的纯原生家宽。` : "仅适合辅助查询或非高敏测试；核心社媒与支付账号请更换原生家宽。",
    ],
    datacenter_clean: [
      `原生普通机房 IP（${asnLabel} · ${locCC}，风险 ${fraud}% / 纯净分 ${trust}；ASN 机器流量 ${bot}%、历史举报 ${reports} 次${riskPorts.length ? `、暴露端口 ${riskPorts.slice(0, 3).join("/")}` : ""}）。`,
      "仅限轻量使用 — 暂无公开代理或高危黑名单，但机房 ASN 属性容易在 ChatGPT / Claude 触发验证码或模型降智。",
      "不推荐 — 非家宽云主机网段直接偏离消费宽带画像，不适合 TikTok 养号、跨境主店或支付结算。",
      envWarn.length ? `请修正本机环境警告（${envWarn.join("、")}）；建议该 IP 仅作开发调试与常规访问，重要账号请换家宽。` : "适合技术开发、API 部署与轻量查阅；涉及 AI 重度使用及社媒/支付请换原生家宽 IP。",
    ],
    datacenter_risky: [
      `高风险机房节点（${routeTagZh} · ${asnLabel}，风险 ${fraud}% / 纯净分 ${trust}；${hitNames.length ? `命中：${hitNames.join("、")}` : `ASN 机器流量 ${bot}%`}${reports ? `、历史举报 ${reports} 次` : ""}）。`,
      "强烈不推荐 — 机房叠加代理/VPN/高滥用或跨区广播信号，极易被 Cloudflare 与各大 AI 平台拦截或直接封限。",
      "严禁使用 — 用于账号注册、广告投放与支付结账会大概率触发秒封、砍单或风控拒付。",
      envWarn.length ? `网络高危且本机存在偏差（${envWarn.join("、")}），敏感操作前必须更换纯净原生家宽。` : "仅建议作一次性无状态访问测试；所有敏感操作请切换低风险原生家宽 IP。",
    ],
    mobile: [
      `移动蜂窝网络 IP（${asnLabel} · ${locCC}，风险 ${fraud}% / 纯净分 ${trust}，属运营商 CGNAT 多人共享出口）。`,
      "基本可用 — 移动基站信誉普遍高于机房，ChatGPT / Claude 多可直连使用，并发高峰期偶发验证属正常情况。",
      "适合移动端社媒与轻量运营 — 天然贴近手机用户画像；但固定长期跨境主店与大额结算仍推荐独享家宽。",
      envWarn.length ? `请注意对齐本地设备参数（${envWarn.join("、")}）。` : "保持本机时区语言与运营商所在国一致，避免高频切换地理位置。",
    ],
    business: [
      `企业 / 高校商业宽带 IP（${asnLabel} · ${locCC}，风险 ${fraud}% / 纯净分 ${trust}）。`,
      "办公场景推荐 — 机构专线信誉稳定、不易误杀，ChatGPT / Claude 常规对话与办公 API 表现流畅。",
      "个人 C 端社媒养号慎用 — 商企固定出口与家庭宽带行为模型不同，部分个人金融/电商风控会另行核验。",
      envWarn.length ? `处理本机警告（${envWarn.join("、")}）后可直接用于日常工作流。` : "科研办公、开发与企业级使用可安心沿用；如需做个人养号孵化，建议搭配消费级家宽。",
    ],
  };
  const [verdict, aiPlat, biz, tip] = map[profile];
  return [
    `- **综合定性**：${verdict}`,
    `- **AI 平台 (ChatGPT/Claude)**：${aiPlat}`,
    `- **跨境 / 社媒 / 支付**：${biz}`,
    `- **实操建议**：${tip}`,
  ].join("\n");
}

function buildAiPrompts(lang: Lang, report: Report, clientEnv: any): { system: string; user: string } {
  const profileCategory = classifyIpProfile(report);
  const payload = JSON.stringify({
    ip: report.ip,
    profileCategory,
    networkType: report.type.code,
    typeReason: report.type.reason,
    isResidential: report.type.residential,
    origin: report.location.isNative === true
      ? `native (${report.location.registeredCountryCode})`
      : report.location.isNative === false
        ? `broadcast (${report.location.registeredCountryCode}->${report.location.countryCode})`
        : "unknown",
    geo: [report.location.city, report.location.region, report.location.countryCode].filter(Boolean).join(", "),
    asn: report.network.asn,
    company: report.company.name || report.network.org,
    riskScore: report.scores.fraud,
    purityScore: report.scores.trust,
    riskLevel: report.scores.riskCode,
    scoreFactors: report.scores.breakdown.map((b) => `${b.key}:+${b.delta}`),
    humanPct: report.humanRatio.human,
    botPct: report.humanRatio.bot,
    botScope: "ASN-wide 7d average, NOT single-IP traffic",
    abuseReports90d: report.abuse?.reports ?? 0,
    abuseConfidence: report.abuse?.confidence ?? 0,
    openPorts: report.exposure.ports,
    exposureTags: report.exposure.tags,
    detectedSignals: report.signals.filter((s) => s.detected).map((s) => `${s.key}(${(s.hits || []).join(",")})`),
    clientWarnings: clientEnv?.warnings || [],
  });

  const taxonomyNoteEn = "Classify accurately by profileCategory: native_residential_clean (clean home broadband; ignore macro ASN botPct 35-65% -> Highly recommended), native_residential_risky (polluted home broadband with abuse hits -> cautious/limit sensitive actions), broadcast_residential (non-native cross-border residential ISP -> usable for browsing/AI, caution on strict KYC/payments), dual_isp (hybrid ISP/hosting or residential proxy -> verification risk), datacenter_clean (native low-noise datacenter -> API/light use ok, CAPTCHA risk on AI, avoid accounts/payments), datacenter_risky (proxy/VPN/Tor/abused/broadcast DC -> Not recommended / avoid strictly), mobile (CGNAT cellular), business (enterprise/edu line).";

  if (lang === "en") {
    return {
      system: `You are a senior IP fraud & risk analyst. Output concise English in EXACTLY 4 Markdown bullets (130-190 words total). Every bullet MUST give a clear conclusion PLUS concrete data evidence from the JSON (profileCategory, origin native/broadcast, riskScore/purityScore, botPct context, detectedSignals, abuseReports90d, openPorts, or clientWarnings). NEVER output vague 3-word filler like "Usable / Browsing only / Avoid risk" without specific reasoning. ${taxonomyNoteEn}`,
      user: `Diagnose this IP telemetry JSON with 4 evidence-backed bullets: 1.**Verdict** 2.**AI Platforms (ChatGPT/Claude)** 3.**Commerce / Social / Payments** 4.**Recommendation**.\n${payload}`,
    };
  }
  if (lang === "zh-TW") {
    return {
      system: "你是資深 IP 風控與網路情報分析專家。請用精準繁體中文輸出恰好 4 條 Markdown 列表（總字數 220–320 字）。每條都必須給出「明確結論 + 具體數據依據」（必須結合 profileCategory、origin 原生/廣播與註冊國→定位國、riskScore/purityScore、detectedSignals、abuseReports90d、openPorts 與 clientWarnings），嚴禁只寫「基本可用」「僅限普通瀏覽」「避免敏感操作」這類空泛短語！必須嚴格區分 8 類畫像：1. native_residential_clean（純淨原生家寬：若大網 botPct 在 35%-65% 僅屬全 ASN 均值，必須明確給出「高度推薦」「推薦」）；2. native_residential_risky（原生家寬但存在舉報/濫用污染，提示具體舉報與降權風險）；3. broadcast_residential（非原生/廣播家寬：說明註冊地與定位地偏差對 AI 與跨境/支付的影響）；4. dual_isp（雙 ISP / 住宅代理或混合託管段）；5. datacenter_clean（原生普通機房/雲主機：開發/輕量可用，AI 易遇驗證或降智，不推薦養號支付）；6. datacenter_risky（命中代理/VPN/Tor/高濫用或廣播機房：明確嚴禁核心帳號與支付）；7. mobile（蜂巢行動 CGNAT 共享出口）；8. business（企業/高校商業專線）。若 clientWarnings 非空，第 4 條必須明確點出本機指紋對齊建議。",
      user: `根據以下 IP 情報 JSON 輸出 4 條具數據依據的精準診斷：1.**綜合定性** 2.**AI 平台 (ChatGPT/Claude)** 3.**跨境 / 社群 / 支付** 4.**實操建議**。\n${payload}`,
    };
  }
  if (lang === "ja") {
    return {
      system: "あなたはシニアIPリスクアナリストです。正確な日本語で4つのMarkdown箇条書きのみ（合計220〜320文字）を出力してください。各項目には必ず「明確な結論＋JSONの実測根拠」（profileCategory、native/broadcast由来、riskScore/purityScore、detectedSignals、abuseReports90d、openPorts、clientWarnings）を含め、「利用可能」「閲覧のみ」だけの曖昧な短文は禁止します。8分類を厳密に区別してください：native_residential_clean（純粋な住宅IP：ASNのbotPctが35-65%でも単一IPの異常ではないため「強く推奨」）、native_residential_risky（不正報告のある汚染住宅IP）、broadcast_residential（非ネイティブ/ブロードキャスト住宅IP：登録国と利用国の差異を指摘）、dual_isp（デュアルISP・住宅プロキシ混在）、datacenter_clean（通常のクラウド/DC：API/軽量向け、決済・SNSアカウント不可）、datacenter_risky（プロキシ/VPN/高不正/ブロードキャストDC：厳禁）、mobile（携帯キャリアCGNAT）、business（法人・教育回線）。clientWarningsがある場合は4項目目で具体的な環境修正を提案してください。",
      user: `以下のIP情報JSONから根拠付きで4項目を診断してください：1.**総合判定** 2.**AI プラットフォーム (ChatGPT/Claude)** 3.**EC / SNS / 決済** 4.**推奨アクション**。\n${payload}`,
    };
  }
  return {
    system: "你是资深 IP 风控与网络情报分析专家。请用精准简体中文输出恰好 4 条 Markdown 列表（总字数 220–320 字）。每条都必须包含「明确结论 + 具体数据依据」（需引用 profileCategory 类别、origin 原生或注册国→定位国广播、riskScore/purityScore、detectedSignals 命中源、abuseReports90d 举报与 openPorts 端口、以及 clientWarnings），严禁只写“基本可用”“仅限普通浏览”“避免敏感操作”这类空泛四字短语！必须精准区分全部 8 类 IP 画像：1. native_residential_clean（原生纯净家宽：明确若 botPct 在 35%-65% 仅为所属 ASN 全网均值不代表单 IP 异常，必须给出「高度推荐」「推荐」）；2. native_residential_risky（原生但存在举报/威胁污染的家宽，点名污染证据）；3. broadcast_residential（非原生/广播家宽：点名注册国与定位国偏差对原生 AI 锁区及跨境店铺/支付审核的影响）；4. dual_isp（双 ISP / 混合托管或家宽代理段）；5. datacenter_clean（原生普通机房/云主机：无匿名代理黑名单实锤时可做开发/API/轻量查询，AI 易遇验证或降智，跨境起号支付不推荐）；6. datacenter_risky（高危或代理/VPN/Tor/广播机房：极易拦截，严禁养号与支付）；7. mobile（移动蜂窝 CGNAT 共享出口）；8. business（企业/高校商用专线）。若 clientWarnings 非空，第 4 条必须给出对应本机浏览器环境修复建议。",
    user: `请根据以下完整 IP 情报 JSON 输出 4 条有据可查的精准诊断：1.**综合定性** 2.**AI 平台 (ChatGPT/Claude)** 3.**跨境 / 社媒 / 支付** 4.**实操建议**。\n${payload}`,
  };
}

async function callOpenAiCompat(
  url: string,
  apiKey: string,
  model: string,
  system: string,
  user: string,
  timeoutMs = 12000,
): Promise<string> {
  const c = new AbortController();
  const t = setTimeout(() => c.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      method: "POST",
      signal: c.signal,
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${apiKey}`,
      },
      body: JSON.stringify({
        model,
        temperature: 0.2,
        max_tokens: 520,
        messages: [
          { role: "system", content: system },
          { role: "user", content: user },
        ],
      }),
    });
    if (!res.ok) throw new Error(`ai ${res.status}`);
    const j = await res.json();
    const text = String(j?.choices?.[0]?.message?.content || "").trim();
    if (text.length < 20) throw new Error("empty");
    return text;
  } finally {
    clearTimeout(t);
  }
}

async function generateAiReport(
  report: Report,
  clientEnv: any,
  lang: Lang,
  env?: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  const envKey = clientEnv ? `${clientEnv.humanScore ?? ""}-${(clientEnv.warnings || []).length}` : "none";
  const cacheKey = `${lang}:${report.ip}:${report.type.code}:${report.scores.fraud}:${report.humanRatio.bot}:${envKey}:v3`;
  const hit = aiCache.get(cacheKey);
  if (hit && Date.now() - hit.at < AI_CACHE_TTL) return { ...hit.data, cached: true };

  const { system, user } = buildAiPrompts(lang, report, clientEnv);
  const providers: Array<{ name: string; run: () => Promise<string> }> = [];

  const zhipuKey = getEnv(env, "ZHIPU_API_KEY");
  if (zhipuKey) {
    const model = getEnv(env, "ZHIPU_MODEL") || "glm-4-flash-250414";
    providers.push({
      name: "GLM-4-Flash",
      run: () => callOpenAiCompat("https://open.bigmodel.cn/api/paas/v4/chat/completions", zhipuKey, model, system, user),
    });
  }

  const sfKey = getEnv(env, "SILICONFLOW_API_KEY");
  if (sfKey) {
    const model = getEnv(env, "SILICONFLOW_MODEL") || "Qwen/Qwen2.5-7B-Instruct";
    providers.push({
      name: "Qwen2.5-7B",
      run: () => callOpenAiCompat("https://api.siliconflow.cn/v1/chat/completions", sfKey, model, system, user),
    });
  }

  const groqKey = getEnv(env, "GROQ_API_KEY");
  if (groqKey) {
    const model = getEnv(env, "GROQ_MODEL") || "llama-3.1-8b-instant";
    providers.push({
      name: "Groq Llama 3.1",
      run: () => callOpenAiCompat("https://api.groq.com/openai/v1/chat/completions", groqKey, model, system, user),
    });
  }

  const cfAi = (env as any)?.AI;
  if (cfAi && typeof cfAi.run === "function") {
    const model = getEnv(env, "CF_AI_MODEL") || "@cf/qwen/qwen2.5-7b-instruct-fast";
    providers.push({
      name: "Workers AI",
      run: async () => {
        const aiRes = await cfAi.run(model, {
          messages: [
            { role: "system", content: system },
            { role: "user", content: user },
          ],
          max_tokens: 520,
        });
        const text = String(aiRes?.response || aiRes?.choices?.[0]?.message?.content || "").trim();
        if (text.length < 20) throw new Error("empty");
        return text;
      },
    });
  }

  const customKey = getEnv(env, "AI_API_KEY");
  if (customKey) {
    const url = getEnv(env, "AI_API_URL") || "https://open.bigmodel.cn/api/paas/v4/chat/completions";
    const model = getEnv(env, "AI_MODEL") || "glm-4-flash";
    providers.push({
      name: model,
      run: () => callOpenAiCompat(url, customKey, model, system, user),
    });
  }

  for (const p of providers) {
    try {
      const text = await p.run();
      const data = { ok: true, provider: p.name, text };
      setBoundedCache(aiCache, 1000, cacheKey, { at: Date.now(), data });
      return data;
    } catch { /* fallback to next */ }
  }

  const data = { ok: true, provider: "Rule Engine", text: buildRuleBasedAnalysis(report, clientEnv, lang) };
  setBoundedCache(aiCache, 1000, cacheKey, { at: Date.now(), data });
  return data;
}

/* ================= ASN & BGP Live Monitor ================= */
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
    const url = "https://ris-live.ripe.net/v1/ws/?client=ipspot-pages";
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
    const raw = await fetchJson(`https://stat.ripe.net/data/as-names/data.json?resource=AS${asn}`, 6000);
    name = raw?.data?.names?.[String(asn)] ?? "";
  } catch { /* optional */ }

  if (prefix) {
    const base = prefix.split("/")[0];
    const ip = publicIp(base);
    if (ip) {
      try {
        const raw = await fetchJson(`https://api.ipquery.io/${encodeURIComponent(ip)}`, 5000);
        if (raw && raw.location) {
          country = raw.location.country ?? "";
          countryCode = (raw.location.country_code ?? "").toUpperCase();
          if (!name) name = raw.isp?.org ?? raw.isp?.isp ?? "";
        }
      } catch { /* optional */ }
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

/* ================= Main Handler ================= */
export async function handler(req: Request, env?: Record<string, unknown>): Promise<Response> {
  const url = new URL(req.url);

  if (req.method === "POST" && url.searchParams.get("action") === "ai") {
    try {
      const payload = await req.json();
      const targetIp = publicIp(payload?.ip);
      if (!targetIp) return json({ ok: false, error: "invalid_ip", message: "Invalid IP address" }, 400);
      const lang = normalizeLang(payload?.lang);
      const report = await lookup(targetIp, undefined, env);
      return json(await generateAiReport(report, payload?.clientEnv || null, lang, env));
    } catch {
      return json({ ok: false, error: "ai_failed", message: "AI analysis failed" }, 500);
    }
  }

  if (req.method !== "GET") {
    return json({ ok: false, error: "method_not_allowed", message: "Method not allowed" }, 405);
  }

  if (url.searchParams.get("action") === "whoami") {
    const clientIp = clientIpFromHeaders(req);
    if (!clientIp) return json({ ok: false, error: "ip_unavailable", message: "Unable to detect client IP" }, 422);
    return json({ ok: true, ip: clientIp });
  }

  if (url.searchParams.get("action") === "geoaddr") {
    const lat = Number(url.searchParams.get("lat"));
    const lon = Number(url.searchParams.get("lon"));
    if (!Number.isFinite(lat) || !Number.isFinite(lon) || Math.abs(lat) > 90 || Math.abs(lon) > 180) {
      return json({ ok: false, error: "invalid_coords", message: "Invalid coordinates" }, 400);
    }
    const tz = url.searchParams.get("tz") || "";
    const jitter = url.searchParams.get("jitter") === "1";
    const result = await lookupGeoAddress(lat, lon, tz, jitter);
    return json(result, result.ok ? 200 : 502);
  }

  if (url.searchParams.get("feed") === "bgp") {
    try { return json(await lookupBgpFeed()); }
    catch { return json({ ok: false, error: "upstream_unavailable", message: "BGP feed unavailable" }, 502); }
  }

  const asnParam = url.searchParams.get("asn");
  if (asnParam !== null) {
    const asn = Number(String(asnParam).replace(/^AS/i, ""));
    if (!Number.isInteger(asn) || asn < 1 || asn > 4294967295) {
      return json({ ok: false, error: "invalid_asn", message: "Invalid ASN" }, 400);
    }
    try { return json(await lookupAsn(asn, url.searchParams.get("pfx"))); }
    catch { return json({ ok: false, error: "upstream_unavailable", message: "ASN lookup unavailable" }, 502); }
  }

  const q = url.searchParams.get("q");
  let ip: string | null = null;
  let queriedDomain: string | undefined;

  if (q !== null && q.trim() !== "") {
    const trimmed = q.trim().replace(/^https?:\/\//i, "").split("/")[0].trim();
    ip = publicIp(trimmed);
    if (!ip) {
      if (IPV4_RE.test(trimmed) || IPV6_RE.test(trimmed)) {
        return json({ ok: false, error: "private_ip", message: "Private or reserved IP cannot be checked" }, 400);
      }
      if (DOMAIN_RE.test(trimmed)) {
        const resolved = await resolveDomain(trimmed);
        if (resolved) { ip = resolved; queriedDomain = trimmed; }
        else return json({ ok: false, error: "domain_resolve_failed", message: `Failed to resolve ${trimmed}` }, 400);
      } else {
        return json({ ok: false, error: "invalid_ip", message: "Invalid IPv4, IPv6, or domain" }, 400);
      }
    }
  } else {
    ip = clientIpFromHeaders(req);
    if (!ip) return json({ ok: false, error: "ip_unavailable", message: "Unable to detect client IP" }, 422);
  }

  try {
    const report = await lookup(ip, queriedDomain, env);
    const conn = connectionMetaFromReq(req);
    return json(conn ? { ...report, connection: conn } : report);
  } catch {
    return json({ ok: false, error: "upstream_unavailable", message: "Upstream IP services unavailable" }, 502);
  }
}