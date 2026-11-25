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
      4000,
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
      4000,
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
  if (fraud <= 50) return { riskLevel: "中性", riskCode: "medium" };
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
      5000,
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
      5000,
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

  const registeredCC =
    rirStatsCC ||
    rdapInfo.countryCode ||
    ripeRirCC ||
    radarEntity?.countryCode ||
    normalizeCountryCode(ipapi?.asn?.country) ||
    normalizeCountryCode(ipguide?.network?.autonomous_system?.country) ||
    "";

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
  if (registeredCC && loc.cc) {
    isNative = registeredCC === loc.cc;
    geoTypeLabel = isNative ? `原生 IP (${registeredCC})` : `广播 IP (${registeredCC}→${loc.cc})`;
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

  let type: Report["type"];
  if (isMobile && !isDc) {
    type = { code: "mobile", label: "移动网络", residential: false, confidence: "high", reason: "蜂窝移动运营商出口" };
  } else if (isDc && (asnType === "isp" || isKnownResAsn) && !dcByKeyword) {
    type = { code: "dual_isp", label: "双 ISP 托管", residential: false, confidence: "high", reason: "ISP 段但命中机房/托管特征" };
  } else if (isDc) {
    type = { code: "datacenter", label: "机房 IP", residential: false, confidence: dcByApi ? "high" : "medium", reason: dcByApi ? "命中数据中心/云主机库" : "组织或 rDNS 命中机房特征" };
  } else if (hasBizWords) {
    type = { code: "business", label: "商业宽带", residential: false, confidence: "medium", reason: "企业/高校/政企专线" };
  } else if ((compType === "isp" || asnType === "isp" || isKnownResAsn || hasResWords) && !isProxy && !isVpn && !isTor) {
    if (isNative === false) {
      type = { code: "dual_isp", label: "广播 ISP", residential: false, confidence: "medium", reason: "ISP 段但跨国广播" };
    } else {
      type = { code: "residential", label: "家宽 IP", residential: true, confidence: (compType === "isp" && asnType === "isp") || isKnownResAsn ? "high" : "medium", reason: "原生住宅运营商宽带" };
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
    if (delta !== 0) breakdown.push({ key, label, delta, reason, ...(meta ? { meta } : {}) });
  };

  if (type.code === "residential") addScore("baseline_residential", "网络基线", type.confidence === "high" ? 5 : 10, "原生住宅宽带基线");
  else if (type.code === "mobile") addScore("baseline_mobile", "网络基线", 12, "移动蜂窝 CGNAT 共享出口");
  else if (type.code === "business") addScore("baseline_business", "网络基线", 18, "企业/机构商用网络");
  else if (type.code === "dual_isp") addScore("baseline_dual_isp", "网络基线", 26, "双 ISP / 广播托管段");
  else if (type.code === "datacenter") addScore("baseline_datacenter", "网络基线", 28, "数据中心 / 云主机网络");
  else addScore("baseline_unknown", "网络基线", 22, "归属证据不足审慎基线");

  if (radar) {
    if (radar.bot >= 90) addScore("radar_bot", "ASN 机器流量", 9, `Radar 实测该 ASN 机器流量占比 ${radar.bot}%`, { bot: radar.bot });
    else if (radar.bot >= 75) addScore("radar_bot", "ASN 机器流量", 6, `Radar 实测该 ASN 机器流量占比 ${radar.bot}%`, { bot: radar.bot });
    else if (radar.bot >= 55) addScore("radar_bot", "ASN 机器流量", 3, `Radar 实测该 ASN 机器流量占比 ${radar.bot}%`, { bot: radar.bot });
  }

  if (isNative === false) addScore("broadcast", "跨区广播", 12, `注册国 ${registeredCC} ≠ 定位国 ${loc.cc}`, { reg: registeredCC, loc: loc.cc });
  if (isTor) addScore("tor", "Tor 节点", 45, "命中 Tor 匿名出口");
  if (isVpn) addScore("vpn", "VPN 出口", 20, "命中 VPN 节点库");
  if (isProxy) addScore("proxy", "代理节点", 22, "命中公开代理或转发节点");
  if (isDc && (isProxy || isVpn)) addScore("dc_proxy", "机房代理叠加", 8, "机房 + 代理/VPN 复合高危特征");

  if (abuseData && abuseDbConf > 0) {
    const scaled = Math.min(35, Math.max(4, Math.round(abuseDbConf * 0.35)));
    addScore("abuseipdb", "AbuseIPDB 举报", scaled, `近 90 天被举报 ${abuseDbReports} 次（置信度 ${abuseDbConf}%）`, { reports: abuseDbReports, conf: abuseDbConf });
  } else if (isAbuser) {
    const abuseDelta = abuserRatio >= 0.1 || ipqThreat >= 60 || shodanCompromised || sfsConf >= 50 ? 24 : 16;
    addScore("abuse_generic", "滥用与威胁", abuseDelta, "命中滥用或威胁情报源");
  }

  if (isCrawler) addScore("crawler", "爬虫来源", 10, "命中商业/抓取爬虫库");
  if (exposure.vulnsCount >= 3) addScore("vulns", "暴露面漏洞", 6, `Shodan 发现 ${exposure.vulnsCount} 个已知漏洞特征`, { count: exposure.vulnsCount });

  const fraud = Math.max(0, Math.min(100, Math.round(breakdown.reduce((s, x) => s + x.delta, 0))));
  const trust = 100 - fraud;

  const proxyChecked = [
    pcData ? "proxycheck.io" : "",
    ip2locOk && "is_proxy" in ip2loc ? "IP2Location" : "",
    ipqueryOk && ipquery.risk ? "ipquery.io" : "",
    ipapiComOk ? "ip-api.com" : "",
    freeipOk && "isProxy" in freeip ? "FreeIPAPI" : "",
    ipapiHasRisk ? "ipapi.is" : "",
    shodanOk ? "Shodan" : "",
  ].filter(Boolean);

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

async function fetchFresh(
  ip: string,
  queriedDomain?: string,
  env?: Record<string, unknown>,
): Promise<Report> {
  const encoded = encodeURIComponent(ip);
  const abuseKey = getEnvAny(env, ["ABUSEIPDB_KEY", "ABUSEIPDB_API_KEY", "ABUSE_KEY"]);
  const ipapiKey = getEnvAny(env, ["IPAPI_IS_KEY"]);
  const ipinfoToken = getEnvAny(env, ["IPINFO_TOKEN"]);
  const ip2locKey = getEnvAny(env, ["IP2LOCATION_KEY"]);
  const pcKey = getEnvAny(env, ["PROXYCHECK_KEY"]);

  const [
    ipapi, ipquery, ipapiCom, ipwho, geojs, freeip,
    ipinfo, ip2loc, ipsb, ipguide, ipapico,
    proxycheck, onionoo, sfs,
    rdap, ripeRir, ripeGeo, shodan, abuseDb,
  ] =
    await Promise.all([
      fetchJson(`https://api.ipapi.is/?q=${encoded}${ipapiKey ? `&key=${encodeURIComponent(ipapiKey)}` : ""}`, 4800).catch(() => null),
      fetchJson(`https://api.ipquery.io/${encoded}`, 5000).catch(() => null),
      fetchJson(
        `http://ip-api.com/json/${encoded}?fields=status,country,countryCode,regionName,city,lat,lon,timezone,zip,isp,org,as,asname,reverse,mobile,proxy,hosting`,
        4500,
      ).catch(() => null),
      fetchJson(`https://ipwho.is/${encoded}`, 4500).catch(() => null),
      fetchJson(`https://get.geojs.io/v1/ip/geo/${encoded}.json`, 4500).catch(() => null),
      fetchJson(`https://freeipapi.com/api/json/${encoded}`, 4500).catch(() => null),
      fetchJson(`https://ipinfo.io/${encoded}/json${ipinfoToken ? `?token=${encodeURIComponent(ipinfoToken)}` : ""}`, 4500).catch(() => null),
      fetchJson(`https://api.ip2location.io/?ip=${encoded}${ip2locKey ? `&key=${encodeURIComponent(ip2locKey)}` : ""}`, 4800).catch(() => null),
      fetchJson(`https://api.ip.sb/geoip/${encoded}`, 4500).catch(() => null),
      fetchJson(`https://ip.guide/${encoded}`, 4800).catch(() => null),
      fetchJson(`https://ipapi.co/${encoded}/json/`, 4500).catch(() => null),
      fetchJson(`https://proxycheck.io/v2/${encoded}?vpn=1&asn=1${pcKey ? `&key=${encodeURIComponent(pcKey)}` : ""}`, 4800).catch(() => null),
      fetchJson(`https://onionoo.torproject.org/details?search=${encoded}&limit=1`, 4800).catch(() => null),
      fetchJson(`https://api.stopforumspam.org/api?ip=${encoded}&json`, 4500).catch(() => null),
      fetchJson(`https://rdap.org/ip/${encoded}`, 6000).catch(() => null),
      fetchJson(`https://stat.ripe.net/data/rir/data.json?resource=${encoded}`, 6500).catch(() => null),
      fetchJson(`https://stat.ripe.net/data/maxmind-geo-lite/data.json?resource=${encoded}`, 6500).catch(() => null),
      IPV4_RE.test(ip) ? fetchJson(`https://internetdb.shodan.io/${encoded}`, 4200).catch(() => null) : Promise.resolve(null),
      abuseKey
        ? fetchJson(`https://api.abuseipdb.com/api/v2/check?ipAddress=${encoded}&maxAgeInDays=90`, 4200, { key: abuseKey }).catch(() => null)
        : Promise.resolve(null),
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

  const resolvedAsn =
    asnNumber(typeof ipapi?.asn === "string" ? ipapi.asn : ipapi?.asn?.asn) ||
    asnNumber(ipquery?.isp?.asn) ||
    asnNumber(ipapiCom?.as) ||
    asnNumber(ipwho?.connection?.asn) ||
    asnNumber(ip2loc?.asn) ||
    asnNumber(ipsb?.asn) ||
    asnNumber(ipguide?.network?.autonomous_system?.asn) ||
    asnNumber(geojs?.asn);

  const rdapQuickCC = extractRdapInfo(rdap).countryCode;
  const needRirCountry = !rdapQuickCC && !normalizeCountryCode(ripeRir?.data?.rirs?.[0]?.country);

  const [radar, radarEntity, ripeHist, rirCountry] = await Promise.all([
    fetchRadarBotClass(resolvedAsn, env),
    fetchRadarAsnEntity(resolvedAsn, env),
    fetchJson(`https://stat.ripe.net/data/routing-history/data.json?resource=${encoded}&min_peers=10`, 5500).catch(() => null),
    needRirCountry
      ? fetchJson(`https://stat.ripe.net/data/rir-stats-country/data.json?resource=${encoded}`, 5500).catch(() => null)
      : Promise.resolve(null),
  ]);

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
      5000,
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
    const ph = await fetchJson(`https://photon.komoot.io/reverse?lat=${qLat}&lon=${qLon}`, 5000);
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
function buildRuleBasedAnalysis(report: Report, clientEnv: any, lang: Lang): string {
  const fraud = report.scores.fraud;
  const bot = report.humanRatio.bot;
  const isRes = report.type.residential;
  const isNative = report.location.isNative !== false;
  const cleanLowRes = isRes && fraud <= 20;
  const envWarn = clientEnv && Array.isArray(clientEnv.warnings) ? clientEnv.warnings : [];

  if (lang === "en") {
    const verdict = cleanLowRes
      ? (isNative ? "Clean native residential IP with minimal risk" : "Low-risk broadcast residential IP, stable for regular use")
      : fraud <= 35 ? "Low-to-moderate risk IP suitable for standard access"
      : fraud <= 55 ? `Neutral risk ${report.type.code} IP (macro ASN bot baseline ${bot}%)`
      : `High-risk ${report.type.code} IP (${fraud}% risk score)`;
    const aiPlat = cleanLowRes ? "Highly recommended — minimal verification friction"
      : fraud <= 45 && (isRes || bot < 75) ? "Usable — occasional CAPTCHA or rate checks"
      : "Not recommended — datacenter or high-risk signals trigger CAPTCHA or blocks";
    const biz = cleanLowRes && isNative ? "Recommended — suitable for social accounts, e-commerce, and payments"
      : cleanLowRes ? "Usable — align local timezone/language for cross-border accounts"
      : fraud <= 38 && isRes ? "Browsing & light registration only"
      : "Not recommended — avoid account sign-ups, ads, or payment checkout";
    const tip = envWarn.length
      ? (cleanLowRes
        ? `IP itself is clean; align local environment (${envWarn.join(", ")}).`
        : `Fix local environment mismatches (${envWarn.join(", ")}) and switch to a clean native residential IP for sensitive workflows.`)
      : fraud > 35 || !isRes ? "Switch to a clean native residential IP for sensitive workflows."
      : "Environment looks clean; keep current network and timezone settings.";
    return [
      `- **Verdict**: ${verdict} (Risk ${fraud}%, Purity ${report.scores.trust}/100)`,
      `- **AI Platforms**: ${aiPlat}`,
      `- **Commerce / Social / Payments**: ${biz}`,
      `- **Recommendation**: ${tip}`,
    ].join("\n");
  }

  if (lang === "zh-TW") {
    const verdict = cleanLowRes
      ? (isNative ? "純淨原生家寬 IP，風控風險極低" : "低風險廣播家寬 IP，日常存取穩定")
      : fraud <= 35 ? "低風險網路節點，常規存取穩定"
      : fraud <= 55 ? `中性風險 ${report.type.label}（所屬 ASN 整網機器流量均值 ${bot}%）`
      : `高風險 ${report.type.label}（風險係數 ${fraud}%）`;
    const aiPlat = cleanLowRes ? "高度推薦，觸發驗證機率極低"
      : fraud <= 45 && (isRes || bot < 75) ? "基本可用，偶發人機驗證或降速"
      : "不推薦，機房或高風險特徵易觸發降智與攔截";
    const biz = cleanLowRes && isNative ? "推薦，適合社群養號、跨境電商與支付場景"
      : cleanLowRes ? "基本可用，建議保持本機時區與出口地區一致"
      : fraud <= 38 && isRes ? "僅建議日常瀏覽，謹慎用於敏感註冊"
      : "不推薦，請勿用於註冊、廣告投放或支付結帳";
    const tip = envWarn.length
      ? (cleanLowRes
        ? `IP 本身純淨，建議對齊本機環境（${envWarn.join("、")}）。`
        : `建議處理本機環境偏差（${envWarn.join("、")}），敏感業務請切換原生家寬 IP。`)
      : fraud > 35 || !isRes ? "敏感業務建議切換至乾淨的原生住宅家寬 IP。"
      : "目前環境良好，保持本機時區與出口地區一致即可。";
    return [
      `- **綜合定性**：${verdict}（風險 ${fraud}% / 純淨分 ${report.scores.trust}）`,
      `- **AI 平台 (ChatGPT/Claude)**：${aiPlat}`,
      `- **跨境 / 社群 / 支付**：${biz}`,
      `- **實操建議**：${tip}`,
    ].join("\n");
  }

  if (lang === "ja") {
    const verdict = cleanLowRes
      ? (isNative ? "クリーンなネイティブ住宅IP（低リスク）" : "低リスクのブロードキャスト住宅IP（通常利用向き）")
      : fraud <= 35 ? "標準利用に適した低〜中リスクIP"
      : fraud <= 55 ? `中立リスクIP（ASN全体のBot平均 ${bot}%）`
      : `高リスクIP（リスク係数 ${fraud}%）`;
    const aiPlat = cleanLowRes ? "強く推奨 — 認証要求の発生率は極めて低い"
      : fraud <= 45 && (isRes || bot < 75) ? "利用可能 — 時々CAPTCHAが表示される可能性あり"
      : "非推奨 — 制限やブロックの可能性が高い";
    const biz = cleanLowRes && isNative ? "推奨 — SNS運用・EC・決済用途に適しています"
      : cleanLowRes ? "利用可能 — 端末のタイムゾーンを一致させてご利用ください"
      : fraud <= 38 && isRes ? "通常閲覧向け、新規登録は慎重に"
      : "非推奨 — アカウント登録や決済には使用しないでください";
    const tip = envWarn.length
      ? (cleanLowRes
        ? `IP自体は良好です。ローカル環境の差異（${envWarn.join("、")}）を調整してください。`
        : `ローカル環境の差異（${envWarn.join("、")}）を修正し、重要業務はクリーンな住宅IPを推奨します。`)
      : fraud > 35 || !isRes ? "重要な業務にはクリーンな住宅IPへの切り替えを推奨します。"
      : "環境は良好です。現在のネットワーク設定を維持してください。";
    return [
      `- **総合判定**：${verdict}（リスク ${fraud}% / 純度 ${report.scores.trust}/100）`,
      `- **AI プラットフォーム**：${aiPlat}`,
      `- **EC / SNS / 決済**：${biz}`,
      `- **推奨アクション**：${tip}`,
    ].join("\n");
  }

  const verdict = cleanLowRes
    ? (isNative ? "纯净原生家宽 IP，风控风险极低" : "低风险广播家宽 IP，日常访问稳定")
    : fraud <= 35 ? "低风险网络节点，常规访问稳定"
    : fraud <= 55 ? `中性风险 ${report.type.label}（所属 ASN 整网机器流量均值 ${bot}%）`
    : `高风险 ${report.type.label}（风险系数 ${fraud}%）`;
  const aiPlat = cleanLowRes ? "高度推荐，触发验证概率极低"
    : fraud <= 45 && (isRes || bot < 75) ? "基本可用，偶发人机校验或限速"
    : "不推荐，机房或高风险特征易触发降智、验证或拦截";
  const biz = cleanLowRes && isNative ? "推荐，适合社媒养号、跨境店铺与常规支付场景"
    : cleanLowRes ? "基本可用，建议保持本机时区与出口地区一致"
    : fraud <= 38 && isRes ? "仅建议日常浏览，谨慎用于敏感注册"
    : "不推荐，请勿用于账号注册、起号或支付结账";
  const tip = envWarn.length
    ? (cleanLowRes
      ? `IP 本身纯净度良好，建议修正本机环境偏差（${envWarn.join("、")}）。`
      : `建议处理本机环境偏差（${envWarn.join("、")}），敏感业务请换原生家宽 IP。`)
    : fraud > 35 || !isRes ? "普通浏览可用；涉及注册或支付建议更换干净的原生家宽 IP。"
    : "当前网络纯净度良好，保持出口地区与本地时区一致即可。";

  return [
    `- **综合定性**：${verdict}（风险 ${fraud}% / 纯净分 ${report.scores.trust}）`,
    `- **AI 平台 (ChatGPT/Claude)**：${aiPlat}`,
    `- **跨境 / 社媒 / 支付**：${biz}`,
    `- **实操建议**：${tip}`,
  ].join("\n");
}

function buildAiPrompts(lang: Lang, report: Report, clientEnv: any): { system: string; user: string } {
  const payload = JSON.stringify({
    ip: report.ip,
    country: report.location.countryCode,
    city: report.location.city,
    isNative: report.location.isNative,
    registeredCountry: report.location.registeredCountryCode,
    asn: report.network.asn,
    networkType: report.type.code,
    isResidential: report.type.residential,
    company: report.company.name,
    riskScore: report.scores.fraud,
    purityScore: report.scores.trust,
    riskLevel: report.scores.riskCode,
    humanPct: report.humanRatio.human,
    botPct: report.humanRatio.bot,
    botScope: "ASN-wide 7d average, not single-IP traffic",
    abuseReports90d: report.abuse?.reports ?? 0,
    abuseConfidence: report.abuse?.confidence ?? 0,
    exposureTags: report.exposure.tags,
    detectedSignals: report.signals.filter((s) => s.detected).map((s) => s.key),
    clientWarnings: clientEnv?.warnings || [],
  });

  if (lang === "en") {
    return {
      system: "You are a strict IP risk analyst. Reply in concise English with exactly 4 Markdown bullet points (under 95 words total). Follow 3 strict rules: 1. botPct is the macro 7-day average of the entire ASN (major consumer ISPs commonly sit at 35%-65%) and does NOT measure a single residential IP. When isResidential is true and riskScore <= 20 with no proxy/vpn/tor/datacenter/abuse signals, you MUST classify it as clean low-risk residential and output 'Highly recommended' / 'Recommended' (never penalize it as 'Not recommended' due to ASN botPct). 2. If riskScore >= 31 or (!isResidential and botPct >= 70), NEVER call it 'high trust'; 31-50 is neutral/moderate risk. 3. Use clear verdicts: 'Highly recommended', 'Recommended', 'Usable', 'Browsing only', or 'Not recommended'.",
      user: `Analyze this IP intelligence JSON and output exactly 4 bullets: 1.**Verdict** 2.**AI Platforms (ChatGPT/Claude)** 3.**Commerce / Social / Payments** 4.**Recommendation**.\n${payload}`,
    };
  }
  if (lang === "zh-TW") {
    return {
      system: "你是嚴謹的 IP 風控專家，請用極簡繁體中文輸出恰好 4 條 Markdown 列表（總字數 160 字內，禁止廢話）。嚴格遵守 3 條規則：1. botPct 是所屬整個電信商 ASN 近 7 天宏觀均值（大型家寬電信商整網常在 35%-65%），不代表當前單個住宅 IP 的行為；當 isResidential 為 true 且 riskScore <= 20（無代理/VPN/Tor/機房與惡意舉報）時，必須優先定性為純淨低風險家寬並給出「高度推薦」「推薦」，絕不可因 ASN 均值偏高而判為「不推薦」。2. 嚴禁前後矛盾：當 riskScore >= 31 或（非家寬且 botPct >= 70）時絕不可稱為「高信任度」，31-50 分定性為中性/中等風險。3. 嚴禁用孤立的「低，風險高」造成誤解，必須明確寫「高度推薦」「推薦」「基本可用」「僅限普通瀏覽」「不推薦（高風險/機房）」。",
      user: `根據以下 IP 情報輸出 4 條精簡診斷：1.**綜合定性** 2.**AI 平台 (ChatGPT/Claude)** 3.**跨境 / 社群 / 支付** 4.**實操建議**。\n${payload}`,
    };
  }
  if (lang === "ja") {
    return {
      system: "あなたは厳格なIPリスクアナリストです。簡潔な日本語で4つのMarkdown箇条書き（合計170文字以内）のみを出力してください。次の3規則を厳守してください：1. botPct は所属ASN全体の7日間平均値であり、単一住宅IPの挙動ではありません。isResidential が true かつ riskScore <= 20（proxy/vpn/tor/datacenter/abuseなし）の場合は、ASNのbotPctが35%-65%前後でも必ず「低リスク住宅IP」「強く推奨」「推奨」と評価し、「非推奨」と誤判定しないでください。2. riskScore >= 31 または（非住宅かつ botPct >= 70）の場合は決して「高信頼」と書かず、31-50は中立リスクとしてください。3.「強く推奨」「推奨」「利用可能」「通常閲覧のみ」「非推奨」などの明確な表現を使ってください。",
      user: `以下のIP情報から4項目を診断してください：1.**総合判定** 2.**AI プラットフォーム (ChatGPT/Claude)** 3.**EC / SNS / 決済** 4.**推奨アクション**。\n${payload}`,
    };
  }
  return {
    system: "你是严谨的 IP 风控专家，请用极简简体中文输出恰好 4 条 Markdown 列表（总字数 160 字内，禁止废话）。严格遵守 3 条规则：1. botPct 仅代表所属整个运营商 ASN 近 7 天宏观均值（电信/联通等大型家宽 ASN 整网常在 35%-65%），不代表当前单个住宅 IP 存在机器行为；当 isResidential 为 true 且 riskScore <= 20（无 proxy/vpn/tor/datacenter 及高危举报）时，必须优先定性为纯净/低风险家宽，并给出“高度推荐”“推荐”，绝不可因大网 botPct 偏高而误判为“不推荐”。2. 严禁前后矛盾：当 riskScore >= 31 或（非家宽且 botPct >= 70）时绝不可称为“高信任度”，31-50 分定性为中性/中等风险。3. 严禁写出“低，风险高”这类歧义短语，必须直接写“高度推荐”“推荐”“基本可用”“仅限普通浏览”“不推荐（高风险/机房）”。",
    user: `根据以下真实 IP 情报输出 4 条简短诊断：1.**综合定性** 2.**AI 平台 (ChatGPT/Claude)** 3.**跨境 / 社媒 / 支付** 4.**实操建议**。\n${payload}`,
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
        max_tokens: 300,
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
  const cacheKey = `${lang}:${report.ip}:${report.type.code}:${report.scores.fraud}:${report.humanRatio.bot}:${envKey}:v2`;
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
          max_tokens: 280,
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