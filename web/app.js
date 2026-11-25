"use strict";

const $ = (id) => document.getElementById(id);
const API = "/functions/v1/app";
const HISTORY_KEY = "ipspot-history";
const OWN_KEY = "ipspot-own-v8";
const THEME_KEY = "ipspot-theme";
const LANG_KEY = "ipspot-lang";

/* ================= 4-Language I18N Dictionary ================= */
const I18N = {
  en: {
    "brand.sub": "IP Intelligence Radar",
    "nav.query": "IP Check",
    "nav.fp": "Fingerprint",
    "nav.asn": "ASN Live",
    "nav.dns": "DNS Leak",
    "nav.webrtc": "WebRTC",
    "nav.api": "Open API",
    "theme.light": "Light",
    "theme.dark": "Dark",
    "hero.eyebrow": "IP INTELLIGENCE · REAL-TIME THREAT RADAR",
    "hero.title1": "Uncover the True Identity",
    "hero.title2": "Behind Every IP Address",
    "hero.sub": "Residential Check · Native/Broadcast · Risk Signals · Real Street Address · Human/Bot Ratio · Fingerprint",
    "hero.placeholder": "Enter IPv4, IPv6, or domain (e.g. 1.1.1.1, openai.com)…",
    "hero.btn": "Check",
    "hero.detectMe": "Detect My IP",
    "hero.recent": "Recent",
    "state.loading": "Scanning IP intelligence…",
    "state.loadingShort": "Loading…",
    "state.waiting": "Waiting…",
    "state.retry": "Retry",
    "state.failed": "Lookup failed",
    "kv.asn": "ASN / Org",
    "kv.range": "IP Range",
    "kv.numeric": "Decimal",
    "kv.source": "IP Origin",
    "kv.attr": "IP Type",
    "kv.hb": "Human / Bot",
    "kv.location": "Geolocation",
    "kv.score": "IPSpot Score",
    "kv.ai": "AI Diagnosis",
    "kv.leak": "Leak Check",
    "kv.fp": "Fingerprint",
    "sub.company": "Company",
    "sub.companyType": "Org Type",
    "sub.domain": "Website",
    "sub.route": "Route CIDR",
    "sub.rdns": "Reverse DNS",
    "sub.netname": "NetName / RIR",
    "sub.abuse": "Abuse Contact",
    "sub.ports": "Open Ports",
    "sub.audio": "Audio Hash",
    "sub.os": "OS & Browser",
    "sub.screen": "Screen / DPR",
    "sub.hw": "CPU / Memory",
    "sub.tz": "Timezone / Lang",
    "sub.bot": "Automation",
    "hb.dim": "Metric",
    "hb.exitIp": "Exit IP",
    "hb.localEnv": "Local Browser",
    "hb.status": "Status",
    "hb.estimated": "Estimated",
    "hb.tz": "Timezone",
    "hb.lang": "Language",
    "hb.auto": "Automation",
    "hb.match": "Match",
    "hb.mismatch": "Mismatch",
    "hb.safe": "Safe",
    "hb.leaked": "Leaked",
    "hb.none": "None",
    "hb.risk": "Risk",
    "hb.normal": "Normal",
    "hb.human": "Human",
    "hb.abnormal": "Abnormal",
    "btn.aiRun": "✦ Run AI Diagnosis",
    "btn.aiView": "✦ View AI Diagnosis",
    "btn.aiHide": "Hide AI Diagnosis",
    "btn.aiRetry": "✦ Retry AI Diagnosis",
    "btn.details": "Details",
    "btn.openFp": "Open full fingerprint report →",
    "btn.latency": "Latency ▾",
    "btn.retest": "Retest",
    "btn.bgpMore": "BGP History ▾",
    "btn.openMap": "Open Map",
    "btn.gaRefresh": "Another Nearby",
    "btn.gaCopyAll": "Copy All",
    "btn.recollect": "Recollect",
    "btn.liveStart": "Start Live",
    "btn.livePause": "Pause",
    "btn.clear": "Clear",
    "btn.recheck": "Run Test",
    "btn.send": "Send",
    "btn.showMore": "Show more ({n}) ▾",
    "btn.collapse": "Collapse ▴",
    "ai.loading": "Analyzing…",
    "ai.cached": "Cached",
    "ai.unavailable": "AI temporarily unavailable",
    "card.signals": "Risk Signals",
    "card.exit": "Network Exits",
    "card.regHistory": "Registry History",
    "card.bgpTitle": "Historical BGP Announcements",
    "card.mapGeo": "Map & Real Street Address",
    "card.realAddr": "Real Geo Address (Based on IP)",
    "exit.v4": "IPv4 Exit",
    "exit.v6": "IPv6 Exit",
    "exit.none": "No Public Exit",
    "exit.unassigned": "Unassigned",
    "exit.timeout": "Timeout",
    "tbl.cidr": "CIDR",
    "tbl.rir": "Registry",
    "tbl.country": "Country / Region",
    "tbl.firstSeen": "First Seen",
    "tbl.lastSeen": "Last Active",
    "tbl.empty": "No records",
    "tbl.emptyReg": "No registry history found",
    "tbl.emptyBgp": "No BGP history found",
    "tbl.prefix": "Prefix",
    "tbl.originAsn": "Origin ASN",
    "tbl.firstAnn": "First Seen",
    "tbl.lastAnn": "Last Seen",
    "tbl.time": "Time",
    "tbl.org": "Organization",
    "tbl.type": "Type",
    "tbl.resolverIp": "Resolver IP",
    "tbl.resolverGeo": "Location / ISP",
    "tbl.hits": "Hits",
    "ga.street": "Street",
    "ga.city": "City",
    "ga.state": "State / Province",
    "ga.country": "Country",
    "ga.zip": "Postal Code",
    "ga.tz": "Timezone",
    "ga.noCoords": "No coords",
    "ga.lookingUp": "Looking up…",
    "ga.noStreet": "Street unavailable",
    "ga.fallbackSrc": "IP Database",
    "faq.summary": "How IPSpot Works & Frequently Asked Questions",
    "faq.count": "8 QUESTIONS",
    "faq.tag1": "Origin",
    "faq.tag2": "Score",
    "faq.tag3": "Security",
    "faq.tag4": "GeoIP",
    "faq.tag5": "Fingerprint",
    "faq.tag6": "Network",
    "faq.tag7": "Map",
    "faq.tag8": "API",
    "faq.q1": "How are Native, Broadcast & Residential IPs classified?",
    "faq.a1": "IPSpot cross-checks RIR registries (ARIN, RIPE, APNIC) and RDAP country records against 12 geolocation feeds to verify native vs broadcast routing, combining ASN type, cloud keywords, rDNS, and Shodan traits to separate residential ISPs from datacenters.",
    "faq.q2": "How are Human/Bot Ratio & IPSpot Purity Score calculated?",
    "faq.a2": "Powered by Cloudflare Radar 7-day ASN bot traffic statistics combined with network baselines, broadcast checks, proxy/VPN/Tor feeds, AbuseIPDB, and StopForumSpam reports for transparent 0–100% scoring without penalizing clean residential ISPs.",
    "faq.q3": "How are the 6 Risk Signals cross-verified?",
    "faq.a3": "Every signal (Proxy, VPN, Tor, Datacenter, Mobile, Abuse) is cross-checked across proxycheck.io, official Tor Onionoo relays, StopForumSpam, IP2Location, ipquery.io, ip-api.com, and Shodan ports, displaying the exact verified or matched sources.",
    "faq.q4": "Why do different IP lookup sites show different locations?",
    "faq.a4": "GeoIP providers (MaxMind, IP2Location, IPInfo, ipapi.is, GeoJS, etc.) update at different intervals and handle anycast or broadcast routing differently. IPSpot displays up to 12 independent feeds side by side and uses consensus matching.",
    "faq.q5": "What does the Browser Fingerprint & Consistency check test?",
    "faq.a5": "Locally collects FingerprintJS v4, Canvas, WebGL, Audio, font hashes, screen DPR, and WebDriver/Headless signals, then compares your browser timezone, language, and WebRTC output against your exit IP.",
    "faq.q6": "How do DNS Leak & WebRTC Leak tests work?",
    "faq.a6": "DNS leak detection probes randomized 32-character subdomains to bypass caches and capture your true recursive resolvers, while WebRTC testing queries multiple global STUN servers to check for exposed local or public IPs.",
    "faq.q7": "How is the Real Street Address under the map generated?",
    "faq.a7": "Using the target IP coordinates, IPSpot queries OpenStreetMap Nominatim and Photon reverse geocoding in real time to return nearby street, city, state, country, postal code, and timezone data with one-click copy.",
    "faq.q8": "What can I do with ASN Live, AI Diagnosis & Open API?",
    "faq.a8": "ASN Live streams real-time BGP route announcements and withdrawals from RIPE RIS Live; AI Diagnosis provides risk advice based on verified metrics; the Open JSON API supports zero-auth IP, domain, and ASN queries.",
    "fp.title": "Browser Fingerprint Diagnostics",
    "fp.visitorLabel": "FingerprintJS Visitor ID",
    "fp.coreTitle": "Core Fingerprint Hashes",
    "fp.hwTitle": "Hardware & Display",
    "fp.envTitle": "System, Timezone & Connection",
    "fp.health": "Health {n}%",
    "fp.verdictOk": "No automation signatures detected. Your browser fingerprint looks natural.",
    "fp.verdictWarn": "Automation signals detected: {w}",
    "fp.normalBrowser": "Normal Human Browser",
    "fp.wdTrue": "true (Automation)",
    "fp.wdFalse": "false (Normal)",
    "fp.none": "None detected",
    "fp.touch": "{n} touch points",
    "fp.noTouch": "Non-touch",
    "fp.media": "Mic {mic} · Speaker {spk} · Cam {cam}",
    "fp.cores": "{n} logical cores",
    "fp.unknown": "Unknown",
    "fp.hidden": "Hidden",
    "fp.on": "Enabled",
    "fp.off": "Disabled",
    "fp.notSet": "Off",
    "fp.unsupported": "Unsupported",
    "fp.blocked": "Blocked",
    "fp.restricted": "Restricted",
    "fp.row.fpId": "FingerprintJS ID",
    "fp.row.canvas": "Canvas Hash",
    "fp.row.webglHash": "WebGL Hash",
    "fp.row.audio": "Audio Hash",
    "fp.row.fonts": "Font Hash",
    "fp.row.wd": "WebDriver",
    "fp.row.headless": "Headless Signals",
    "fp.row.os": "Operating System",
    "fp.row.browser": "Browser",
    "fp.row.gpuVendor": "GPU Vendor",
    "fp.row.gpuRenderer": "GPU Renderer",
    "fp.row.screen": "Screen & Scaling",
    "fp.row.hw": "CPU / Memory",
    "fp.row.touch": "Touch Support",
    "fp.row.media": "Media Devices",
    "fp.row.tz": "Timezone",
    "fp.row.lang": "Languages",
    "fp.row.cookie": "Cookies / DNT",
    "fp.row.proto": "Protocol / TLS",
    "fp.row.cipher": "TLS Cipher",
    "fp.row.colo": "Edge Node",
    "fp.row.ua": "User-Agent",
    "asn.title": "Live ASN / BGP Monitor",
    "asn.snapshot": "Static Snapshot",
    "asn.live": "Live Stream",
    "asn.polling": "Polling",
    "asn.paused": "Paused",
    "asn.connecting": "Connecting…",
    "asn.announce": "Announce",
    "asn.withdraw": "Withdraw",
    "asn.noData": "No updates yet",
    "dns.title": "DNS Leak Test",
    "dns.probing": "Probing random subdomains…",
    "dns.probingSub": "Probing via 32-char random subdomains…",
    "dns.fallback1": "Switching to backup DNS probe…",
    "dns.fallback2": "Switching to secondary DNS probe…",
    "dns.noResolvers": "No recursive DNS resolvers captured (check ad-blockers or network rules)",
    "dns.warnTitle": "No Resolvers Detected",
    "dns.warnDesc": "All probe channels were blocked by network or browser extensions.",
    "dns.leakTitle": "Potential DNS Leak Detected",
    "dns.leakDesc": "Resolver regions ({c}) differ from your exit IP country ({e}).",
    "dns.okTitle": "No DNS Leak Detected",
    "dns.okDesc": "Captured {n} resolver(s), consistent with your exit IP.",
    "dns.summary": "Done ({m}): {n} resolver(s) captured.",
    "dns.hitsUnit": "{n}x",
    "rtc.title": "WebRTC Leak Test",
    "rtc.probing": "Probing STUN servers…",
    "rtc.noLeak": "No WebRTC leak detected",
    "rtc.matchExit": "Matches exit IP ({ip})",
    "rtc.leakBrief": "WebRTC leak: {ips}",
    "rtc.noExpose": "No public IP exposed",
    "rtc.leakTag": "Leak {ips}",
    "rtc.badTitle": "WebRTC Leak Detected",
    "rtc.badDesc": "Exposed IP(s): {ips}",
    "rtc.okTitle": "No WebRTC Leak Detected",
    "rtc.okDescMatch": "Matches HTTP exit IP ({ips})",
    "rtc.okDescNone": "Browser exposed no public IP via STUN",
    "api.title": "Open JSON API",
    "api.examples": "Examples",
    "api.self": "Self",
    "api.target": "Query",
    "api.asn": "ASN",
    "api.playground": "Live Playground",
    "api.placeholder": "IP or domain (leave blank for your IP)",
    "api.requesting": "Requesting…",
    "footer.title": "IPSpot · IP Purity & Network Diagnostics",
    "footer.privacy": "Privacy & Disclaimer",
    "privacy.title": "Privacy Policy & Disclaimer",
    "privacy.p1": "IPSpot (ipspot.org) queries public IP intelligence and OpenStreetMap coordinates in real time. Browser fingerprinting and WebRTC probes run locally in your browser without storing personal identity data.",
    "privacy.p2": "This site uses Google Analytics for anonymous traffic measurement and may display Google AdSense ads. Diagnostics are for network reference only. Contact: hezhanleiok@gmail.com",
    "score.purity": "Purity Score: <b>{n} / 100</b>",
    "score.cleanBaseline": "Clean baseline",
    "signals.count": "{n} checks",
    "signals.hit": "Detected",
    "signals.clean": "Clean",
    "map.noCoords": "No coordinates available",
    "map.target": "Target location",
    "ports.none": "None listed",
    "toast.copiedIp": "IP copied",
    "toast.copiedLink": "Link copied",
    "toast.copiedV4": "IPv4 copied",
    "toast.copiedV6": "IPv6 copied",
    "toast.copiedCmd": "Command copied",
    "toast.copiedAllAddr": "Full address copied",
    "toast.copiedField": "{label} copied",
    "toast.addrSwitched": "Loaded another nearby street address",
    "toast.fpRefreshed": "Browser fingerprint refreshed",
    "toast.cacheUsed": "Refresh failed, showing cached data",
    "toast.copyFail": "Copy failed",
    "title.base": "IPSpot · Free IP Purity Checker — Residential & Native IP · Fraud Score · Fingerprint Test",
    "title.fp": "Browser Fingerprint Diagnostics — IPSpot",
    "title.asn": "Live Global ASN & BGP Route Monitor — IPSpot",
    "title.dns": "Free Online DNS Leak Test — IPSpot",
    "title.webrtc": "Free Online WebRTC Leak Test — IPSpot",
    "title.api": "Open IP Intelligence JSON API — IPSpot",
    "origin.native": "Native IP ({cc})",
    "origin.broadcast": "Broadcast IP ({reg}→{loc})",
    "origin.unknown": "Unknown Origin",
    "type.residential": "Residential IP",
    "type.dual_isp": "Dual ISP / Broadcast",
    "type.datacenter": "Datacenter IP",
    "type.mobile": "Mobile Network",
    "type.business": "Business ISP",
    "type.unknown": "Unclassified",
    "badge.nonRes": "Non-Residential · {label}",
    "risk.minimal": "Ultra Clean",
    "risk.low": "Low Risk",
    "risk.medium": "Neutral",
    "risk.high": "High Risk",
    "risk.critical": "Critical Risk",
    "org.isp": "ISP",
    "org.hosting": "Hosting / Datacenter",
    "org.business": "Business",
    "org.education": "Education",
    "org.government": "Government",
    "org.banking": "Banking",
    "sig.proxy.label": "Proxy Server",
    "sig.proxy.desc": "Whether traffic is relayed through a public or anonymous proxy",
    "sig.vpn.label": "VPN Exit",
    "sig.vpn.desc": "Whether this IP belongs to a known VPN exit node",
    "sig.tor.label": "Tor Network",
    "sig.tor.desc": "Whether this IP is an active Tor anonymity exit node",
    "sig.datacenter.label": "Datacenter",
    "sig.datacenter.desc": "Whether hosted in a cloud provider or server facility rather than a home ISP",
    "sig.mobile.label": "Mobile Carrier",
    "sig.mobile.desc": "Whether connected via a cellular mobile carrier network",
    "sig.abuse.label": "Abuse / Threat",
    "sig.abuse.desc": "Whether flagged in abuse, blocklist, or automated crawler intelligence feeds",
    "sig.abuse.descDb": "AbuseIPDB: {reports} reports in 90d ({conf}% confidence)",
    "sig.hitSources": "Detected by: {hits}",
    "sig.cleanChecked": "Verified via {sources} · no risk found",
    "sig.abuseStat.db": "AbuseIPDB {n} ({c}%)",
    "sig.abuseStat.sfs": "StopForumSpam {n}",
    "sig.abuseStat.cve": "Shodan {n} CVE",
    "sig.abuseStat.ipq": "ipquery risk {n}",
    "bd.baseline_residential": ["Network Baseline", "Native residential ISP baseline"],
    "bd.baseline_mobile": ["Network Baseline", "Mobile carrier CGNAT shared exit"],
    "bd.baseline_business": ["Network Baseline", "Corporate / institutional line"],
    "bd.baseline_dual_isp": ["Network Baseline", "Dual ISP / broadcast hosted block"],
    "bd.baseline_datacenter": ["Network Baseline", "Cloud / datacenter hosting network"],
    "bd.baseline_unknown": ["Network Baseline", "Insufficient residential proof"],
    "bd.radar_bot": ["ASN Bot Traffic", "Cloudflare Radar measured {bot}% bot traffic on ASN"],
    "bd.broadcast": ["Broadcast Routing", "Registered in {reg} ≠ geolocated in {loc}"],
    "bd.tor": ["Tor Exit", "Listed in Tor exit node feeds"],
    "bd.vpn": ["VPN Exit", "Matched known VPN exit ranges"],
    "bd.proxy": ["Proxy Node", "Matched public or shared proxy pools"],
    "bd.dc_proxy": ["DC + Proxy Combo", "Combined datacenter and proxy risk"],
    "bd.abuseipdb": ["AbuseIPDB", "{reports} reports in 90d ({conf}% confidence)"],
    "bd.abuse_generic": ["Abuse / Threat", "Flagged by threat intelligence sources"],
    "bd.crawler": ["Crawler Source", "Identified as commercial or automated scraper"],
    "bd.vulns": ["Exposed CVEs", "Shodan detected {count} known vulnerability signatures"],
  },

  "zh-CN": {
    "brand.sub": "IP 检测雷达",
    "nav.query": "IP 查询",
    "nav.fp": "指纹检测",
    "nav.asn": "ASN 监控",
    "nav.dns": "DNS 泄露",
    "nav.webrtc": "WebRTC",
    "nav.api": "开放 API",
    "theme.light": "浅色",
    "theme.dark": "深色",
    "hero.eyebrow": "IP INTELLIGENCE · 实时威胁情报",
    "hero.title1": "看清每一个 IP",
    "hero.title2": "背后的真实身份",
    "hero.sub": "家宽判定 · 原生/广播 · 风险信号 · 真实地理地址 · 人机对比 · 指纹检测",
    "hero.placeholder": "输入 IPv4 / IPv6 地址或域名…",
    "hero.btn": "检测",
    "hero.detectMe": "重新识别本机 IP",
    "hero.recent": "最近查询",
    "state.loading": "正在检测 IP 情报…",
    "state.loadingShort": "加载中…",
    "state.waiting": "等待检测…",
    "state.retry": "重试",
    "state.failed": "检测失败",
    "kv.asn": "ASN / 企业",
    "kv.range": "IP 范围",
    "kv.numeric": "数字地址",
    "kv.source": "IP 来源",
    "kv.attr": "IP 属性",
    "kv.hb": "人机流量比",
    "kv.location": "IP 位置",
    "kv.score": "IPSpot 系数",
    "kv.ai": "AI 分析",
    "kv.leak": "泄露检测",
    "kv.fp": "浏览器指纹",
    "sub.company": "所属企业",
    "sub.companyType": "企业性质",
    "sub.domain": "官网域名",
    "sub.route": "路由段",
    "sub.rdns": "反向解析",
    "sub.netname": "网段 / RIR",
    "sub.abuse": "滥用联系",
    "sub.ports": "开放端口",
    "sub.audio": "Audio 哈希",
    "sub.os": "操作系统",
    "sub.screen": "屏幕 / 缩放",
    "sub.hw": "处理器 / 内存",
    "sub.tz": "时区 / 语言",
    "sub.bot": "自动化特征",
    "hb.dim": "维度",
    "hb.exitIp": "出口 IP",
    "hb.localEnv": "本机环境",
    "hb.status": "状态",
    "hb.estimated": "估算",
    "hb.tz": "时区",
    "hb.lang": "语言",
    "hb.auto": "自动化",
    "hb.match": "一致",
    "hb.mismatch": "偏差",
    "hb.safe": "安全",
    "hb.leaked": "泄露",
    "hb.none": "无记录",
    "hb.risk": "风险",
    "hb.normal": "正常",
    "hb.human": "真人",
    "hb.abnormal": "异常",
    "btn.aiRun": "✦ 生成 AI 诊断",
    "btn.aiView": "✦ 查看 AI 诊断",
    "btn.aiHide": "收起 AI 诊断",
    "btn.aiRetry": "✦ 重试 AI 诊断",
    "btn.details": "详情",
    "btn.openFp": "打开完整指纹环境检测 →",
    "btn.latency": "站点延迟 ▾",
    "btn.retest": "重测",
    "btn.bgpMore": "BGP 历史 ▾",
    "btn.openMap": "外部打开",
    "btn.gaRefresh": "换一个同区地址",
    "btn.gaCopyAll": "复制全部",
    "btn.recollect": "重新采集",
    "btn.liveStart": "开启实时",
    "btn.livePause": "暂停",
    "btn.clear": "清空",
    "btn.recheck": "重新检测",
    "btn.send": "请求",
    "btn.showMore": "展开更多 ({n}) ▾",
    "btn.collapse": "收起 ▴",
    "ai.loading": "AI 分析中…",
    "ai.cached": "缓存",
    "ai.unavailable": "AI 暂不可用",
    "card.signals": "风险信号",
    "card.exit": "网络出口",
    "card.regHistory": "注册地历史",
    "card.bgpTitle": "BGP 历史路由宣告",
    "card.mapGeo": "地图定位与真实地理位置",
    "card.realAddr": "IP 真实地理位置",
    "exit.v4": "IPv4 出口",
    "exit.v6": "IPv6 出口",
    "exit.none": "无公网出口",
    "exit.unassigned": "未分配",
    "exit.timeout": "超时",
    "tbl.cidr": "网段 (CIDR)",
    "tbl.rir": "注册局",
    "tbl.country": "国家/地区",
    "tbl.firstSeen": "首次出现",
    "tbl.lastSeen": "最近活跃",
    "tbl.empty": "暂无记录",
    "tbl.emptyReg": "注册局暂无历史变更记录",
    "tbl.emptyBgp": "暂无 BGP 历史记录",
    "tbl.prefix": "前缀",
    "tbl.originAsn": "起源 ASN",
    "tbl.firstAnn": "首次宣告",
    "tbl.lastAnn": "最近宣告",
    "tbl.time": "时间",
    "tbl.org": "组织",
    "tbl.type": "类型",
    "tbl.resolverIp": "解析服务器 IP",
    "tbl.resolverGeo": "归属地",
    "tbl.hits": "命中",
    "ga.street": "街道",
    "ga.city": "城市",
    "ga.state": "州 / 省",
    "ga.country": "国家",
    "ga.zip": "邮编",
    "ga.tz": "时区",
    "ga.noCoords": "无坐标",
    "ga.lookingUp": "反查中…",
    "ga.noStreet": "暂未获取到具体街道",
    "ga.fallbackSrc": "IP 基础库",
    "faq.summary": "关于 IPSpot 检测原理与常见问题",
    "faq.count": "8 项问答",
    "faq.tag1": "判定",
    "faq.tag2": "评分",
    "faq.tag3": "安全",
    "faq.tag4": "数据",
    "faq.tag5": "指纹",
    "faq.tag6": "网络",
    "faq.tag7": "地图",
    "faq.tag8": "开发",
    "faq.q1": "如何精准判定原生 IP、广播 IP 与家宽/机房？",
    "faq.a1": "通过对比 RIR 注册局（ARIN / RIPE / APNIC）与 RDAP 归属国家及 12 源物理定位识别原生或广播属性，并结合 ASN 类型、云厂商关键词、rDNS 反向解析与 Shodan 特征精准区分原生家宽、双 ISP 与机房 IP。",
    "faq.q2": "人机流量比与 IPSpot 纯净度评分如何计算？",
    "faq.a2": "接入 Cloudflare Radar 近 7 天 ASN 全网真实人机请求占比，结合网络基线、跨区广播、代理/VPN/Tor、AbuseIPDB 与 StopForumSpam 举报记录透明加权计算 0–100% 风险值与纯净分，且不对大网家宽误伤。",
    "faq.q3": "6 项风险信号是如何做到真实交叉验证的？",
    "faq.a3": "每项风险信号均由 proxycheck.io、Tor 官方 Onionoo 节点库、StopForumSpam、IP2Location、ipquery.io、ip-api.com 与 Shodan 开放端口并行核验，并在卡片中直接列出实际参与核验或命中的数据源。",
    "faq.q4": "为什么不同平台的 IP 地理位置显示不一样？",
    "faq.a4": "各家 GeoIP 数据库（MaxMind、IP2Location、IPInfo、ipapi.is、GeoJS 等）更新周期与任播/广播收敛策略不同。IPSpot 同屏聚合最多 12 个独立地理库并以共识算法定位，避免单库偏差误判。",
    "faq.q5": "浏览器指纹检测与人机环境比对测哪些内容？",
    "faq.a5": "本地浏览器集成 FingerprintJS v4 及 Canvas、WebGL、Audio、字体、屏幕缩放与 WebDriver/Headless 自动化特征采集，并与出口 IP 的国家、时区、语言和 WebRTC 实时交叉比对一致性。",
    "faq.q6": "DNS 泄露与 WebRTC 泄露检测的原理是什么？",
    "faq.a6": "DNS 泄露通过 32 位高随机子域名探测绕过本地与运营商缓存，捕获真实出口递归解析服务器；WebRTC 泄露则并发连接多组国际 STUN 节点，排查浏览器是否绕过代理暴露真实公网 IP。",
    "faq.q7": "IP 真实街道地址反查与地图定位如何工作？",
    "faq.a7": "根据目标 IP 经纬度坐标，通过 OpenStreetMap Nominatim 与 Photon 逆地理编码服务实时反查同区域真实存在的街道、城市、州省、国家、邮编与时区，支持点击“换一个同区地址”及一键复制。",
    "faq.q8": "ASN 实时监控、AI 风控诊断与开放 API 怎么用？",
    "faq.a8": "ASN 监控直连 RIPE RIS Live 监听全球实时 BGP 路由宣告与撤销；AI 诊断基于真实检测结果输出业务可用性建议；开放 API 支持免鉴权传入 IP、域名或 ASN 查询结构化 JSON 数据。",
    "fp.title": "浏览器指纹环境检测",
    "fp.visitorLabel": "FingerprintJS 访客 ID",
    "fp.coreTitle": "核心指纹哈希",
    "fp.hwTitle": "硬件与显示环境",
    "fp.envTitle": "系统、时区与连接环境",
    "fp.health": "环境健康度 {n}%",
    "fp.verdictOk": "未检测到自动化脚本特征，浏览器指纹环境自然一致。",
    "fp.verdictWarn": "检测到自动化特征：{w}",
    "fp.normalBrowser": "正常真人浏览器",
    "fp.wdTrue": "true（检测到自动化）",
    "fp.wdFalse": "false（正常）",
    "fp.none": "未检测到",
    "fp.touch": "{n} 点触控",
    "fp.noTouch": "无触控屏",
    "fp.media": "麦克风 {mic} · 扬声器 {spk} · 摄像头 {cam}",
    "fp.cores": "{n} 逻辑核",
    "fp.unknown": "未知",
    "fp.hidden": "未公开",
    "fp.on": "开启",
    "fp.off": "禁用",
    "fp.notSet": "未开启",
    "fp.unsupported": "不支持",
    "fp.blocked": "已屏蔽",
    "fp.restricted": "受限",
    "fp.row.fpId": "FingerprintJS ID",
    "fp.row.canvas": "Canvas 哈希",
    "fp.row.webglHash": "WebGL 哈希",
    "fp.row.audio": "Audio 音频哈希",
    "fp.row.fonts": "字体集合哈希",
    "fp.row.wd": "WebDriver",
    "fp.row.headless": "无头浏览器特征",
    "fp.row.os": "操作系统",
    "fp.row.browser": "浏览器版本",
    "fp.row.gpuVendor": "GPU 厂商",
    "fp.row.gpuRenderer": "GPU 渲染器",
    "fp.row.screen": "屏幕与缩放",
    "fp.row.hw": "处理器 / 内存",
    "fp.row.touch": "触控支持",
    "fp.row.media": "媒体设备",
    "fp.row.tz": "系统时区",
    "fp.row.lang": "浏览器语言",
    "fp.row.cookie": "Cookie / DNT",
    "fp.row.proto": "连接协议",
    "fp.row.cipher": "TLS 加密套件",
    "fp.row.colo": "接入边缘节点",
    "fp.row.ua": "User-Agent",
    "asn.title": "ASN 实时监控",
    "asn.snapshot": "静态快照",
    "asn.live": "实时连接",
    "asn.polling": "中转刷新",
    "asn.paused": "已暂停",
    "asn.connecting": "连接中…",
    "asn.announce": "公告",
    "asn.withdraw": "撤销",
    "asn.noData": "暂无数据",
    "dns.title": "DNS 泄露检测",
    "dns.probing": "随机子域探测中…",
    "dns.probingSub": "正在通过 32 位随机子域探测…",
    "dns.fallback1": "切换备用 DNS 探测通道…",
    "dns.fallback2": "切换第二备用 DNS 探测通道…",
    "dns.noResolvers": "未捕获到递归 DNS，请检查是否开启了广告拦截插件或网络限制",
    "dns.warnTitle": "未获取到解析服务器",
    "dns.warnDesc": "三个探测通道均被当前网络或浏览器插件拦截，请关闭拦截后重试",
    "dns.leakTitle": "发现 DNS 泄露迹象",
    "dns.leakDesc": "部分解析服务器归属地（{c}）与出口国家（{e}）不一致",
    "dns.okTitle": "未发现 DNS 泄露",
    "dns.okDesc": "共捕获 {n} 台解析服务器，归属地与出口一致",
    "dns.summary": "探测完成（通道：{m}），共捕获 {n} 台递归解析服务器。",
    "dns.hitsUnit": "{n} 次",
    "rtc.title": "WebRTC 泄露检测",
    "rtc.probing": "STUN 探测中…",
    "rtc.noLeak": "未检测到 WebRTC 泄露",
    "rtc.matchExit": "与出口一致 ({ip})",
    "rtc.leakBrief": "WebRTC 泄露：{ips}",
    "rtc.noExpose": "无公网暴露",
    "rtc.leakTag": "泄露 {ips}",
    "rtc.badTitle": "发现 WebRTC 泄露",
    "rtc.badDesc": "暴露地址：{ips}",
    "rtc.okTitle": "未发现 WebRTC 泄露",
    "rtc.okDescMatch": "与 HTTP 出口一致 ({ips})",
    "rtc.okDescNone": "浏览器未暴露公网地址",
    "api.title": "开放 API",
    "api.examples": "调用示例",
    "api.self": "本机",
    "api.target": "指定",
    "api.asn": "ASN",
    "api.playground": "在线调试",
    "api.placeholder": "IP 或域名（留空查本机）",
    "api.requesting": "请求中…",
    "footer.title": "IPSpot · IP 纯净度与网络环境检测",
    "footer.privacy": "隐私与免责声明",
    "privacy.title": "隐私政策与免责声明",
    "privacy.p1": "IPSpot (ipspot.org) 仅实时查询公网 IP 公开情报与 OpenStreetMap 公开地理坐标；指纹检测与 WebRTC 探测均在本地浏览器完成，不存储个人身份信息。",
    "privacy.p2": "本站使用 Google Analytics 统计匿名访问，并可能接入 Google AdSense 广告服务。结果仅供网络诊断参考，联系邮箱：hezhanleiok@gmail.com",
    "score.purity": "综合纯净分：<b>{n} / 100</b>",
    "score.cleanBaseline": "基线纯净",
    "signals.count": "{n} 项检测",
    "signals.hit": "检测到",
    "signals.clean": "未检测到",
    "map.noCoords": "暂无可用坐标",
    "map.target": "目标位置",
    "ports.none": "无公开记录",
    "toast.copiedIp": "已复制 IP",
    "toast.copiedLink": "已复制链接",
    "toast.copiedV4": "已复制 IPv4",
    "toast.copiedV6": "已复制 IPv6",
    "toast.copiedCmd": "已复制命令",
    "toast.copiedAllAddr": "已复制完整真实地址",
    "toast.copiedField": "已复制{label}",
    "toast.addrSwitched": "已切换同区真实街道地址",
    "toast.fpRefreshed": "已重新采集浏览器指纹",
    "toast.cacheUsed": "刷新失败，已显示缓存",
    "toast.copyFail": "复制失败",
    "title.base": "IPSpot · 免费 IP 纯净度检测 — 原生/家宽判定 · 欺诈评分 · 浏览器指纹 · 真实地理地址",
    "title.fp": "浏览器指纹环境检测 — IPSpot",
    "title.asn": "全球 ASN 与 BGP 路由实时监控 — IPSpot",
    "title.dns": "DNS 泄露在线检测 — IPSpot",
    "title.webrtc": "WebRTC 真实 IP 泄露在线检测 — IPSpot",
    "title.api": "开放 IP 情报 JSON API 文档 — IPSpot",
    "origin.native": "原生 IP ({cc})",
    "origin.broadcast": "广播 IP ({reg}→{loc})",
    "origin.unknown": "未知来源",
    "type.residential": "家宽 IP",
    "type.dual_isp": "双 ISP / 广播",
    "type.datacenter": "机房 IP",
    "type.mobile": "移动网络",
    "type.business": "商业宽带",
    "type.unknown": "商业/未分类",
    "badge.nonRes": "非家宽 · {label}",
    "risk.minimal": "极度纯净",
    "risk.low": "低风险",
    "risk.medium": "中性",
    "risk.high": "高风险",
    "risk.critical": "极度风险",
    "org.isp": "运营商 (ISP)",
    "org.hosting": "数据中心 / 托管商",
    "org.business": "商业企业",
    "org.education": "教育科研",
    "org.government": "政府机构",
    "org.banking": "金融机构",
    "sig.proxy.label": "代理服务器",
    "sig.proxy.desc": "流量是否经过公开代理或匿名代理转发",
    "sig.vpn.label": "VPN 出口",
    "sig.vpn.desc": "是否为已知 VPN 服务的出口节点",
    "sig.tor.label": "Tor 网络",
    "sig.tor.desc": "是否为 Tor 匿名网络的出口节点",
    "sig.datacenter.label": "数据中心",
    "sig.datacenter.desc": "是否托管于云服务商或机房，而非家庭网络",
    "sig.mobile.label": "移动网络",
    "sig.mobile.desc": "是否通过蜂窝移动网络接入互联网",
    "sig.abuse.label": "滥用威胁",
    "sig.abuse.desc": "是否出现在滥用、黑名单或自动化爬虫情报源中",
    "sig.abuse.descDb": "AbuseIPDB 近 90 天举报 {reports} 次（置信度 {conf}%）",
    "sig.hitSources": "命中来源：{hits}",
    "sig.cleanChecked": "已核验 {sources}，未见风险特征",
    "sig.abuseStat.db": "AbuseIPDB {n}次({c}%)",
    "sig.abuseStat.sfs": "StopForumSpam {n}次",
    "sig.abuseStat.cve": "Shodan {n}漏洞",
    "sig.abuseStat.ipq": "ipquery 风险 {n}",
    "bd.baseline_residential": ["网络基线", "原生住宅宽带基线"],
    "bd.baseline_mobile": ["网络基线", "移动蜂窝 CGNAT 共享出口"],
    "bd.baseline_business": ["网络基线", "企业/机构商用网络"],
    "bd.baseline_dual_isp": ["网络基线", "双 ISP / 广播托管段"],
    "bd.baseline_datacenter": ["网络基线", "数据中心 / 云主机网络"],
    "bd.baseline_unknown": ["网络基线", "归属证据不足审慎基线"],
    "bd.radar_bot": ["ASN 机器流量", "Radar 实测该 ASN 机器流量占比 {bot}%"],
    "bd.broadcast": ["跨区广播", "注册国 {reg} ≠ 定位国 {loc}"],
    "bd.tor": ["Tor 节点", "命中 Tor 匿名出口"],
    "bd.vpn": ["VPN 出口", "命中 VPN 节点库"],
    "bd.proxy": ["代理节点", "命中公开代理或转发节点"],
    "bd.dc_proxy": ["机房代理叠加", "机房 + 代理复合高危特征"],
    "bd.abuseipdb": ["AbuseIPDB 举报", "近 90 天被举报 {reports} 次（置信度 {conf}%）"],
    "bd.abuse_generic": ["滥用与威胁", "命中滥用或威胁情报源"],
    "bd.crawler": ["爬虫来源", "命中商业/抓取爬虫库"],
    "bd.vulns": ["暴露面漏洞", "Shodan 发现 {count} 个已知漏洞特征"],
  },

  "zh-TW": {
    "brand.sub": "IP 偵測雷達",
    "nav.query": "IP 查詢",
    "nav.fp": "指紋檢測",
    "nav.asn": "ASN 監控",
    "nav.dns": "DNS 洩露",
    "nav.webrtc": "WebRTC",
    "nav.api": "開放 API",
    "theme.light": "淺色",
    "theme.dark": "深色",
    "hero.eyebrow": "IP INTELLIGENCE · 即時威脅情報",
    "hero.title1": "看清每一個 IP",
    "hero.title2": "背後的真實身份",
    "hero.sub": "家寬判定 · 原生/廣播 · 風險信號 · 真實地理地址 · 人機對比 · 指紋檢測",
    "hero.placeholder": "輸入 IPv4 / IPv6 位址或網域…",
    "hero.btn": "檢測",
    "hero.detectMe": "重新識別本機 IP",
    "hero.recent": "最近查詢",
    "state.loading": "正在檢測 IP 情報…",
    "state.loadingShort": "載入中…",
    "state.waiting": "等待檢測…",
    "state.retry": "重試",
    "state.failed": "檢測失敗",
    "kv.asn": "ASN / 企業",
    "kv.range": "IP 範圍",
    "kv.numeric": "數字位址",
    "kv.source": "IP 來源",
    "kv.attr": "IP 屬性",
    "kv.hb": "人機流量比",
    "kv.location": "IP 位置",
    "kv.score": "IPSpot 係數",
    "kv.ai": "AI 分析",
    "kv.leak": "洩露檢測",
    "kv.fp": "瀏覽器指紋",
    "sub.company": "所屬企業",
    "sub.companyType": "企業性質",
    "sub.domain": "官網網域",
    "sub.route": "路由段",
    "sub.rdns": "反向解析",
    "sub.netname": "網段 / RIR",
    "sub.abuse": "濫用聯繫",
    "sub.ports": "開放連接埠",
    "sub.audio": "Audio 雜湊",
    "sub.os": "作業系統",
    "sub.screen": "螢幕 / 縮放",
    "sub.hw": "處理器 / 記憶體",
    "sub.tz": "時區 / 語言",
    "sub.bot": "自動化特徵",
    "hb.dim": "維度",
    "hb.exitIp": "出口 IP",
    "hb.localEnv": "本機環境",
    "hb.status": "狀態",
    "hb.estimated": "估算",
    "hb.tz": "時區",
    "hb.lang": "語言",
    "hb.auto": "自動化",
    "hb.match": "一致",
    "hb.mismatch": "偏差",
    "hb.safe": "安全",
    "hb.leaked": "洩露",
    "hb.none": "無紀錄",
    "hb.risk": "風險",
    "hb.normal": "正常",
    "hb.human": "真人",
    "hb.abnormal": "異常",
    "btn.aiRun": "✦ 生成 AI 診斷",
    "btn.aiView": "✦ 查看 AI 診斷",
    "btn.aiHide": "收起 AI 診斷",
    "btn.aiRetry": "✦ 重試 AI 診斷",
    "btn.details": "詳情",
    "btn.openFp": "打開完整指紋環境檢測 →",
    "btn.latency": "站點延遲 ▾",
    "btn.retest": "重測",
    "btn.bgpMore": "BGP 歷史 ▾",
    "btn.openMap": "外部開啟",
    "btn.gaRefresh": "換一個同區地址",
    "btn.gaCopyAll": "複製全部",
    "btn.recollect": "重新採集",
    "btn.liveStart": "開啟即時",
    "btn.livePause": "暫停",
    "btn.clear": "清空",
    "btn.recheck": "重新檢測",
    "btn.send": "請求",
    "btn.showMore": "展開更多 ({n}) ▾",
    "btn.collapse": "收起 ▴",
    "ai.loading": "AI 分析中…",
    "ai.cached": "快取",
    "ai.unavailable": "AI 暫不可用",
    "card.signals": "風險信號",
    "card.exit": "網路出口",
    "card.regHistory": "註冊地歷史",
    "card.bgpTitle": "BGP 歷史路由宣告",
    "card.mapGeo": "地圖定位與真實地理位置",
    "card.realAddr": "IP 真實地理位置",
    "exit.v4": "IPv4 出口",
    "exit.v6": "IPv6 出口",
    "exit.none": "無公網出口",
    "exit.unassigned": "未分配",
    "exit.timeout": "逾時",
    "tbl.cidr": "網段 (CIDR)",
    "tbl.rir": "註冊局",
    "tbl.country": "國家/地區",
    "tbl.firstSeen": "首次出現",
    "tbl.lastSeen": "最近活躍",
    "tbl.empty": "暫無紀錄",
    "tbl.emptyReg": "註冊局暫無歷史變更紀錄",
    "tbl.emptyBgp": "暫無 BGP 歷史紀錄",
    "tbl.prefix": "前綴",
    "tbl.originAsn": "起源 ASN",
    "tbl.firstAnn": "首次宣告",
    "tbl.lastAnn": "最近宣告",
    "tbl.time": "時間",
    "tbl.org": "組織",
    "tbl.type": "類型",
    "tbl.resolverIp": "解析伺服器 IP",
    "tbl.resolverGeo": "歸屬地",
    "tbl.hits": "命中",
    "ga.street": "街道",
    "ga.city": "城市",
    "ga.state": "州 / 省",
    "ga.country": "國家",
    "ga.zip": "郵遞區號",
    "ga.tz": "時區",
    "ga.noCoords": "無座標",
    "ga.lookingUp": "反查中…",
    "ga.noStreet": "暫未取得具體街道",
    "ga.fallbackSrc": "IP 基礎庫",
    "faq.summary": "關於 IPSpot 檢測原理與常見問題",
    "faq.count": "8 項問答",
    "faq.tag1": "判定",
    "faq.tag2": "評分",
    "faq.tag3": "安全",
    "faq.tag4": "數據",
    "faq.tag5": "指紋",
    "faq.tag6": "網路",
    "faq.tag7": "地圖",
    "faq.tag8": "開發",
    "faq.q1": "如何精準判定原生 IP、廣播 IP 與家寬/機房？",
    "faq.a1": "對比 RIR 註冊局（ARIN / RIPE / APNIC）與 RDAP 歸屬國家及 12 源定位識別原生或廣播屬性，並融合 ASN 類型、雲廠商關鍵字、rDNS 與 Shodan 特徵精準區分原生家寬、雙 ISP 與機房 IP。",
    "faq.q2": "人機流量比與 IPSpot 純淨度評分如何計算？",
    "faq.a2": "接入 Cloudflare Radar 近 7 天 ASN 全網真實人機請求佔比，結合網路基線、跨區廣播、代理/VPN/Tor、AbuseIPDB 與 StopForumSpam 舉報記錄透明計算 0–100% 風險值與純淨分。",
    "faq.q3": "6 項風險信號是如何做到真實交叉驗證的？",
    "faq.a3": "每項風險信號均由 proxycheck.io、Tor 官方 Onionoo 節點庫、StopForumSpam、IP2Location、ipquery.io、ip-api.com 與 Shodan 連接埠並行核驗，並直接顯示參與核驗或命中的資料來源。",
    "faq.q4": "為什麼不同平台的 IP 地理位置顯示不一樣？",
    "faq.a4": "各家 GeoIP 資料庫（MaxMind、IP2Location、IPInfo、ipapi.is、GeoJS 等）更新週期與任播策略不同。IPSpot 同屏聚合最多 12 個獨立地理庫並以共識演算法定位，避免單庫偏差誤判。",
    "faq.q5": "瀏覽器指紋檢測與人機環境比對測哪些內容？",
    "faq.a5": "本地瀏覽器整合 FingerprintJS v4 與 Canvas、WebGL、Audio、字體、螢幕縮放及 WebDriver/Headless 特徵採集，並與出口 IP 的國家、時區、語言和 WebRTC 即時交叉比對一致性。",
    "faq.q6": "DNS 洩漏與 WebRTC 洩漏檢測的原理是什麼？",
    "faq.a6": "DNS 洩漏透過 32 位隨機子網域探測繞過快取，捕獲真實出口遞迴解析伺服器；WebRTC 洩漏則併發連接多組國際 STUN 節點，排查瀏覽器是否繞過代理暴露真實公網 IP。",
    "faq.q7": "IP 真實街道地址反查與地圖定位如何運作？",
    "faq.a7": "根據目標 IP 經緯度座標，透過 OpenStreetMap Nominatim 與 Photon 逆地理編碼即時反查同區真實街道、城市、州省、國家、郵遞區號與時區，支援切換附近地址與一鍵複製。",
    "faq.q8": "ASN 即時監控、AI 風控診斷與開放 API 怎麼用？",
    "faq.a8": "ASN 監控直連 RIPE RIS Live 監聽全球即時 BGP 路由宣告與撤銷；AI 診斷依據真實檢測結果輸出可用性建議；開放 API 支援免鑑權查詢 IP、網域或 ASN 結構化 JSON 資料。",
    "fp.title": "瀏覽器指紋環境檢測",
    "fp.visitorLabel": "FingerprintJS 訪客 ID",
    "fp.coreTitle": "核心指紋雜湊",
    "fp.hwTitle": "硬體與顯示環境",
    "fp.envTitle": "系統、時區與連線環境",
    "fp.health": "環境健康度 {n}%",
    "fp.verdictOk": "未偵測到自動化腳本特徵，瀏覽器指紋環境自然一致。",
    "fp.verdictWarn": "偵測到自動化特徵：{w}",
    "fp.normalBrowser": "正常真人瀏覽器",
    "fp.wdTrue": "true（偵測到自動化）",
    "fp.wdFalse": "false（正常）",
    "fp.none": "未偵測到",
    "fp.touch": "{n} 點觸控",
    "fp.noTouch": "無觸控螢幕",
    "fp.media": "麥克風 {mic} · 揚聲器 {spk} · 攝影機 {cam}",
    "fp.cores": "{n} 邏輯核心",
    "fp.unknown": "未知",
    "fp.hidden": "未公開",
    "fp.on": "開啟",
    "fp.off": "停用",
    "fp.notSet": "未開啟",
    "fp.unsupported": "不支援",
    "fp.blocked": "已封鎖",
    "fp.restricted": "受限",
    "fp.row.fpId": "FingerprintJS ID",
    "fp.row.canvas": "Canvas 雜湊",
    "fp.row.webglHash": "WebGL 雜湊",
    "fp.row.audio": "Audio 音訊雜湊",
    "fp.row.fonts": "字體集合雜湊",
    "fp.row.wd": "WebDriver",
    "fp.row.headless": "無頭瀏覽器特徵",
    "fp.row.os": "作業系統",
    "fp.row.browser": "瀏覽器版本",
    "fp.row.gpuVendor": "GPU 廠商",
    "fp.row.gpuRenderer": "GPU 渲染器",
    "fp.row.screen": "螢幕與縮放",
    "fp.row.hw": "處理器 / 記憶體",
    "fp.row.touch": "觸控支援",
    "fp.row.media": "媒體裝置",
    "fp.row.tz": "系統時區",
    "fp.row.lang": "瀏覽器語言",
    "fp.row.cookie": "Cookie / DNT",
    "fp.row.proto": "連線協定",
    "fp.row.cipher": "TLS 加密套件",
    "fp.row.colo": "接入邊緣節點",
    "fp.row.ua": "User-Agent",
    "asn.title": "ASN 即時監控",
    "asn.snapshot": "靜態快照",
    "asn.live": "即時連線",
    "asn.polling": "中轉刷新",
    "asn.paused": "已暫停",
    "asn.connecting": "連線中…",
    "asn.announce": "公告",
    "asn.withdraw": "撤銷",
    "asn.noData": "暫無資料",
    "dns.title": "DNS 洩露檢測",
    "dns.probing": "隨機子網域探測中…",
    "dns.probingSub": "正在透過 32 位隨機子網域探測…",
    "dns.fallback1": "切換備用 DNS 探測通道…",
    "dns.fallback2": "切換第二備用 DNS 探測通道…",
    "dns.noResolvers": "未捕獲到遞迴 DNS，請檢查廣告封鎖外掛或網路限制",
    "dns.warnTitle": "未取得解析伺服器",
    "dns.warnDesc": "所有探測通道皆被網路或外掛攔截，請停用後重試",
    "dns.leakTitle": "發現 DNS 洩露跡象",
    "dns.leakDesc": "部分解析伺服器歸屬地（{c}）與出口國家（{e}）不一致",
    "dns.okTitle": "未發現 DNS 洩露",
    "dns.okDesc": "共捕獲 {n} 台解析伺服器，歸屬地與出口一致",
    "dns.summary": "探測完成（通道：{m}），共捕獲 {n} 台遞迴解析伺服器。",
    "dns.hitsUnit": "{n} 次",
    "rtc.title": "WebRTC 洩露檢測",
    "rtc.probing": "STUN 探測中…",
    "rtc.noLeak": "未偵測到 WebRTC 洩露",
    "rtc.matchExit": "與出口一致 ({ip})",
    "rtc.leakBrief": "WebRTC 洩露：{ips}",
    "rtc.noExpose": "無公網暴露",
    "rtc.leakTag": "洩露 {ips}",
    "rtc.badTitle": "發現 WebRTC 洩露",
    "rtc.badDesc": "暴露位址：{ips}",
    "rtc.okTitle": "未發現 WebRTC 洩露",
    "rtc.okDescMatch": "與 HTTP 出口一致 ({ips})",
    "rtc.okDescNone": "瀏覽器未暴露公網位址",
    "api.title": "開放 API",
    "api.examples": "呼叫範例",
    "api.self": "本機",
    "api.target": "指定",
    "api.asn": "ASN",
    "api.playground": "線上除錯",
    "api.placeholder": "IP 或網域（留空查本機）",
    "api.requesting": "請求中…",
    "footer.title": "IPSpot · IP 純淨度與網路環境檢測",
    "footer.privacy": "隱私與免責聲明",
    "privacy.title": "隱私權政策與免責聲明",
    "privacy.p1": "IPSpot (ipspot.org) 僅即時查詢公網 IP 公開情報與 OpenStreetMap 公開地理座標；指紋檢測與 WebRTC 探測均在本機瀏覽器完成，不儲存個人身份資訊。",
    "privacy.p2": "本站使用 Google Analytics 統計匿名造訪，並可能接入 Google AdSense 廣告服務。結果僅供網路診斷參考，聯繫信箱：hezhanleiok@gmail.com",
    "score.purity": "綜合純淨分：<b>{n} / 100</b>",
    "score.cleanBaseline": "基線純淨",
    "signals.count": "{n} 項檢測",
    "signals.hit": "偵測到",
    "signals.clean": "未偵測到",
    "map.noCoords": "暫無可用座標",
    "map.target": "目標位置",
    "ports.none": "無公開紀錄",
    "toast.copiedIp": "已複製 IP",
    "toast.copiedLink": "已複製連結",
    "toast.copiedV4": "已複製 IPv4",
    "toast.copiedV6": "已複製 IPv6",
    "toast.copiedCmd": "已複製指令",
    "toast.copiedAllAddr": "已複製完整真實地址",
    "toast.copiedField": "已複製{label}",
    "toast.addrSwitched": "已切換同區真實街道地址",
    "toast.fpRefreshed": "已重新採集瀏覽器指紋",
    "toast.cacheUsed": "刷新失敗，已顯示快取",
    "toast.copyFail": "複製失敗",
    "title.base": "IPSpot · 免費 IP 純淨度檢測 — 原生/家寬判定 · 欺詐評分 · 瀏覽器指紋 · 真實地理地址",
    "title.fp": "瀏覽器指紋環境檢測 — IPSpot",
    "title.asn": "全球 ASN 與 BGP 路由即時監控 — IPSpot",
    "title.dns": "DNS 洩露線上檢測 — IPSpot",
    "title.webrtc": "WebRTC 真實 IP 洩露線上檢測 — IPSpot",
    "title.api": "開放 IP 情報 JSON API 文件 — IPSpot",
    "origin.native": "原生 IP ({cc})",
    "origin.broadcast": "廣播 IP ({reg}→{loc})",
    "origin.unknown": "未知來源",
    "type.residential": "家寬 IP",
    "type.dual_isp": "雙 ISP / 廣播",
    "type.datacenter": "機房 IP",
    "type.mobile": "行動網路",
    "type.business": "商業寬頻",
    "type.unknown": "商業/未分類",
    "badge.nonRes": "非家寬 · {label}",
    "risk.minimal": "極度純淨",
    "risk.low": "低風險",
    "risk.medium": "中性",
    "risk.high": "高風險",
    "risk.critical": "極度風險",
    "org.isp": "電信業者 (ISP)",
    "org.hosting": "資料中心 / 託管商",
    "org.business": "商業企業",
    "org.education": "教育科研",
    "org.government": "政府機構",
    "org.banking": "金融機構",
    "sig.proxy.label": "代理伺服器",
    "sig.proxy.desc": "流量是否經過公開代理或匿名代理轉發",
    "sig.vpn.label": "VPN 出口",
    "sig.vpn.desc": "是否為已知 VPN 服務的出口節點",
    "sig.tor.label": "Tor 網路",
    "sig.tor.desc": "是否為 Tor 匿名網路的出口節點",
    "sig.datacenter.label": "資料中心",
    "sig.datacenter.desc": "是否託管於雲服務商或機房，而非家庭網路",
    "sig.mobile.label": "行動網路",
    "sig.mobile.desc": "是否透過行動電信網路接入網際網路",
    "sig.abuse.label": "濫用威脅",
    "sig.abuse.desc": "是否出現在濫用、黑名單或自動化爬蟲情報源中",
    "sig.abuse.descDb": "AbuseIPDB 近 90 天舉報 {reports} 次（置信度 {conf}%）",
    "sig.hitSources": "命中來源：{hits}",
    "sig.cleanChecked": "已核驗 {sources}，未見風險特徵",
    "sig.abuseStat.db": "AbuseIPDB {n}次({c}%)",
    "sig.abuseStat.sfs": "StopForumSpam {n}次",
    "sig.abuseStat.cve": "Shodan {n}漏洞",
    "sig.abuseStat.ipq": "ipquery 風險 {n}",
    "bd.baseline_residential": ["網路基線", "原生住宅寬頻基線"],
    "bd.baseline_mobile": ["網路基線", "行動電信 CGNAT 共享出口"],
    "bd.baseline_business": ["網路基線", "企業/機構商用網路"],
    "bd.baseline_dual_isp": ["網路基線", "雙 ISP / 廣播託管段"],
    "bd.baseline_datacenter": ["網路基線", "資料中心 / 雲主機網路"],
    "bd.baseline_unknown": ["網路基線", "歸屬證據不足審慎基線"],
    "bd.radar_bot": ["ASN 機器流量", "Radar 實測該 ASN 機器流量占比 {bot}%"],
    "bd.broadcast": ["跨區廣播", "註冊國 {reg} ≠ 定位國 {loc}"],
    "bd.tor": ["Tor 節點", "命中 Tor 匿名出口"],
    "bd.vpn": ["VPN 出口", "命中 VPN 節點庫"],
    "bd.proxy": ["代理節點", "命中公開代理或轉發節點"],
    "bd.dc_proxy": ["機房代理疊加", "機房 + 代理複合高危特徵"],
    "bd.abuseipdb": ["AbuseIPDB 舉報", "近 90 天被舉報 {reports} 次（置信度 {conf}%）"],
    "bd.abuse_generic": ["濫用與威脅", "命中濫用或威脅情報源"],
    "bd.crawler": ["爬蟲來源", "命中商業/抓取爬蟲庫"],
    "bd.vulns": ["暴露面漏洞", "Shodan 發現 {count} 個已知漏洞特徵"],
  },

  ja: {
    "brand.sub": "IP インテリジェンス",
    "nav.query": "IP 診断",
    "nav.fp": "フィンガープリント",
    "nav.asn": "ASN 監視",
    "nav.dns": "DNS リーク",
    "nav.webrtc": "WebRTC",
    "nav.api": "API",
    "theme.light": "ライト",
    "theme.dark": "ダーク",
    "hero.eyebrow": "IP INTELLIGENCE · リアルタイム脅威レーダー",
    "hero.title1": "すべての IP アドレスの",
    "hero.title2": "真の正体を見抜く",
    "hero.sub": "住宅回線判定 · ネイティブ/ブロードキャスト · リスク信号 · 実住所 · 人間/Bot比率 · 指紋検査",
    "hero.placeholder": "IPv4 / IPv6 アドレスまたはドメインを入力…",
    "hero.btn": "診断",
    "hero.detectMe": "自分の IP を検出",
    "hero.recent": "履歴",
    "state.loading": "IP 情報をスキャン中…",
    "state.loadingShort": "読み込み中…",
    "state.waiting": "待機中…",
    "state.retry": "再試行",
    "state.failed": "取得に失敗しました",
    "kv.asn": "ASN / 組織",
    "kv.range": "IP 範囲",
    "kv.numeric": "数値形式",
    "kv.source": "IP 由来",
    "kv.attr": "回線属性",
    "kv.hb": "人間 / Bot 比",
    "kv.location": "位置情報",
    "kv.score": "IPSpot 係数",
    "kv.ai": "AI 診断",
    "kv.leak": "リーク検査",
    "kv.fp": "ブラウザ指紋",
    "sub.company": "所有組織",
    "sub.companyType": "組織種別",
    "sub.domain": "公式サイト",
    "sub.route": "ルート CIDR",
    "sub.rdns": "逆引き DNS",
    "sub.netname": "NetName / RIR",
    "sub.abuse": "不正連絡先",
    "sub.ports": "開放ポート",
    "sub.audio": "Audio ハッシュ",
    "sub.os": "OS / ブラウザ",
    "sub.screen": "画面 / DPR",
    "sub.hw": "CPU / メモリ",
    "sub.tz": "タイムゾーン / 言語",
    "sub.bot": "自動化兆候",
    "hb.dim": "項目",
    "hb.exitIp": "出口 IP",
    "hb.localEnv": "ローカル環境",
    "hb.status": "判定",
    "hb.estimated": "推定",
    "hb.tz": "タイムゾーン",
    "hb.lang": "言語",
    "hb.auto": "自動化",
    "hb.match": "一致",
    "hb.mismatch": "不一致",
    "hb.safe": "安全",
    "hb.leaked": "漏洩",
    "hb.none": "記録なし",
    "hb.risk": "リスク",
    "hb.normal": "正常",
    "hb.human": "人間",
    "hb.abnormal": "異常",
    "btn.aiRun": "✦ AI 診断を生成",
    "btn.aiView": "✦ AI 診断を表示",
    "btn.aiHide": "AI 診断を閉じる",
    "btn.aiRetry": "✦ AI 診断を再試行",
    "btn.details": "詳細",
    "btn.openFp": "詳細なブラウザ指紋を見る →",
    "btn.latency": "遅延測定 ▾",
    "btn.retest": "再測定",
    "btn.bgpMore": "BGP 履歴 ▾",
    "btn.openMap": "地図を開く",
    "btn.gaRefresh": "周辺の別住所",
    "btn.gaCopyAll": "すべてコピー",
    "btn.recollect": "再取得",
    "btn.liveStart": "リアルタイム開始",
    "btn.livePause": "一時停止",
    "btn.clear": "クリア",
    "btn.recheck": "テスト実行",
    "btn.send": "送信",
    "btn.showMore": "さらに表示 ({n}) ▾",
    "btn.collapse": "閉じる ▴",
    "ai.loading": "AI 分析中…",
    "ai.cached": "キャッシュ",
    "ai.unavailable": "AI は現在利用できません",
    "card.signals": "リスク信号",
    "card.exit": "ネットワーク出口",
    "card.regHistory": "登録地履歴",
    "card.bgpTitle": "BGP 経路アナウンス履歴",
    "card.mapGeo": "マップと実際の地理住所",
    "card.realAddr": "IP ベースの実住所",
    "exit.v4": "IPv4 出口",
    "exit.v6": "IPv6 出口",
    "exit.none": "公開出口なし",
    "exit.unassigned": "未割当",
    "exit.timeout": "タイムアウト",
    "tbl.cidr": "CIDR",
    "tbl.rir": "レジストリ",
    "tbl.country": "国・地域",
    "tbl.firstSeen": "初回確認",
    "tbl.lastSeen": "最終確認",
    "tbl.empty": "記録なし",
    "tbl.emptyReg": "レジストリの履歴記録がありません",
    "tbl.emptyBgp": "BGP 履歴記録がありません",
    "tbl.prefix": "プレフィックス",
    "tbl.originAsn": "オリジン ASN",
    "tbl.firstAnn": "初回アナウンス",
    "tbl.lastAnn": "最終アナウンス",
    "tbl.time": "時刻",
    "tbl.org": "組織名",
    "tbl.type": "種別",
    "tbl.resolverIp": "リゾルバ IP",
    "tbl.resolverGeo": "所在地 / ISP",
    "tbl.hits": "回数",
    "ga.street": "番地・通り",
    "ga.city": "市区町村",
    "ga.state": "都道府県 / 州",
    "ga.country": "国",
    "ga.zip": "郵便番号",
    "ga.tz": "タイムゾーン",
    "ga.noCoords": "座標なし",
    "ga.lookingUp": "取得中…",
    "ga.noStreet": "通り情報なし",
    "ga.fallbackSrc": "IP データベース",
    "faq.summary": "IPSpot の仕組みとよくある質問",
    "faq.count": "8つの質問",
    "faq.tag1": "判定",
    "faq.tag2": "スコア",
    "faq.tag3": "安全",
    "faq.tag4": "位置情報",
    "faq.tag5": "指紋",
    "faq.tag6": "通信",
    "faq.tag7": "マップ",
    "faq.tag8": "API",
    "faq.q1": "ネイティブ / ブロードキャスト・住宅回線はどう判定されますか？",
    "faq.a1": "RIR 登録国（ARIN/RIPE/APNIC）・RDAP 情報と 12 種類の GeoIP データベースを照合し、ASN 種別・クラウド判定・rDNS・Shodan 特徴を組み合わせて住宅回線とデータセンターを正確に識別します。",
    "faq.q2": "人間/Bot トラフィック比率と純度スコアの算出方法は？",
    "faq.a2": "Cloudflare Radar の過去 7 日間 ASN Bot 統計と、回線ベースライン、プロキシ/VPN/Tor、AbuseIPDB、StopForumSpam 報告を統合して透明に 0–100% スコアを算出します。",
    "faq.q3": "6 項目のリスク信号はどのように検証されていますか？",
    "faq.a3": "proxycheck.io、Tor 公式 Onionoo ノード、StopForumSpam、IP2Location、ipquery.io、ip-api.com、Shodan ポートを並列検証し、一致または確認したソースをそのまま表示します。",
    "faq.q4": "サイトによって IP の位置情報が異なるのはなぜですか？",
    "faq.a4": "GeoIP 各社（MaxMind、IP2Location、IPInfo、ipapi.is、GeoJS など）で更新周期やエニーキャスト処理が異なります。IPSpot は最大 12 ソースを並べてコンセンサス判定を行います。",
    "faq.q5": "ブラウザ指紋・環境整合性チェックでは何を調べますか？",
    "faq.a5": "FingerprintJS v4・Canvas・WebGL・Audio・フォント・画面倍率・WebDriver 兆候をローカル計測し、出口 IP の国・タイムゾーン・言語・WebRTC と照合します。",
    "faq.q6": "DNS リークと WebRTC リーク検査の仕組みは？",
    "faq.a6": "DNS 検査は 32 文字ランダムサブドメインでキャッシュを回避して実リゾルバを特定し、WebRTC 検査は複数 STUN サーバーでパブリック IP の露出有無を確認します。",
    "faq.q7": "実住所の逆ジオコーディングとマップ表示の仕組みは？",
    "faq.a7": "IP 座標から OpenStreetMap Nominatim と Photon を用いて周辺の実在する番地・市区町村・都道府県・郵便番号を取得し、ワンクリックでコピーできます。",
    "faq.q8": "ASN 監視・AI 診断・オープン API の用途は？",
    "faq.a8": "ASN 監視は RIPE RIS Live のリアルタイム BGP 経路更新を受信し、AI 診断は検証済み指標に基づく実務アドバイスを提供し、API は認証不要で JSON 取得が可能です。",
    "fp.title": "ブラウザ指紋・環境診断",
    "fp.visitorLabel": "FingerprintJS ビジター ID",
    "fp.coreTitle": "コア指紋ハッシュ",
    "fp.hwTitle": "ハードウェア・ディスプレイ",
    "fp.envTitle": "システム・タイムゾーン・接続",
    "fp.health": "環境健全度 {n}%",
    "fp.verdictOk": "自動化の兆候は検出されませんでした。自然なブラウザ環境です。",
    "fp.verdictWarn": "自動化の特徴を検出：{w}",
    "fp.normalBrowser": "通常ブラウザ",
    "fp.wdTrue": "true（自動化検出）",
    "fp.wdFalse": "false（正常）",
    "fp.none": "検出なし",
    "fp.touch": "{n} 点マルチタッチ",
    "fp.noTouch": "タッチ非対応",
    "fp.media": "マイク {mic} · スピーカー {spk} · カメラ {cam}",
    "fp.cores": "{n} 論理コア",
    "fp.unknown": "不明",
    "fp.hidden": "非公開",
    "fp.on": "有効",
    "fp.off": "無効",
    "fp.notSet": "未設定",
    "fp.unsupported": "非対応",
    "fp.blocked": "ブロック済",
    "fp.restricted": "制限あり",
    "fp.row.fpId": "FingerprintJS ID",
    "fp.row.canvas": "Canvas ハッシュ",
    "fp.row.webglHash": "WebGL ハッシュ",
    "fp.row.audio": "Audio ハッシュ",
    "fp.row.fonts": "フォントハッシュ",
    "fp.row.wd": "WebDriver",
    "fp.row.headless": "ヘッドレス兆候",
    "fp.row.os": "OS",
    "fp.row.browser": "ブラウザ",
    "fp.row.gpuVendor": "GPU ベンダー",
    "fp.row.gpuRenderer": "GPU レンダラー",
    "fp.row.screen": "画面・スケーリング",
    "fp.row.hw": "CPU / メモリ",
    "fp.row.touch": "タッチ対応",
    "fp.row.media": "メディアデバイス",
    "fp.row.tz": "タイムゾーン",
    "fp.row.lang": "言語設定",
    "fp.row.cookie": "Cookie / DNT",
    "fp.row.proto": "プロトコル / TLS",
    "fp.row.cipher": "TLS 暗号スイート",
    "fp.row.colo": "エッジノード",
    "fp.row.ua": "User-Agent",
    "asn.title": "ASN / BGP リアルタイム監視",
    "asn.snapshot": "静的スナップショット",
    "asn.live": "ライブ接続中",
    "asn.polling": "ポーリング中",
    "asn.paused": "一時停止",
    "asn.connecting": "接続中…",
    "asn.announce": "アナウンス",
    "asn.withdraw": "取り下げ",
    "asn.noData": "データなし",
    "dns.title": "DNS リークテスト",
    "dns.probing": "ランダムサブドメインを検証中…",
    "dns.probingSub": "32 文字ランダムサブドメインで検証中…",
    "dns.fallback1": "予備の DNS 検証に切り替え中…",
    "dns.fallback2": "第 2 予備 DNS 検証に切り替え中…",
    "dns.noResolvers": "再帰 DNS が検出されませんでした（広告ブロッカー等をご確認ください）",
    "dns.warnTitle": "リゾルバを取得できませんでした",
    "dns.warnDesc": "すべての検証チャネルがブロックされました。拡張機能をオフにして再試行してください。",
    "dns.leakTitle": "DNS リークの可能性あり",
    "dns.leakDesc": "リゾルバ地域（{c}）が出口国（{e}）と一致しません。",
    "dns.okTitle": "DNS リークは検出されませんでした",
    "dns.okDesc": "{n} 台のリゾルバを検出。出口 IP と一致しています。",
    "dns.summary": "完了（{m}）：{n} 台のリゾルバを検出。",
    "dns.hitsUnit": "{n} 回",
    "rtc.title": "WebRTC リークテスト",
    "rtc.probing": "STUN サーバーを検証中…",
    "rtc.noLeak": "WebRTC リークなし",
    "rtc.matchExit": "出口 IP と一致 ({ip})",
    "rtc.leakBrief": "WebRTC リーク：{ips}",
    "rtc.noExpose": "公開 IP 露出なし",
    "rtc.leakTag": "リーク {ips}",
    "rtc.badTitle": "WebRTC リークを検出",
    "rtc.badDesc": "露出した IP：{ips}",
    "rtc.okTitle": "WebRTC リークは検出されませんでした",
    "rtc.okDescMatch": "HTTP 出口 IP と一致 ({ips})",
    "rtc.okDescNone": "STUN 経由での公開 IP 露出はありません",
    "api.title": "オープン JSON API",
    "api.examples": "使用例",
    "api.self": "自分",
    "api.target": "指定",
    "api.asn": "ASN",
    "api.playground": "オンラインテスト",
    "api.placeholder": "IP またはドメイン（空欄で自分の IP）",
    "api.requesting": "リクエスト中…",
    "footer.title": "IPSpot · IP 純度・ネットワーク環境診断",
    "footer.privacy": "プライバシー・免責事項",
    "privacy.title": "プライバシーポリシーと免責事項",
    "privacy.p1": "IPSpot (ipspot.org) は公開 IP 情報と OpenStreetMap 座標をリアルタイム参照します。ブラウザ指紋および WebRTC 検査は端末内で完結し、個人情報は保存しません。",
    "privacy.p2": "当サイトは匿名アクセス解析に Google Analytics を利用し、Google AdSense 広告を掲載する場合があります。連絡先：hezhanleiok@gmail.com",
    "score.purity": "総合純度スコア：<b>{n} / 100</b>",
    "score.cleanBaseline": "クリーンなベースライン",
    "signals.count": "{n} 項目検査",
    "signals.hit": "検出",
    "signals.clean": "未検出",
    "map.noCoords": "利用可能な座標がありません",
    "map.target": "対象位置",
    "ports.none": "公開記録なし",
    "toast.copiedIp": "IP をコピーしました",
    "toast.copiedLink": "リンクをコピーしました",
    "toast.copiedV4": "IPv4 をコピーしました",
    "toast.copiedV6": "IPv6 をコピーしました",
    "toast.copiedCmd": "コマンドをコピーしました",
    "toast.copiedAllAddr": "住所をすべてコピーしました",
    "toast.copiedField": "{label}をコピーしました",
    "toast.addrSwitched": "周辺の別の実住所を取得しました",
    "toast.fpRefreshed": "ブラウザ指紋を再取得しました",
    "toast.cacheUsed": "更新に失敗したためキャッシュを表示中",
    "toast.copyFail": "コピーに失敗しました",
    "title.base": "IPSpot · 無料 IP 純度診断 — 住宅/ネイティブ判定・リスク評価・ブラウザ指紋",
    "title.fp": "ブラウザ指紋・環境診断 — IPSpot",
    "title.asn": "グローバル ASN / BGP リアルタイム監視 — IPSpot",
    "title.dns": "無料 DNS リークテスト — IPSpot",
    "title.webrtc": "無料 WebRTC リークテスト — IPSpot",
    "title.api": "オープン IP 情報 JSON API — IPSpot",
    "origin.native": "ネイティブ IP ({cc})",
    "origin.broadcast": "ブロードキャスト ({reg}→{loc})",
    "origin.unknown": "由来不明",
    "type.residential": "住宅回線 IP",
    "type.dual_isp": "デュアル ISP",
    "type.datacenter": "データセンター IP",
    "type.mobile": "モバイル回線",
    "type.business": "法人回線",
    "type.unknown": "未分類",
    "badge.nonRes": "非住宅 · {label}",
    "risk.minimal": "極めて安全",
    "risk.low": "低リスク",
    "risk.medium": "中立",
    "risk.high": "高リスク",
    "risk.critical": "極めて高リスク",
    "org.isp": "ISP (通信事業者)",
    "org.hosting": "データセンター / ホスティング",
    "org.business": "一般企業",
    "org.education": "教育・研究機関",
    "org.government": "政府機関",
    "org.banking": "金融機関",
    "sig.proxy.label": "プロキシ",
    "sig.proxy.desc": "公開プロキシまたは匿名プロキシ経由の通信かどうか",
    "sig.vpn.label": "VPN 出口",
    "sig.vpn.desc": "既知の VPN サービスの出口ノードかどうか",
    "sig.tor.label": "Tor ネットワーク",
    "sig.tor.desc": "Tor 匿名ネットワークの出口ノードかどうか",
    "sig.datacenter.label": "データセンター",
    "sig.datacenter.desc": "家庭回線ではなくクラウドやサーバー施設に属するか",
    "sig.mobile.label": "モバイル回線",
    "sig.mobile.desc": "携帯キャリア回線からの接続かどうか",
    "sig.abuse.label": "不正・脅威",
    "sig.abuse.desc": "不正利用・ブラックリスト・クローラー情報源に該当するか",
    "sig.abuse.descDb": "AbuseIPDB 過去90日 {reports} 件報告（信頼度 {conf}%）",
    "sig.hitSources": "該当ソース：{hits}",
    "sig.cleanChecked": "{sources} で検証済み・異常なし",
    "sig.abuseStat.db": "AbuseIPDB {n}件({c}%)",
    "sig.abuseStat.sfs": "StopForumSpam {n}件",
    "sig.abuseStat.cve": "Shodan {n}件脆弱性",
    "sig.abuseStat.ipq": "ipquery リスク {n}",
    "bd.baseline_residential": ["回線ベースライン", "ネイティブ住宅 ISP 基準"],
    "bd.baseline_mobile": ["回線ベースライン", "モバイル CGNAT 共有出口"],
    "bd.baseline_business": ["回線ベースライン", "法人・組織回線"],
    "bd.baseline_dual_isp": ["回線ベースライン", "デュアル ISP / ブロードキャスト"],
    "bd.baseline_datacenter": ["回線ベースライン", "データセンター / クラウド回線"],
    "bd.baseline_unknown": ["回線ベースライン", "住宅回線の根拠不足"],
    "bd.radar_bot": ["ASN Bot 比率", "Cloudflare Radar 実測 Bot 比率 {bot}%"],
    "bd.broadcast": ["ブロードキャスト", "登録国 {reg} ≠ 位置国 {loc}"],
    "bd.tor": ["Tor ノード", "Tor 出口ノードに該当"],
    "bd.vpn": ["VPN 出口", "既知の VPN ノードに該当"],
    "bd.proxy": ["プロキシ", "公開・共有プロキシに該当"],
    "bd.dc_proxy": ["DC + プロキシ複合", "データセンターとプロキシの複合リスク"],
    "bd.abuseipdb": ["AbuseIPDB 報告", "過去90日 {reports} 件（信頼度 {conf}%）"],
    "bd.abuse_generic": ["不正・脅威", "脅威インテリジェンスに該当"],
    "bd.crawler": ["クローラー", "自動化クローラーに該当"],
    "bd.vulns": ["既知の脆弱性", "Shodan により {count} 件の CVE 兆候を検出"],
  },
};

function isEnPath() {
  return /^\/en(\/|$)/.test(location.pathname);
}

function resolveInitialLang() {
  const pageDefault = document.documentElement.getAttribute("data-default-lang") || (isEnPath() ? "en" : "zh-CN");
  try {
    const saved = localStorage.getItem(LANG_KEY);
    if (saved === "zh-TW" || saved === "ja") return saved;
  } catch {}
  return I18N[pageDefault] ? pageDefault : "zh-CN";
}

const state = {
  lang: resolveInitialLang(),
  currentView: "query",
  current: null,
  own: null,
  fp: null,
  clientEnv: null,
  geoAddr: null,
  aiLoadedKey: null,
  reqSeq: 0,
  controller: null,
  map: null,
  marker: null,
  lastQuery: null,
  queryStarted: false,
  pingRan: false,
};

function t(key, vars = null) {
  const pack = I18N[state.lang] || I18N.en;
  let val = pack[key] ?? I18N.en[key] ?? key;
  if (vars && typeof val === "string") {
    for (const [k, v] of Object.entries(vars)) val = val.replaceAll(`{${k}}`, String(v));
  }
  return val;
}

const regionDisplayCache = new Map();
function getRegionName(cc, fallback = "") {
  const c = (cc || "").toUpperCase();
  if (!c || !/^[A-Z]{2}$/.test(c)) return fallback || "—";
  try {
    let dn = regionDisplayCache.get(state.lang);
    if (!dn && typeof Intl !== "undefined" && Intl.DisplayNames) {
      dn = new Intl.DisplayNames([state.lang], { type: "region" });
      regionDisplayCache.set(state.lang, dn);
    }
    const name = dn ? dn.of(c) : "";
    if (name && name !== c) return name;
  } catch {}
  return fallback || c;
}
function countryName(cc, fallback = "") {
  const localized = getRegionName(cc, fallback);
  if (state.lang !== "en" && fallback && localized && localized.toLowerCase() !== fallback.toLowerCase()) {
    return `${localized} (${fallback})`;
  }
  return localized || fallback || cc || "—";
}
function countryShort(cc, fallback = "") {
  return getRegionName(cc, fallback) || fallback || cc || "—";
}

function localizedOrigin(loc) {
  if (!loc) return t("origin.unknown");
  if (loc.isNative === true && loc.registeredCountryCode) {
    return t("origin.native", { cc: loc.registeredCountryCode });
  }
  if (loc.isNative === false && loc.registeredCountryCode && loc.countryCode) {
    return t("origin.broadcast", { reg: loc.registeredCountryCode, loc: loc.countryCode });
  }
  return t("origin.unknown");
}
function localizedType(type) {
  return t(`type.${type?.code || "unknown"}`);
}
function localizedRisk(scores) {
  return t(`risk.${scores?.riskCode || "medium"}`);
}
function localizedOrgType(rawType) {
  const k = String(rawType || "").toLowerCase();
  return k && I18N.en[`org.${k}`] ? t(`org.${k}`) : "—";
}
function localizedBreakdown(item) {
  const pair = (I18N[state.lang] || I18N.en)[`bd.${item.key}`] || I18N.en[`bd.${item.key}`];
  if (!Array.isArray(pair)) return { label: item.label, reason: item.reason };
  let reason = pair[1];
  if (item.meta) {
    for (const [k, v] of Object.entries(item.meta)) reason = reason.replaceAll(`{${k}}`, String(v));
  }
  return { label: pair[0], reason };
}

const LANG_LABELS = {
  "zh-CN": { "zh-CN": "中国", "zh-TW": "繁體", en: "英文", ja: "日文" },
  "zh-TW": { "zh-CN": "中國", "zh-TW": "繁體", en: "英文", ja: "日文" },
  en: { "zh-CN": "CN", "zh-TW": "TW", en: "EN", ja: "JA" },
  ja: { "zh-CN": "CN", "zh-TW": "TW", en: "EN", ja: "JP" },
};

function renderLangMenu() {
  const labels = LANG_LABELS[state.lang] || LANG_LABELS.en;
  document.querySelectorAll(".lang-opt").forEach((btn) => {
    const code = btn.dataset.lang;
    const isActive = code === state.lang;
    btn.classList.toggle("active", isActive);
    btn.setAttribute("aria-selected", String(isActive));
    const span = btn.querySelector(".lang-opt-name");
    if (span && labels[code]) span.textContent = labels[code];
  });
}

function applyStaticI18n() {
  document.documentElement.setAttribute("lang", state.lang);
  renderLangMenu();
  document.querySelectorAll("[data-i18n]").forEach((el) => {
    const key = el.getAttribute("data-i18n");
    if (key) el.textContent = t(key);
  });
  document.querySelectorAll("[data-i18n-placeholder]").forEach((el) => {
    const key = el.getAttribute("data-i18n-placeholder");
    if (key) el.setAttribute("placeholder", t(key));
  });
  syncThemeUI();
  renderHistory();
  updateSeoTitle(state.currentView, state.current);
  if (typeof moveGlider === "function") requestAnimationFrame(moveGlider);
}

function handleLanguageChange(nextLang) {
  if (!I18N[nextLang]) return;
  try { localStorage.setItem(LANG_KEY, nextLang); } catch {}
  const hash = location.hash || "";

  if (nextLang === "en" && !isEnPath()) {
    location.href = `/en/${hash}`;
    return;
  }
  if (nextLang === "zh-CN" && isEnPath()) {
    location.href = `/${hash}`;
    return;
  }

  state.lang = nextLang;
  state.aiLoadedKey = null;
  applyStaticI18n();
  if (state.current) renderReport(state.current);
  else if (state.currentView === "fp") fpEngine.renderPage();
  if (exit.started) exit.refreshLabels();
  if (asn.started) asn.render();
  if (state.currentView === "api") api.init();
}

const SIGNAL_ORDER = ["proxy", "vpn", "tor", "datacenter", "mobile", "abuse"];
const SIGNAL_ICONS = {
  proxy: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M4 7h11l-3-3M20 17H9l3 3"/><path d="M20 7h-2M4 17h2"/></svg>',
  vpn: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M12 3l8 4v5c0 5-3.5 8-8 9-4.5-1-8-4-8-9V7z"/><path d="M12 8v4M12 15h.01"/></svg>',
  tor: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="5"/><circle cx="12" cy="12" r="1.4" fill="currentColor"/></svg>',
  datacenter: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="3" y="4" width="18" height="6" rx="1.5"/><rect x="3" y="14" width="18" height="6" rx="1.5"/><path d="M7 7h.01M7 17h.01M12 7h4M12 17h4"/></svg>',
  mobile: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="7" y="2.5" width="10" height="19" rx="2.5"/><path d="M11 18.5h2"/></svg>',
  abuse: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M12 2c1 3-2 4-2 7 0 1.5 1 2.5 2 2.5S14 10.5 14 9c2 1.5 3 3.5 3 5.5a5 5 0 0 1-10 0C7 10 9.5 6.5 12 2z"/></svg>',
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
    try { document.execCommand("copy"); toast(msg); } catch { toast(t("toast.copyFail")); }
    ta.remove();
  }
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

/* ================= Dynamic SEO Title ================= */
function updateSeoTitle(view, report) {
  if (view === "fp") { document.title = t("title.fp"); return; }
  if (view === "asn") { document.title = t("title.asn"); return; }
  if (view === "dns") { document.title = t("title.dns"); return; }
  if (view === "webrtc") { document.title = t("title.webrtc"); return; }
  if (view === "api") { document.title = t("title.api"); return; }
  if (report && report.ip) {
    const loc = countryShort(report.location.countryCode, report.location.country);
    document.title = `${report.ip} · ${localizedType(report.type)} · ${loc} (${report.scores.fraud}%) — IPSpot`;
  } else {
    document.title = t("title.base");
  }
}

/* ================= Theme ================= */
function currentTheme() {
  return document.documentElement.getAttribute("data-theme") === "light" ? "light" : "dark";
}
function syncThemeUI() {
  const th = currentTheme();
  const nextLabel = th === "dark" ? t("theme.light") : t("theme.dark");
  const btn = $("theme-toggle");
  if (btn) {
    btn.setAttribute("title", nextLabel);
    btn.setAttribute("aria-label", nextLabel);
  }
  $("meta-theme-color").setAttribute("content", th === "light" ? "#F4F7FB" : "#070B14");
}
function toggleTheme() {
  const next = currentTheme() === "dark" ? "light" : "dark";
  document.documentElement.setAttribute("data-theme", next);
  try { localStorage.setItem(THEME_KEY, next); } catch {}
  syncThemeUI();
}

/* ================= Smooth Collapsible & Scroll Reveal ================= */
function isDrawerOpen(box) {
  if (!box) return false;
  return box.classList.contains("smooth-collapse") ? box.classList.contains("open") : !box.hidden;
}
function setDrawerOpen(box, open, btn) {
  if (!box) return;
  if (box.classList.contains("smooth-collapse")) {
    box.classList.toggle("open", open);
    box.setAttribute("aria-hidden", String(!open));
  } else {
    box.hidden = !open;
  }
  if (btn) btn.setAttribute("aria-expanded", String(open));
}
function bindToggle(btnId, boxId, onOpen) {
  const btn = $(btnId); const box = $(boxId);
  if (!btn || !box) return;
  btn.addEventListener("click", () => {
    const open = !isDrawerOpen(box);
    setDrawerOpen(box, open, btn);
    if (open && onOpen) onOpen();
  });
}

let revealScrollDir = "down";
let revealLastY = typeof window !== "undefined" ? window.scrollY : 0;
let revealObserver = null;
function initRevealObserver() {
  if (revealObserver) return;
  window.addEventListener("scroll", () => {
    const cur = window.scrollY;
    revealScrollDir = cur >= revealLastY ? "down" : "up";
    revealLastY = cur;
  }, { passive: true });
  if (typeof IntersectionObserver !== "function") return;
  revealObserver = new IntersectionObserver((entries) => {
    for (const en of entries) {
      if (en.isIntersecting) {
        en.target.classList.remove("from-up");
        en.target.classList.add("in");
      } else if (!en.target.closest("[hidden]")) {
        en.target.classList.remove("in");
        en.target.classList.toggle("from-up", revealScrollDir === "up");
      }
    }
  }, { threshold: 0.06, rootMargin: "0px 0px -16px 0px" });
}
function observeReveals() {
  initRevealObserver();
  const els = document.querySelectorAll(".reveal");
  if (!revealObserver) {
    els.forEach((el) => el.classList.add("in"));
    return;
  }
  const vh = window.innerHeight || 800;
  els.forEach((el) => {
    if (el.closest("[hidden]")) return;
    revealObserver.observe(el);
    const r = el.getBoundingClientRect();
    if (r.top < vh && r.bottom > 0) {
      el.classList.remove("from-up");
      el.classList.add("in");
    }
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
  label.className = "history-label"; label.textContent = t("hero.recent");
  box.appendChild(label);
  for (const item of list) {
    const b = document.createElement("button");
    b.type = "button"; b.className = "chip"; b.textContent = item;
    b.addEventListener("click", () => { location.hash = `#ip=${encodeURIComponent(item)}`; });
    box.appendChild(b);
  }
}

/* ================= Accurate Fingerprint Engine ================= */
const fpEngine = {
  _collecting: null,
  getCanvas() {
    try {
      const c = document.createElement("canvas"); c.width = 240; c.height = 48;
      const ctx = c.getContext("2d"); if (!ctx) return null;
      ctx.textBaseline = "top"; ctx.font = "14px Arial";
      ctx.fillStyle = "#0ea5e9"; ctx.fillRect(8, 6, 86, 20);
      ctx.fillStyle = "#0f172a"; ctx.fillText("IPSpot.org · FP2026", 12, 11);
      return fnv1a(c.toDataURL());
    } catch { return "blocked"; }
  },
  getWebGL() {
    try {
      const c = document.createElement("canvas");
      const gl = c.getContext("webgl") || c.getContext("experimental-webgl");
      if (!gl) return { vendor: "—", renderer: "—", hash: "—" };
      const dbg = gl.getExtension("WEBGL_debug_renderer_info");
      const vendor = dbg ? String(gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL) || "—") : String(gl.getParameter(gl.VENDOR) || "—");
      const renderer = dbg ? String(gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL) || "—") : String(gl.getParameter(gl.RENDERER) || "—");
      const exts = (gl.getSupportedExtensions() || []).join(",");
      return { vendor, renderer, hash: fnv1a(`${vendor}|${renderer}|${exts}`) };
    } catch { return { vendor: "—", renderer: "—", hash: "—" }; }
  },
  async getAudio() {
    try {
      const AC = window.OfflineAudioContext || window.webkitOfflineAudioContext;
      if (!AC) return null;
      const ctx = new AC(1, 44100, 44100);
      const osc = ctx.createOscillator(); osc.type = "triangle"; osc.frequency.value = 10000;
      const comp = ctx.createDynamicsCompressor();
      osc.connect(comp); comp.connect(ctx.destination); osc.start(0);
      const buf = await ctx.startRendering();
      const ch = buf.getChannelData(0);
      let acc = 0; for (let i = 4500; i < 5000; i++) acc += Math.abs(ch[i]);
      return fnv1a(acc.toFixed(6));
    } catch { return "restricted"; }
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
      if (!ctx) return { count: 0, hash: "—", list: [] };
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
      return { count: matched.length, hash: fnv1a(matched.join(",")), list: matched };
    } catch {
      return { count: 0, hash: "—", list: [] };
    }
  },
  async detectMediaDevices() {
    try {
      if (!navigator.mediaDevices || typeof navigator.mediaDevices.enumerateDevices !== "function") return null;
      const list = await navigator.mediaDevices.enumerateDevices();
      let mic = 0; let spk = 0; let cam = 0;
      for (const d of list) {
        if (d.kind === "audioinput") mic++;
        else if (d.kind === "audiooutput") spk++;
        else if (d.kind === "videoinput") cam++;
      }
      return { mic, spk, cam };
    } catch { return null; }
  },
  async detectOsAndBrowser() {
    const ua = navigator.userAgent || "";
    let os = navigator.platform || "Unknown";
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
    } catch {}
    if (os === "Win32" || os === "Win64") os = "Windows (64-bit)";
    else if (/MacIntel/i.test(os)) os = "macOS";
    if (!browser) {
      const m = ua.match(/(Edg|Chrome|Firefox|Safari)\/([\d.]+)/);
      browser = m ? `${m[1] === "Edg" ? "Edge" : m[1]} ${m[2]}` : "Browser";
    }
    return { os, browser };
  },
  getScreenData() {
    const rawDpr = Number(window.devicePixelRatio || 1);
    const dpr = Math.round(rawDpr * 100) / 100;
    return {
      sw: screen.width, sh: screen.height, depth: screen.colorDepth, dpr,
      estW: Math.round(screen.width * rawDpr), estH: Math.round(screen.height * rawDpr),
      vpW: window.innerWidth, vpH: window.innerHeight,
    };
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
    } catch {}
    return hashHex32(fallbackSeed);
  },
  async collect(force = false) {
    if (state.fp && !force) return state.fp;
    if (this._collecting && !force) return this._collecting;

    this._collecting = (async () => {
      const canvas = this.getCanvas();
      const webgl = this.getWebGL();
      const fonts = this.detectFonts();
      const scr = this.getScreenData();
      const [audio, media, sys] = await Promise.all([
        this.getAudio(),
        this.detectMediaDevices(),
        this.detectOsAndBrowser(),
      ]);

      const tz = (() => { try { return Intl.DateTimeFormat().resolvedOptions().timeZone || "—"; } catch { return "—"; } })();
      const langs = (navigator.languages?.length ? [...navigator.languages] : [navigator.language || ""]).filter(Boolean);
      const ua = navigator.userAgent || "";
      const webdriver = navigator.webdriver === true;
      const headless = [];
      if (/HeadlessChrome|PhantomJS|Playwright|Puppeteer|Selenium/i.test(ua)) headless.push("Headless UA");
      if (webdriver) headless.push("webdriver=true");
      if (/SwiftShader|llvmpipe/i.test(webgl.renderer)) headless.push("Software GPU");

      const seed = [canvas, audio, webgl.hash, fonts.hash, `${scr.sw}x${scr.sh}`, sys.os, tz, langs.join(",")].join("|");
      const id = await this.getFingerprintJsId(seed);

      const fp = {
        id, canvas, audio, fonts, media,
        os: sys.os, browser: sys.browser,
        webglVendor: webgl.vendor, webglRenderer: webgl.renderer, webglHash: webgl.hash,
        tz, langs, scr,
        cores: navigator.hardwareConcurrency || 0,
        deviceMemory: navigator.deviceMemory || 0,
        touch: navigator.maxTouchPoints ?? 0,
        cookieEnabled: navigator.cookieEnabled,
        dnt: navigator.doNotTrack === "1",
        webdriver, headless, ua,
      };
      state.fp = fp;
      return fp;
    })().finally(() => { this._collecting = null; });

    return this._collecting;
  },
  formatHw(fp) {
    const cores = fp.cores ? t("fp.cores", { n: fp.cores }) : t("fp.unknown");
    const mem = fp.deviceMemory ? (fp.deviceMemory >= 8 ? "≥ 8 GB" : `${fp.deviceMemory} GB`) : t("fp.hidden");
    return `${cores} / ${mem}`;
  },
  formatScreenMain(scr) {
    return `${scr.sw}×${scr.sh} (DPR ${scr.dpr} · ${scr.depth}bit)`;
  },
  formatScreenDetail(scr) {
    return `${scr.sw}×${scr.sh} (CSS) · ~${scr.estW}×${scr.estH} (Phys) · ${scr.vpW}×${scr.vpH} (VP) · DPR ${scr.dpr}`;
  },
  async quickWebRtc(httpIp) {
    return new Promise((resolve) => {
      if (typeof RTCPeerConnection === "undefined") { resolve({ type: "none", ips: [], leak: false }); return; }
      let pc;
      try { pc = new RTCPeerConnection({ iceServers: [{ urls: "stun:stun.cloudflare.com:3478" }] }); }
      catch { resolve({ type: "none", ips: [], leak: false }); return; }
      const ips = new Set(); let done = false;
      const finish = () => {
        if (done) return; done = true;
        try { pc.close(); } catch {}
        const list = [...ips];
        if (!list.length) resolve({ type: "none", ips: [], leak: false });
        else if (httpIp && list.some((x) => x !== httpIp)) resolve({ type: "leak", ips: list, leak: true });
        else resolve({ type: "match", ips: list, leak: false });
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

    const rtcText = rtcRes.type === "leak"
      ? t("rtc.leakBrief", { ips: rtcRes.ips.join(", ") })
      : rtcRes.type === "match"
        ? t("rtc.matchExit", { ip: rtcRes.ips[0] })
        : t("rtc.noLeak");

    $("r-webrtc-brief").innerHTML = rtcRes.leak
      ? `<span class="pill red">${esc(rtcText)}</span>`
      : `<span class="pill green">${esc(rtcText)}</span>`;

    const canvasLabel = fp.canvas === "blocked" ? t("fp.blocked") : (fp.canvas || t("fp.unsupported"));
    const audioLabel = fp.audio === "restricted" ? t("fp.restricted") : (fp.audio || t("fp.unsupported"));

    $("r-fp-id").textContent = fp.id;
    $("r-fp-canvas").textContent = canvasLabel;
    $("r-fp-webgl").textContent = fp.webglRenderer;
    $("r-fp-audio").textContent = audioLabel;
    if ($("r-fp-os")) $("r-fp-os").textContent = `${fp.os} · ${fp.browser}`;
    $("r-fp-screen").textContent = this.formatScreenMain(fp.scr);
    $("r-fp-hw").textContent = this.formatHw(fp);
    $("r-fp-tz").textContent = `${fp.tz} · ${fp.langs[0] || "—"}`;
    $("r-fp-bot").innerHTML = fp.headless.length
      ? `<span class="pill red">${esc(fp.headless.join(" / "))}</span>`
      : `<span class="pill green">${esc(t("fp.normalBrowser"))}</span>`;

    const isRadar = r?.humanRatio?.source === "cloudflare-radar";
    const human = typeof r?.humanRatio?.human === "number" ? r.humanRatio.human : 50;
    const bot = typeof r?.humanRatio?.bot === "number" ? r.humanRatio.bot : Number((100 - human).toFixed(2));
    requestAnimationFrame(() => {
      $("hb-human-bar").style.width = `${human}%`;
      $("hb-bot-bar").style.width = `${bot}%`;
    });
    $("hb-human-pct").textContent = isRadar ? `${human.toFixed(2)}%` : `${Math.round(human)}%`;
    $("hb-bot-pct").textContent = isRadar ? `${bot.toFixed(2)}%` : `${Math.round(bot)}%`;
    const srcEl = $("hb-source");
    if (srcEl) {
      srcEl.hidden = false;
      srcEl.textContent = isRadar ? "Cloudflare Radar" : t("hb.estimated");
    }

    const ipTz = r?.location?.timezone || "";
    const ipCC = (r?.location?.countryCode || "").toUpperCase();
    const tzOk = !ipTz || ipTz.toLowerCase() === fp.tz.toLowerCase();
    const langAllow = COUNTRY_LANG[ipCC] || [];
    const primaryLang = (fp.langs[0] || "").toLowerCase();
    const langOk = !langAllow.length || langAllow.some((p) => primaryLang.startsWith(p));

    const warnings = [];
    if (fp.webdriver) warnings.push("webdriver");
    if (fp.headless.length && !fp.webdriver) warnings.push(fp.headless[0]);
    if (rtcRes.leak) warnings.push("WebRTC leak");
    if (!tzOk) warnings.push("timezone mismatch");
    if (!langOk) warnings.push("language mismatch");

    const rows = [
      [t("hb.tz"), ipTz || "—", fp.tz, tzOk ? ["green", t("hb.match")] : ["amber", t("hb.mismatch")]],
      [t("hb.lang"), ipCC || "—", fp.langs[0] || "—", langOk ? ["green", t("hb.match")] : ["amber", t("hb.mismatch")]],
      ["WebRTC", r?.ip || "—", rtcRes.leak ? t("hb.leaked") : t("hb.safe"), rtcRes.leak ? ["red", t("hb.leaked")] : ["green", t("hb.safe")]],
      [t("hb.auto"), r?.signals?.find((s) => s.key === "abuse")?.detected ? t("hb.risk") : t("hb.none"), fp.headless.length ? fp.headless[0] : t("hb.normal"), fp.headless.length ? ["red", t("hb.abnormal")] : ["green", t("hb.human")]],
    ];
    $("hb-table-body").innerHTML = rows.map(([k, a, b, [cls, st]]) =>
      `<tr><td>${esc(k)}</td><td class="mono">${esc(a)}</td><td class="mono">${esc(b)}</td><td><span class="pill ${cls}">${esc(st)}</span></td></tr>`
    ).join("");

    state.clientEnv = { humanScore: human, warnings };
    this.renderPage();
  },
  async renderPage(force = false) {
    const fp = await this.collect(force);
    const score = fp.webdriver ? 35 : fp.headless.length ? 60 : (state.clientEnv?.warnings?.includes("WebRTC leak") ? 72 : 96);
    $("fp-page-id").textContent = fp.id;
    const pill = $("fp-page-score");
    pill.textContent = t("fp.health", { n: score });
    pill.className = `fp-score-pill ${score >= 85 ? "" : score >= 60 ? "warn" : "bad"}`;
    $("fp-page-verdict").textContent = fp.headless.length
      ? t("fp.verdictWarn", { w: fp.headless.join(" · ") })
      : t("fp.verdictOk");

    const mkRows = (list) => list.map(([k, v]) =>
      `<div class="kv-row"><div class="kv-k">${esc(k)}</div><div class="kv-v mono">${esc(v)}</div></div>`
    ).join("");

    const canvasLabel = fp.canvas === "blocked" ? t("fp.blocked") : (fp.canvas || t("fp.unsupported"));
    const audioLabel = fp.audio === "restricted" ? t("fp.restricted") : (fp.audio || t("fp.unsupported"));
    const fontSample = fp.fonts.list.length
      ? `${fp.fonts.hash} · ${fp.fonts.count} (${fp.fonts.list.slice(0, 4).join(", ")}${fp.fonts.list.length > 4 ? "…" : ""})`
      : fp.fonts.hash;
    const mediaLabel = fp.media ? t("fp.media", fp.media) : t("fp.restricted");

    $("fp-page-core").innerHTML = mkRows([
      [t("fp.row.fpId"), fp.id],
      [t("fp.row.canvas"), canvasLabel],
      [t("fp.row.webglHash"), fp.webglHash],
      [t("fp.row.audio"), audioLabel],
      [t("fp.row.fonts"), fontSample],
      [t("fp.row.wd"), fp.webdriver ? t("fp.wdTrue") : t("fp.wdFalse")],
      [t("fp.row.headless"), fp.headless.length ? fp.headless.join(" / ") : t("fp.none")],
    ]);

    $("fp-page-hardware").innerHTML = mkRows([
      [t("fp.row.os"), fp.os],
      [t("fp.row.browser"), fp.browser],
      [t("fp.row.gpuVendor"), fp.webglVendor],
      [t("fp.row.gpuRenderer"), fp.webglRenderer],
      [t("fp.row.screen"), this.formatScreenDetail(fp.scr)],
      [t("fp.row.hw"), this.formatHw(fp)],
      [t("fp.row.touch"), fp.touch > 0 ? t("fp.touch", { n: fp.touch }) : t("fp.noTouch")],
      [t("fp.row.media"), mediaLabel],
    ]);

    const conn = state.current?.connection;
    const envRows = [
      [t("fp.row.tz"), fp.tz],
      [t("fp.row.lang"), fp.langs.join(", ") || "—"],
      [t("fp.row.cookie"), `${fp.cookieEnabled ? t("fp.on") : t("fp.off")} / ${fp.dnt ? t("fp.on") : t("fp.notSet")}`],
    ];
    if (conn && (conn.httpProtocol || conn.tlsVersion)) {
      envRows.push([t("fp.row.proto"), `${conn.httpProtocol || "—"} · ${conn.tlsVersion || "—"}`]);
      if (conn.tlsCipher) envRows.push([t("fp.row.cipher"), conn.tlsCipher]);
      if (conn.colo) envRows.push([t("fp.row.colo"), conn.colo]);
    }
    envRows.push([t("fp.row.ua"), fp.ua]);
    $("fp-page-env").innerHTML = mkRows(envRows);
  },
};

/* ================= Real Geo Street Address ================= */
async function loadGeoAddress(loc, jitter = false) {
  if (!loc || loc.lat == null || loc.lon == null) {
    $("ga-source").textContent = t("ga.noCoords");
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
  $("ga-street").textContent = t("ga.lookingUp");

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
    if (jitter) toast(t("toast.addrSwitched"));
  } catch {
    const fallback = {
      street: t("ga.noStreet"),
      city: loc.city || "—",
      state: loc.region || "—",
      country: countryName(loc.countryCode, loc.country),
      zip: loc.zip || "—",
      tz: loc.timezone || "—",
      source: t("ga.fallbackSrc"),
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
    openBtn.href = loc.countryCode === "CN" && state.lang.startsWith("zh")
      ? `https://uri.amap.com/marker?position=${loc.lon},${loc.lat}&name=${encodeURIComponent(r.ip)}&src=ipspot&callnative=0`
      : `https://www.google.com/maps?q=${loc.lat},${loc.lon}`;
  } else openBtn.hidden = true;

  if (!has || typeof L === "undefined") {
    fb.hidden = false;
    $("map-fallback-text").textContent = t("map.noCoords");
    if (state.map) { state.map.remove(); state.map = null; state.marker = null; }
    return;
  }
  fb.hidden = true;

  if (!state.map) {
    state.map = L.map("map", { scrollWheelZoom: true }).setView([loc.lat, loc.lon], 9);
    L.tileLayer("https://server.arcgisonline.com/ArcGIS/rest/services/World_Street_Map/MapServer/tile/{z}/{y}/{x}", {
      attribution: "Tiles &copy; Esri",
      maxZoom: 17,
    }).addTo(state.map);
  } else {
    state.map.setView([loc.lat, loc.lon], 9);
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
  place.textContent = [loc.city, loc.region, countryName(loc.countryCode, loc.country)].filter(Boolean).join(" · ") || t("map.target");
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
function renderSignals(r) {
  const raw = Array.isArray(r.signals) ? r.signals : [];
  const byKey = new Map(raw.map((s) => [s.key, s]));
  const list = SIGNAL_ORDER.map((k) => byKey.get(k)).filter(Boolean);
  const finalList = list.length === 6 ? list : raw.slice(0, 6);

  $("signals-count").textContent = t("signals.count", { n: finalList.length });
  $("signals-grid").innerHTML = finalList.map((s) => {
    const label = t(`sig.${s.key}.label`) || s.label;
    let desc = "";
    if (s.detected && Array.isArray(s.hits) && s.hits.length) {
      desc = t("sig.hitSources", { hits: s.hits.join(" · ") });
    } else if (s.key === "abuse" && s.meta) {
      const parts = [];
      if (typeof s.meta.abuseReports === "number") parts.push(t("sig.abuseStat.db", { n: s.meta.abuseReports, c: s.meta.abuseConf ?? 0 }));
      if (typeof s.meta.sfsFreq === "number") parts.push(t("sig.abuseStat.sfs", { n: s.meta.sfsFreq }));
      if (typeof s.meta.vulns === "number") parts.push(t("sig.abuseStat.cve", { n: s.meta.vulns }));
      if (typeof s.meta.ipqRisk === "number") parts.push(t("sig.abuseStat.ipq", { n: s.meta.ipqRisk }));
      desc = parts.length ? parts.join(" · ") : (s.detail || s.desc || t("sig.abuse.desc"));
    } else if (s.key === "abuse" && s.detail) {
      desc = s.detail;
    } else if (!s.detected && Array.isArray(s.checked) && s.checked.length) {
      desc = t("sig.cleanChecked", { sources: s.checked.join(" · ") });
    } else if (s.key === "abuse" && r.abuse) {
      desc = t("sig.abuse.descDb", { reports: r.abuse.reports, conf: r.abuse.confidence });
    } else {
      desc = s.desc || t(`sig.${s.key}.desc`);
    }
    return `
      <div class="signal ${s.detected ? "hit" : "clean"}">
        <div class="signal-icon">${SIGNAL_ICONS[s.key] || SIGNAL_ICONS.abuse}</div>
        <div class="signal-body">
          <div class="signal-top">
            <span class="signal-name">${esc(label)}</span>
            <span class="signal-state">${esc(s.detected ? t("signals.hit") : t("signals.clean"))}</span>
          </div>
          <p class="signal-desc">${esc(desc)}</p>
        </div>
      </div>
    `;
  }).join("");
}

function renderMultiGeo(r) {
  const list = r.location.multiSource || [];
  const box = $("r-geo-list");
  const extraBox = $("r-geo-extra");
  const extraWrap = $("geo-extra-wrap");
  const moreBtn = $("btn-geo-more");
  const limit = 4;

  const mkGeoLine = (g) => {
    const place = [countryShort(g.countryCode, g.country), g.region, g.city].filter(Boolean).join(", ");
    return `<div class="geo-line"><span class="geo-src">${esc(g.source)}</span><span class="geo-place">${flagHtml(g.countryCode)}<span>${esc(place)}</span></span></div>`;
  };

  if (!list.length) {
    box.innerHTML = `<div class="geo-line"><span>${esc(countryName(r.location.countryCode, r.location.country))}</span></div>`;
    if (extraBox) extraBox.innerHTML = "";
    setDrawerOpen(extraWrap, false, moreBtn);
    moreBtn.hidden = true;
    return;
  }

  box.innerHTML = list.slice(0, limit).map(mkGeoLine).join("");
  const extraList = list.slice(limit);

  if (extraList.length && extraBox && extraWrap) {
    extraBox.innerHTML = extraList.map(mkGeoLine).join("");
    const wasOpen = isDrawerOpen(extraWrap);
    moreBtn.hidden = false;
    moreBtn.dataset.count = String(extraList.length);
    setDrawerOpen(extraWrap, wasOpen, moreBtn);
    moreBtn.textContent = wasOpen ? t("btn.collapse") : t("btn.showMore", { n: extraList.length });
  } else {
    if (extraBox) extraBox.innerHTML = "";
    setDrawerOpen(extraWrap, false, moreBtn);
    moreBtn.hidden = true;
  }
}

function renderReport(r) {
  const sameIp = state.current && state.current.ip === r.ip;
  const wasHidden = $("report").hidden;
  state.current = r;
  if (!sameIp) state.aiLoadedKey = null;
  $("report").hidden = false;
  if (wasHidden) requestAnimationFrame(observeReveals);
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
      tagBox.innerHTML = tags.map((tag) => {
        const danger = /^(compromised|malware|botnet|tor|proxy|cve:)/i.test(tag);
        return `<span class="asset-tag ${danger ? "warn" : ""}">${esc(tag)}</span>`;
      }).join("");
    } else {
      tagBox.hidden = true;
      tagBox.innerHTML = "";
    }
  }

  const originText = localizedOrigin(r.location);
  const typeText = localizedType(r.type);
  const riskText = localizedRisk(r.scores);

  $("r-version").textContent = `IPv${r.version}`;
  const nb = $("r-native-badge");
  nb.textContent = originText;
  nb.className = `badge ${r.location.isNative === true ? "green" : r.location.isNative === false ? "amber" : ""}`;

  const tb = $("r-type-badge");
  tb.textContent = r.type.residential ? typeText : t("badge.nonRes", { label: typeText });
  tb.className = `badge ${r.type.residential ? "green" : r.type.code === "datacenter" ? "amber" : "blue"}`;

  const rb = $("r-risk-badge");
  rb.textContent = riskText;
  rb.className = `badge ${(r.scores.riskCode === "minimal" || r.scores.riskCode === "low") ? "green" : r.scores.riskCode === "medium" ? "amber" : "red"}`;

  const orgTypeText = localizedOrgType(r.company.type);
  $("r-asn-org").textContent = [r.network.asn, r.company.name || r.network.org].filter(Boolean).join(" · ") || "—";
  $("r-company-brief").textContent = [r.company.domain, orgTypeText !== "—" ? orgTypeText : "", r.network.route].filter(Boolean).join(" · ") || "—";
  $("r-company-name").textContent = r.company.name || "—";
  $("r-company-type").textContent = orgTypeText;
  $("r-company-domain").innerHTML = r.company.domain
    ? `<a href="https://${esc(r.company.domain)}" target="_blank" rel="noopener noreferrer">${esc(r.company.domain)}</a>` : "—";
  $("r-route").textContent = r.network.route || "—";
  $("r-rdns").textContent = r.network.rdns || "—";
  $("r-netname").textContent = [r.company.netName, r.company.rir].filter(Boolean).join(" · ") || "—";
  $("r-abuse").textContent = [r.company.abuserScore, r.company.abuseEmail].filter(Boolean).join(" · ") || "—";
  if ($("r-ports")) {
    const ports = r.exposure?.ports || [];
    $("r-ports").textContent = ports.length ? ports.join(", ") : t("ports.none");
  }

  $("r-range").textContent = r.network.ipRange || r.network.route || "—";
  if (r.ipNumeric && r.ipNumeric !== "—") {
    $("r-numeric-wrap").hidden = false;
    $("r-numeric").textContent = r.ipNumeric;
  } else $("r-numeric-wrap").hidden = true;

  const srcPill = $("r-ip-source");
  srcPill.textContent = originText;
  srcPill.className = `pill ${r.location.isNative === true ? "green" : r.location.isNative === false ? "red" : ""}`;

  const attrPill = $("r-ip-attr");
  attrPill.textContent = typeText;
  attrPill.className = `pill ${r.type.residential ? "green" : r.type.code === "datacenter" ? "red" : "amber"}`;

  renderMultiGeo(r);

  const fraud = r.scores.fraud;
  const pin = $("fraud-marker");
  const pinLeft = `${Math.max(2, Math.min(98, fraud))}%`;
  if (wasHidden) {
    pin.style.left = "0%";
    requestAnimationFrame(() => requestAnimationFrame(() => { pin.style.left = pinLeft; }));
  } else {
    pin.style.left = pinLeft;
  }
  pin.classList.toggle("edge-left", fraud <= 15);
  pin.classList.toggle("edge-right", fraud >= 85);

  const bubble = $("fraud-marker-tip");
  bubble.textContent = `${fraud}% ${riskText}`;
  bubble.className = `risk-bubble ${fraud <= 30 ? "" : fraud <= 50 ? "amber" : "red"}`;
  if ($("r-ip-score")) {
    $("r-ip-score").innerHTML = t("score.purity", { n: r.scores.trust });
  }
  $("r-breakdown").innerHTML = (r.scores.breakdown || []).map((b) => {
    const locB = localizedBreakdown(b);
    return `<li><span>${esc(locB.label)} (${esc(locB.reason)})</span><b>+${b.delta}%</b></li>`;
  }).join("") || `<li><span>${esc(t("score.cleanBaseline"))}</span><b>+0%</b></li>`;

  const aiKey = `${state.lang}:${r.ip}`;
  if (state.aiLoadedKey !== aiKey) {
    setDrawerOpen($("ai-expand"), false, $("ai-run"));
    $("ai-provider").hidden = true;
    $("ai-content").innerHTML = "";
    $("ai-run").disabled = false;
    $("ai-run").textContent = t("btn.aiRun");
  }

  renderSignals(r);

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
    regBody.innerHTML = `<tr><td colspan="5" class="empty-td">${esc(t("tbl.emptyReg"))}</td></tr>`;
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
    bgpBody.innerHTML = `<tr><td colspan="4" class="empty-td">${esc(t("tbl.emptyBgp"))}</td></tr>`;
  }

  renderMap(r);
  if (!sameIp || !state.geoAddr) loadGeoAddress(r.location, false);
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
  const aiKey = `${state.lang}:${state.current.ip}`;
  const expandBox = $("ai-expand");
  const aiBtn = $("ai-run");
  if (state.aiLoadedKey === aiKey && $("ai-content").innerHTML) {
    const nextOpen = !isDrawerOpen(expandBox);
    setDrawerOpen(expandBox, nextOpen, aiBtn);
    aiBtn.textContent = nextOpen ? t("btn.aiHide") : t("btn.aiView");
    return;
  }

  setDrawerOpen(expandBox, true, aiBtn);
  $("ai-loading").hidden = false;
  $("ai-content").innerHTML = "";
  aiBtn.disabled = true;
  try {
    const res = await fetchTimeout(`${API}?action=ai`, 16000, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ ip: state.current.ip, lang: state.lang, clientEnv: state.clientEnv }),
    });
    const d = await res.json();
    if (!res.ok || !d.ok) throw new Error(d.message || t("ai.unavailable"));
    state.aiLoadedKey = aiKey;
    $("ai-provider").hidden = false;
    $("ai-provider").textContent = `${d.provider}${d.cached ? ` · ${t("ai.cached")}` : ""}`;
    $("ai-content").innerHTML = mdListToHtml(d.text || "");
    aiBtn.textContent = t("btn.aiHide");
  } catch (e) {
    $("ai-content").textContent = e.message || t("ai.unavailable");
    aiBtn.textContent = t("btn.aiRetry");
  } finally {
    $("ai-loading").hidden = true;
    aiBtn.disabled = false;
  }
}

/* ================= Dual Stack Exit & Site Latency ================= */
const PING_SITES = [
  { name: "Baidu", url: "https://www.baidu.com/favicon.ico" },
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
      el.textContent = t("exit.timeout");
      el.className = "ping-ms slow";
    }
  }));
}

const exit = {
  started: false, running: false, _own: null, _vals: { v4: null, v6: null },
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
    this._vals[fam] = { ip, sub };
    const ipEl = $(`exit-${fam}-ip`);
    if (ip) { ipEl.textContent = ip; ipEl.classList.remove("none"); $(`exit-${fam}-geo`).textContent = sub || "—"; }
    else { ipEl.textContent = t("exit.none"); ipEl.classList.add("none"); $(`exit-${fam}-geo`).textContent = t("exit.unassigned"); }
  },
  refreshLabels() {
    for (const fam of ["v4", "v6"]) {
      const v = this._vals[fam];
      if (v) this.set(fam, v.ip, v.sub);
    }
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
  if (!res.ok || !d || d.ok !== true) { const e = new Error(d?.message || t("state.failed")); e.code = d?.error; throw e; }
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
      throw new Error(t("state.failed"));
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
    if (showedCache) { toast(t("toast.cacheUsed")); return; }
    $("report").hidden = true; $("error").hidden = false; $("error-msg").textContent = e.message || t("state.failed");
  }
}

/* ================= Subviews: ASN / DNS / WebRTC / API ================= */
const asn = {
  ws: null, started: false, paused: true, initialDone: false,
  rows: [], cache: new Map(), pending: new Map(), queue: [], active: 0, timer: null, poll: null,
  start() {
    if (this.started) return;
    this.started = true; this.rows = [];
    this.setConn("", t("state.loadingShort"));
    fetchTimeout(`${API}?feed=bgp`, 12000).then((r) => r.json()).then((d) => {
      if (d?.ok && Array.isArray(d.rows)) this.rows = d.rows.slice(-100);
    }).catch(() => {}).finally(() => {
      this.initialDone = true; this.paused = true; $("asn-pause").textContent = t("btn.liveStart");
      this.render(); this.setConn("paused", t("asn.snapshot"));
    });
  },
  setConn(cls, txt) { $("asn-conn").className = `conn-state ${cls}`; $("asn-conn-text").textContent = txt; },
  connect() {
    let ws; try { ws = new WebSocket("wss://ris-live.ripe.net/v1/ws/?client=ipspot"); } catch { this.startPoll(); return; }
    this.ws = ws;
    ws.onopen = () => { ws.send(JSON.stringify({ type: "ris_subscribe", data: { type: "UPDATE" } })); this.stopPoll(); this.setConn("live", t("asn.live")); };
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
    this.setConn("live", t("asn.polling"));
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
    if (!sorted.length) { body.innerHTML = `<tr><td colspan="6" class="empty-td">${esc(t("asn.noData"))}</td></tr>`; return; }
    for (const r of sorted) {
      const tr = document.createElement("tr");
      tr.innerHTML = `<td class="mono">${esc(new Date(r.ts).toLocaleTimeString(state.lang, { hour12: false }))}</td><td>—</td><td class="mono">${esc(r.pfx)}</td><td class="mono">${r.origin ? `AS${r.origin}` : "—"}</td><td>—</td><td><span class="pill ${r.type === "announce" ? "green" : "amber"}">${esc(r.type === "announce" ? t("asn.announce") : t("asn.withdraw"))}</span></td>`;
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
    this.paused = !this.paused; $("asn-pause").textContent = this.paused ? t("btn.liveStart") : t("btn.livePause");
    if (this.paused) { this.stopPoll(); try { this.ws?.close(); } catch {} this.ws = null; this.setConn("paused", t("asn.paused")); }
    else { this.setConn("", t("asn.connecting")); this.connect(); }
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
    $("dns-body").innerHTML = `<tr><td colspan="4" class="empty-td">${esc(t("dns.probing"))}</td></tr>`;
    $("dns-summary").textContent = t("dns.probingSub");

    let exitC = ""; try { exitC = (await ownReport()).location.country; } catch {}
    const map = new Map();
    let method = "edns-32";

    await this.probeEdnsSubdomains(map, 6);
    if (!map.size) {
      method = "edns-direct";
      $("dns-summary").textContent = t("dns.fallback1");
      await this.probeEdnsDirect(map, 5);
    }
    if (!map.size) {
      method = "bash.ws";
      $("dns-summary").textContent = t("dns.fallback2");
      await this.probeBashWs(map);
    }

    const rows = [...map.values()].sort((a, b) => b.n - a.n);
    $("dns-body").innerHTML = rows.length
      ? rows.map((r, i) => `<tr><td>${i + 1}</td><td class="mono">${esc(r.ip)}</td><td>${esc(r.geo || "—")}</td><td class="mono">${esc(t("dns.hitsUnit", { n: r.n }))}</td></tr>`).join("")
      : `<tr><td colspan="4" class="empty-td">${esc(t("dns.noResolvers"))}</td></tr>`;

    const countries = new Set(rows.map((r) => (r.geo || "").split(" - ")[0].trim()).filter(Boolean));
    const v = $("dns-verdict"); v.hidden = false;
    if (!rows.length) {
      v.className = "verdict-bar warn";
      $("dns-verdict-title").textContent = t("dns.warnTitle");
      $("dns-verdict-desc").textContent = t("dns.warnDesc");
    } else if (exitC && [...countries].some((c) => c.toLowerCase() !== exitC.toLowerCase())) {
      v.className = "verdict-bar bad";
      $("dns-verdict-title").textContent = t("dns.leakTitle");
      $("dns-verdict-desc").textContent = t("dns.leakDesc", { c: [...countries].join(", "), e: exitC });
    } else {
      v.className = "verdict-bar good";
      $("dns-verdict-title").textContent = t("dns.okTitle");
      $("dns-verdict-desc").textContent = t("dns.okDesc", { n: rows.length });
    }
    $("dns-summary").textContent = t("dns.summary", { m: method, n: rows.length });
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
    $("stun-list").innerHTML = STUNS.map((h, i) => `<div class="stun-row" id="sr-${i}"><span class="mono">stun:${esc(h)}</span><span id="sv-${i}">${esc(t("state.loadingShort"))}</span></div>`).join("");
    const all = new Set();
    await Promise.all(STUNS.map(async (h, i) => {
      const ips = await this.probe(h);
      ips.forEach((x) => all.add(x));
      const leak = this.httpIp && ips.some((x) => x !== this.httpIp);
      const row = $(`sr-${i}`); const val = $(`sv-${i}`);
      if (leak) { row.classList.add("leak"); val.innerHTML = `<span class="pill red">${esc(t("rtc.leakTag", { ips: ips.join(", ") }))}</span>`; }
      else if (ips.length) val.innerHTML = `<span class="pill green">${esc(ips.join(", "))}</span>`;
      else val.innerHTML = `<span class="pill green">${esc(t("rtc.noExpose"))}</span>`;
    }));
    const pub = [...all]; const v = $("rtc-verdict"); v.hidden = false;
    if (this.httpIp && pub.some((x) => x !== this.httpIp)) {
      v.className = "verdict-bar bad";
      $("rtc-verdict-title").textContent = t("rtc.badTitle");
      $("rtc-verdict-desc").textContent = t("rtc.badDesc", { ips: pub.join(", ") });
    } else {
      v.className = "verdict-bar good";
      $("rtc-verdict-title").textContent = t("rtc.okTitle");
      $("rtc-verdict-desc").textContent = pub.length ? t("rtc.okDescMatch", { ips: pub.join(", ") }) : t("rtc.okDescNone");
    }
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
    const pre = $("api-response"); pre.hidden = false; pre.textContent = t("api.requesting");
    try {
      const res = await fetchTimeout(q ? `${API}?q=${encodeURIComponent(q)}` : API, 14000);
      pre.textContent = JSON.stringify(await res.json(), null, 2);
    } catch (e) { pre.textContent = `Error: ${e.message || e}`; }
  },
};

/* ================= Router, Nav Glider & FAQ Accordion ================= */
const VIEWS = ["query", "fp", "asn", "dns", "webrtc", "api"];
function moveGlider() {
  const wrap = $("nav-links");
  const glider = $("nav-glider");
  const active = wrap && wrap.querySelector("a.active");
  if (!wrap || !glider || !active) return;
  glider.style.width = `${active.offsetWidth}px`;
  glider.style.transform = `translate(${active.offsetLeft}px, -50%)`;
  glider.classList.add("ready");
}
function showView(view) {
  state.currentView = view;
  for (const v of VIEWS) $(`view-${v}`).hidden = v !== view;
  document.querySelectorAll("[data-nav]").forEach((a) => a.classList.toggle("active", a.dataset.route === view));
  const navLinks = $("nav-links") || document.querySelector(".nav-links");
  const active = navLinks?.querySelector("a.active");
  if (navLinks && active) {
    const targetLeft = active.offsetLeft - navLinks.clientWidth / 2 + active.clientWidth / 2;
    navLinks.scrollTo({ left: Math.max(0, targetLeft), behavior: "smooth" });
  }
  requestAnimationFrame(moveGlider);
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
if ($("lang-btn") && $("lang-menu")) {
  const langBtn = $("lang-btn");
  const langMenu = $("lang-menu");
  const closeLangMenu = () => {
    langMenu.hidden = true;
    langBtn.setAttribute("aria-expanded", "false");
  };
  langBtn.addEventListener("click", (e) => {
    e.stopPropagation();
    const open = langMenu.hidden;
    langMenu.hidden = !open;
    langBtn.setAttribute("aria-expanded", String(open));
  });
  langMenu.querySelectorAll(".lang-opt").forEach((opt) => {
    opt.addEventListener("click", () => {
      closeLangMenu();
      handleLanguageChange(opt.dataset.lang);
    });
  });
  document.addEventListener("click", (e) => {
    if (!langMenu.hidden && !$("lang-switch")?.contains(e.target)) closeLangMenu();
  });
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && !langMenu.hidden) closeLangMenu();
  });
}

bindToggle("btn-asn-more", "asn-more");
bindToggle("btn-hb-more", "hb-more");
bindToggle("btn-score-more", "score-more");
bindToggle("btn-fp-more", "fp-more");
bindToggle("btn-bgp-more", "bgp-more");
bindToggle("btn-ping-toggle", "ping-panel", () => { if (!state.pingRan) runLatency(); });

$("btn-geo-more").addEventListener("click", () => {
  const btn = $("btn-geo-more");
  const wrap = $("geo-extra-wrap");
  const count = Number(btn.dataset.count) || $("r-geo-extra")?.children.length || 0;
  const open = !isDrawerOpen(wrap);
  setDrawerOpen(wrap, open, btn);
  btn.textContent = open ? t("btn.collapse") : t("btn.showMore", { n: count });
});

document.querySelectorAll(".faq-item").forEach((item) => {
  const btn = item.querySelector(".faq-q");
  if (!btn) return;
  btn.addEventListener("click", () => {
    const open = !item.classList.contains("is-open");
    item.classList.toggle("is-open", open);
    btn.setAttribute("aria-expanded", String(open));
  });
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
$("copy-ip").addEventListener("click", () => state.current && copyText(state.current.ip, t("toast.copiedIp")));
$("share-link").addEventListener("click", () => state.current && copyText(`${location.origin}${location.pathname}#ip=${encodeURIComponent(state.current.ip)}`, t("toast.copiedLink")));
$("ai-run").addEventListener("click", runAiDeep);

$("ga-refresh").addEventListener("click", () => state.current && loadGeoAddress(state.current.location, true));
$("ga-copy-all").addEventListener("click", () => {
  const g = state.geoAddr;
  if (!g) return;
  const text = `${t("ga.street")}: ${g.street}\n${t("ga.city")}: ${g.city}\n${t("ga.state")}: ${g.state}\n${t("ga.country")}: ${g.country}\n${t("ga.zip")}: ${g.zip}\n${t("ga.tz")}: ${g.tz}`;
  copyText(text, t("toast.copiedAllAddr"));
});
document.querySelectorAll(".ga-item").forEach((btn) => {
  btn.addEventListener("click", () => {
    const val = btn.querySelector(".ga-v")?.textContent?.trim();
    const label = btn.querySelector(".ga-k")?.textContent?.trim() || "";
    if (val && val !== "—" && !val.endsWith("…")) copyText(val, t("toast.copiedField", { label }));
  });
});

$("exit-run").addEventListener("click", () => { exit.run(); if (isDrawerOpen($("ping-panel"))) runLatency(); });
$("exit-v4-copy").addEventListener("click", () => { const v = exit._vals.v4?.ip; if (v) copyText(v, t("toast.copiedV4")); });
$("exit-v6-copy").addEventListener("click", () => { const v = exit._vals.v6?.ip; if (v) copyText(v, t("toast.copiedV6")); });
$("fp-page-run").addEventListener("click", async () => {
  state.fp = null;
  await fpEngine.renderPage(true);
  if (state.current) await fpEngine.evaluateWithReport(state.current);
  toast(t("toast.fpRefreshed"));
});
$("asn-pause").addEventListener("click", () => asn.toggle());
$("asn-clear").addEventListener("click", () => asn.clear());
$("dns-run").addEventListener("click", () => dns.run());
$("rtc-run").addEventListener("click", () => rtc.run());
$("api-try-form").addEventListener("submit", (e) => { e.preventDefault(); api.tryIt($("api-try-input").value.trim()); });
document.querySelectorAll(".api-copy").forEach((b) => b.addEventListener("click", () => {
  const m = { self: "api-ex-self", ip: "api-ex-ip", asn: "api-ex-asn" };
  copyText($(m[b.dataset.copy]).textContent, t("toast.copiedCmd"));
}));
$("open-privacy").addEventListener("click", () => $("privacy-dialog").showModal());
$("close-privacy").addEventListener("click", () => $("privacy-dialog").close());
$("privacy-dialog").addEventListener("click", (e) => { if (e.target === $("privacy-dialog")) $("privacy-dialog").close(); });
window.addEventListener("hashchange", route);
window.addEventListener("resize", moveGlider);
window.addEventListener("load", moveGlider);
if (document.fonts && document.fonts.ready) {
  document.fonts.ready.then(moveGlider).catch(() => {});
}

/* Init */
applyStaticI18n();
route();
observeReveals();