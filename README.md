# IPLens · IP 检测雷达

现代响应式的 IP 检测网站：家宽判定、欺诈值、信任评分、代理 / VPN / Tor / 数据中心 / 移动 / 滥用威胁六项风险信号、地理位置地图、ASN 变化监控、DNS 泄露、WebRTC 泄露、IPv4/IPv6 出口检测与开放 API。

所有数据均来自真实公开数据源，无编造：

- **ipquery.io** + **ip-api.com** 双源交叉验证（机房 / 代理 / 移动网络任一源命中即采纳，避免单源漏判）
- **ipwho.is** 补全邮政编码
- **RIPE RIS Live** 实时 ASN 路由变化
- **Esri** 带标注地图底图

## 目录结构

```
web/                       前端静态文件（Cloudflare Pages 构建输出目录）
  index.html
  app.js
  styles.css
functions/                 Cloudflare Pages Functions（根目录自动编译）
  functions/v1/app.ts      → 路由 /functions/v1/app
lib/
  handler.ts               共享后端逻辑（仅标准 Web API，可移植）
deno/
  index.ts                 Deno 入口（本地 / Qoder Sites 用）
dev/
  serve.mjs                本地开发服务器
```

后端 `lib/handler.ts` 只用标准 Web API（fetch / Request / Response / Headers），同一份代码同时跑在 Cloudflare Workers 运行时与本地 Node/Deno。Cloudflare 会自动给请求带上 `cf-connecting-ip` 头，服务端据此识别访客真实 IP；ip-api 的 HTTP 请求在服务端发出，不受浏览器混合内容限制，双源校验完整保留。

## 部署到 Cloudflare Pages（GitHub 集成）

1. 将本仓库推送到 GitHub。
2. Cloudflare 控制台 → **Workers & Pages → Create → Pages → Connect to Git**，选择本仓库。
3. 构建设置：
   - **Framework preset**：`None`
   - **Build command**：留空
   - **Build output directory**：`web`
   - **Root directory**：`/`（默认）
4. 保存并部署。Cloudflare 会自动编译根目录 `functions/` 并把 `web/` 作为静态资源。
5. 完成后站点地址形如 `https://<项目名>.pages.dev`，打开即自动识别访客 IP。

每次 push 到生产分支会自动重新部署。

### 直接上传（可选，不用 GitHub）

```bash
npx wrangler pages deploy web --project-name=iplens
```

## 本地开发

```bash
node dev/serve.mjs
# 打开 http://127.0.0.1:4173/
```

本地无公网出口头时会回退到浏览器侧 IP 识别（icanhazip / ipify）。

## 开放 API

```bash
curl https://<站点>/functions/v1/app                 # 识别请求者 IP
curl "https://<站点>/functions/v1/app?q=1.1.1.1"      # 查询指定 IP
curl "https://<站点>/functions/v1/app?asn=15169&pfx=8.8.8.0/24"   # ASN 归属
```

结果在服务端缓存 15 分钟（ASN 归属缓存 1 小时），同一 IP 在缓存期内评分保持一致。