\# IPSpot (`ipspot.org`)



专业、透明、免费的在线 IP 纯净度与网络环境诊断平台。默认深色科技主题，支持一键切换浅色模式（含地图底图联动），提供多源防误判家宽/机房识别、透明扣分明细、原生/广播地理对照、所属企业与 RDAP/RIPEstat 历史记录、人机指纹环境对比、全球免费 AI 诊断、DNS/WebRTC 泄露检测及实时 ASN 监控。



\## 核心能力与真实数据源



\- \*\*多源防误判引擎\*\*：并行聚合 `ipapi.is`、`ipquery.io`、`ip-api.com`、`ipwho.is` 与官方 `RDAP`，引入云商/IDC 关键词与 `rDNS` 一票否决，精准区分原生家宽、双 ISP 商宽托管与数据中心机房，支持直接输入域名自动解析 IP。

\- \*\*透明风险评分\*\*：0–100% 风险值与信任分，逐项列出扣分依据（网络基线、跨区广播、代理/VPN/Tor、滥用与爬虫信号）。

\- \*\*所属企业与历史记录\*\*：实时拉取 RDAP 网段名、RIR 机构、注册/更新日期及 `RIPEstat` BGP 历史路由宣告。

\- \*\*人机对比与浏览器指纹\*\*：本地实时采集 WebDriver、Headless 特征、Canvas/WebGL 指纹、时区与语言设置，与出口 IP 交叉核验。

\- \*\*免费全球可用 AI 诊断\*\*：同源后端中转（`POST /functions/v1/app?action=ai`），国内直连与海外均可正常使用。

\- \*\*隐私与网络工具\*\*：随机子域防缓存 DNS 泄露检测、多 STUN WebRTC 泄露检测、IPv4/IPv6 双栈出口与主流平台连通延迟探测、RIPE RIS Live 实时 BGP 监控。



\## 目录结构



```text

web/                       前端静态文件（Cloudflare Pages 构建输出目录）

&#x20; index.html               主页面与 Bento 仪表盘骨架

&#x20; styles.css               默认深色 + 浅色双主题样式与预留广告槽

&#x20; app.js                   多源渲染、人机指纹对比、AI 诊断与工具逻辑

&#x20; favicon.svg              浏览器地址栏标签图标

&#x20; logo.svg                 IPSpot 品牌矢量 Logo

&#x20; robots.txt               搜索引擎抓取规则

&#x20; sitemap.xml              站点地图

functions/                 Cloudflare Pages Functions（自动编译）

&#x20; functions/v1/app.ts      → 路由 /functions/v1/app（透传 env）

lib/

&#x20; handler.ts               共享后端逻辑（多源聚合、防误判打分、AI 中转）

deno/

&#x20; index.ts                 Deno 部署入口

dev/

&#x20; serve.mjs                本地预览开发服务器

```



\## 本地预览（无需推送仓库）



需要 Node.js 22+（支持直接运行 `.ts` 文件，若版本较低可使用 `npx tsx dev/serve.mjs`）：



```bash

node dev/serve.mjs

```



启动后浏览器打开：\*\*`http://127.0.0.1:4173/`\*\*



> 如需在本地预览时测试免费大模型 AI 诊断，可在项目根目录新建 `.env` 文件（请勿提交到 Git）：

>

> ```env

> AI\_API\_KEY=你的免费API密钥

> AI\_API\_URL=\[https://open.bigmodel.cn/api/paas/v4/chat/completions](https://open.bigmodel.cn/api/paas/v4/chat/completions)

> AI\_MODEL=glm-4-flash

> ```

>

> 不配置任何 Key 时，AI 诊断会自动走内置的 \*\*IPSpot 专家规则引擎\*\*，保证 100% 正常响应不报错。



\## Cloudflare Pages 部署与免费 AI 一键绑定



1\. 将仓库推送至 GitHub，在 Cloudflare 控制台选择 \*\*Workers \& Pages -> 创建 -> Pages -> 连接到 Git\*\*。

2\. 构建配置：

&#x20;  - \*\*框架预设\*\*：`None`

&#x20;  - \*\*构建命令\*\*：留空

&#x20;  - \*\*构建输出目录\*\*：`web`

3\. \*\*开启免费 Cloudflare Workers AI（每日免费 10,000 Neurons，零 Key，全球含国内同源直连）\*\*：

&#x20;  - 进入该 Pages 项目的 \*\*设置 (Settings) -> 绑定 (Bindings) -> 添加 (Add)\*\*。

&#x20;  - 选择 \*\*Workers AI\*\*，变量名称填写 \*\*`AI`\*\*，保存并重新部署即可生效。

4\. \*\*可选备用免费大模型\*\*：

&#x20;  - 在 \*\*设置 -> 环境变量\*\* 中添加 `AI\_API\_KEY`（如智谱 `glm-4-flash`、硅基流动或 Groq 免费 Key）、`AI\_API\_URL` 和 `AI\_MODEL`，系统会在 Workers AI 额度耗尽时自动无缝切换。



\## 开放 API



```bash

curl \[https://ipspot.org/functions/v1/app](https://ipspot.org/functions/v1/app)

curl "\[https://ipspot.org/functions/v1/app?q=1.1.1.1](https://ipspot.org/functions/v1/app?q=1.1.1.1)"

curl "\[https://ipspot.org/functions/v1/app?q=openai.com](https://ipspot.org/functions/v1/app?q=openai.com)"

curl "\[https://ipspot.org/functions/v1/app?asn=15169\&pfx=8.8.8.0/24](https://ipspot.org/functions/v1/app?asn=15169\&pfx=8.8.8.0/24)"

```



AI 诊断接口（POST）：



```bash

curl -X POST "\[https://ipspot.org/functions/v1/app?action=ai](https://ipspot.org/functions/v1/app?action=ai)" \\

&#x20; -H "Content-Type: application/json" \\

&#x20; -d '{"ip":"1.1.1.1"}'

```



\## 联系方式



邮箱：\[hezhanleiok@gmail.com](mailto:hezhanleiok@gmail.com)

