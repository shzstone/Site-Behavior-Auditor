# SBA 综合安全运维引擎 (v4.0.1) 🛡️

[简体中文](#-简体中文) | [English](#-english)

---

## 🇨🇳 简体中文

**SBA (Site Behavior Auditor)** 是一款专为 WordPress 深度定制的高性能、全链路安全加固与审计套件。

不同于传统的统计插件，SBA 采用了 **“计算下沉”** 与 **“异步写回”** 架构，将安全拦截、指纹抹除、出站防御、行为审计与高性能统计完美集成于一个 300KB 的轻量化核心中，旨在日均百万级流量环境下实现“零感运行”。

### 💎 核心功能模块解析

#### 1. 📊 全维度行为审计系统 (Behavioral Auditing)
*   **实时轨迹追踪**：毫秒级记录访客 IP、地理位置（基于 ip2region xdb 内存镜像）、设备指纹及详细访问路径。
*   **增量汇总排行榜**：独创威胁统计表，自动从海量日志中提取高频攻击者，无需扫表即可秒级查看「头号公敌」。
*   **隐私保护脱敏**：在展示访客轨迹时自动对 IP 进行掩码处理（如 `122.67.***.***`），兼顾管理审计与隐私合规。
*   **高性能分页引擎**：采用流式分页（Stream Pagination）技术，彻底杜绝大数据量下翻页卡顿。

#### 2. 🛡️ 静态加固与指纹抹除 (System Hardening)
*   **隐身模式**：自动移除 WordPress 版本号、资源链接后的 `ver` 变量、以及后端 PHP 的 `X-Powered-By` 标签，消除黑客侦察指纹。
*   **安全响应头注入**：一键注入 HSTS、X-Frame-Options (防点击劫持)、X-Content-Type-Options (防嗅探) 等五大安全头，提升全站安全评分。
*   **接口与目录锁**：阻断非登录用户探测 REST API 根目录及插件列表；物理隔离 `.env`、`.sql`、`.bak` 等敏感后缀的访问。

#### 3. 🔒 双向流量过滤网关 (WAF & SSRF)
*   **入站防御**：集成 CC 阶梯限流、智能蜜罐陷阱（Honeypot）、自动化扫描器识别及 Gate 钥匙级后台隐藏。
*   **出站安全 (SSRF)**：强制执行协议白名单（仅 HTTP/HTTPS），阻断服务器被利用探测内网 IP 或访问危险协议（Gopher/File）。
*   **智能 Loopback**：自动识别并放行内部通讯（如 WP-Cron），确保系统调度与更新功能在严苛策略下依然正常运行。

#### 4. 🚀 工业级写缓冲架构 (High Performance)
*   **Write-Back 引擎**：PV 统计先进入内存缓冲区，每 10-20 分钟合并写回数据库。**数据库写入压力降低 99% 以上**。
*   **防刷签名校验**：异步统计接口引入“动态时间戳签名”，防止黑客利用统计接口进行反向 DDoS。

---

### 📖 快速配置指南

#### 第一步：部署与初始化
1.  将插件上传并启用。
2.  **IP 数据准备**：前往「防御设置」底部，通过分片上传组件上传 `ip2region_v4.xdb` 文件。

#### 第二步：信任来源配置 (关键)
*   若您的站点使用了 **Cloudflare**：在 IP 信任来源中选 `Cloudflare (CF_IP)`。
*   若您使用了 **Nginx 反向代理**：选 `Nginx 转发 (REAL_IP)`。
*   *验证方法*：看仪表盘显示的 IP 是否为您本人的真实公网 IP。

#### 第三步：开启「AJAX 统计补丁」
*   **判断条件**：开启无痕窗口访问首页，若后台「访客轨迹」没实时增加记录，说明 PHP 被静态缓存（如 WP Rocket）拦截，此时**必须开启**此开关以确保统计准确。

#### 第四步：设置「Gate 钥匙」
*   填入一个私密字符串（如 `mystone`），保存后，您的登录地址将变为 `wp-login.php?gate=mystone`。直接访问原登录页将返回 403。

---

## 🇺🇸 English

**SBA (Site Behavior Auditor)** is a professional-grade, all-in-one security hardening and auditing infrastructure for WordPress. Engineered for high-load environments, SBA balances advanced defense with extreme performance using **Write-Back Buffering** and **Summary Aggregation** technologies.

### 💎 Key Feature Modules

#### 1. 📊 Behavioral Auditing & Privacy
*   **Real-time Trace**: Microsecond-level logging of visitor IP, Geo-location, and request paths.
*   **Threat Ranking**: A dedicated summary table aggregates millions of attack logs into a "Top Offenders" list instantly.
*   **Privacy Obfuscation**: Automatic IP masking (`1.2.***.***`) for public tracking logs to ensure data privacy.
*   **High-Speed Navigation**: Stream pagination eliminates `COUNT(*)` overhead, providing smooth browsing through millions of records.

#### 2. 🛡️ System Hardening
*   **Fingerprint Erasure**: Removes WP versions, script tags, and `X-Powered-By` headers to stop attackers from fingerprinting your stack.
*   **Security Header Injection**: Automatically enforces HSTS, X-Frame-Options (SAMEORIGIN), and Referrer Policies.
*   **Endpoint Lockdown**: Restricts anonymous REST API index probing and blocks access to sensitive files (.sql, .env, .log).

#### 3. 🔒 Traffic Filtering Gateway (WAF & SSRF)
*   **Inbound Defense**: Tiered rate limiting, Honeypot traps, and "Gate Key" backend hiding.
*   **Outbound SSRF Shield**: Restricts outbound traffic to standard HTTP/HTTPS and prevents internal network probing.
*   **Cron-Friendly**: Intelligently bypasses Loopback requests to ensure WP-Cron and core updates remain functional.

#### 4. 🚀 Enterprise Performance
*   **Write-Back Buffering**: PV counts are cached in memory and merged into the DB every 10-20 minutes, reducing DB writes by **over 99%**.
*   **Secure Heartbeat**: AJAX tracking uses HMAC-based dynamic tokens to prevent traffic inflation attacks.

### 📥 Getting Started

1.  **Sync IP Data**: Upload the `ip2region.xdb` file via the chunked uploader in Settings.
2.  **Configure IP Source**: If behind **Cloudflare** or **Nginx Proxy**, select the appropriate header source to ensure correct IP identification.
3.  **Enable AJAX Patch**: If using static caching (e.g., WP Rocket), enable the AJAX Patch to ensure visitors are tracked even on cached pages.
4.  **Set Gate Key**: Secure your login page by appending a secret key requirement (e.g., `wp-login.php?gate=secret`).

---

### 🖼️ 界面预览 (Screenshots)

#### 可视化审计面板 (Audit Dashboard)
<div style="text-align: left;">
  <img src="https://github.com/user-attachments/assets/bea56093-224b-4124-aa43-a15a06032091" alt="Audit Dashboard" width="60%">
</div>

#### 实时轨迹与威胁排行 (Tracks & Threat Ranking)
<div style="display: flex; gap: 10px;">
  <img src="https://github.com/user-attachments/assets/1a323212-bdf8-46ae-b079-9563f80a4eac" alt="Trace" width="45%">
  <img src="https://github.com/user-attachments/assets/d1595991-1dde-455e-91b7-4eccbf805230" alt="Blocked Logs" width="45%">
</div>

#### 防御设置 (Detailed Settings)
<div style="text-align: left;">
  <img src="https://github.com/user-attachments/assets/4b1daf8e-3223-41eb-bbde-9cce9f390a80" alt="Settings" width="60%">
</div>

---

## 📄 License

GPL v2 or later

---

**Developed by Stone** | *Architect-grade stability for WordPress systems.*