# SBA All-in-One Security & Auditing Engine (v3.0.2) 🛡️

[简体中文](#-简体中文) | [English](#-english)

---

## 🇨🇳 简体中文

**SBA (Site Behavior Auditor)** 是一款专为 WordPress 深度定制的高性能综合安全套件。它不是简单的统计插件，而是一个将 **全行为审计、双向流量过滤、高级身份鉴权、系统自维护** 融为一体的运维引擎。

> ⚡ **3.0.1 性能标杆**：专为高并发站点设计。通过 **Write-Back 内存写回架构**，将数据库写入压力降低了 99% 以上。即便在低配服务器上，也能支撑起百万级流量的实时监控。

### 💎 核心功能模块

#### 1. 📊 全行为行为审计 (Behavior Auditing)
*   **实时轨迹追踪**：毫秒级记录访客 IP、地理位置（ip2region xdb）、访问路径及实时 PV。
*   **多维数据看板**：可视化 30 天访问趋势图、50 天审计详表，支持在线人数实时监控。
*   **高性能计数引擎**：原子化更新 PV/UV，彻底杜绝高并发下的数据丢失。

#### 2. 🛡️ 入站流量防御 (Inbound WAF)
*   **扫描器封禁**：自动识别并阻断 `sqlmap`, `nmap`, `dirbuster`, `nikto` 等百余种自动化攻击工具。
*   **Gate 隐藏入口**：为 `wp-login.php` 设置专属钥匙参数，彻底隐藏后台入口，使暴力破解无从下手。
*   **用户枚举防护**：阻断针对 `author=n` 参数及 REST API 的恶意用户资料探测。
*   **CC 阶梯限流**：针对正常访问与 API 采集（RSS/Feed/REST）执行差异化的频率限制策略。
*   **诱饵陷阱 (Honeypot)**：动态注入隐藏蜜罐链接，自动化脚本一旦触碰即刻封禁 IP。

#### 3. 🔒 出站安全网关 (Outbound SSRF Shield)
*   **内网隔离**：强制阻断服务器对 127.0.0.1、192.168.x.x 等私有网段的请求，防止服务器被当作攻击跳板。
*   **DNS Rebinding 防御**：强制执行 IP 直连 + Host 头校验，防御利用 DNS 切换绕过安全策略的攻击。
*   **协议白名单**：仅放行标准的 HTTP/HTTPS，阻断 Gopher、File 等高危伪协议。

#### 4. 👤 iOS 风格登录套件 (iOS Style Login)
*   **全 AJAX 交互**：提供包含登录、注册、找回密码三位一体的 iOS 风格毛玻璃面板。
*   **增强认证体系**：集成算术验证码、邮箱激活流程、登录失败次数自动梯度封禁。
*   **完全兼容缓存**：采用无 Session 设计，完美支持 Redis/Memcached 内存环境。

#### 5. 📧 SMTP 邮件引擎 (SMTP Engine)
*   **原生集成**：取代第三方臃肿插件，支持 TLS/SSL 加密，确保验证邮件精准送达。

---

## 🇺🇸 English

**SBA (Site Behavior Auditor)** is a professional-grade security and auditing engine custom-tailored for WordPress. It goes beyond simple statistics, integrating **Real-time Auditing, Bi-directional Traffic Filtering, Advanced Authentication, and Self-Healing Maintenance** into a single, high-performance core.

> ⚡ **v3.0.1 Performance Milestone**: Engineered for high-concurrency environments. Featuring a **Write-Back Memory Architecture**, it reduces database write I/O pressure by **over 99%**. Even on entry-level servers, SBA comfortably handles millions of hits with real-time accuracy.

### 💎 Key Functional Modules

#### 1. 📊 Granular Behavior Auditing
*   **Real-time Trace**: Microsecond-level logging of visitor IP, Geo-location (ip2region xdb), request paths, and instant PV.
*   **Visual Analytics**: Interactive 30-day trend charts and 50-day detailed audit tables.
*   **Atomic Counting**: Native MySQL atomic operations for PV/UV updates, eliminating race conditions and data loss.

#### 2. 🛡️ Inbound WAF & Defense
*   **Scanner Mitigation**: Automatically detects and blocks 100+ automated tools like `sqlmap`, `nmap`, and `dirbuster`.
*   **Gatekeeper Logic**: Protects `wp-login.php` with a unique "Gate Key," making the backend entrance invisible to brute-force bots.
*   **Anti-Enumeration**: Blocks user profile probing via `author=n` parameters and REST API endpoints.
*   **Tiered Rate Limiting**: Intelligent frequency control that differentiates between human browsing and aggressive API scraping (RSS/Feed).
*   **Honeypot Traps**: Dynamically injects invisible bait links that instantly ban IP addresses upon access.

#### 3. 🔒 Outbound Security Gateway (SSRF Shield)
*   **Internal Network Sequestration**: Forcefully blocks requests to private ranges (127.0.0.1, 192.168.x.x, etc.) to prevent internal penetration.
*   **Anti-DNS Rebinding**: Enforces direct IP routing with Host-header validation to defeat DNS-based bypass techniques.
*   **Protocol Whitelisting**: Allows only standard HTTP/HTTPS; dangerous pseudo-protocols like Gopher/File are strictly blocked.

#### 4. 👤 iOS-Style Interaction Suite
*   **Full AJAX Workflow**: A seamless, modern UI for Login, Registration, and Password Recovery.
*   **Enhanced Auth**: Integrated math captcha, email activation workflows, and adaptive failed-login banning.
*   **Redis-Ready**: A session-less design utilizing the WordPress Transient API, fully compatible with object-caching environments.

#### 5. 📧 Integrated SMTP Engine
*   **Native Mailer**: Replaces bulky third-party plugins with a lean, encrypted (TLS/SSL) SMTP handler.

---

### 🚀 3.0.1 Technical Advantages

*   **Write-Back Buffering**: PV counts reside in memory and are merged into the DB every 10 minutes, drastically extending disk life.
*   **Force-Sync Calibration**: Recognizes the `no-cache` browser directive. Admins can press `Ctrl+F5` to instantly flush buffers and reconcile statistics.
*   **Auto-Maintenance**: Monthly `OPTIMIZE TABLE` execution on the 1st to eliminate fragmentation and maintain peak performance.

### 📥 Getting Started

1.  **Deployment**: Upload the plugin to `/wp-content/plugins/` and activate.
2.  **Sync Data**: Under "Defense Settings," use the chunked uploader to sync your `ip2region.xdb` file.
3.  **Shortcodes**:
    *   `[sba_login_box]`: Inserts the iOS-style login panel on any page.
    *   `[sba_stats]`: Displays real-time online users and visitor stats in widgets.

### 🤝 Acknowledgments
High-performance geolocation engine powered by [ip2region](https://github.com/lionsoul2014/ip2region).

---

### 🖼️ 界面预览 (Screenshots)

#### 可视化审计面板 (Audit Dashboard)
<div style="text-align: left;">
  <img src="https://github.com/user-attachments/assets/bea56093-224b-4124-aa43-a15a06032091" alt="Audit Dashboard" width="60%">
</div>

#### 实时轨迹与日志 (Real-time Trace & Logs)
<div style="display: flex; gap: 10px;">
  <img src="https://github.com/user-attachments/assets/1a323212-bdf8-46ae-b079-9563f80a4eac" alt="Trace" width="45%">
  <img src="https://github.com/user-attachments/assets/d1595991-1dde-455e-91b7-4eccbf805230" alt="Blocked Logs" width="45%">
</div>

#### 防御设置与环境检测 (Settings & Env Check)
<div style="text-align: left;">
  <img src="https://github.com/user-attachments/assets/4b1daf8e-3223-41eb-bbde-9cce9f390a80" alt="Settings" width="60%">
</div>

#### iOS 风格登录交互 (iOS Style Login)
<table border="0" cellpadding="0" cellspacing="0" align="left">
  <tr>
    <td valign="top" width="140">
      <img src="https://github.com/user-attachments/assets/1be6cceb-887d-4b44-97b5-304a69e3ba04" width="130">
    </td>
    <td valign="top" width="140">
      <img src="https://github.com/user-attachments/assets/9de3d9ed-8f44-4c4a-9080-1b6133ddf884" width="130">
    </td>
    <td valign="top" width="140">
      <img src="https://github.com/user-attachments/assets/c28151e0-fd64-43a7-bc18-40463c9b4fa1" width="130">
    </td>
  </tr>
</table>
<br clear="all">

#### SMTP邮件设置 (SMTP Mail Settings)
<div style="text-align: left;">
  <img src="https://github.com/user-attachments/assets/4550941c-f32f-4626-98ec-c7d6a3ed7620" alt="Settings" width="60%">
</div>

---

## 📄 License

GPL v2 or later

---

**Developed by Stone** | *Architect-grade stability for WordPress systems.*