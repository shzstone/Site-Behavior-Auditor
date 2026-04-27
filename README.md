# SBA 综合安全运维引擎 (v4.0.6) 🛡️

[简体中文](#-简体中文) | [English](#-english)

---

## 🇨🇳 简体中文

**SBA (Site Behavior Auditor)** 是一款专为 WordPress 深度定制的高性能、全链路安全加固与审计套件。

v4.0.6 版本实现了 **“攻击面清零”** 战略：通过弃用传统的 Gate 钥匙，转而将 `wp-login.php` 与 `wp-admin` 进行物理级封锁。所有身份鉴权逻辑均收缩至前端 AJAX 容器中，彻底根治了高并发与强缓存环境下的登录冲突及崩溃隐患。

### 💎 核心功能模块解析

#### 1. 🚫 入口物理封锁 (Entrance Sequestration)
*   **正门焊死**：直接拦截所有未登录用户对 `wp-login.php` 和 `wp-admin` 的访问，从物理层阻断暴力破解与漏洞探测。
*   **身份感知重定向**：已登录用户访问登录页将自动、丝滑地重定向至后台，杜绝 Fatal Error 产生。
*   **唯一安全入口**：强制所有登录、注册、找回密码行为通过 `[sba_login_box]` 渲染的前台 iOS 风格面板进行。

#### 2. 📊 全维度行为审计系统 (Behavioral Auditing)
*   **审计豁免锁**：自动识别内网 IP（如 Nginx 容器的 `172.20.0.7`），不计入 PV/UV 及轨迹，保持审计报表绝对纯净。
*   **增量汇总排行**：基于汇总表架构，秒级聚合百万级拦截数据，直观展示高频攻击者。
*   **隐私保护脱敏**：访客轨迹 IP 自动执行掩码处理（如 `122.67.***.***`），兼顾审计需求与隐私合规。

#### 3. 🛡️ 静态加固与 WAF 防御 (System Hardening)
*   **全域参数清洗**：即使利用 `action=lostpassword` 等合法动作作为掩护，任何携带非法参数（如模板切换、无值探测键）的请求都将被即刻拦截。
*   **指纹全面抹除**：移除 WordPress 版本、脚本 `ver` 参数及 `X-Powered-By` 头，实现全站“深度隐身”。
*   **安全头注入**：自动强制开启 HSTS、X-Frame-Options、X-Content-Type-Options 等五大安全头。

#### 4. 🚀 工业级写缓冲架构 (High Performance)
*   **Write-Back 引擎**：PV 统计采用内存级缓冲，每 10-20 分钟合并写回，数据库写入压力降低 99% 以上。
*   **安全心跳 Token**：异步统计接口引入“双时段动态签名”，解决跨点统计丢失并防御恶意刷量。

---

### 📖 快速配置指南

#### 第一步：部署与初始化
1.  将插件上传至 `/wp-content/plugins/` 并启用。
2.  **IP 数据准备**：在「防御设置」底部上传 `ip2region_v4.xdb` 文件以启用精准归属地解析。

#### 第二步：创建唯一入口 (关键)
1.  新建一个 WordPress 页面（页面地址建议设为私密，如 `/safe-entry`）。
2.  在页面内容中填入短代码：`[sba_login_box]`。
3.  **从此以后，这是您和用户登录网站的唯一合法入口。**

#### 第三步：信任来源与统计补丁
*   若在仪表盘看到的 IP 是 `127.0.0.1`：请在「IP 信任来源」中切换至 `Nginx 转发` 或 `Cloudflare`。
*   若使用了静态缓存（如 WP Rocket）：请务必开启「AJAX 统计补丁」。

---

## 🇺🇸 English

**SBA (Site Behavior Auditor)** is a professional-grade security hardening and auditing infrastructure for WordPress. v4.0.6 introduces the **"Zero Attack Surface"** strategy by physically sequestering standard login entrances.

### ✨ Key Features

*   **🔒 Physical Entrance Sequestration**: Blocks all direct access to `wp-login.php` and `wp-admin` for unauthenticated users. The only way in is through your custom shortcode page.
*   **📊 Clean Audit Stream**: Automatically excludes internal/proxy IPs (e.g., Docker gateway `172.20.0.1`) from statistics to ensure data purity.
*   **🛡️ Parameter Sanitization**: Deeply inspects Query Strings even on "allowed actions" to prevent attackers from using `lostpassword` as a shield for scanning.
*   **🚀 Write-Back Architecture**: PV/UV counts are buffered in memory and flushed to the DB every 10-20 minutes, reducing write I/O by **99%+**.
*   **👤 iOS-Style Auth UI**: A modern, glassmorphism UI for all authentication needs, fully compatible with object caching and static environments.

### 📥 Getting Started

1.  **Sync IP Data**: Upload the `ip2region.xdb` file via the settings page.
2.  **Deploy Login Portal**: Create a new page and insert the shortcode `[sba_login_box]`. **This is now your only secure entrance.**
3.  **Identity Redirection**: Logged-in users visiting the standard login page will be automatically and safely redirected to the dashboard.

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

---

## 📄 License

GPL v2 or later

---

**Developed by Stone** | *Architect-grade stability for WordPress systems.*