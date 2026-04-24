# SBA 综合安全运维引擎 (v2.2.3) 🛡️

[简体中文](#-简体中文) | [English](#-english)

---

## 🇨🇳 简体中文

**SBA (Site Behavior Auditor)** 是一款专为 WordPress 深度定制的高性能综合安全套件。将 **全行为审计、双向流量防护、iOS 风格登录交互、SMTP 发信** 四大模块通过全内存架构完美融合。

> ⚡ **核心突破**：2.1.7 版本引入了 **原子化增量记账 (Atomic Counting)**、**三级 UV 验证** 以及 **SSRF 出站安全网关**。即使面对日均千万级的访问量，看板加载依然实现“秒开”，并能有效阻断服务器被利用作为攻击跳板。

### ✨ 核心特性

* **🚀 微秒级 IP 解析**：集成 `ip2region xdb` 内存版，解析耗时仅 0.0x 毫秒，完全脱离数据库依赖。
* **📊 计数架构**：采用 MySQL 原子操作 (`ON DUPLICATE KEY UPDATE`) 更新 PV/UV，杜绝高并发下的数据丢失与行锁竞争。
* **🔒 全方位出站网关 (SSRF Shield)**：
  * **内网隔离**：自动阻断服务器访问 127.0.0.1、192.168.x.x 等私有网段及云平台元数据接口。
  * **DNS Rebinding 防御**：强制执行 IP 直连 + Host 头校验，防止通过 DNS 切换绕过安全策略。
  * **协议白名单**：仅放行标准的 HTTP/HTTPS，阻断 Gopher、File 等危险伪协议。
* **🛡️ 主动爬虫防御系统**：
  * **阶梯限流**：针对 `feed`、`rest_route` 等采集路径执行更严苛的频率限制。
  * **Cookie 身份指纹**：自动识别真实浏览器，对无状态爬虫进行强力拦截。
  * **诱饵陷阱 (Honeypot)**：动态生成隐藏诱饵，脚本一旦触碰即刻触发永久封禁。
* **👤 极致交互体验**：全 AJAX 驱动的 iOS 风格登录/注册面板，去 Session 化设计，完美兼容 Redis 缓存环境。
* **📦 稳健传输**：内置分片上传组件，支持大体积 `.xdb` 库文件的断点续传。

### 📥 快速开始

1. **部署**：将 `site-behavior-auditor` 文件夹上传至 `/wp-content/plugins/` 并启用。
2. **准备数据**：从 [ip2region 官方](https://github.com/lionsoul2014/ip2region/tree/master/data) 下载 `ip2region.xdb`。
3. **上传同步**：在「防御设置」页面底部，使用分片上传组件同步库文件。
4. **环境建议**：为确保最佳性能，建议配置 PHP `memory_limit = 512M`。

### 🤝 鸣谢

本项目高性能解析引擎由 [ip2region](https://github.com/lionsoul2014/ip2region) 驱动。

[返回顶部](#sba-综合安全运维引擎-v217-️)

---

## 🇺🇸 English

**SBA (Site Behavior Auditor)** is a high-performance, all-in-one security suite custom-built for WordPress. Designed with a architectural mindset, it integrates **Real-time Auditing, Inbound & Outbound Defense, iOS-style Login UI, and SMTP** into a single, memory-optimized engine.

### ✨ Key Features

- **🚀 Microsecond IP Resolution**: Powered by `ip2region xdb` in-memory lookup, resolving locations in 0.0x ms with zero database overhead.
- **📊 Atomic Counting Architecture**: Uses native MySQL atomic operations to handle high-concurrency PV/UV counts without row-lock contention.
- **🔒 Outbound Security Gateway (SSRF Shield)**:
  - **Internal Network Isolation**: Blocks access to 127.0.0.1, 192.168.x.x, and Cloud metadata endpoints (169.254.169.254).
  - **DNS Rebinding Protection**: Enforces IP-direct connection with Host-header validation to prevent DNS-based bypasses.
  - **Protocol Whitelist**: Only standard HTTP/HTTPS allowed; dangerous protocols like Gopher/File are blocked.
- **🛡️ Active Bot Shield**:
  - **Tiered Rate Limiting**: Intelligent frequency control for sensitive paths (RSS, REST API).
  - **Cookie Validation**: Differentiates human browsers from stateless scraping scripts.
  - **Honeypot Traps**: Dynamically injected bait links that instantly ban automated bots upon access.
- **👤 Modern User Interaction**: Full AJAX-driven iOS-style login/register box. Session-less design using WordPress Transient API, fully compatible with Redis/Memcached.
- **📦 Resilient Data Sync**: Chunked upload component with breakpoint resume for large `.xdb` database files.

### 📥 Quick Start

1. **Deploy**: Upload the plugin to `/wp-content/plugins/` and activate it.
2. **Data Prep**: Download `ip2region.xdb` from the [official repository](https://github.com/lionsoul2014/ip2region/tree/master/data).
3. **Sync**: Upload the xdb file via the chunked uploader at the bottom of the settings page.
4. **Server Tuning**: Recommend setting PHP `memory_limit = 512M` for optimal performance.

### 🤝 Acknowledgments

High-performance IP resolution is powered by [ip2region](https://github.com/lionsoul2014/ip2region).

[Back to Top](#sba-综合安全运维引擎-v217-️)

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
