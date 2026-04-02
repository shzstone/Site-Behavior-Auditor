# SBA 综合安全运维引擎 (v2.1.7) 🛡️

[简体中文](#-简体中文) | [English](#-english)

---

## 🇨🇳 简体中文

**SBA (Site Behavior Auditor)** 是一款专为 WordPress 深度定制的高性能综合安全套件。不同于传统的安全插件，它采用银行级架构思维，将 **全行为审计、三层爬虫防御、iOS 风格登录交互、SMTP 发信** 四大模块通过全内存架构完美融合。

> ⚡ **核心突破**：2.1.7 版本引入了 **原子化增量记账 (Atomic Counting)** 和 **三级 UV 验证** 逻辑。即使面对日均千万级的访问量，看板加载依然实现“秒开”，且对服务器数据库压力降至最低。

### ✨ 核心特性
*   **🚀 微秒级 IP 解析**：集成 `ip2region xdb` 内存版，单次解析仅需 0.0x 毫秒，完全脱离数据库依赖。
*   **📊 银行级计数架构**：采用 MySQL 原子操作 (`ON DUPLICATE KEY UPDATE`) 更新 PV/UV，彻底杜绝高并发下的数据丢失与行锁竞争。
*   **🛡️ 三层主动防御系统**：
    *   **阶梯限流**：针对 `feed`、`rest_route` 等采集路径执行更严苛的频率限制。
    *   **Cookie 身份指纹**：自动识别真实浏览器，对无状态爬虫进行拦截。
    *   **诱饵陷阱 (Honeypot)**：动态生成隐藏诱饵，脚本一旦触碰即刻触发永久封禁。
*   **👤 极致交互体验**：全 AJAX 驱动的 iOS 风格登录/注册面板，去 Session 化设计，完美兼容 Redis/Memcached 缓存环境。
*   **📦 稳健传输**：内置分片上传组件，支持大体积 `.xdb` 库文件的断点续传。

### 📥 快速开始
1.  **部署**：下载 ZIP 包上传至 `/wp-content/plugins/` 并启用。
2.  **准备数据**：从 [ip2region 官方](https://github.com/lionsoul2014/ip2region/tree/master/data) 下载 `ip2region.xdb`。
3.  **上传同步**：在「设置」页面底部，使用分片上传组件同步库文件。
4.  **环境建议**：为确保最佳性能，建议配置 PHP `memory_limit = 512M`。

### 🤝 鸣谢
本项目高性能解析引擎由 [ip2region](https://github.com/lionsoul2014/ip2region) 驱动。

[返回顶部](#sba-综合安全运维引擎-v217-️)

---

## 🇺🇸 English

**SBA (Site Behavior Auditor)** is a high-performance, all-in-one security suite custom-built for WordPress. Designed with a bank-grade architectural mindset, it integrates **Real-time Auditing, Three-layer Anti-Scraper Defense, iOS-style Login UI, and SMTP** into a single, memory-optimized engine.

### ✨ Key Features
- **🚀 Microsecond IP Resolution**: Powered by `ip2region xdb` in-memory lookup, resolving locations in 0.0x ms with zero database overhead.
- **📊 Atomic Counting Architecture**: Uses native MySQL atomic operations to handle millions of daily PV/UV counts without row-lock contention or data loss.
- **🛡️ Layered Anti-Scraper Shield**: 
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

## 📄 License
GPL v2 or later

---
**Developed by Stone** | *Architect-grade stability for WordPress systems.*

<div style="text-align: left;">
  <img src="https://github.com/user-attachments/assets/2ec59019-108d-4f61-a2a0-e1f0abf61cb8" alt="Site Behavior Auditor" width="45%">
</div>

<div style="text-align: left;">
  <img src="https://github.com/user-attachments/assets/b773d840-b64a-4e1e-807d-05e3707dec51" alt="访客轨迹" width="35%">
</div>
<div style="text-align: left;">
  <img src="https://github.com/user-attachments/assets/171bc999-e8d6-4978-870a-9760000478b1" alt="拦截日志" width="35%">
</div>

<div style="text-align: left;">
  <img src="https://github.com/user-attachments/assets/f15a3ed2-5896-4910-b98e-05bc863a0978" alt="防御设置" width="35%">
</div>

<table border="0" cellpadding="0" cellspacing="0" align="left">
  <tr>
    <td valign="top" width="130">
      <img src="https://github.com/user-attachments/assets/977d3c9c-6b45-4abd-9786-4f5c4b9d3685" width="130" style="display: block;">
    </td>
    <td valign="top" width="130">
      <img src="https://github.com/user-attachments/assets/be10d996-2585-4a5c-92c5-092869debb24" width="130" style="display: block;">
    </td>
    <td valign="top" width="130">
      <img src="https://github.com/user-attachments/assets/37c346f0-386b-477e-b789-c68b6f384c5b" width="130" style="display: block;">
    </td>
  </tr>
</table>
<br clear="all">

<div style="text-align: left;">
  <img src="https://github.com/user-attachments/assets/efcdb931-0517-459c-8e7b-d60099e09f15" alt="Site Behavior Auditor" width="35%">
</div>

