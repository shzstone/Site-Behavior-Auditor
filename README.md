# SBA 综合安全引擎 (v2.0) 🛡️

[![Version](https://img.shields.io/badge/Version-2.0-brightgreen)](https://github.com/your-username/sba-security-suite)
[![PHP](https://img.shields.io/badge/PHP-7.4%2B-blue)](https://www.php.net/)
[![WordPress](https://img.shields.io/badge/WordPress-5.0%2B-brightgreen)](https://wordpress.org/)
[![License](https://img.shields.io/badge/License-GPL%20v2-orange)](https://www.gnu.org/licenses/old-licenses/gpl-2.0.html)

SBA (Site Behavior Auditor) 是一款专为 WordPress 深度定制的高性能综合安全套件。它集成了 **访客审计、iOS 风格登录面板、SMTP 发信** 三大核心功能。

> ⚡ **核心突破**：2.0 版本彻底抛弃传统数据库 IP 查询，改为 **全内存索引 (xdb) 查询**，单次解析耗时仅 **0.0x 毫秒**。配合**分片上传**技术，大体积 IP 库也能轻松部署。

---

## ⚙️ 服务器环境配置建议 (重要)

为了发挥全内存查询的极致性能，并确保 `.xdb` 库文件分片上传的稳定性，请务必根据以下建议调整服务器参数：

### 1. PHP 配置 (`php.ini`)
建议将以下参数统一设为 **512M**，以支撑大数据量处理：
```ini
upload_max_filesize = 512M
post_max_size = 512M
memory_limit = 512M
max_execution_time = 0
```

### 2. Nginx 配置 (`nginx.conf`)
若使用 Nginx，请在 `http` 或 `server` 段增加以下配置，防止上传大文件时出现 413 错误：
```nginx
client_max_body_size 512M;
```

---

## ✨ 核心特性

- **🔍 站点全行为审计**：实时记录轨迹，自动识别并阻断 `sqlmap`、`python` 等自动化扫描器。
- **🔐 iOS 风格登录盒**：精美的 AJAX 交互面板，内置基于 IP 的暴力破解防护与自动封禁。
- **📧 SMTP 邮件系统**：原生集成加密发信逻辑，完美闭环注册验证与密码重置。
- **⚡ 极致性能架构**：
    - **内存查询**：集成 `ip2region xdb` 内存版，查询速度提升百倍。
    - **去 Session 化**：采用 Transients API，完美兼容 Redis/Memcached 缓存。
    - **分片上传**：内置**动态分片 + 断点续传**，无视网络波动。

---

## 🛠️ 安装与部署

### 1. 插件安装
- 下载本项目 ZIP 包。
- 将文件夹 `sba-security-suite` 上传至 WP 插件目录 `/wp-content/plugins/`。
- 在后台启用 “综合安全套件”。

### 2. 获取并上传 IP 库 (必选)
- **下载 xdb**：前往 [ip2region 官方仓库](https://github.com/lionsoul2014/ip2region/tree/master/data) 下载 `ip2region.xdb`。
- **执行上传**：进入「工具」→「全行为审计」→「防御设置」，在页面底部通过分片上传组件上传该文件。
- **生效**：上传完成后页面自动刷新，审计系统的归属地功能即刻启用。

---

## 🚀 快速入门

1. **Gate 钥匙**：在设置中填写一个 Slug（如 `myadmin`）。此后您必须访问 `域名/wp-login.php?gate=myadmin` 才能看到登录框。
2. **SMTP 配置**：在「SMTP 邮件」中填写发信信息，建议使用专用授权码。
3. **前端调用**：
    - 使用简码 `[sba_login_box]` 调用登录面板。
    - 使用简码 `[sba_stats]` 展示实时访客统计。

---

## 📊 还原与维护
- **自动清理**：系统每日凌晨自动清理 30 天前的访问日志与 7 天前的拦截记录，确保数据库轻量化。
- **安全保护**：库文件存储于 `uploads/sba_ip_data/`，内置 `.htaccess` 严格禁止 Web 访问。

---

## 🤝 鸣谢

本项目的高性能 IP 解析能力得益于以下开源项目：
*   **[ip2region](https://github.com/lionsoul2014/ip2region)**：由 [lionsoul2014](https://github.com/lionsoul2014) 开发的高性能 IP 地址定位库。

---

## 📄 许可证
GPL v2 or later

---
**Developed by Stone** | 追求极致性能的 WordPress 运维实践。
