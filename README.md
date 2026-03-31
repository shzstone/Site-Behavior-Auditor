# SBA 综合安全引擎 (v2.0) 🛡️

[![Version](https://img.shields.io/badge/Version-2.0-brightgreen)](https://github.com/your-username/sba-security-suite)
[![PHP](https://img.shields.io/badge/PHP-7.4%2B-blue)](https://www.php.net/)
[![WordPress](https://img.shields.io/badge/WordPress-5.0%2B-brightgreen)](https://wordpress.org/)

SBA (Site Behavior Auditor) 是一款为 WordPress 深度定制的高性能综合安全套件。它不仅是一个防火墙，更是一个集成了 **访客审计、iOS 风格登录交互、SMTP 发信** 的全能运维中心。

> ⚡ **核心突破**：2.0 版本彻底摒弃了传统的数据库查询 IP 逻辑，改为 **全内存索引 (xdb)** 查询，单次解析耗时仅 **0.0x 毫秒**。

---

## ✨ 核心模块

### 1. 🔍 站点行为审计 (Auditor)
- **实时轨迹**：精确记录访客 IP、路径、PV 统计及归属地。
- **可视化看板**：内置 Chart.js 绘制的 30 天访问趋势图。
- **智能拦截**：自动识别并阻断 `sqlmap`、`nmap`、`python-requests` 等自动化扫描工具。
- **恶意路径防护**：内置针对 `.env`、`.git`、`xmlrpc.php` 等敏感路径的实时阻断。

### 2. 🔐 iOS 风格登录盒 (Login Box)
- **极简美学**：精心设计的 iOS 风格 AJAX 登录/注册/忘记密码面板。
- **暴力破解防护**：基于 IP 的错误频率限制，支持自动封禁恶意 IP 24 小时。
- **去 Session 化**：采用 WordPress Transient API 存储令牌，完美兼容开启 Redis 缓存的服务器。
- **Gate 钥匙保护**：支持隐藏后端登录地址，仅限持有“钥匙”的 URL 访问。

### 3. 📧 SMTP 邮件系统
- **原生集成**：无需安装第三方臃肿的 SMTP 插件。
- **发信稳定**：支持主流服务商（Gmail, 阿里云, 腾讯云等）的 TLS/SSL 加密发信。
- **业务闭环**：配合登录盒，实现新用户注册验证与重置密码功能。

---

## 🚀 技术亮点 (v2.0)

- **内存级查询**：集成高性能 IP 定位库，11MB 库文件全量加载至内存，查询效率提升 100 倍。
- **分片上传技术**：针对大体积 `.xdb` 库文件，内置**动态分片上传 + 断点续传**机制。
- **零数据库负载**：CC 频率统计与网关令牌均在内存（Transient）中完成计算，不再频繁读写 SQL。
- **自动数据脱水**：每日定时清理陈旧日志，确保数据库始终轻盈。

---

## 🛠️ 安装与配置

1. **上传插件**：将 `sba-security-suite` 文件夹上传至 `/wp-content/plugins/`。
2. **启用插件**：在后台启用“综合安全套件”。
3. **初始化 IP 库**：
   - 进入「工具」→「全行为审计」→「防御设置」。
   - 在页面底部，通过分片上传组件上传最新的 `ip2region_v4.xdb` 文件（及可选的 v6 库）。
4. **启用 SMTP**：在设置页面填写发信账户，建议使用专用授权码。

---

## 📋 简码说明

| 简码 | 功能说明 |
| :--- | :--- |
| `[sba_login_box]` | 在前端页面任何位置调用 iOS 风格登录盒。 |
| `[sba_stats]` | 在侧边栏或页脚显示实时在线人数及访问统计。 |

---

## 🤝 鸣谢与技术支持 (Acknowledgments)

本项目的高性能 IP 解析功能离不开以下优秀的开源项目支持：

*   **[ip2region](https://github.com/lionsoul2014/ip2region)**：由 [lionsoul2014](https://github.com/lionsoul2014) 开发的高性能 IP 地址定位库。本项目集成了其最新的 **xdb 内存查询方案**。在此对其提供的精准数据与高效算法表示衷心的感谢！

---

## 🔒 运维建议

- **Gate 钥匙**：启用后，您的登录地址将变为 `wp-login.php?gate=您的钥匙`。
- **日志监控**：审计系统会自动保留 7 天内的拦截记录，便于复盘分析攻击源。
- **环境要求**：建议 PHP 7.4+，MySQL 5.7+，服务器剩余空间 > 50MB。

---

## 📄 许可证
GPL v2 or later

---
**Developed by Stone** | 追求极致性能的 WordPress 运维实践。
