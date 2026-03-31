# SBA 综合安全引擎 (v2.0) 🛡️

[![Version](https://img.shields.io/badge/Version-2.0-brightgreen)](https://github.com/your-username/sba-security-suite)
[![PHP](https://img.shields.io/badge/PHP-7.4%2B-blue)](https://www.php.net/)
[![WordPress](https://img.shields.io/badge/WordPress-5.0%2B-brightgreen)](https://wordpress.org/)

SBA (Site Behavior Auditor) 是一款专为 WordPress 深度定制的高性能综合安全套件。它集成了 **访客审计、高颜值登录面板、SMTP 发信** 三大核心功能，并采用 **xdb 内存查询技术** 实现了微秒级的 IP 解析。

---

## 📥 获取 IP 数据库 (XDB)

由于 IP 库文件较大且更新频繁，插件不内置库文件，请前往官方仓库下载最新版：

1.  **下载地址**：[ip2region 官方数据目录](https://github.com/lionsoul2014/ip2region/tree/master/data)
2.  **所需文件**：
    *   `ip2region.xdb` (必选，用于 IPv4 解析)
    *   如果你有 IPv6 环境需求，请自行准备兼容的 IPv6 xdb 文件。
3.  **下载方式**：点击文件名后，点击右侧的 **Download** 按钮下载原始二进制文件。

---

## 🛠️ 安装与部署

### 1. 插件安装
- 将本插件文件夹 `sba-security-suite` 上传至 WordPress 站点的 `/wp-content/plugins/` 目录。
- 进入 WordPress 后台「插件」页面，点击 **启用** “综合安全套件”。

### 2. 初始化 IP 库 (核心步骤)
- 进入「工具」→「全行为审计」→「防御设置」。
- 滑动到页面底部的 **“IP 归属地库分片上传”** 区域。
- 分别选择你下载好的 `.xdb` 文件，点击 **上传**。
- **注意**：本插件支持分片上传与断点续传，大文件也能稳定传输。上传完成后页面会自动刷新，此时归属地解析功能正式生效。

### 3. 环境要求
- **PHP 版本**：7.4 或更高。
- **目录权限**：确保 `/wp-content/uploads/` 目录可写，插件会自动创建加密存储目录。
- **内存建议**：PHP `memory_limit` 建议设置为 128M 以上，以支持 xdb 全内存加载。

---

## 🚀 使用指南

### 1. 开启“Gate 钥匙”保护后台
- 在「防御设置」中填写 **“Gate 钥匙”**（例如：`open123`）。
- 保存后，默认的登录地址 `wp-login.php` 将被屏蔽。
- 您必须访问 `你的域名/wp-login.php?gate=open123` 才能开启登录入口。

### 2. 配置 SMTP 发信
- 在「SMTP 邮件」菜单中填写您的发信服务器信息。
- **重要**：建议使用邮箱服务商提供的“授权码”而非登录密码。
- 配置完成后，点击“发送测试邮件”确保链路通畅。

### 3. 前端调用 iOS 风格登录盒
- 在 WordPress 的 **页面、文章或侧边栏** 中插入简码：`[sba_login_box]`。
- 访客即可通过精美的 iOS 风格面板进行登录、注册或找回密码。注册用户将收到您配置的 SMTP 系统发出的激活邮件。

### 4. 实时监控审计
- 进入「全行为审计」主面板，您可以实时看到访客的 IP、归属地、访问路径和 PV 统计。
- 系统会自动根据 UA 特征拦截扫描器，您可以在底部的“拦截日志”中查看防御记录。

---

## ✨ v2.0 技术亮点

-   **⚡ 内存级加速**：集成 `ip2region xdb` 内存查询，单次解析仅需 **0.0x 毫秒**，完全不占数据库资源。
-   **🛡️ 去 Session 化**：彻底抛弃 `session_start()`，采用 WP Transient API，完美支持开启了 Redis/Memcached 缓存的服务器。
-   **🔄 原子级防御**：CC 频率统计在内存中完成，在高并发攻击下依然能保持站点响应。
-   **🧹 自动瘦身**：每日凌晨自动清理陈旧审计日志，防止数据库表冗余。

---

## 📋 简码参考表

| 简码 | 功能 | 放置建议 |
| :--- | :--- | :--- |
| `[sba_login_box]` | iOS 风格登录/注册/重置面板 | 独立登录页、会员中心 |
| `[sba_stats]` | 显示当前在线人数/访客统计 | 侧边栏小工具、页脚 |

---

## 🤝 鸣谢

本项目的高性能解析功能由以下开源项目驱动：

*   **[ip2region](https://github.com/lionsoul2014/ip2region)**：由 [lionsoul2014](https://github.com/lionsoul2014) 开发的高性能 IP 定位库。

---

## 📄 许可证
GPL v2 or later

---
**Developed by Stone** | 追求极致性能的 WordPress 运维实践。
