# 🛡️ SBA 综合安全套件 (Security Behavior Audit)

[![WordPress-5.0+](https://img.shields.io/badge/WordPress-5.0%2B-blue.svg?style=flat-square&logo=wordpress)](https://wordpress.org)
[![PHP-7.4+](https://img.shields.io/badge/PHP-7.4%2B-777BB4.svg?style=flat-square&logo=php)](https://www.php.net)
[![License-GPLv2-green](https://img.shields.io/badge/License-GPLv2-green.svg?style=flat-square)](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html)

**SBA 综合安全套件** 是一个集站点行为审计、iOS 风格登录面板、SMTP 邮件配置于一体的安全增强插件，专为中小型网站设计，提供易用的安全防护和用户体验优化。

---

## ✨ 功能特性

### 🔒 站点行为审计 (Security Audit)
* **信息泄露防护**：屏蔽 REST API 用户枚举接口，拦截 `?author=X` 及 `/author/` 作者存档页面访问，自动重定向至首页。
* **恶意路径扫描防护**：内置常见敏感路径拦截（如 `/.env`, `/.git`, `/xmlrpc.php` 等），支持通过后台追加自定义拦截路径。
* **自动化工具拦截**：自动识别并拦截 `sqlmap`, `curl`, `wget`, `python-requests` 等扫描工具 UA。
* **CC 攻击防护**：对非浏览器请求进行频率限制（支持后台配置每分钟请求阈值）。
* **Gate 钥匙机制**：必须通过 `wp-login.php?gate=钥匙` 访问才能进入登录页，生成一次性会话令牌，退出后令牌失效。
* **实时统计与日志**：
    * IP 归属地本地解析（支持 IPv4/IPv6，支持手动上传自定义 IP 段库）。
    * 可视化监控：UV/PV/在线人数/访客轨迹及拦截日志。
* **豁免机制**：支持用户名/IP 白名单，管理员登录后自动放行所有防御规则。

### 📱 iOS 风格登录简码
* **全 AJAX 无刷新**：通过简码 `[sba_login_box]` 调用，支持登录/注册/忘记密码无跳转操作。
* **安全策略**：
    * 登录失败 **3 次**后显示算术验证码，失败 **6 次**封禁 IP 24 小时。
    * 注册和忘记密码始终强制开启验证码校验，防止机器人滥用。
* **用户体验**：登录成功后自动显示用户头像、控制台链接、个人资料链接，注销后返回首页。

### 📧 SMTP 邮件配置
* **可视化配置**：支持设置 SMTP 主机、端口、加密方式（TLS/SSL）、认证、用户名及密码。
* **稳定投递**：自动覆盖 WordPress 默认邮件发送，确保注册激活、密码重置等邮件 100% 送达。
* **自测功能**：内置测试邮件发送模块，便于实时验证配置准确性。

---

## 📥 安装方法

1.  **下载插件**：从 [GitHub Releases](https://github.com/yourusername/security-suite/releases) 下载最新版 ZIP。
2.  **上传安装**：WP 后台 -> 插件 -> 安装插件 -> 上传 ZIP；或解压后上传至 `/wp-content/plugins/`。
3.  **启用配置**：
    * 进入“全行为审计” → “SMTP 邮件设置”填写服务器信息。
    * 在“防御设置”中调整白名单、CC 阈值、Gate 钥匙等参数。

---

## ⚙️ 配置说明

### 防御设置
| 选项 | 说明 |
| :--- | :--- |
| **用户名白名单** | 填入用户名，登录后自动豁免所有拦截（包括 CC、Gate、UA 等） |
| **IP 白名单** | 每行一个 IP，该范围内 IP 完全豁免 |
| **CC 封禁阈值** | 非浏览器请求每分钟最大请求数，超出则封禁（0 为关闭） |
| **Gate 钥匙** | 必填参数，必须通过 `wp-login.php?gate=钥匙` 生成会话 |
| **追加拦截路径** | 逗号分隔的自定义路径，与内置恶意路径合并拦截 |
| **拦截重定向 URL** | 拦截后跳转地址（留空则显示默认 403 页面） |

---

## 🎯 使用简码

* **登录面板**：在任意页面加入 `[sba_login_box]`。
* **访问统计卡片**：在侧边栏或页脚加入 `[sba_stats]`（显示在线人数、今日访客、累计浏览）。

---

## 🛠️ 技术栈与扩展

* **技术架构**：PHP 7.4+ / jQuery / Chart.js / PHPMailer / Session 管理。
* **代码扩展**：
    * **禁用新用户通知邮件**：
        ```php
        add_filter( 'wp_new_user_notification_email_admin', '__return_false' );
        ```

---

## 🐛 常见问题 (FAQ)

> **Q: 注册后收不到激活邮件？**
> A: 请在“SMTP 邮件设置”中发送测试邮件。QQ 等邮箱需使用“授权码”。

> **Q: 访问统计显示“未知”归属地？**
> A: 您可以在“防御设置”中按照 `起始IP|结束IP|地址` 格式上传自定义 IP 段库。

---
**License**: GPLv2 | **Repository**: [Link](https://github.com/yourusername/security-suite)
