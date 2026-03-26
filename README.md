# 🛡️ SBA 综合安全套件 (Site Behavior Auditor)

[![WordPress-5.0+](https://img.shields.io/badge/WordPress-5.0%2B-blue.svg?style=flat-square&logo=wordpress)](https://wordpress.org)
[![PHP-7.4+](https://img.shields.io/badge/PHP-7.4%2B-777BB4.svg?style=flat-square&logo=php)](https://www.php.net)
[![License-GPLv2-green](https://img.shields.io/badge/License-GPLv2-green.svg?style=flat-square)](https://github.com/guoshh1978/Site-Behavior-Auditor/blob/main/LICENSE)

**SBA 综合安全套件** 是一个集站点行为审计、iOS 风格登录面板、SMTP 邮件配置于一体的安全增强插件，专为中小型网站设计，提供易用的安全防护和用户体验优化。

---

## ✨ 功能特性

### 🔒 站点行为审计 (Security Audit)
* **信息泄露防护**：屏蔽 REST API 用户枚举接口，拦截 `?author=X` 及 `/author/` 作者存档页面访问，自动重定向至首页。
* **恶意路径扫描防护**：内置常见敏感路径拦截（如 `/.env`, `/.git`, `/xmlrpc.php` 等），支持通过后台追加自定义拦截路径。
* **自动化工具拦截**：自动识别并拦截 `sqlmap`, `curl`, `wget`, `python-requests` 等扫描工具 UA。
* **CC 攻击防护**：对非浏览器请求进行频率限制（支持后台配置每分钟请求阈值）。
* **Gate 钥匙机制**：必须通过 `wp-login.php?gate=钥匙` 访问才能进入登录页，生成一次性会话令牌，退出后令牌失效。
* **实时统计与日志**：支持 IPv4/IPv6 归属地本地解析，提供可视化监控（UV/PV/在线人数/访客轨迹及拦截日志）。

### 📱 iOS 风格登录面板 (AJAX)
* **无刷新交互**：通过简码 `[sba_login_box]` 调用，实现登录/注册/忘记密码全流程 AJAX 操作。
* **注册验证机制**：**强制开启邮件地址验证**。新用户注册后需在 **24 小时内** 点击邮件中的验证链接才能激活账号并注册成功，有效杜绝垃圾注册。
* **暴力破解防护**：
    * 登录失败 **3 次**后显示算术验证码。
    * 连续失败 **6 次**封禁 IP 24 小时。
    * 注册与找回密码流程强制开启验证码校验。

### 📧 SMTP 邮件配置
* **可视化配置**：支持设置 SMTP 主机、端口、加密方式（TLS/SSL）、认证、用户名及密码。
* **稳定投递**：自动覆盖 WordPress 默认邮件发送，确保注册激活、密码重置等邮件 100% 送达。

---

## 📥 安装方法

1.  **下载插件**：从 [Releases](https://github.com/guoshh1978/Site-Behavior-Auditor/releases) 下载最新版 ZIP。
2.  **上传安装**：WP 后台 -> 插件 -> 安装插件 -> 上传 ZIP；或解压后上传至 `/wp-content/plugins/`。
3.  **配置**：进入“全行为审计”菜单，优先完成 **SMTP 邮件设置**（注册验证依赖此项）。

---

## ⚙️ 配置说明

### 防御设置
| 选项 | 说明 |
| :--- | :--- |
| **用户名白名单** | 填入用户名，登录后自动豁免所有拦截 |
| **IP 白名单** | 每行一个 IP，该范围内 IP 完全豁免 |
| **CC 封禁阈值** | 非浏览器请求每分钟最大请求数，超出则封禁 |
| **Gate 钥匙** | 必填参数，必须通过 `wp-login.php?gate=钥匙` 生成会话 |
| **追加拦截路径** | 逗号分隔的自定义路径，与内置恶意路径合并拦截 |

---

## 🎯 使用简码

* **登录面板**：在任意页面加入 `[sba_login_box]`。
* **访问统计卡片**：在侧边栏或页脚加入 `[sba_stats]`。

---

## 🐛 常见问题 (FAQ)

> **Q: 为什么新用户注册后无法直接登录？**
> A: 插件启用了严格的邮件验证机制。用户必须在收到邮件后的 **24 小时内** 点击验证链接完成激活，否则注册流程不会完成。

> **Q: 设置 Gate 钥匙后进不去后台怎么办？**
> A: 请访问 `你的域名/wp-login.php?gate=你的钥匙`。若忘记钥匙，请在数据库 `wp_options` 表中修改 `sba_settings` 字段。

---
**License**: [GPLv2](https://github.com/guoshh1978/Site-Behavior-Auditor/blob/main/LICENSE) | **GitHub**: [guoshh1978/Site-Behavior-Auditor](https://github.com/guoshh1978/Site-Behavior-Auditor)
