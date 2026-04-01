# SBA 综合安全运维引擎 (v2.1.6) 🛡️

[![Version](https://img.shields.io/badge/Version-2.1.6-brightgreen)](https://github.com/your-username/sba-security-suite)
[![PHP](https://img.shields.io/badge/PHP-7.4%2B-blue)](https://www.php.net/)
[![WordPress](https://img.shields.io/badge/WordPress-5.0%2B-brightgreen)](https://wordpress.org/)
[![License](https://img.shields.io/badge/License-GPL%20v2-orange)](https://www.gnu.org/licenses/old-licenses/gpl-2.0.html)

**SBA (Site Behavior Auditor)** 是一款专为 WordPress 深度定制的高性能综合安全套件。它不是简单的功能堆砌，而是将 **全行为审计、主动爬虫防御、iOS 风格登录交互、SMTP 发信** 四大核心运维模块通过“全内存架构”完美融合。

> ⚡ **开发初衷**：解决市面安全插件臃肿、消耗数据库资源、无法有效拦截高级伪装采集器的痛点。本套件追求：**极致性能、静默防御、业务闭环**。

<div style="text-align: left;">
  <img src="https://github.com/user-attachments/assets/2ec59019-108d-4f61-a2a0-e1f0abf61cb8" alt="Site Behavior Auditor" width="45%">
</div>


---

## ✨ 核心模块能力

### 1. 🔍 站点行为审计 (Auditor)
*   **实时轨迹**：毫秒级记录访客 IP、路径、归属地及 PV 状态，支持 30 天可视化趋势图。
*   **本地解析**：集成 `ip2region xdb` 内存版。单次解析耗时仅 **0.0x 毫秒**，完全不请求外部接口，不占 SQL 资源。
*   **自动化清理**：系统每日自动“脱水”，清理陈旧日志，确保数据库始终轻盈。
<div style="text-align: left;">
  <img src="https://github.com/user-attachments/assets/b773d840-b64a-4e1e-807d-05e3707dec51" alt="访客轨迹" width="35%">
</div>
<div style="text-align: left;">
  <img src="https://github.com/user-attachments/assets/171bc999-e8d6-4978-870a-9760000478b1" alt="拦截日志" width="35%">
</div>

### 2. 🚫 三层主动防御系统 (Bot Shield)
*   **阶梯限流 (Tiered Rate Limit)**：针对 `feed`、`rest_route`、`?m=` 等高频采集路径执行更严苛的 CC 限制（默认阈值的 1/3）。
*   **Cookie 身份校验**：自动识别真实浏览器指纹，对无法维持会话的恶意采集脚本进行强力降速。
*   **诱饵陷阱 (Honeypot)**：页面底部自动布设动态隐藏诱饵，脚本一旦触碰即刻触发“死路”，封禁该 IP。
<div style="text-align: left;">
  <img src="https://github.com/user-attachments/assets/f15a3ed2-5896-4910-b98e-05bc863a0978" alt="防御设置" width="35%">
</div>


### 3. 🔐 iOS 风格登录盒 (Login Box)
*   **极简美学**：全 AJAX 驱动的 iOS 风格登录/注册/重置密码面板。
*   **去 Session 化**：彻底抛弃 `session_start()`，采用 WP Transient API，完美兼容 Redis/Memcached 环境，用户登录永不掉线。
*   **Gate 钥匙保护**：支持隐藏后端登录地址，只有持有特定“钥匙”的 URL 才能开启入口。

<table border="0" cellpadding="0" cellspacing="0" align="left">
  <tr>
    <td valign="top" width="100">
      <img src="https://github.com/user-attachments/assets/977d3c9c-6b45-4abd-9786-4f5c4b9d3685" width="100" style="display: block;">
    </td>
    <td valign="top" width="100">
      <img src="https://github.com/user-attachments/assets/be10d996-2585-4a5c-92c5-092869debb24" width="100" style="display: block;">
    </td>
    <td valign="top" width="100">
      <img src="https://github.com/user-attachments/assets/37c346f0-386b-477e-b789-c68b6f384c5b" width="100" style="display: block;">
    </td>
  </tr>
</table>
<br clear="all">




### 4. 📧 SMTP 发信系统
*   **原生集成**：内置轻量级发信逻辑，支持 TLS/SSL 加密，完美闭环注册激活与密码找回流程。
<div style="text-align: left;">
  <img src="https://github.com/user-attachments/assets/efcdb931-0517-459c-8e7b-d60099e09f15" alt="Site Behavior Auditor" width="35%">
</div>


---

## ⚙️ 推荐服务器配置

为确保分片上传及全内存索引的高效运行，建议调整以下参数：

**PHP (`php.ini`)**:
```ini
upload_max_filesize = 512M
post_max_size = 512M
memory_limit = 512M
max_execution_time = 0
```
*注：Nginx 用户请设置 `client_max_body_size 512M;`*

---

## 🛠️ 安装与部署

### 1. 获取插件
- 下载本项目 ZIP 包，上传至 WordPress 插件目录 `/wp-content/plugins/` 并启用。

### 2. 准备 IP 库文件 (核心步骤)
- 前往 [ip2region 官方数据目录](https://github.com/lionsoul2014/ip2region/tree/master/data) 下载最新的 `ip2region.xdb`。
- 进入「工具」→「全行为审计」→「防御设置」，在页面底部上传该文件。
- **技术特色**：支持**动态分片上传 + 断点续传**，即便在弱网环境下也能轻松完成 11MB+ 的库文件同步。

### 3. 配置 Gate 钥匙
- 在设置中填写一个独特的 Slug（如 `myadmin`）。
- 您必须访问 `你的域名/wp-login.php?gate=myadmin` 才能开启登录入口。

---

## 📋 简码参考 (Shortcodes)

| 简码 | 功能 | 建议位置 |
| :--- | :--- | :--- |
| `[sba_login_box]` | 弹出/嵌入式 iOS 风格登录面板 | 自定义登录页、会员中心 |
| `[sba_stats]` | 实时在线人数与访客统计统计 | 侧边栏 Widget、页脚区域 |

---

## 🤝 鸣谢与支持

本项目的高性能解析引擎离不开以下开源项目的支持：

*   **[ip2region](https://github.com/lionsoul2014/ip2region)**：由 [lionsoul2014](https://github.com/lionsoul2014) 开发的高性能 IP 地址定位库。本项目集成了其最新的 **xdb 内存查询方案**。

---

## 📄 许可证
GPL v2 or later

---
**Developed by Stone** | 追求极致性能的 WordPress 运维实践。
