<?php
/**
 * Plugin Name: 综合安全套件 (Site Behavior Auditor + Login Box + SMTP)
 * Description: 集成站点全行为审计、iOS风格登录/注册/忘记密码面板（简码: sba_login_box）和SMTP邮件配置。
 * Version: 1.0
 * Author: Stone
 */

if ( ! defined( 'ABSPATH' ) ) exit;

/* ================= 会话初始化 ================= */
add_action( 'init', function() {
    if ( session_status() === PHP_SESSION_NONE && ! is_admin() ) {
        ini_set( 'session.gc_maxlifetime', 1800 );
        session_set_cookie_params( 1800 );
        session_start();
    }
}, 1 );

/* ================= 数据库表创建 ================= */
register_activation_hook( __FILE__, 'sba_combined_activate' );
function sba_combined_activate() {
    global $wpdb;
    $charset_collate = $wpdb->get_charset_collate();

    // 审计统计表
    $sql[] = "CREATE TABLE IF NOT EXISTS {$wpdb->prefix}dis_stats (
        id BIGINT AUTO_INCREMENT PRIMARY KEY,
        ip VARCHAR(45),
        url TEXT,
        visit_date DATE,
        visit_hour TINYINT,
        pv INT DEFAULT 1,
        last_visit TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE KEY ip_date_url (ip, visit_date, url(191)),
        INDEX idx_lookup (visit_date, last_visit DESC)
    ) $charset_collate;";

    // IP 归属地库表
    $sql[] = "CREATE TABLE IF NOT EXISTS {$wpdb->prefix}sba_ip_data (
        id int(11) NOT NULL AUTO_INCREMENT,
        ip_type tinyint(1) DEFAULT 4,
        start_bin varbinary(16) NOT NULL,
        end_bin varbinary(16) NOT NULL,
        addr varchar(255) NOT NULL,
        PRIMARY KEY (id),
        KEY range_idx (ip_type, start_bin, end_bin)
    ) $charset_collate;";

    // 拦截日志表
    $sql[] = "CREATE TABLE IF NOT EXISTS {$wpdb->prefix}sba_blocked_log (
        id BIGINT AUTO_INCREMENT PRIMARY KEY,
        ip VARCHAR(45),
        reason VARCHAR(100),
        target_url TEXT,
        block_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    ) $charset_collate;";

    // 登录失败记录表
    $sql[] = "CREATE TABLE IF NOT EXISTS {$wpdb->prefix}sba_login_failures (
        id bigint(20) NOT NULL AUTO_INCREMENT,
        ip varchar(45) NOT NULL,
        failed_count int(11) DEFAULT 0,
        last_failed_time datetime DEFAULT NULL,
        banned_until datetime DEFAULT NULL,
        request_count int(11) DEFAULT 0,
        last_request_time datetime DEFAULT NULL,
        PRIMARY KEY (id),
        UNIQUE KEY ip (ip)
    ) $charset_collate;";

    require_once ABSPATH . 'wp-admin/includes/upgrade.php';
    foreach ( $sql as $s ) {
        dbDelta( $s );
    }
}

/* ================= 通用工具函数 ================= */
function sba_combined_get_ip() {
    $ip = $_SERVER['HTTP_CF_CONNECTING_IP'] ?? $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'];
    return filter_var( trim( explode( ',', $ip )[0] ), FILTER_VALIDATE_IP ) ?: '0.0.0.0';
}

/* ================= 站点行为审计模块 ================= */
function sba_audit_get_opt( $k, $d = '' ) {
    $o = get_option( 'sba_settings' );
    return ( isset( $o[ $k ] ) && $o[ $k ] !== '' ) ? $o[ $k ] : $d;
}

function sba_audit_execute_block( $reason ) {
    if ( get_current_user_id() === 1 ) return;

    $u_white = array_filter( array_map( 'trim', explode( ',', sba_audit_get_opt( 'user_whitelist', '' ) ) ) );
    $user = wp_get_current_user();
    if ( $user->exists() && in_array( $user->user_login, $u_white ) ) return;

    $ip = sba_combined_get_ip();
    $ip_white = array_filter( array_map( 'trim', explode( ',', sba_audit_get_opt( 'ip_whitelist', '' ) ) ) );
    if ( in_array( $ip, $ip_white ) || current_user_can( 'manage_options' ) ) return;

    global $wpdb;
    $wpdb->insert( $wpdb->prefix . 'sba_blocked_log', [
        'ip'         => $ip,
        'reason'     => $reason,
        'target_url' => $_SERVER['REQUEST_URI']
    ] );

    $target = sba_audit_get_opt( 'block_target_url', '' );
    if ( ! empty( $target ) && filter_var( $target, FILTER_VALIDATE_URL ) ) {
        wp_redirect( $target );
        exit;
    }
    wp_die( "🛡️ SBA 系统拦截：$reason", "Security Block", 403 );
}

// 屏蔽 REST API 用户枚举
add_filter( 'rest_endpoints', function( $endpoints ) {
    if ( isset( $endpoints['/wp/v2/users'] ) ) unset( $endpoints['/wp/v2/users'] );
    if ( isset( $endpoints['/wp/v2/users/(?P<id>[\d]+)'] ) ) unset( $endpoints['/wp/v2/users/(?P<id>[\d]+)'] );
    return $endpoints;
} );

// 主拦截逻辑
add_action( 'init', function() {
    if ( is_admin() ) return;

    // 跳过注销请求
    if ( isset( $_GET['action'] ) && $_GET['action'] === 'logout' ) {
        return;
    }

    // 跳过登录简码的 AJAX 请求
    if ( defined( 'DOING_AJAX' ) && DOING_AJAX && isset( $_POST['action'] ) && strpos( $_POST['action'], 'sba_ios_' ) === 0 ) {
        return;
    }

    $ip = sba_combined_get_ip();
    $uri = strtolower( $_SERVER['REQUEST_URI'] );
    $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';

    $current_action = $_REQUEST['action'] ?? '';
    $is_login_page = ( strpos( $uri, 'wp-login.php' ) !== false );
    $is_signup_page = ( strpos( $uri, 'wp-signup.php' ) !== false );
    $allowed_actions = [ 'register', 'lostpassword', 'retrievepassword', 'rp', 'resetpass', 'postpass', 'checkemail' ];

    if ( ( $is_login_page || $is_signup_page ) && in_array( $current_action, $allowed_actions ) ) {
        return;
    }

    // 自动化工具 UA 拦截
    $scan_tools = [ 'sqlmap', 'nmap', 'dirbuster', 'nikto', 'zgrab', 'python-requests', 'go-http-client', 'java/', 'curl/', 'wget', 'masscan' ];
    foreach ( $scan_tools as $tool ) {
        if ( stripos( $ua, $tool ) !== false ) sba_audit_execute_block( "自动化扫描器: $tool" );
    }

    // 作者枚举拦截
    if ( isset( $_GET['author'] ) || strpos( $uri, 'author=' ) !== false ) {
        sba_audit_execute_block( "作者枚举探测 (?author=X)" );
    }

    // 恶意路径拦截
    $fixed_evil = [ '/.env', '/.git', '/.sql', '/.ssh', '/wp-config.php.bak', '/phpinfo.php', '/config.php.swp', '/.vscode', '/xmlrpc.php' ];
    $custom_evil = array_filter( array_map( 'trim', explode( ',', sba_audit_get_opt( 'evil_paths', '' ) ) ) );
    $all_evil = array_unique( array_merge( $fixed_evil, $custom_evil ) );
    foreach ( $all_evil as $path ) {
        if ( ! empty( $path ) && strpos( $uri, $path ) !== false ) sba_audit_execute_block( "非法路径探测: $path" );
    }

    // Gate 钥匙（支持 URL 一次性入口 + 会话令牌）
    $stored_slug = sba_audit_get_opt( 'login_slug', '' );
    if ( ! empty( $stored_slug ) && $is_login_page && empty( $current_action ) ) {
        // 1. 检查 URL 中的 gate 参数（一次性入口）
        if ( isset( $_GET['gate'] ) && ! empty( $_GET['gate'] ) ) {
            $provided_gate = $_GET['gate'];
            $salt_fixed = defined( 'NONCE_SALT' ) ? NONCE_SALT : 'sba_fallback_salt';
            $expected_token_fixed = hash_hmac( 'sha256', $stored_slug, $salt_fixed );
            $provided_token_fixed = hash_hmac( 'sha256', $provided_gate, $salt_fixed );

            if ( hash_equals( $expected_token_fixed, $provided_token_fixed ) ) {
                if ( ! isset( $_SESSION['sba_gate_salt'] ) ) {
                    $_SESSION['sba_gate_salt'] = wp_generate_password( 20, false );
                }
                $redirect_url = remove_query_arg( 'gate' );
                wp_redirect( $redirect_url );
                exit;
            } else {
                sba_audit_execute_block( "Gate 钥匙错误或已失效" );
            }
        }

        // 2. 页面加载时检查会话令牌是否存在
        if ( $_SERVER['REQUEST_METHOD'] !== 'POST' ) {
            if ( ! isset( $_SESSION['sba_gate_salt'] ) ) {
                sba_audit_execute_block( "Gate 钥匙错误或已失效" );
            }
            return;
        }

        // 3. POST 请求验证隐藏字段
        if ( ! isset( $_SESSION['sba_gate_salt'] ) ) {
            $_SESSION['sba_gate_salt'] = wp_generate_password( 20, false );
        }
        $salt = $_SESSION['sba_gate_salt'];
        $expected_token = hash_hmac( 'sha256', $stored_slug, $salt );
        $provided_token = $_POST['sba_gate_token'] ?? '';
        if ( ! hash_equals( $expected_token, $provided_token ) ) {
            sba_audit_execute_block( "Gate 钥匙错误或已失效" );
        }
    }

	// CC 频率限制（仅对非浏览器且未登录的请求进行限制）
	$limit = (int) sba_audit_get_opt( 'auto_block_limit', 0 );
	if ( $limit > 0 ) {
		if ( is_user_logged_in() ) {
		} else {
			$ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
			$is_browser = preg_match( '/Mozilla\/|Chrome\/|Firefox\/|Safari\/|Edge\/|Opera\/|MSIE/', $ua );
			if ( ! $is_browser ) {
				global $wpdb;
				$count = $wpdb->get_var( $wpdb->prepare(
					"SELECT SUM(pv) FROM {$wpdb->prefix}dis_stats WHERE ip = %s AND last_visit > DATE_SUB(NOW(), INTERVAL 1 MINUTE)",
					$ip
				) );
				if ( $count > $limit ) {
					sba_audit_execute_block( "频率超限 (CC风险)" );
				}
			}
		}
	}

    // 写入访问统计
    global $wpdb;
    $local_time = current_time( 'mysql' );
    $local_date = substr( $local_time, 0, 10 );
    $local_hour = (int) substr( $local_time, 11, 2 );
    $wpdb->query( $wpdb->prepare(
        "INSERT INTO {$wpdb->prefix}dis_stats (ip, url, visit_date, visit_hour, pv, last_visit)
         VALUES (%s, %s, %s, %d, 1, %s)
         ON DUPLICATE KEY UPDATE pv = pv + 1, last_visit = %s",
        $ip, $_SERVER['REQUEST_URI'], $local_date, $local_hour, $local_time, $local_time
    ) );
} );

// 强制重定向作者存档页面
add_action( 'template_redirect', function() {
    if ( is_author() || isset( $_GET['author'] ) ) {
        wp_redirect( home_url(), 301 );
        exit;
    }
} );

// 登录表单注入隐藏令牌
add_action( 'login_form', function() {
    $stored_slug = sba_audit_get_opt( 'login_slug', '' );
    if ( ! empty( $stored_slug ) && isset( $_SESSION['sba_gate_salt'] ) ) {
        $salt = $_SESSION['sba_gate_salt'];
        $token = hash_hmac( 'sha256', $stored_slug, $salt );
        echo '<input type="hidden" name="sba_gate_token" value="' . esc_attr( $token ) . '" />';
    }
} );

// 登录/退出时销毁会话令牌
add_action( 'wp_login', function() {
    if ( isset( $_SESSION['sba_gate_salt'] ) ) unset( $_SESSION['sba_gate_salt'] );
} );
add_action( 'wp_logout', function() {
    if ( isset( $_SESSION['sba_gate_salt'] ) ) unset( $_SESSION['sba_gate_salt'] );
} );

// AJAX 归属地解析
add_action( 'wp_ajax_sba_get_geo', 'sba_audit_ajax_geo' );
function sba_audit_ajax_geo() {
    global $wpdb;
    $ips = (array) $_POST['ips'];
    $cache = get_option( 'sba_geo_v1', [] );
    $results = [];
    foreach ( $ips as $ip ) {
        if ( isset( $cache[ $ip ] ) ) {
            $results[ $ip ] = $cache[ $ip ];
            continue;
        }
        $loc = '';
        $ip_bin = @inet_pton( $ip );
        if ( $ip_bin ) {
            $type = ( strpos( $ip, ':' ) !== false ) ? 6 : 4;
            $loc = $wpdb->get_var( $wpdb->prepare(
                "SELECT addr FROM {$wpdb->prefix}sba_ip_data WHERE ip_type = %d AND %s BETWEEN start_bin AND end_bin LIMIT 1",
                $type, $ip_bin
            ) );
        }
        if ( ! $loc ) {
            $res = wp_remote_get( "https://whois.pconline.com.cn/ipJson.jsp?ip=$ip&json=true", [ 'timeout' => 2 ] );
            if ( ! is_wp_error( $res ) ) {
                $d = json_decode( mb_convert_encoding( wp_remote_retrieve_body( $res ), 'UTF-8', 'GBK' ), true );
                $loc = $d['addr'] ?? '';
            }
        }
        $final = ( $loc ?: "未知" );
        $results[ $ip ] = $final;
        $cache[ $ip ] = $final;
    }
    update_option( 'sba_geo_v1', $cache, false );
    wp_send_json_success( $results );
}

// AJAX 加载访客轨迹
add_action( 'wp_ajax_sba_load_tracks', 'sba_audit_ajax_tracks' );
function sba_audit_ajax_tracks() {
    global $wpdb;
    $p = intval( $_POST['page'] ?? 1 );
    $per = 50;
    $off = ( $p - 1 ) * $per;
    $latest_date = $wpdb->get_var( "SELECT MAX(visit_date) FROM {$wpdb->prefix}dis_stats" );
    if ( ! $latest_date ) $latest_date = current_time( 'Y-m-d' );
    $total = $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$wpdb->prefix}dis_stats WHERE visit_date = %s", $latest_date ) );
    $pages = ceil( $total / $per );
    $rows = $wpdb->get_results( $wpdb->prepare(
        "SELECT ip, url, pv, last_visit FROM {$wpdb->prefix}dis_stats WHERE visit_date = %s ORDER BY last_visit DESC LIMIT %d, %d",
        $latest_date, $off, $per
    ) );
    $html = "";
    if ( $rows ) {
        foreach ( $rows as $r ) {
            $html .= "<tr>
                <td>" . date( 'H:i', strtotime( $r->last_visit ) ) . "</td>
                <td><code>{$r->ip}</code></td>
                <td><small class='geo-tag' data-ip='{$r->ip}'>解析中...</small></td>
                <td><div class='sba-cell-wrap'><small>" . esc_html( $r->url ) . "</small></div></td>
                <td><b>{$r->pv}</b></td>
            </tr>";
        }
    }
    wp_send_json_success( [ 'html' => $html, 'pages' => $pages, 'total' => $total, 'date' => $latest_date ] );
}

/* ================= iOS 风格登录简码模块 ================= */
function sba_ios_check_rate_limit( $ip, $limit = 10 ) {
    global $wpdb;
    $table = $wpdb->prefix . 'sba_login_failures';
    $row = $wpdb->get_row( $wpdb->prepare( "SELECT request_count, last_request_time FROM $table WHERE ip = %s", $ip ) );
    $now = current_time( 'mysql' );
    $now_ts = strtotime( $now );
    if ( ! $row ) {
        $wpdb->insert( $table, [ 'ip' => $ip, 'request_count' => 1, 'last_request_time' => $now ] );
        return true;
    }
    $last_ts = strtotime( $row->last_request_time );
    $diff_hours = ( $now_ts - $last_ts ) / 3600;
    if ( $diff_hours >= 1 ) {
        $wpdb->update( $table, [ 'request_count' => 1, 'last_request_time' => $now ], [ 'ip' => $ip ] );
        return true;
    } else {
        $new_count = $row->request_count + 1;
        $wpdb->update( $table, [ 'request_count' => $new_count, 'last_request_time' => $now ], [ 'ip' => $ip ] );
        return $new_count <= $limit;
    }
}

function sba_ios_record_failure( $ip, $success = false ) {
    global $wpdb;
    $table = $wpdb->prefix . 'sba_login_failures';
    $row = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM $table WHERE ip = %s", $ip ) );
    $now = current_time( 'mysql' );
    if ( $success ) {
        if ( $row ) $wpdb->delete( $table, [ 'ip' => $ip ] );
        return;
    }
    if ( ! $row ) {
        $wpdb->insert( $table, [
            'ip'               => $ip,
            'failed_count'     => 1,
            'last_failed_time' => $now,
            'banned_until'     => null,
            'request_count'    => 1,
            'last_request_time'=> $now,
        ] );
        return 1;
    }
    if ( $row->banned_until && strtotime( $row->banned_until ) > strtotime( $now ) ) {
        return 'banned';
    }
    $new_count = $row->failed_count + 1;
    $banned_until = null;
    if ( $new_count >= 6 ) {
        $banned_until = date( 'Y-m-d H:i:s', strtotime( $now . ' +24 hours' ) );
        $admin_email = get_option( 'admin_email' );
        if ( $admin_email ) {
            wp_mail( $admin_email, '【安全提醒】IP被封禁', "IP: $ip\n失败次数: $new_count\n封禁至: $banned_until" );
        }
    }
    $wpdb->update( $table, [
        'failed_count'     => $new_count,
        'last_failed_time' => $now,
        'banned_until'     => $banned_until,
    ], [ 'ip' => $ip ] );
    return $new_count;
}

function sba_ios_check_ban_and_captcha( $ip, $action = '' ) {
    global $wpdb;
    $row = $wpdb->get_row( $wpdb->prepare( "SELECT failed_count, banned_until FROM {$wpdb->prefix}sba_login_failures WHERE ip = %s", $ip ) );
    if ( ! $row ) return [ 'banned' => false, 'need_captcha' => false ];
    if ( $row->banned_until && strtotime( $row->banned_until ) > time() ) return [ 'banned' => true, 'need_captcha' => false ];

    $need_captcha = ( $row->failed_count >= 3 && $row->failed_count < 6 );
    if ( in_array( $action, [ 'register', 'forgot' ] ) ) {
        $need_captcha = true;
    }
    return [ 'banned' => false, 'need_captcha' => $need_captcha ];
}

add_action( 'wp_enqueue_scripts', 'sba_ios_register_scripts' );
function sba_ios_register_scripts() {
    wp_register_script( 'sba-ios-login-js', '', [ 'jquery' ], '1.0', true );
}

add_shortcode( 'sba_login_box', 'sba_ios_login_shortcode' );
function sba_ios_login_shortcode() {
    if ( is_user_logged_in() ) {
        $user = wp_get_current_user();
        $logout_url = wp_logout_url( home_url() );
        return sba_ios_logged_in_html( $user, $logout_url );
    }

    $nonce = wp_create_nonce( 'sba_ios_action' );
    ob_start();
    ?>
    <div id="sba-ios-login-container" data-nonce="<?php echo esc_attr( $nonce ); ?>">
        <div class="sba-ios-card">
            <div class="sba-ios-tabs">
                <button class="sba-ios-tab active" data-tab="login">登录</button>
                <button class="sba-ios-tab" data-tab="register">注册</button>
                <button class="sba-ios-tab" data-tab="forgot">忘记密码</button>
            </div>

            <div id="sba-ios-login-form" class="sba-ios-form active">
                <div class="sba-ios-field">
                    <input type="text" id="sba-ios-login-username" placeholder="用户名或邮箱">
                </div>
                <div class="sba-ios-field">
                    <input type="password" id="sba-ios-login-password" placeholder="密码">
                </div>
                <div class="sba-ios-field checkbox-field">
                    <label><input type="checkbox" id="sba-ios-login-remember" checked> 记住我</label>
                </div>
                <div id="sba-ios-login-captcha-area" style="display:none;">
                    <div class="sba-ios-field">
                        <input type="text" id="sba-ios-login-captcha" placeholder="验证码">
                    </div>
                    <div id="sba-ios-login-captcha-question"></div>
                </div>
                <div id="sba-ios-login-message" class="sba-ios-message"></div>
                <button id="sba-ios-login-submit" class="sba-ios-button">登录</button>
            </div>

            <div id="sba-ios-register-form" class="sba-ios-form">
                <div class="sba-ios-field">
                    <input type="text" id="sba-ios-reg-username" placeholder="用户名">
                </div>
                <div class="sba-ios-field">
                    <input type="email" id="sba-ios-reg-email" placeholder="邮箱">
                </div>
                <div class="sba-ios-field">
                    <input type="password" id="sba-ios-reg-password" placeholder="密码">
                </div>
                <div class="sba-ios-field">
                    <input type="password" id="sba-ios-reg-confirm-password" placeholder="确认密码">
                </div>
                <div id="sba-ios-reg-captcha-area" style="display:none;">
                    <div class="sba-ios-field">
                        <input type="text" id="sba-ios-reg-captcha" placeholder="验证码">
                    </div>
                    <div id="sba-ios-reg-captcha-question"></div>
                </div>
                <div id="sba-ios-reg-message" class="sba-ios-message"></div>
                <button id="sba-ios-reg-submit" class="sba-ios-button">注册</button>
            </div>

            <div id="sba-ios-forgot-form" class="sba-ios-form">
                <div class="sba-ios-field">
                    <input type="text" id="sba-ios-forgot-email" placeholder="用户名或邮箱">
                </div>
                <div id="sba-ios-forgot-captcha-area" style="display:none;">
                    <div class="sba-ios-field">
                        <input type="text" id="sba-ios-forgot-captcha" placeholder="验证码">
                    </div>
                    <div id="sba-ios-forgot-captcha-question"></div>
                </div>
                <div id="sba-ios-forgot-message" class="sba-ios-message"></div>
                <button id="sba-ios-forgot-submit" class="sba-ios-button">发送重置链接</button>
            </div>
        </div>
    </div>

    <style>
        #sba-ios-login-container { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; max-width: 380px; margin: 30px auto; padding: 0 16px; }
        .sba-ios-card { background: #ffffff; border-radius: 20px; box-shadow: 0 8px 28px rgba(0,0,0,0.08), 0 0 0 1px rgba(0,0,0,0.02); overflow: hidden; }
        .sba-ios-tabs { display: flex; border-bottom: 1px solid #e9ecef; background: #ffffff; }
        .sba-ios-tab { flex: 1; text-align: center; padding: 16px 0; font-size: 17px; font-weight: 500; color: #8e8e93; background: none; border: none; cursor: pointer; transition: all 0.2s ease; }
        .sba-ios-tab.active { color: #007aff; border-bottom: 2px solid #007aff; }
        .sba-ios-form { padding: 24px 20px; display: none; }
        .sba-ios-form.active { display: block; }
        .sba-ios-field { margin-bottom: 16px; }
        .sba-ios-field input[type="text"], .sba-ios-field input[type="password"], .sba-ios-field input[type="email"] { width: 100%; padding: 12px 16px; font-size: 16px; border: 1px solid #c6c6c8; border-radius: 12px; background-color: #ffffff; transition: border-color 0.2s; box-sizing: border-box; }
        .sba-ios-field input:focus { outline: none; border-color: #007aff; }
        .checkbox-field { margin: -8px 0 16px; text-align: left; }
        .checkbox-field label { font-size: 14px; color: #8e8e93; }
        .sba-ios-field input[type="checkbox"] { width: auto; margin-right: 6px; vertical-align: middle; }
        .sba-ios-button { background: #007aff; color: white; border: none; border-radius: 12px; padding: 12px 20px; font-size: 17px; font-weight: 600; width: 100%; cursor: pointer; transition: opacity 0.2s; }
        .sba-ios-button:hover { opacity: 0.85; }
        .sba-ios-message { margin: 12px 0; font-size: 14px; text-align: center; color: #ff3b30; min-height: 40px; }
        .sba-ios-captcha-question { margin-top: -10px; margin-bottom: 10px; font-size: 14px; color: #8e8e93; text-align: center; }
        .sba-ios-logged-in { background: #ffffff; border-radius: 20px; box-shadow: 0 8px 28px rgba(0,0,0,0.08); padding: 24px 20px; text-align: center; max-width: 380px; margin: 30px auto; }
        .sba-ios-avatar { width: 80px; height: 80px; border-radius: 50%; margin: 0 auto 16px; background: #f0f0f0; display: flex; align-items: center; justify-content: center; overflow: hidden; }
        .sba-ios-avatar img { width: 100%; height: 100%; object-fit: cover; }
        .sba-ios-welcome { font-size: 20px; font-weight: 600; margin-bottom: 8px; }
        .sba-ios-user { font-size: 17px; color: #007aff; margin-bottom: 24px; }
        .sba-ios-links a { display: inline-block; margin: 0 12px; color: #007aff; text-decoration: none; font-size: 15px; }
        .sba-ios-links a:hover { text-decoration: underline; }
        @media (max-width: 480px) { #sba-ios-login-container, .sba-ios-logged-in { margin: 20px auto; } }
    </style>
    <?php
    $html = ob_get_clean();

    static $script_added = false;
    if ( ! $script_added ) {
        $script_added = true;
        $ajaxurl = admin_url( 'admin-ajax.php' );
        $script = <<<JS
var ajaxurl = '{$ajaxurl}';
jQuery(document).ready(function($) {
    var nonce = $('#sba-ios-login-container').data('nonce');
    var loginCaptchaShown = false;
    var regCaptchaShown = false;
    var forgotCaptchaShown = false;

    $('.sba-ios-tab').click(function() {
        var tab = $(this).data('tab');
        $('.sba-ios-tab').removeClass('active');
        $(this).addClass('active');
        $('.sba-ios-form').removeClass('active');
        $('#sba-ios-' + tab + '-form').addClass('active');
        $('.sba-ios-message').html('');
        if (tab === 'login') {
            if (!loginCaptchaShown) loginCheckCaptcha();
        } else if (tab === 'register') {
            if (!regCaptchaShown) loadRegCaptcha();
        } else if (tab === 'forgot') {
            if (!forgotCaptchaShown) loadForgotCaptcha();
        }
    });

    function loadCaptcha(formType, callback, force) {
        var data = { action: 'sba_ios_get_captcha', _ajax_nonce: nonce };
        if (force) data.force = 1;
        $.post(ajaxurl, data, function(res) {
            if (res.success) {
                var areaId = '#sba-ios-' + formType + '-captcha-area';
                var questionId = '#sba-ios-' + formType + '-captcha-question';
                $(areaId).show();
                $(questionId).html(res.data.question);
                if (callback) callback(true);
                if (formType === 'login') loginCaptchaShown = true;
                else if (formType === 'reg') regCaptchaShown = true;
                else if (formType === 'forgot') forgotCaptchaShown = true;
            } else {
                if (callback) callback(false);
            }
        });
    }

    var loginNeedCaptcha = false;
    function loginCheckCaptcha() {
        if (loginCaptchaShown) return;
        $.post(ajaxurl, { action: 'sba_ios_check_captcha', _ajax_nonce: nonce }, function(res) {
            if (res.success && res.data.need_captcha) {
                loginNeedCaptcha = true;
                loadCaptcha('login', function(ok) { if (!ok) $('#sba-ios-login-captcha-area').hide(); });
            } else {
                loginNeedCaptcha = false;
                $('#sba-ios-login-captcha-area').hide();
                loginCaptchaShown = false;
            }
        });
    }

    function loadRegCaptcha() {
        if (regCaptchaShown) return;
        loadCaptcha('reg', function(ok) {
            if (!ok) $('#sba-ios-reg-captcha-area').hide();
            else regCaptchaShown = true;
        }, true);
    }

    function loadForgotCaptcha() {
        if (forgotCaptchaShown) return;
        loadCaptcha('forgot', function(ok) {
            if (!ok) $('#sba-ios-forgot-captcha-area').hide();
            else forgotCaptchaShown = true;
        }, true);
    }

    $('#sba-ios-login-submit').click(function() {
        var username = $('#sba-ios-login-username').val();
        var password = $('#sba-ios-login-password').val();
        var remember = $('#sba-ios-login-remember').is(':checked') ? 1 : 0;
        var captcha = $('#sba-ios-login-captcha').val();
        var btn = $(this);
        btn.prop('disabled', true).text('登录中...');
        $.post(ajaxurl, {
            action: 'sba_ios_login',
            username: username,
            password: password,
            remember: remember,
            captcha: captcha,
            need_captcha: loginNeedCaptcha ? 1 : 0,
            _ajax_nonce: nonce
        }, function(res) {
            if (res.success) {
                location.reload();
            } else {
                $('#sba-ios-login-message').html(res.data.message);
                if (res.data.need_captcha) {
                    loginNeedCaptcha = true;
                    loginCaptchaShown = false;
                    loadCaptcha('login');
                } else {
                    $('#sba-ios-login-captcha-area').hide();
                    loginNeedCaptcha = false;
                    loginCaptchaShown = false;
                }
                btn.prop('disabled', false).text('登录');
            }
        }).fail(function() {
            $('#sba-ios-login-message').html('网络错误，请稍后重试。');
            btn.prop('disabled', false).text('登录');
        });
    });

    $('#sba-ios-reg-submit').click(function() {
        if (!regCaptchaShown) {
            loadRegCaptcha();
            $('#sba-ios-reg-message').html('请先填写验证码。');
            return;
        }
        var username = $('#sba-ios-reg-username').val();
        var email = $('#sba-ios-reg-email').val();
        var password = $('#sba-ios-reg-password').val();
        var confirm_password = $('#sba-ios-reg-confirm-password').val();
        var captcha = $('#sba-ios-reg-captcha').val();
        var btn = $(this);
        btn.prop('disabled', true).text('注册中...');
        if (password !== confirm_password) {
            $('#sba-ios-reg-message').html('两次输入的密码不一致。');
            btn.prop('disabled', false).text('注册');
            return;
        }
        if (password.length < 8 || !/[a-zA-Z]/.test(password) || !/[0-9]/.test(password)) {
            $('#sba-ios-reg-message').html('密码必须至少8位，且包含字母和数字。');
            btn.prop('disabled', false).text('注册');
            return;
        }
        $.post(ajaxurl, {
            action: 'sba_ios_register',
            username: username,
            email: email,
            password: password,
            captcha: captcha,
            need_captcha: 1,
            _ajax_nonce: nonce
        }, function(res) {
            if (res.success) {
                $('#sba-ios-reg-message').html('<span style="color:#28cd41;">' + res.data.message + '</span>');
                setTimeout(function() { location.reload(); }, 1500);
            } else {
                $('#sba-ios-reg-message').html(res.data.message);
                if (res.data.need_captcha) {
                    regCaptchaShown = false;
                    loadRegCaptcha();
                } else {
                    $('#sba-ios-reg-captcha-area').hide();
                }
                btn.prop('disabled', false).text('注册');
            }
        }).fail(function() {
            $('#sba-ios-reg-message').html('网络错误，请稍后重试。');
            btn.prop('disabled', false).text('注册');
        });
    });

    $('#sba-ios-forgot-submit').click(function() {
        if (!forgotCaptchaShown) {
            loadForgotCaptcha();
            $('#sba-ios-forgot-message').html('请先填写验证码。');
            return;
        }
        var email = $('#sba-ios-forgot-email').val();
        var captcha = $('#sba-ios-forgot-captcha').val();
        var btn = $(this);
        btn.prop('disabled', true).text('发送中...');
        $.post(ajaxurl, {
            action: 'sba_ios_forgot',
            email: email,
            captcha: captcha,
            need_captcha: 1,
            _ajax_nonce: nonce
        }, function(res) {
            if (res.success) {
                $('#sba-ios-forgot-message').html('<span style="color:#28cd41;">' + res.data.message + '</span>');
                btn.prop('disabled', false).text('发送重置链接');
            } else {
                $('#sba-ios-forgot-message').html(res.data.message);
                if (res.data.need_captcha) {
                    forgotCaptchaShown = false;
                    loadForgotCaptcha();
                } else {
                    $('#sba-ios-forgot-captcha-area').hide();
                }
                btn.prop('disabled', false).text('发送重置链接');
            }
        }).fail(function() {
            $('#sba-ios-forgot-message').html('网络错误，请稍后重试。');
            btn.prop('disabled', false).text('发送重置链接');
        });
    });

    loginCheckCaptcha();
    if ($('#sba-ios-register-form').hasClass('active')) loadRegCaptcha();
    if ($('#sba-ios-forgot-form').hasClass('active')) loadForgotCaptcha();
    $('#sba-ios-login-username, #sba-ios-login-password').focus(loginCheckCaptcha);
});
JS;
        wp_add_inline_script( 'sba-ios-login-js', $script );
        wp_enqueue_script( 'sba-ios-login-js' );
    }

    return $html;
}

// 处理邮箱激活
add_action( 'init', function() {
    if ( isset( $_GET['action'] ) && $_GET['action'] === 'sba_activate' ) {
        $user_id = intval( $_GET['user'] );
        $key     = sanitize_text_field( $_GET['key'] );

        $stored_key = get_user_meta( $user_id, '_activation_key', true );
        $activated  = get_user_meta( $user_id, '_activated', true );

        if ( ! $stored_key || $activated === '1' ) {
            wp_die( '激活链接无效或已使用。', '激活失败', array( 'response' => 400 ) );
        }

        if ( $stored_key === $key ) {
            update_user_meta( $user_id, '_activated', '1' );
            delete_user_meta( $user_id, '_activation_key' );
            wp_set_current_user( $user_id );
            wp_set_auth_cookie( $user_id, false );
            wp_redirect( home_url( '/?activation=success' ) );
            exit;
        } else {
            wp_die( '激活码不正确。', '激活失败', array( 'response' => 400 ) );
        }
    }
} );

function sba_ios_logged_in_html( $user, $logout_url ) {
    $avatar = get_avatar( $user->ID, 80, '', '', [ 'class' => 'sba-ios-avatar-img' ] );
    ob_start();
    ?>
    <div class="sba-ios-logged-in">
        <div class="sba-ios-avatar"><?php echo $avatar; ?></div>
        <div class="sba-ios-welcome">欢迎回来</div>
        <div class="sba-ios-user"><?php echo esc_html( $user->display_name ); ?></div>
        <div class="sba-ios-links">
            <a href="<?php echo admin_url(); ?>">控制台</a>
            <a href="<?php echo admin_url( 'profile.php' ); ?>">个人资料</a>
            <a href="<?php echo esc_url( wp_logout_url( home_url() ) ); ?>">注销</a>
        </div>
    </div>
    <?php
    return ob_get_clean();
}

// AJAX 获取验证码
add_action( 'wp_ajax_nopriv_sba_ios_get_captcha', 'sba_ios_ajax_get_captcha' );
function sba_ios_ajax_get_captcha() {
    if (session_status() === PHP_SESSION_NONE) session_start();
    check_ajax_referer( 'sba_ios_action', '_ajax_nonce' );
    $ip = sba_combined_get_ip();
    $force = isset($_POST['force']) ? (int)$_POST['force'] : 0;
    if ( $force ) {
        $status = [ 'banned' => false, 'need_captcha' => true ];
    } else {
        $status = sba_ios_check_ban_and_captcha( $ip );
    }
    if ( $status['banned'] ) wp_send_json_error( [ 'message' => '您已被封禁24小时，请稍后再试。' ] );
    if ( ! $status['need_captcha'] ) wp_send_json_error( [ 'message' => '当前无需验证码' ] );
    $num1 = rand( 1, 9 );
    $num2 = rand( 1, 9 );
    $answer = $num1 + $num2;
    $_SESSION['sba_captcha_answer'] = $answer;
    wp_send_json_success( [ 'question' => "验证码：$num1 + $num2 = ?", 'answer' => $answer ] );
}

// AJAX 检查是否需要验证码
add_action( 'wp_ajax_nopriv_sba_ios_check_captcha', 'sba_ios_ajax_check_captcha' );
function sba_ios_ajax_check_captcha() {
    if (session_status() === PHP_SESSION_NONE) session_start();
    check_ajax_referer( 'sba_ios_action', '_ajax_nonce' );
    $ip = sba_combined_get_ip();
    $status = sba_ios_check_ban_and_captcha( $ip );
    if ( $status['banned'] ) wp_send_json_error( [ 'banned' => true ] );
    wp_send_json_success( [ 'need_captcha' => $status['need_captcha'] ] );
}

// AJAX 登录处理
add_action( 'wp_ajax_nopriv_sba_ios_login', 'sba_ios_ajax_login' );
function sba_ios_ajax_login() {
    if (session_status() === PHP_SESSION_NONE) session_start();
    check_ajax_referer( 'sba_ios_action', '_ajax_nonce' );
    $ip = sba_combined_get_ip();
    if ( ! sba_ios_check_rate_limit( $ip, 10 ) ) wp_send_json_error( [ 'message' => '操作过于频繁，请稍后再试。' ] );
    $status = sba_ios_check_ban_and_captcha( $ip );
    if ( $status['banned'] ) wp_send_json_error( [ 'message' => '由于多次失败，您的IP已被封禁24小时。' ] );

    $username = sanitize_user( $_POST['username'] );
    $password = $_POST['password'];
    $remember = (int) $_POST['remember'];
    $provided_captcha = sanitize_text_field( $_POST['captcha'] );
    $need_captcha = (int) $_POST['need_captcha'];

    sleep(2);

    if ( $need_captcha ) {
        if ( ! isset( $_SESSION['sba_captcha_answer'] ) || $provided_captcha != $_SESSION['sba_captcha_answer'] ) {
            sba_ios_record_failure( $ip, false );
            wp_send_json_error( [ 'message' => '验证码错误', 'need_captcha' => true ] );
        }
        unset( $_SESSION['sba_captcha_answer'] );
    }

    $creds = [
        'user_login'    => $username,
        'user_password' => $password,
        'remember'      => (bool) $remember,
    ];
    $user = wp_signon( $creds, false );

    if ( is_wp_error( $user ) ) {
        $fail_count = sba_ios_record_failure( $ip, false );
        $message = $user->get_error_message();
        $need_captcha_now = ( $fail_count >= 3 && $fail_count < 6 );
        wp_send_json_error( [ 'message' => $message, 'need_captcha' => $need_captcha_now ] );
    } else {
        $activated = get_user_meta( $user->ID, '_activated', true );
        if ( $activated !== '' && $activated !== '1' ) {
            wp_clear_auth_cookie();
            sba_ios_record_failure( $ip, false );
            wp_send_json_error( [ 'message' => '账号尚未激活，请查收激活邮件。' ] );
        }
        sba_ios_record_failure( $ip, true );
        wp_set_current_user( $user->ID );
        wp_set_auth_cookie( $user->ID, (bool) $remember );
        wp_send_json_success( [ 'message' => '登录成功' ] );
    }
}

// AJAX 注册处理
add_action( 'wp_ajax_nopriv_sba_ios_register', 'sba_ios_ajax_register' );
function sba_ios_ajax_register() {
    if (session_status() === PHP_SESSION_NONE) session_start();
    check_ajax_referer( 'sba_ios_action', '_ajax_nonce' );
    $ip = sba_combined_get_ip();
    if ( ! sba_ios_check_rate_limit( $ip, 10 ) ) wp_send_json_error( [ 'message' => '操作过于频繁，请稍后再试。' ] );
    $status = sba_ios_check_ban_and_captcha( $ip, 'register' );
    if ( $status['banned'] ) wp_send_json_error( [ 'message' => '由于多次失败，您的IP已被封禁24小时。' ] );

    $username = sanitize_user( $_POST['username'] );
    $email    = sanitize_email( $_POST['email'] );
    $password = $_POST['password'];
    $provided_captcha = sanitize_text_field( $_POST['captcha'] );
    $need_captcha = (int) $_POST['need_captcha'];

    if ( $need_captcha ) {
        if ( ! isset( $_SESSION['sba_captcha_answer'] ) || $provided_captcha != $_SESSION['sba_captcha_answer'] ) {
            sba_ios_record_failure( $ip, false );
            wp_send_json_error( [ 'message' => '验证码错误', 'need_captcha' => true ] );
        }
        unset( $_SESSION['sba_captcha_answer'] );
    }

    if ( empty( $username ) || empty( $email ) || empty( $password ) ) {
        sba_ios_record_failure( $ip, false );
        wp_send_json_error( [ 'message' => '所有字段都不能为空。' ] );
    }
    if ( strlen( $password ) < 8 || ! preg_match( '/[a-zA-Z]/', $password ) || ! preg_match( '/[0-9]/', $password ) ) {
        sba_ios_record_failure( $ip, false );
        wp_send_json_error( [ 'message' => '密码必须至少8位，且包含字母和数字。' ] );
    }
    if ( username_exists( $username ) ) {
        sba_ios_record_failure( $ip, false );
        wp_send_json_error( [ 'message' => '用户名已存在。' ] );
    }
    if ( email_exists( $email ) ) {
        sba_ios_record_failure( $ip, false );
        wp_send_json_error( [ 'message' => '邮箱已被注册。' ] );
    }

    $user_id = wp_create_user( $username, $password, $email );
    if ( is_wp_error( $user_id ) ) {
        sba_ios_record_failure( $ip, false );
        wp_send_json_error( [ 'message' => $user_id->get_error_message() ] );
    }

    $activation_key = wp_generate_password( 20, false );
    update_user_meta( $user_id, '_activation_key', $activation_key );
    update_user_meta( $user_id, '_activated', '0' );

    $activation_url = add_query_arg( array(
        'action' => 'sba_activate',
        'user'   => $user_id,
        'key'    => $activation_key,
    ), home_url() );
    $subject = '请激活您的账号 - ' . get_bloginfo( 'name' );
    $message = "您好 {$username},\n\n请点击以下链接激活您的账号（链接24小时内有效）：\n{$activation_url}\n\n如果没有注册过，请忽略此邮件。";
    $sent = wp_mail( $email, $subject, $message );

    if ( ! $sent ) {
        wp_delete_user( $user_id );
        sba_ios_record_failure( $ip, false );
        wp_send_json_error( [ 'message' => '邮件发送失败，请联系管理员。' ] );
    }

    sba_ios_record_failure( $ip, true );
    wp_send_json_success( [ 'message' => '注册成功，请查收激活邮件。' ] );
}

// AJAX 忘记密码处理
add_action( 'wp_ajax_nopriv_sba_ios_forgot', 'sba_ios_ajax_forgot' );
function sba_ios_ajax_forgot() {
    if (session_status() === PHP_SESSION_NONE) session_start();
    check_ajax_referer( 'sba_ios_action', '_ajax_nonce' );
    $ip = sba_combined_get_ip();
    if ( ! sba_ios_check_rate_limit( $ip, 10 ) ) wp_send_json_error( [ 'message' => '操作过于频繁，请稍后再试。' ] );
    $status = sba_ios_check_ban_and_captcha( $ip, 'forgot' );
    if ( $status['banned'] ) wp_send_json_error( [ 'message' => '由于多次失败，您的IP已被封禁24小时。' ] );

    $login_or_email = sanitize_text_field( $_POST['email'] );
    $provided_captcha = sanitize_text_field( $_POST['captcha'] );
    $need_captcha = (int) $_POST['need_captcha'];

    if ( $need_captcha ) {
        if ( ! isset( $_SESSION['sba_captcha_answer'] ) || $provided_captcha != $_SESSION['sba_captcha_answer'] ) {
            sba_ios_record_failure( $ip, false );
            wp_send_json_error( [ 'message' => '验证码错误', 'need_captcha' => true ] );
        }
        unset( $_SESSION['sba_captcha_answer'] );
    }

    $user = false;
    if ( is_email( $login_or_email ) ) {
        $user = get_user_by( 'email', $login_or_email );
    } else {
        $user = get_user_by( 'login', $login_or_email );
    }
    if ( ! $user ) {
        sba_ios_record_failure( $ip, false );
        wp_send_json_error( [ 'message' => '用户名或邮箱未注册。' ] );
    }

    $key = get_password_reset_key( $user );
    if ( is_wp_error( $key ) ) {
        sba_ios_record_failure( $ip, false );
        wp_send_json_error( [ 'message' => '无法生成重置链接，请稍后重试。' ] );
    }

    $reset_url = network_site_url( "wp-login.php?action=rp&key=$key&login=" . rawurlencode( $user->user_login ), 'login' );
    $subject = '重置密码';
    $message = "请点击以下链接重置密码（链接24小时内有效）：\n" . $reset_url;
    $sent = wp_mail( $user->user_email, $subject, $message );

    if ( $sent ) {
        sba_ios_record_failure( $ip, true );
        wp_send_json_success( [ 'message' => '重置链接已发送至您的邮箱。' ] );
    } else {
        sba_ios_record_failure( $ip, false );
        wp_send_json_error( [ 'message' => '邮件发送失败，请联系管理员。' ] );
    }
}

/* ================= SMTP 邮件配置模块 ================= */
function sba_smtp_activate() {
    $defaults = [
        'smtp_host'      => '',
        'smtp_port'      => '587',
        'smtp_encryption'=> 'tls',
        'smtp_auth'      => 1,
        'smtp_username'  => '',
        'smtp_password'  => '',
        'from_email'     => '',
        'from_name'      => '',
    ];
    add_option( 'sba_smtp_settings', $defaults );
}
register_activation_hook( __FILE__, 'sba_smtp_activate' );

add_action( 'admin_menu', 'sba_combined_admin_menu' );
function sba_combined_admin_menu() {
    add_menu_page( '全行为审计', '全行为审计', 'manage_options', 'sba_audit', 'sba_audit_render_dashboard', 'dashicons-shield-alt' );
    add_submenu_page( 'sba_audit', '防御设置', '防御设置', 'manage_options', 'sba_settings', 'sba_audit_render_settings' );
    add_submenu_page( 'sba_audit', 'SMTP 邮件设置', 'SMTP 邮件', 'manage_options', 'sba-smtp', 'sba_smtp_settings_page' );
}

add_action( 'admin_init', function() {
    register_setting( 'sba_settings_group', 'sba_settings' );
} );

function sba_audit_render_dashboard() {
    global $wpdb;
    $online = $wpdb->get_var( "SELECT COUNT(DISTINCT ip) FROM {$wpdb->prefix}dis_stats WHERE last_visit > DATE_SUB(NOW(), INTERVAL 5 MINUTE)" );
    $latest_date = $wpdb->get_var( "SELECT MAX(visit_date) FROM {$wpdb->prefix}dis_stats" );
    if ( ! $latest_date ) $latest_date = current_time( 'Y-m-d' );
    $latest_ts = strtotime( $latest_date );
    $today_stat = $wpdb->get_row( $wpdb->prepare( "SELECT COUNT(DISTINCT ip) as uv, SUM(pv) as pv FROM {$wpdb->prefix}dis_stats WHERE visit_date = %s", $latest_date ) );
    $history_50 = $wpdb->get_results( "SELECT visit_date, COUNT(DISTINCT ip) as uv, SUM(pv) as pv FROM {$wpdb->prefix}dis_stats GROUP BY visit_date ORDER BY visit_date DESC LIMIT 50", OBJECT_K );
    $chart_labels = []; $chart_uv = []; $chart_pv = [];
    for ( $i = 29; $i >= 0; $i-- ) {
        $target_date = date( 'Y-m-d', $latest_ts - ( $i * 86400 ) );
        $chart_labels[] = $target_date;
        $chart_uv[] = isset( $history_50[ $target_date ] ) ? (int) $history_50[ $target_date ]->uv : 0;
        $chart_pv[] = isset( $history_50[ $target_date ] ) ? (int) $history_50[ $target_date ]->pv : 0;
    }
    $blocks = $wpdb->get_results( "SELECT * FROM {$wpdb->prefix}sba_blocked_log ORDER BY block_time DESC LIMIT 15" );
    ?>
	<style>
		.sba-wrap { max-width: 1400px; margin-top: 15px; }
		.sba-card { background:#fff; padding:20px; border-radius:12px; margin-bottom:20px; box-shadow:0 4px 15px rgba(0,0,0,0.05); }
		.sba-grid { display:grid; grid-template-columns: 1fr 1fr; gap:20px; }
		@media (max-width: 1000px) { .sba-grid { grid-template-columns: 1fr; } }
		.sba-scroll-x { width: 100%; overflow-x: auto; border: 1px solid #eee; border-radius:8px; }
		.sba-table {
			width: 100%;
			min-width: 850px;
			border-collapse: collapse;
			table-layout: fixed;
		}
		.sba-table th,
		.sba-table td {
			text-align: left;
			padding: 12px 10px;
			border-bottom: 1px solid #f9f9f9;
			font-size: 13px;
			background-color: #fff;
			color: #333;
			vertical-align: middle;
		}
		.sba-table td code {
			font-size: inherit;
			background: none;
			padding: 0;
			color: inherit;
		}

		.col-time { width: 80px; }
		.col-ip { width: 240px; min-width: 200px; max-width: 280px; word-break: keep-all; }
		.col-geo { width: 180px; }
		.col-pv { width: 70px; }
		.sba-table tbody tr td:first-child,
		.sba-table thead tr th:first-child {
			width: 100px;
		}
		.sba-table tbody tr td:nth-child(2),
		.sba-table thead tr th:nth-child(2) {
			width: 240px;
			word-break: keep-all;
		}
		.sba-cell-wrap {
			white-space: normal;
			word-break: break-all;
			display: -webkit-box;
			-webkit-line-clamp: 2;
			-webkit-box-orient: vertical;
			overflow: hidden;
			line-height: 1.4;
			font-size: 12px;
		}
		.stat-val {
			font-size: 26px;
			font-weight: bold;
			display: block;
			margin-top: 5px;
		}
		/* 手机端优化：保留横向滚动，调整列宽 */
		@media (max-width: 768px) {
			.sba-table {
				min-width: 700px;
			}
			.col-time { width: 65px; }
			.col-ip   { width: 160px; }
			.col-geo  { width: 140px; }
			.col-pv   { width: 55px; }
			.sba-table td:nth-child(4) { width: 55px; }
			.sba-table th, .sba-table td {
				font-size: 12px;
				padding: 8px 5px;
			}
		}
	</style>
    <div class="wrap sba-wrap">
        <h2>🚀 SBA 站点行为监控 v1.0</h2>
        <div style="display:flex; gap:15px; margin-bottom:20px; flex-wrap:wrap;">
            <div class="sba-card" style="flex:1; border-left:4px solid #46b450;">当前在线: <span class="stat-val" style="color:#46b450;"><?php echo $online ?: 0; ?></span></div>
            <div class="sba-card" style="flex:1; border-left:4px solid #2271b1;">今日 (<?php echo $latest_date; ?>) UV: <span class="stat-val" style="color:#2271b1;"><?php echo $today_stat->uv ?: 0; ?></span></div>
            <div class="sba-card" style="flex:1; border-left:4px solid #4fc3f7;">今日 (<?php echo $latest_date; ?>) PV: <span class="stat-val" style="color:#4fc3f7;"><?php echo $today_stat->pv ?: 0; ?></span></div>
        </div>
        <div class="sba-grid">
            <div class="sba-card"><h3>📈 30天访问趋势</h3><div style="height:250px;"><canvas id="sbaChart10"></canvas></div></div>
            <div class="sba-card"><h3>📊 50天审计详表</h3>
                <div class="sba-scroll-x" style="height:250px;"><table class="sba-table" style="min-width:400px;">
                <thead><tr><th>日期</th><th>UV (人)</th><th>PV (次)</th><th>深度</th></tr></thead>
                <tbody><?php for ( $j = 0; $j < 50; $j++ ): $d = date( 'Y-m-d', $latest_ts - ( $j * 86400 ) ); $u = isset( $history_50[ $d ] ) ? $history_50[ $d ]->uv : 0; $p = isset( $history_50[ $d ] ) ? $history_50[ $d ]->pv : 0; ?>
                <tr><td><b><?php echo $d; ?></b></td><td><?php echo $u; ?></td><td><?php echo $p; ?></td><td><code><?php echo round( $p / max( 1, $u ), 1 ); ?></code></td></tr>
                <?php endfor; ?></tbody>
                </table></div>
            </div>
        </div>
        <div class="sba-card">
            <h3>👣 访客轨迹 (<?php echo $latest_date; ?>)</h3>
            <div class="sba-scroll-x"><table class="sba-table">
                <thead><tr><th class="col-time">时间</th><th class="col-ip">IP</th><th class="col-geo">归属地</th><th class="col-url">访问路径</th><th class="col-pv">PV</th></tr></thead>
                <tbody id="track-body"></tbody>
            </table></div>
            <div style="margin-top:15px; display:flex; justify-content: space-between;">
                <div>总记录: <b id="total-rows">0</b></div>
                <div><button id="prev-page" class="button">上页</button> 第 <b id="current-page">1</b> / <b id="total-pages">1</b> 页 <button id="next-page" class="button">下页</button></div>
            </div>
        </div>
        <div class="sba-card" style="border-top:3px solid #d63638;">
            <h3>🚫 拦截日志</h3>
            <div class="sba-scroll-x"><table class="sba-table">
                <thead><tr><th width="100">时间</th><th width="150">拦截 IP</th><th>原因与目标</th></tr></thead>
                <tbody><?php foreach ( $blocks as $b ): ?><tr><td><?php echo date( 'm-d H:i', strtotime( $b->block_time ) ); ?></td><td><code><?php echo $b->ip; ?></code></td><td class="sba-cell-wrap" style="color:#d63638;"><?php echo $b->reason; ?> ⚡ <?php echo esc_html( $b->target_url ); ?></td></tr><?php endforeach; ?></tbody>
            </table></div>
        </div>
    </div>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script>
    new Chart(document.getElementById('sbaChart10'), {
        type:'line', data:{
            labels:<?php echo json_encode( $chart_labels ); ?>,
            datasets:[
                {label:'UV', data:<?php echo json_encode( $chart_uv ); ?>, borderColor:'#2271b1', backgroundColor:'rgba(34,113,177,0.1)', tension:0.1, fill:true},
                {label:'PV', data:<?php echo json_encode( $chart_pv ); ?>, borderColor:'#4fc3f7', backgroundColor:'rgba(79,195,247,0.1)', tension:0.1, fill:true}
            ]
        }, options:{maintainAspectRatio:false, interaction:{intersect:false, mode:'index'}}
    });
    let curP = 1, maxP = 1;
    const loadT = (p) => {
        fetch(ajaxurl, { method: 'POST', body: new URLSearchParams({action:'sba_load_tracks', page:p}) }).then(r => r.json()).then(res => {
            if(res.success) { document.getElementById('track-body').innerHTML = res.data.html; curP = p; maxP = res.data.pages; document.getElementById('current-page').innerText = p; document.getElementById('total-pages').innerText = maxP; document.getElementById('total-rows').innerText = res.data.total; processGeos(); }
        });
    };
    async function processGeos() {
        const badges = Array.from(document.querySelectorAll('.geo-tag')).filter(b => b.innerText === '解析中...');
        for (let i = 0; i < badges.length; i += 5) {
            const chunk = badges.slice(i, i + 5);
            const fd = new FormData(); fd.append('action', 'sba_get_geo'); chunk.forEach(b => fd.append('ips[]', b.dataset.ip));
            fetch(ajaxurl, { method: 'POST', body: fd }).then(r => r.json()).then(j => { if(j.success) chunk.forEach(b => b.innerText = j.data[b.dataset.ip]); });
        }
    }
    document.getElementById('prev-page').onclick = () => { if(curP > 1) loadT(curP - 1); };
    document.getElementById('next-page').onclick = () => { if(curP < maxP) loadT(curP + 1); };
    loadT(1);
    </script>
    <?php
}

function sba_audit_render_settings() {
    $opts = get_option( 'sba_settings' );
    global $wpdb;
    $v4 = $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->prefix}sba_ip_data WHERE ip_type = 4" );
    $v6 = $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->prefix}sba_ip_data WHERE ip_type = 6" );
    ?>
    <div class="wrap sba-wrap">
        <h1>🛠️ SBA 防御设置</h1>
        <div class="sba-card" style="background:#fffbe6; border-left:5px solid #faad14;">
            <h3>📖 使用说明</h3>
            <p>1. <b>防误杀：</b> 填入用户名后，登录时将免疫所有频率拦截和路径检测。</p>
            <p>2. <b>Gate 钥匙：</b> 设置后，访问 <code>wp-login.php?gate=钥匙</code> 可开启登录入口（地址栏自动去除参数）。此后登录表单通过隐藏字段提交令牌，退出后令牌失效。</p>
            <p>3. <b>指纹库：</b> 自动识别 <code>sqlmap, curl, wget, python</code> 等 UA 特征并阻断。</p>
            <p>4. <b>归属地：</b> 毫秒级本地解析。上传 7 列 TXT 格式（| 分隔）的 IP 段文件即可。</p>
        </div>
        <form method="post" action="options.php">
            <?php settings_fields( 'sba_settings_group' ); ?>
            <div class="sba-grid">
                <div class="sba-card">
                    <h3>✅ 信任通道</h3>
                    <table class="form-table">
                        <tr>
                            <th>用户名白名单</th>
                            <td><input type="text" name="sba_settings[user_whitelist]" value="<?php echo esc_attr( $opts['user_whitelist'] ?? '' ); ?>" class="regular-text" /><br><small>登录此用户时，系统自动信任，不执行拦截逻辑。</small></td>
                        </tr>
                        <tr>
                            <th>IP 白名单</th>
                            <td><textarea name="sba_settings[ip_whitelist]" rows="3" style="width:100%"><?php echo esc_textarea( $opts['ip_whitelist'] ?? '' ); ?></textarea><br><small>每行一个 IP。</small></td>
                        </tr>
                    </table>
                </div>
                <div class="sba-card">
                    <h3>🚫 防御配置</h3>
                    <table class="form-table">
                        <tr>
                            <th>CC 封禁阈值</th>
                            <td><input type="number" name="sba_settings[auto_block_limit]" value="<?php echo esc_attr( $opts['auto_block_limit'] ?? '60' ); ?>" /> 次/分<br><small>单 IP 每分钟请求超过此值自动封禁（0 为关闭）。</small></td>
                        </tr>
                        <tr>
                            <th>Gate 钥匙</th>
                            <td><input type="text" name="sba_settings[login_slug]" value="<?php echo esc_attr( $opts['login_slug'] ?? '' ); ?>" /><br><small>保护登录入口。访问 <code>wp-login.php?gate=钥匙</code> 开启入口，之后自动隐藏。</small></td>
                        </tr>
                        <tr>
                            <th>追加拦截路径</th>
                            <td><input type="text" name="sba_settings[evil_paths]" value="<?php echo esc_attr( $opts['evil_paths'] ?? '' ); ?>" style="width:100%" placeholder="/test.php, /backup.zip" /><br><small>逗号分隔。内置已含 .env/.git 等，此处用于扩充。</small></td>
                        </tr>
                        <tr>
                            <th>拦截重定向 URL</th>
                            <td><input type="text" name="sba_settings[block_target_url]" value="<?php echo esc_attr( $opts['block_target_url'] ?? '' ); ?>" style="width:100%" placeholder="https://127.0.0.1" /><br><small>拦截后将对方跳转至此页面（留空则显示默认 403 页面）。</small></td>
                        </tr>
                    </table>
                    <?php submit_button( '保存核心配置' ); ?>
                </div>
            </div>
        </form>
        <div class="sba-card">
            <h3>📡 本地 IP 归属地库</h3>
            <div style="display:flex; gap:15px; margin-bottom:15px;">
                <div style="background:#f5f5f5; padding:10px 15px; border-radius:6px;">IPv4 记录: <b><?php echo number_format( $v4 ); ?></b></div>
                <div style="background:#f5f5f5; padding:10px 15px; border-radius:6px;">IPv6 记录: <b><?php echo number_format( $v6 ); ?></b></div>
            </div>
            <form method="post" enctype="multipart/form-data">
                <input type="file" name="sba_ip_file" accept=".txt">
                <input type="submit" name="sba_import_action" class="button button-primary" value="同步 7 列 IP 库">
            </form>
        </div>
    </div>
    <?php
}

add_action( 'admin_init', 'sba_audit_handle_import' );
function sba_audit_handle_import() {
    if ( isset( $_POST['sba_import_action'] ) && ! empty( $_FILES['sba_ip_file']['tmp_name'] ) ) {
        global $wpdb;
        $table = $wpdb->prefix . 'sba_ip_data';
        $handle = fopen( $_FILES['sba_ip_file']['tmp_name'], 'r' );
        if ( $handle ) {
            $first = fgets( $handle );
            if ( $first ) {
                $p = explode( '|', trim( $first ) );
                $type = ( strpos( $p[0] ?? '', ':' ) !== false ) ? 6 : 4;
                $wpdb->query( $wpdb->prepare( "DELETE FROM $table WHERE ip_type = %d", $type ) );
                rewind( $handle );
            }
            $batch = [];
            $i = 0;
            while ( ( $line = fgets( $handle ) ) !== false ) {
                $p = explode( '|', trim( $line ) );
                if ( count( $p ) >= 3 ) {
                    $s_bin = @inet_pton( $p[0] );
                    $e_bin = @inet_pton( $p[1] );
                    if ( ! $s_bin || ! $e_bin ) continue;
                    $batch[] = $wpdb->prepare( "(%d, %s, %s, %s)", $type, $s_bin, $e_bin, implode( '·', array_slice( $p, 2 ) ) );
                    if ( count( $batch ) >= 800 ) {
                        $wpdb->query( "INSERT INTO $table (ip_type, start_bin, end_bin, addr) VALUES " . implode( ',', $batch ) );
                        $batch = [];
                    }
                    $i++;
                }
            }
            if ( ! empty( $batch ) ) {
                $wpdb->query( "INSERT INTO $table (ip_type, start_bin, end_bin, addr) VALUES " . implode( ',', $batch ) );
            }
            fclose( $handle );
            add_settings_error( 'sba_settings', 'import', "成功载入 $i 条。", 'updated' );
        }
    }
}

function sba_smtp_settings_page() {
    $opts = get_option( 'sba_smtp_settings', array() );

    // 处理保存
    if ( isset( $_POST['smtp_save'] ) && check_admin_referer( 'sba_smtp_save' ) ) {
        $settings = array(
            'smtp_host'      => sanitize_text_field( $_POST['smtp_host'] ),
            'smtp_port'      => intval( $_POST['smtp_port'] ),
            'smtp_encryption'=> sanitize_text_field( $_POST['smtp_encryption'] ),
            'smtp_auth'      => isset( $_POST['smtp_auth'] ) ? 1 : 0,
            'smtp_username'  => sanitize_text_field( $_POST['smtp_username'] ),
            'smtp_password'  => sanitize_text_field( $_POST['smtp_password'] ),
            'from_email'     => sanitize_email( $_POST['from_email'] ),
            'from_name'      => sanitize_text_field( $_POST['from_name'] ),
        );
        update_option( 'sba_smtp_settings', $settings );
        echo '<div class="updated"><p>设置已保存。</p></div>';
        $opts = get_option( 'sba_smtp_settings', array() );
    }

    // 处理测试邮件
    if ( isset( $_POST['test_email'] ) && check_admin_referer( 'sba_smtp_save' ) ) {
        $to = sanitize_email( $_POST['test_to'] );
        if ( $to ) {
            $result = sba_smtp_send_test_mail( $to );
            if ( $result === true ) {
                echo '<div class="updated"><p>测试邮件已发送到 ' . esc_html( $to ) . '，请检查收件箱。</p></div>';
            } else {
                echo '<div class="error"><p>测试邮件发送失败：' . esc_html( $result ) . '</p></div>';
            }
        } else {
            echo '<div class="error"><p>请输入有效的测试邮箱地址。</p></div>';
        }
    }

    ?>
    <div class="wrap">
        <h1>SMTP 邮件设置</h1>
        <form method="post" action="">
            <?php wp_nonce_field( 'sba_smtp_save' ); ?>
            <table class="form-table">
                 <tr>
                    <th><label for="smtp_host">SMTP 主机</label></th>
                    <td><input type="text" id="smtp_host" name="smtp_host" value="<?php echo esc_attr( $opts['smtp_host'] ?? '' ); ?>" class="regular-text" placeholder="例如：smtp.gmail.com" /></td>
                 </tr>
                 <tr>
                    <th><label for="smtp_port">端口</label></th>
                    <td><input type="number" id="smtp_port" name="smtp_port" value="<?php echo esc_attr( $opts['smtp_port'] ?? '587' ); ?>" class="small-text" /> 常用：587 (TLS) 或 465 (SSL)</td>
                 </tr>
                 <tr>
                    <th><label for="smtp_encryption">加密方式</label></th>
                    <td>
                        <select id="smtp_encryption" name="smtp_encryption">
                            <option value="none" <?php selected( $opts['smtp_encryption'] ?? '', 'none' ); ?>>无</option>
                            <option value="tls" <?php selected( $opts['smtp_encryption'] ?? '', 'tls' ); ?>>TLS</option>
                            <option value="ssl" <?php selected( $opts['smtp_encryption'] ?? '', 'ssl' ); ?>>SSL</option>
                        </select>
                    </td>
                 </tr>
                 <tr>
                    <th><label for="smtp_auth">启用认证</label></th>
                    <td><input type="checkbox" id="smtp_auth" name="smtp_auth" value="1" <?php checked( $opts['smtp_auth'] ?? 1, 1 ); ?> /> 通常需要勾选</td>
                 </tr>
                 <tr>
                    <th><label for="smtp_username">用户名</label></th>
                    <td><input type="text" id="smtp_username" name="smtp_username" value="<?php echo esc_attr( $opts['smtp_username'] ?? '' ); ?>" class="regular-text" /></td>
                 </tr>
                 <tr>
                    <th><label for="smtp_password">密码</label></th>
                    <td><input type="password" id="smtp_password" name="smtp_password" value="<?php echo esc_attr( $opts['smtp_password'] ?? '' ); ?>" class="regular-text" /></td>
                 </tr>
                 <tr>
                    <th><label for="from_email">发件人邮箱</label></th>
                    <td><input type="email" id="from_email" name="from_email" value="<?php echo esc_attr( $opts['from_email'] ?? '' ); ?>" class="regular-text" placeholder="留空则使用 WordPress 默认" /></td>
                 </tr>
                 <tr>
                    <th><label for="from_name">发件人名称</label></th>
                    <td><input type="text" id="from_name" name="from_name" value="<?php echo esc_attr( $opts['from_name'] ?? '' ); ?>" class="regular-text" placeholder="例如：网站名称" /></td>
                 </tr>
            </table>
            <?php submit_button( '保存设置', 'primary', 'smtp_save' ); ?>
        </form>

        <hr />
        <h2>测试邮件发送</h2>
        <form method="post" action="">
            <?php wp_nonce_field( 'sba_smtp_save' ); ?>
            <table class="form-table">
                 <tr>
                    <th><label for="test_to">接收测试邮箱</label></th>
                    <td><input type="email" id="test_to" name="test_to" class="regular-text" placeholder="your@email.com" /></td>
                 </tr>
            </table>
            <?php submit_button( '发送测试邮件', 'secondary', 'test_email' ); ?>
        </form>
    </div>
    <?php
}

function sba_smtp_send_test_mail( $to ) {
    $subject = 'SMTP 测试邮件 - ' . get_bloginfo( 'name' );
    $message = '这是一封测试邮件，确认您的 SMTP 配置正确。';
    $headers = array( 'Content-Type: text/plain; charset=UTF-8' );
    $result = wp_mail( $to, $subject, $message, $headers );
    if ( $result ) {
        return true;
    } else {
        global $phpmailer;
        if ( isset( $phpmailer ) && $phpmailer instanceof PHPMailer\PHPMailer\PHPMailer ) {
            return $phpmailer->ErrorInfo;
        }
        return '未知错误，请检查日志。';
    }
}

add_action( 'phpmailer_init', 'sba_smtp_phpmailer_init' );
function sba_smtp_phpmailer_init( $phpmailer ) {
    $opts = get_option( 'sba_smtp_settings', array() );
    if ( empty( $opts['smtp_host'] ) ) return;
    $phpmailer->isSMTP();
    $phpmailer->Host       = $opts['smtp_host'];
    $phpmailer->Port       = $opts['smtp_port'];
    $phpmailer->SMTPAuth   = (bool) $opts['smtp_auth'];
    $enc = strtolower( $opts['smtp_encryption'] );
    if ( $enc === 'tls' ) {
        $phpmailer->SMTPSecure = PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_STARTTLS;
    } elseif ( $enc === 'ssl' ) {
        $phpmailer->SMTPSecure = PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_SMTPS;
    } else {
        $phpmailer->SMTPSecure = false;
    }
    if ( ! empty( $opts['smtp_username'] ) && ! empty( $opts['smtp_password'] ) ) {
        $phpmailer->Username   = $opts['smtp_username'];
        $phpmailer->Password   = $opts['smtp_password'];
    }
    $from_email = ! empty( $opts['from_email'] ) ? $opts['from_email'] : get_option( 'admin_email' );
    $from_name  = ! empty( $opts['from_name'] )  ? $opts['from_name']  : get_bloginfo( 'name' );
    $phpmailer->setFrom( $from_email, $from_name );
}

/* ================= 前端简码 [sba_stats] ================= */
add_shortcode( 'sba_stats', function() {
    global $wpdb;
    $online = $wpdb->get_var( "SELECT COUNT(DISTINCT ip) FROM {$wpdb->prefix}dis_stats WHERE last_visit > DATE_SUB(NOW(), INTERVAL 5 MINUTE)" );
    $latest_date = $wpdb->get_var( "SELECT MAX(visit_date) FROM {$wpdb->prefix}dis_stats" );
    if ( ! $latest_date ) $latest_date = current_time( 'Y-m-d' );
    $today = $wpdb->get_row( $wpdb->prepare( "SELECT COUNT(DISTINCT ip) as uv, SUM(pv) as pv FROM {$wpdb->prefix}dis_stats WHERE visit_date = %s", $latest_date ) );
    $online_count = $online ?: 0;
    $uv_count = $today->uv ?: 0;
    $pv_count = $today->pv ?: 0;
    return "<div class='sba-sidebar-card' style='padding:15px; background:#fff; border:1px solid #e5e7eb; border-radius:12px; box-shadow:0 1px 3px rgba(0,0,0,0.1); font-family:monospace; font-size:13px; line-height:2;'>
        <div style='display:flex; justify-content:space-between; border-bottom:1px solid #f3f4f6; padding-bottom:5px; margin-bottom:5px;'><span>● 当前在线</span><strong style='color:#10b981;'>{$online_count}</strong></div>
        <div style='display:flex; justify-content:space-between; border-bottom:1px solid #f3f4f6; padding-bottom:5px; margin-bottom:5px;'><span>📈 今日访客</span><strong style='color:#3b82f6;'>{$uv_count}</strong></div>
        <div style='display:flex; justify-content:space-between;'><span>🔥 累积浏览</span><strong style='color:#8b5cf6;'>{$pv_count}</strong></div>
    </div>";
} );
add_filter( 'widget_text', 'do_shortcode' );

/* 注销后重定向到首页 */
add_action( 'wp_logout', function() {
    wp_redirect( home_url() );
    exit;
} );
