<?php
/**
 * Plugin Name: 综合安全套件 (Site Behavior Auditor + Login Box + SMTP)
 * Description: 集成站点全行为审计、iOS风格登录/注册/忘记密码面板。
 * Version: 4.1.0
 * Author: Stone
 * Text Domain: site-behavior-auditor
 */

if (!defined('ABSPATH')) exit;

// ==================== 常量定义 ====================
define('SBA_VERSION', '4.1.0');
define('SBA_TEXT_DOMAIN', 'site-behavior-auditor');
define('SBA_IP_DATA_DIR', WP_CONTENT_DIR . '/uploads/sba_ip_data/');
define('SBA_IP_V4_FILE', SBA_IP_DATA_DIR . 'ip2region_v4.xdb');
define('SBA_IP_V6_FILE', SBA_IP_DATA_DIR . 'ip2region_v6.xdb');
define('SBA_CHUNK_SIZE_INITIAL', 2 * 1024 * 1024);
define('SBA_MIN_CHUNK_SIZE', 512 * 1024);
define('SBA_MAX_CHUNK_SIZE', 10 * 1024 * 1024);
define('SBA_PREFIX_PV', 'sba_counter_pv_today_');
define('SBA_PREFIX_UV', 'sba_counter_uv_today_');
define('SBA_PREFIX_BLOCKED', 'sba_counter_blocked_today_');
define('SBA_WRITE_LOCK_TTL', 600);
define('SBA_READ_CACHE_TTL', 600);
define('SBA_HEARTBEAT_SALT', 'sba_hb_salt_');

// ==================== 初始化 ====================
add_action( 'plugins_loaded', 'sba_load_textdomain', -1 );
function sba_load_textdomain() {
    load_plugin_textdomain(SBA_TEXT_DOMAIN, false, dirname(plugin_basename(__FILE__)) . '/languages');
}

$sba_lib_path = plugin_dir_path(__FILE__) . 'lib/ip2region/xdb/Searcher.class.php';
define('SBA_USE_OFFICIAL', file_exists($sba_lib_path));
if (SBA_USE_OFFICIAL) require_once $sba_lib_path;

if (!defined('SBA_RAW_POST_DATA')) {
    define('SBA_RAW_POST_DATA', file_get_contents('php://input') ?: '');
}

add_action('admin_notices', 'sba_official_lib_missing_notice');
function sba_official_lib_missing_notice() {
    if (SBA_USE_OFFICIAL) return;
    $screen = get_current_screen();
    if ($screen && strpos($screen->id, 'sba_') === false && strpos($screen->id, 'toplevel_page_sba_audit') === false) return;
    echo '<div class="notice notice-warning is-dismissible"><p>⚠️ <strong>' . __('SBA 安全套件', SBA_TEXT_DOMAIN) . '</strong>：' .
        __('未检测到官方 ip2region 类库，已自动降级为内置简化版（仅支持 IPv4 查询）。如需完整 IPv6 支持，请将官方类库放置于', SBA_TEXT_DOMAIN) .
        ' <code>' . plugin_dir_path(__FILE__) . 'lib/ip2region/xdb/Searcher.class.php</code>。</p></div>';
}

// ==================== 数据库安装 ====================
register_activation_hook(__FILE__, 'sba_install');
function sba_install() {
    if (!file_exists(SBA_IP_DATA_DIR)) wp_mkdir_p(SBA_IP_DATA_DIR);
    if (!file_exists(SBA_IP_DATA_DIR . '.htaccess')) file_put_contents(SBA_IP_DATA_DIR . '.htaccess', "Deny from all\n");

    global $wpdb;
    $charset = $wpdb->get_charset_collate();

    $tables = [
        "CREATE TABLE IF NOT EXISTS {$wpdb->prefix}dis_stats (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            ip VARCHAR(45), url TEXT, visit_date DATE, visit_hour TINYINT,
            pv INT DEFAULT 1, last_visit TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE KEY ip_date_url (ip, visit_date, url(191)),
            INDEX idx_composite (visit_date, visit_hour, last_visit DESC),
            INDEX idx_lookup (visit_date, last_visit DESC)
        ) $charset;",
        "CREATE TABLE IF NOT EXISTS {$wpdb->prefix}sba_blocked_log (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            ip VARCHAR(45), reason VARCHAR(100), target_url TEXT,
            block_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_block_time (block_time)
        ) $charset;",
        "CREATE TABLE IF NOT EXISTS {$wpdb->prefix}sba_login_failures (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            ip VARCHAR(45) NOT NULL UNIQUE,
            failed_count INT DEFAULT 0, last_failed_time DATETIME,
            banned_until DATETIME, request_count INT DEFAULT 0, last_request_time DATETIME
        ) $charset;",
        "CREATE TABLE IF NOT EXISTS {$wpdb->prefix}sba_threat_summary (
            ip VARCHAR(45) NOT NULL PRIMARY KEY,
            total_blocks INT DEFAULT 0,
            last_block_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_total_blocks (total_blocks DESC)
        ) $charset;"
    ];

    require_once ABSPATH . 'wp-admin/includes/upgrade.php';
    foreach ($tables as $sql) dbDelta($sql);

    if (version_compare(get_option('sba_version', '0'), '2.0', '<')) {
        $wpdb->query("DROP TABLE IF EXISTS {$wpdb->prefix}sba_ip_data");
        delete_option('sba_geo_v1');
    }

    $defaults = [
        'auto_block_limit' => '60',
        'evil_paths' => '',
        'block_target_url' => '',
        'user_whitelist' => '',
        'ip_whitelist' => '',
        'scraper_paths' => 'feed=|rest_route=|[\?&]m=|\?p=',
        'enable_cookie_check' => 1,
        'ssrf_prevent_dns_rebind' => 1,
        'outbound_whitelist' => '',
        'ssrf_blacklist' => '',
        'enable_ajax_patch' => 0,
        'ip_source' => 'REMOTE_ADDR',
    ];
    $cur = get_option('sba_settings', []);
    if (empty($cur)) {
        update_option('sba_settings', $defaults);
    } else {
        $updated = false;
        foreach ($defaults as $k => $v) {
            if (!isset($cur[$k])) {
                $cur[$k] = $v;
                $updated = true;
            }
        }
        if (isset($cur['login_slug'])) {
            unset($cur['login_slug']);
            $updated = true;
        }
        if ($updated) update_option('sba_settings', $cur);
    }

    if (!get_option('sba_smtp_settings')) update_option('sba_smtp_settings', [
        'smtp_host' => '', 'smtp_port' => '587', 'smtp_encryption' => 'tls',
        'smtp_auth' => 1, 'smtp_username' => '', 'smtp_password' => '',
        'from_email' => '', 'from_name' => '',
    ]);

    $summary_count = $wpdb->get_var("SELECT COUNT(*) FROM {$wpdb->prefix}sba_threat_summary");
    if ($summary_count == 0) {
        $wpdb->query("INSERT INTO {$wpdb->prefix}sba_threat_summary (ip, total_blocks, last_block_time)
            SELECT ip, COUNT(*), MAX(block_time)
            FROM {$wpdb->prefix}sba_blocked_log
            WHERE block_time > DATE_SUB(NOW(), INTERVAL 30 DAY)
            GROUP BY ip
            ON DUPLICATE KEY UPDATE total_blocks = VALUES(total_blocks)");
    }

    update_option('sba_version', SBA_VERSION);
    if (!wp_next_scheduled('sba_daily_cleanup')) wp_schedule_event(time(), 'daily', 'sba_daily_cleanup');
    if (!wp_next_scheduled('sba_weekly_optimize')) wp_schedule_event(strtotime('next sunday 3:00'), 'weekly', 'sba_weekly_optimize');

    $today = current_time('Y-m-d');
    foreach ([SBA_PREFIX_UV, SBA_PREFIX_PV, SBA_PREFIX_BLOCKED] as $p) {
        if (get_option($p . $today) === false) update_option($p . $today, 0, false);
    }
}

register_deactivation_hook(__FILE__, 'sba_on_deactivation');
function sba_on_deactivation() {
    $today = current_time('Y-m-d');
    sba_flush_pv_buffer_batch($today);
    delete_transient('sba_pv_flush_lock_' . $today);
    wp_clear_scheduled_hook('sba_daily_cleanup');
    wp_clear_scheduled_hook('sba_weekly_optimize');
}

add_action('sba_daily_cleanup', 'sba_cleanup_old_data');
function sba_cleanup_old_data() {
    global $wpdb;
    $wpdb->query("DELETE FROM {$wpdb->prefix}dis_stats WHERE visit_date < DATE_SUB(NOW(), INTERVAL 30 DAY)");
    $wpdb->query("DELETE FROM {$wpdb->prefix}sba_blocked_log WHERE block_time < DATE_SUB(NOW(), INTERVAL 7 DAY)");
    $wpdb->query("DELETE FROM {$wpdb->prefix}sba_login_failures WHERE last_failed_time < DATE_SUB(NOW(), INTERVAL 30 DAY)");
    $wpdb->query("DELETE FROM {$wpdb->prefix}sba_threat_summary WHERE last_block_time < DATE_SUB(NOW(), INTERVAL 30 DAY)");

    for ($i = 31; $i <= 60; $i++) {
        $old_date = date('Y-m-d', strtotime("-$i days"));
        delete_option(SBA_PREFIX_PV . $old_date);
        delete_option(SBA_PREFIX_UV . $old_date);
        delete_option(SBA_PREFIX_BLOCKED . $old_date);
    }
    sba_clear_trend_cache();
}

add_action('sba_weekly_optimize', 'sba_weekly_optimize');
function sba_weekly_optimize() {
    global $wpdb;
    $tables = ["{$wpdb->prefix}dis_stats", "{$wpdb->prefix}sba_blocked_log", "{$wpdb->prefix}sba_login_failures", "{$wpdb->prefix}sba_threat_summary"];
    foreach ($tables as $table) $wpdb->query("OPTIMIZE TABLE $table");
}

// ==================== 基础工具函数 ====================
function sba_get_ip() {
    static $ip = null;
    if ($ip !== null) return $ip;
    $header_pool = [
        'HTTP_CF_CONNECTING_IP', 'HTTP_X_REAL_IP', 'HTTP_X_FORWARDED_FOR',
        'HTTP_CLIENT_IP', 'HTTP_X_CLIENT_IP', 'HTTP_X_CLUSTER_CLIENT_IP',
        'HTTP_FORWARDED_FOR', 'HTTP_FORWARDED', 'HTTP_VIA',
        'HTTP_TRUE_CLIENT_IP', 'HTTP_ALI_CDN_REAL_IP', 'REMOTE_ADDR'
    ];

    $all_found = [];
    foreach ($header_pool as $h) {
        if (empty($_SERVER[$h])) continue;
        $parts = explode(',', $_SERVER[$h]);
        if (stripos($h, 'FORWARDED') !== false) $parts = array_reverse($parts);

        foreach ($parts as $p) {
            $p = trim($p);
            if (strpos($p, '[') === 0 && ($closing_bracket = strpos($p, ']')) !== false) {
                $p = substr($p, 1, $closing_bracket - 1);
            } elseif (strpos($p, ':') !== false && strpos($p, ':') === strrpos($p, ':')) {
                $p = explode(':', $p)[0];
            }
            if (filter_var($p, FILTER_VALIDATE_IP)) $all_found[] = $p;
        }
    }

    foreach ($all_found as $candidate) {
        if (filter_var($candidate, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
            return $ip = $candidate;
        }
    }

    if (!empty($all_found)) {
        $ip = $all_found[0];
    } else {
        $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    }

    return $ip;
}

function sba_get_option($key, $default = '') {
    $opts = get_option('sba_settings', []);
    return isset($opts[$key]) && $opts[$key] !== '' ? $opts[$key] : $default;
}

function sba_is_search_engine() {
    $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
    if (empty($ua)) return false;
    $bots = ['Googlebot', 'Baiduspider', 'bingbot', 'msnbot', 'BingPreview', 'MicrosoftPreview', 'Sogou', 'YisouSpiderman', '360Spider', 'YandexBot', 'Applebot', 'DuckDuckBot', 'DotBot', 'PetalBot'];
    foreach ($bots as $b) if (stripos($ua, $b) !== false) return true;
    return false;
}

function sba_is_user_whitelisted() {
    if (!function_exists('wp_get_current_user')) return false;
    $user = wp_get_current_user();
    if (!$user->exists()) return false;
    if ($user->ID === 1) return true;
    $list = array_filter(array_map('trim', explode(',', sba_get_option('user_whitelist', ''))));
    return in_array($user->user_login, $list);
}

function sba_is_ip_whitelisted($ip = null) {
    $ip = $ip ?: sba_get_ip();
    if (empty($ip) || $ip === '0.0.0.0') return false;

    if (function_exists('current_user_can') && current_user_can('manage_options')) return true;

    $opts = get_option('sba_settings', []);
    $raw = str_replace(["\r", "\n"], ',', (string)($opts['ip_whitelist'] ?? ''));
    $list = array_filter(array_map('trim', explode(',', $raw)));

    $current_ip_hex = bin2hex((string)@inet_pton($ip));

    foreach ($list as $w_ip) {
        if ($ip === $w_ip) return true;
        $w_ip_hex = bin2hex((string)@inet_pton($w_ip));
        if (!empty($w_ip_hex) && $current_ip_hex === $w_ip_hex) return true;
    }
    return false;
}

function sba_is_internal_ip($ip = null) {
    $ip = $ip ?: sba_get_ip();
    if ($ip === '127.0.0.1' || $ip === '::1') return true;
    return !filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE);
}

function sba_normalize_uri($raw_uri) {
    static $cache = [];
    $key = md5($raw_uri);
    if (isset($cache[$key])) return $cache[$key];

    if (sba_is_ip_whitelisted()) {
        $result = $raw_uri;
        $depth = 0;
        while ($depth++ < 5 && strpos($result, '%') !== false) {
            $decoded = rawurldecode($result);
            if ($decoded === $result) break;
            $result = $decoded;
        }
        $result = preg_replace('#/\./#', '/', $result);
        $cache[$key] = $result;
        return $result;
    }

    if (strpos($raw_uri, '%00') !== false) sba_execute_block(__('空字节注入攻击', SBA_TEXT_DOMAIN));

    $result = $raw_uri;
    $depth = 0;
    while ($depth++ < 5 && strpos($result, '%') !== false) {
        $decoded = rawurldecode($result);
        if (strpos($decoded, "\0") !== false) sba_execute_block(__('空字节注入攻击', SBA_TEXT_DOMAIN));
        if ($decoded === $result) break;
        $result = $decoded;
    }
    $result = preg_replace('#/\./#', '/', $result);
    $cache[$key] = $result;
    return $result;
}

function sba_scan_malicious_payload() {
    $qs = $_SERVER['QUERY_STRING'] ?? '';
    $post_body = defined('SBA_RAW_POST_DATA') ? SBA_RAW_POST_DATA : '';
    if (empty($qs) && empty($post_body) && empty($_GET) && empty($_POST)) return false;

    $inputs = [$qs, $post_body];
    foreach ($_GET as $v) if (is_string($v)) $inputs[] = $v;
    foreach ($_POST as $v) if (is_string($v)) $inputs[] = $v;
    $combined = implode("\n", $inputs);

    $pattern = '/(?:\b(?:system|exec|passthru|shell_exec|popen|proc_open|eval|assert|create_function|base64_decode|gzinflate)\s*\(|`[^`]*`|\b(?:sleep|benchmark)\s*\(\s*[\d]+|information_schema\.|load_file\s*\(|into\s+(?:outfile|dumpfile)|(?:;|\||&)\s*(?:ls|cat|dir|id|whoami|net\s+user)|phpinfo\s*\(|eval\s*\(\s*base64_decode\s*\(|\b(?:php|data|expect|phar|zip|zlib):\/\/)/i';
    return preg_match($pattern, $combined) === 1;
}

function sba_is_static_resource($uri) {
    static $exts = null;
    if ($exts === null) $exts = implode('|', ['jpg','jpeg','png','gif','webp','svg','bmp','css','js','map','ico','woff','woff2','ttf','eot','mp4','webm','pdf','zip','rar','7z']);
    return (bool)preg_match('/\.(' . $exts . ')(?:\?.*)?$/i', $uri);
}

// ==================== 安全头与指纹抹除 ====================
add_action('init', 'sba_remove_version_fingerprints');
function sba_remove_version_fingerprints() {
    remove_action('wp_head', 'wp_generator');
    add_filter('the_generator', '__return_empty_string');
    add_filter('style_loader_src', 'sba_remove_script_version', 9999);
    add_filter('script_loader_src', 'sba_remove_script_version', 9999);
    header_remove('X-Powered-By');
}
function sba_remove_script_version($src) {
    return strpos($src, 'ver=') ? remove_query_arg('ver', $src) : $src;
}

add_action('send_headers', 'sba_security_headers');
function sba_security_headers() {
    if (is_admin() && !defined('DOING_AJAX')) return;
    header('X-Frame-Options: SAMEORIGIN');
    header('X-Content-Type-Options: nosniff');
    header('Referrer-Policy: strict-origin-when-cross-origin');
    header("Permissions-Policy: geolocation=(), microphone=(), camera=(), payment=(), usb=()");
    if (!is_admin() && !isset($_GET['action'])) header('X-XSS-Protection: 1; mode=block');
    if (is_ssl()) header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
}

// ==================== REST API 目录锁 ====================
add_action('rest_api_init', function() {
    if (!is_user_logged_in() && !sba_is_ip_whitelisted()) {
        $route = $_SERVER['REQUEST_URI'] ?? '';
        if (strpos($route, '/wp-json/') !== false && strpos($route, '/wp-json/sba_') !== 0) {
            wp_die(__('REST API 访问受限', SBA_TEXT_DOMAIN), 403);
        }
    }
});

add_filter('rest_endpoints', 'sba_disable_user_endpoints');
function sba_disable_user_endpoints($endpoints) {
    if (!is_user_logged_in()) {
        $blocked = [
            '/wp/v2/users', '/wp/v2/users/(?P<id>[\d]+)',
            '/wp/v2/posts', '/wp/v2/posts/(?P<id>[\d]+)',
            '/wp/v2/pages', '/wp/v2/pages/(?P<id>[\d]+)',
            '/wp/v2/comments', '/wp/v2/comments/(?P<id>[\d]+)',
            '/wp/v2/media', '/wp/v2/media/(?P<id>[\d]+)',
            '/wp/v2/types', '/wp/v2/types/(?P<type>[\w-]+)',
            '/wp/v2/taxonomies', '/wp/v2/taxonomies/(?P<taxonomy>[\w-]+)',
            '/wp/v2/settings', '/wp/v2/themes', '/wp/v2/themes/(?P<stylesheet>[\w-]+)',
            '/wp/v2/plugins', '/wp/v2/plugins/(?P<plugin>[\w-]+/[\w-]+)',
            '/wp/v2/blocks', '/wp/v2/blocks/(?P<id>[\d]+)',
            '/wp/v2/block-types', '/wp/v2/block-types/(?P<namespace>[\w-]+)/(?P<name>[\w-]+)',
            '/wp/v2/block-renderer/(?P<name>[\w-]+/[\w-]+)',
            '/wp/v2/search', '/wp/v2/categories', '/wp/v2/categories/(?P<id>[\d]+)',
            '/wp/v2/tags', '/wp/v2/tags/(?P<id>[\d]+)',
            '/wp/v2/font-families', '/wp/v2/font-families/(?P<id>[\d]+)',
            '/wp/v2/font-faces', '/wp/v2/font-faces/(?P<id>[\d]+)',
        ];
        foreach ($blocked as $r) unset($endpoints[$r], $endpoints['/wp/v2' . $r]);
    }
    return $endpoints;
}

add_filter('rest_pre_dispatch', 'sba_rest_pre_dispatch', 10, 3);
function sba_rest_pre_dispatch($result, $server, $request) {
    if (!is_user_logged_in() && !sba_is_ip_whitelisted()) {
        $route = $request->get_route();
        $patterns = ['#/wp/v2/(users|posts|pages|comments|media|types|taxonomies|statuses|settings|themes|plugins|blocks|block-types|block-renderer|search|categories|tags|font-families|font-faces)#i'];
        foreach ($patterns as $p) {
            if (preg_match($p, $route)) return new WP_Error('rest_forbidden', __('无权限访问此 API', SBA_TEXT_DOMAIN), ['status' => 403]);
        }
    }
    return $result;
}

add_filter('rest_pre_serve_request', 'sba_rest_pre_serve', 10, 4);
function sba_rest_pre_serve($served, $result, $request, $server) {
    if (!is_user_logged_in() && !sba_is_ip_whitelisted()) {
        $route = $request->get_route();
        if ($route === '/' || $route === '/wp/v2' || empty($route)) {
            status_header(403);
            echo json_encode(['code' => 'rest_forbidden', 'message' => __('REST API 索引访问受限', SBA_TEXT_DOMAIN)]);
            return true;
        }
    }
    return $served;
}

// ==================== Cookie 验证与速率限制 ====================
function sba_has_valid_cookie() {
    static $valid = null;
    if ($valid !== null) return $valid;
    $ip = sba_get_ip();
    $name = 'sba_human_' . md5($ip);
    if (!isset($_COOKIE[$name])) return false;
    $salt = function_exists('wp_salt') ? wp_salt() : (defined('NONCE_SALT') ? NONCE_SALT : 'fallback');
    $expected = hash_hmac('sha256', $ip . NONCE_SALT, $salt);
    return hash_equals($expected, $_COOKIE[$name]);
}

function sba_set_human_cookie() {
    $ip = sba_get_ip();
    $name = 'sba_human_' . md5($ip);
    $salt = function_exists('wp_salt') ? wp_salt() : (defined('NONCE_SALT') ? NONCE_SALT : 'fallback');
    $value = hash_hmac('sha256', $ip . NONCE_SALT, $salt);
    setcookie($name, $value, time() + 86400, COOKIEPATH, COOKIE_DOMAIN, is_ssl(), true);
}

function sba_check_rate_limit($ip, $limit) {
    if ($limit <= 0) return false;
    $key = 'sba_cc_' . $ip;
    $count = get_transient($key);
    if ($count === false) { set_transient($key, 1, 60); return false; }
    if ($count >= $limit) return true;
    set_transient($key, $count + 1, 60);
    return false;
}

function sba_execute_block($reason) {
    $ip = sba_get_ip();
    if (empty($ip) || $ip === '0.0.0.0') return;
    if (sba_is_ip_whitelisted($ip)) return;

    global $wpdb;
    $wpdb->insert($wpdb->prefix . 'sba_blocked_log', [
        'ip' => $ip,
        'reason' => $reason,
        'target_url' => $_SERVER['REQUEST_URI']
    ]);
    $wpdb->query($wpdb->prepare(
        "INSERT INTO {$wpdb->prefix}sba_threat_summary (ip, total_blocks, last_block_time)
         VALUES (%s, 1, NOW()) ON DUPLICATE KEY UPDATE total_blocks = total_blocks + 1, last_block_time = NOW()", $ip));
    sba_inc_blocked();

    $url = sba_get_option('block_target_url', '');
    if (!empty($url) && filter_var($url, FILTER_VALIDATE_URL)) {
        wp_redirect($url);
        exit;
    }
    wp_die(sprintf(__("🛡️ SBA 拦截：%s", SBA_TEXT_DOMAIN), $reason), __('Security Block', SBA_TEXT_DOMAIN), 403);
    exit;
}

// ==================== 蜜罐陷阱 ====================
add_action('wp_footer', 'sba_output_honeypot_links', 999);
function sba_output_honeypot_links() {
    if (is_user_logged_in() || sba_is_search_engine()) return;
    $salt = defined('NONCE_SALT') ? NONCE_SALT : 'sba_default_salt';
    $token = substr(md5(date('Y-m-d') . $salt), 0, 8);
    $param = 'sba_trap_' . $token;
    echo '<a href="' . home_url('/?' . $param . '=1') . '" style="display:none" aria-hidden="true" rel="nofollow">.</a>';
}

// ==================== 高性能计数器引擎 ====================
function sba_atomic_increment($prefix) {
    $today = current_time('Y-m-d');
    $key = $prefix . $today;
    $val = (int)get_option($key, 0);
    update_option($key, $val + 1, false);
    wp_cache_delete($key, 'options');
    sba_clear_trend_cache();
    return true;
}

function sba_get_counter($prefix, $date = null) {
    $date = $date ?: current_time('Y-m-d');
    $opt_key = $prefix . $date;
    $snapshot = 'sba_read_snapshot_' . $opt_key;
    $is_admin = function_exists('current_user_can') && current_user_can('manage_options');
    $force = isset($_SERVER['HTTP_CACHE_CONTROL']) && $_SERVER['HTTP_CACHE_CONTROL'] === 'no-cache' && $is_admin && $prefix === SBA_PREFIX_PV;

    if ($force) {
        $total_in_buf = (int)get_transient('sba_pv_dirty_buffer_' . $date);
        if ($total_in_buf > 0) {
            sba_flush_pv_buffer_batch($date, $total_in_buf);
            set_transient('sba_pv_dirty_buffer_' . $date, 0, HOUR_IN_SECONDS);
        }
    }

    if (!$force) {
        $cached = get_transient($snapshot);
        if ($cached !== false) return (int)$cached;
    }

    global $wpdb;
    $real = 0;
    if ($prefix === SBA_PREFIX_UV) {
        $real = (int)$wpdb->get_var($wpdb->prepare("SELECT COUNT(DISTINCT ip) FROM {$wpdb->prefix}dis_stats WHERE visit_date = %s", $date));
    } elseif ($prefix === SBA_PREFIX_PV) {
        $db_val = (int)get_option($opt_key, 0);
        $buffer_val = (int)get_transient('sba_pv_dirty_buffer_' . $date);
        $real = $db_val + $buffer_val;
    } elseif ($prefix === SBA_PREFIX_BLOCKED) {
        $real = (int)$wpdb->get_var($wpdb->prepare("SELECT COUNT(*) FROM {$wpdb->prefix}sba_blocked_log WHERE DATE(block_time) = %s", $date));
    }

    if ($prefix !== SBA_PREFIX_PV) update_option($opt_key, $real, false);
    set_transient($snapshot, $real, SBA_READ_CACHE_TTL);
    return $real;
}

function sba_inc_pv() {
    static $last_lock_attempt = 0;
    $date = current_time('Y-m-d');
    $buffer_key = 'sba_pv_dirty_buffer_' . $date;
    $last_flush_key = 'sba_pv_last_flush_' . $date;
    $lock_key = 'sba_pv_flush_lock_' . $date;

    $current = (int)get_transient($buffer_key);
    set_transient($buffer_key, $current + 1, HOUR_IN_SECONDS);

    $last_flush = (int)get_transient($last_flush_key);
    $now = time();
    if (($now - $last_flush) >= 600) {
        if ($now - $last_lock_attempt >= 5) {
            $last_lock_attempt = $now;
            if (add_option($lock_key, $now, '', 'no')) {
                $total = (int)get_transient($buffer_key);
                if ($total > 0) sba_flush_pv_buffer_batch($date, $total);
                set_transient($buffer_key, 0, HOUR_IN_SECONDS);
                set_transient($last_flush_key, $now, HOUR_IN_SECONDS);
                delete_option($lock_key);
            } else {
                $lock_time = (int)get_option($lock_key);
                if ($now - $lock_time > 600) delete_option($lock_key);
            }
        }
    }
}

function sba_flush_pv_buffer_batch($date, $increment = 0) {
    if ($increment <= 0) return;
    $key = SBA_PREFIX_PV . $date;
    global $wpdb;
    $wpdb->query($wpdb->prepare(
        "INSERT INTO {$wpdb->options} (option_name, option_value, autoload) VALUES (%s, %s, 'no') ON DUPLICATE KEY UPDATE option_value = option_value + %d",
        $key, (string)$increment, $increment
    ));
    delete_transient('sba_read_snapshot_' . $key);
    sba_clear_trend_cache();
}

function sba_inc_uv() { return sba_atomic_increment(SBA_PREFIX_UV); }
function sba_inc_blocked() { return sba_atomic_increment(SBA_PREFIX_BLOCKED); }
function sba_get_pv($d = null) { return sba_get_counter(SBA_PREFIX_PV, $d); }
function sba_get_uv($d = null) { return sba_get_counter(SBA_PREFIX_UV, $d); }
function sba_get_blocked($d = null) { return sba_get_counter(SBA_PREFIX_BLOCKED, $d); }
function sba_get_trend_data($days = 30) {
    $key = 'sba_trend_v4_' . $days;
    $cached = get_transient($key);
    if ($cached !== false) return $cached;
    $result = ['labels' => [], 'uv' => [], 'pv' => [], 'blocked' => []];
    $end_ts = strtotime(current_time('Y-m-d'));
    for ($i = $days - 1; $i >= 0; $i--) {
        $d = date('Y-m-d', $end_ts - $i * 86400);
        $result['labels'][] = $d;
        $result['uv'][] = sba_get_uv($d);
        $result['pv'][] = sba_get_pv($d);
        $result['blocked'][] = sba_get_blocked($d);
    }
    set_transient($key, $result, SBA_READ_CACHE_TTL);
    return $result;
}
function sba_clear_trend_cache() {
    foreach ([7, 14, 30, 50] as $d) delete_transient('sba_trend_v4_' . $d);
}

function sba_mask_ip($ip) {
    if (current_user_can('manage_options') || sba_is_user_whitelisted()) return $ip;
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        $parts = explode('.', $ip);
        if (count($parts) === 4) return $parts[0] . '.' . $parts[1] . '.***.***';
    } elseif (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
        $short = inet_ntop(inet_pton($ip));
        $parts = explode(':', $short);
        if (count($parts) >= 3) return $parts[0] . ':' . $parts[1] . ':***:***:***:***:***:***';
    }
    return '***.***.***.***';
}

// ==================== 统计引擎与安全检测 ====================
add_action('plugins_loaded', 'sba_stats_engine', 0);
function sba_stats_engine() {
    if (!function_exists('is_user_logged_in')) require_once ABSPATH . WPINC . '/pluggable.php';
    $is_admin = function_exists('current_user_can') && current_user_can('manage_options');
    $ip = sba_get_ip();
    $opts = get_option('sba_settings', []);

    $raw_uri = $_SERVER['REQUEST_URI'] ?? '';
    $uri = sba_normalize_uri($raw_uri);
    $rest_route = sba_normalize_uri($_GET['rest_route'] ?? '');

    // 应急密钥
    $provided_key = $_GET['sba_key'] ?? '';
    $emergency_key = $opts['emergency_entrance_key'] ?? '';
    if (!empty($provided_key) && !empty($emergency_key) && $provided_key === $emergency_key) {
        $whitelist = (string)($opts['ip_whitelist'] ?? '');
        if (stripos($whitelist, $ip) === false) {
            $opts['ip_whitelist'] = trim($whitelist) . "\n" . $ip;
            update_option('sba_settings', $opts);
            wp_cache_delete('sba_settings', 'options');
        }
        wp_redirect(home_url('/?sba_msg=whitelisted'));
        exit;
    }

    // XML-RPC 防护
    if (strpos($uri, 'xmlrpc.php') !== false) {
        $fail_key = 'sba_xmlrpc_fail_' . md5($ip);
        $attempts = (int)get_transient($fail_key) + 1;
        set_transient($fail_key, $attempts, HOUR_IN_SECONDS);
        if ($attempts >= 10) {
            set_transient('sba_temp_block_' . $ip, 1, 900);
            sba_execute_block(__('XML-RPC 请求过多，IP 已被临时封锁', SBA_TEXT_DOMAIN));
        }
        $xml_body = defined('SBA_RAW_POST_DATA') ? SBA_RAW_POST_DATA : '';
        if ($_SERVER['REQUEST_METHOD'] === 'POST' && (stripos($xml_body, '<methodName>pingback.ping') !== false || stripos($xml_body, '<methodName>system.multicall') !== false)) {
            sba_execute_block(__('XML-RPC 高危方法拦截', SBA_TEXT_DOMAIN));
        }
    }

    if (is_admin()) return;
    if (isset($_GET['action']) && $_GET['action'] === 'logout') return;
    if (defined('DOING_AJAX') && DOING_AJAX && strpos($_POST['action'] ?? '', 'sba_ios_') === 0) return;

    // 统计逻辑
    if (!sba_is_internal_ip($ip)) {
        if (!defined('SBA_TRACKED')) define('SBA_TRACKED', true);
        $now = current_time('mysql');
        $date = substr($now, 0, 10);
        $hour = (int)substr($now, 11, 2);
        $lock = 'sba_write_lock_' . $ip . '_' . $date;
        if (get_transient($lock) === false) {
            $uv_cookie = 'sba_uv_' . str_replace('-', '', $date);
            if (!isset($_COOKIE[$uv_cookie])) {
                sba_inc_uv();
                setcookie($uv_cookie, '1', strtotime('tomorrow'), COOKIEPATH, COOKIE_DOMAIN, is_ssl(), true);
            }
            global $wpdb;
            $wpdb->query($wpdb->prepare(
                "INSERT INTO {$wpdb->prefix}dis_stats (ip, url, visit_date, visit_hour, pv, last_visit)
                 VALUES (%s, %s, %s, %d, 1, %s) ON DUPLICATE KEY UPDATE pv = pv + 1, last_visit = %s",
                $ip, $raw_uri, $date, $hour, $now, $now
            ));
            set_transient($lock, '1', SBA_WRITE_LOCK_TTL);
        }
        sba_inc_pv();
    }

    if (sba_is_ip_whitelisted($ip)) return;

    $is_static = sba_is_static_resource($uri);
    if ($is_static && !$is_admin) {
        if (sba_scan_malicious_payload()) sba_execute_block(__('恶意载荷注入（静态资源）', SBA_TEXT_DOMAIN));
        return;
    }

    // 完整安全检测
    $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
    $is_bot = sba_is_search_engine();

    // 蜜罐陷阱
    foreach ($_GET as $key => $val) {
        if (strpos($key, 'sba_trap_') === 0) {
            if ($is_bot) { status_header(404); exit; }
            sba_execute_block(__('触碰隐藏蜜罐陷阱', SBA_TEXT_DOMAIN));
        }
    }

    // 敏感文件探测（基础 + 扩展）
    $sensitive_patterns = [
        '/\.sql$/' => __('探测敏感文件: SQL', SBA_TEXT_DOMAIN),
        '/\.log$/' => __('探测敏感文件: LOG', SBA_TEXT_DOMAIN),
        '/\.bak$/' => __('探测敏感文件: BAK', SBA_TEXT_DOMAIN),
        '/\.env$/' => __('探测敏感文件: ENV', SBA_TEXT_DOMAIN),
        '/\.git/' => __('探测敏感文件: GIT', SBA_TEXT_DOMAIN),
        '/\.svn/' => __('探测敏感文件: SVN', SBA_TEXT_DOMAIN),
        '/readme\.html$/' => __('探测敏感文件: README', SBA_TEXT_DOMAIN),
        '/license\.txt$/' => __('探测敏感文件: LICENSE', SBA_TEXT_DOMAIN),
        '/wp-config\.php/' => __('探测敏感文件: CONFIG', SBA_TEXT_DOMAIN),
        '/phpinfo\.php/' => __('探测敏感文件: PHPINFO', SBA_TEXT_DOMAIN),
        '/\.htaccess$/' => __('探测敏感文件: HTACCESS', SBA_TEXT_DOMAIN),
        '/\.htpasswd$/' => __('探测敏感文件: HTPASSWD', SBA_TEXT_DOMAIN),
        '/\.ini$/' => __('探测敏感文件: INI', SBA_TEXT_DOMAIN),
        '/wp-mail\.php$/' => __('探测敏感文件: MAIL', SBA_TEXT_DOMAIN),
        '/wp-links-opml\.php$/' => __('探测敏感文件: OPML', SBA_TEXT_DOMAIN),
        '/\.bgbk$/i' => __('备份文件 (.bgbk)', SBA_TEXT_DOMAIN),
        '/\.(zip|tar\.gz|7z|rar|sql\.gz)$/i' => __('压缩包文件', SBA_TEXT_DOMAIN),
        '/\.(db|sqlite|sqlite3)$/i' => __('数据库文件', SBA_TEXT_DOMAIN),
        '/\/docker-compose\.ya?ml$/i' => __('Docker Compose 配置', SBA_TEXT_DOMAIN),
        '/\/Dockerfile$/i' => __('Dockerfile', SBA_TEXT_DOMAIN),
        '/\.(idea|vscode)\//i' => __('IDE 配置目录', SBA_TEXT_DOMAIN),
        '/\/(package\.json|package-lock\.json|node_modules\/)/i' => __('Node.js 项目文件', SBA_TEXT_DOMAIN),
        '/\/wp-content\/debug\.log$/i' => __('WordPress 调试日志', SBA_TEXT_DOMAIN),
        '/\.env\.(local|example|production)$/i' => __('环境配置备份', SBA_TEXT_DOMAIN),
        '/\.(swp|swo|old|orig)$/i' => __('编辑器临时文件', SBA_TEXT_DOMAIN),
        '/\.(bak[0-9]+|backup)$/i' => __('自动备份文件', SBA_TEXT_DOMAIN),
    ];
    foreach ($sensitive_patterns as $pattern => $msg) {
        if (preg_match($pattern, $uri)) sba_execute_block($msg);
    }

    // 非法路径探测
    $evil_paths = array_filter(array_map('trim', explode(',', sba_get_option('evil_paths', ''))));
    $builtin_evil = ['/.env', '/.git', '/.sql', '/.ssh', '/wp-config.php.bak', '/phpinfo.php', '/config.php.swp', '/.vscode', '/wp-links-opml.php', '/wp-admin/install.php'];
    foreach (array_merge($builtin_evil, $evil_paths) as $p) {
        if (!empty($p) && strpos($uri, $p) !== false) sba_execute_block(sprintf(__('非法路径探测: %s', SBA_TEXT_DOMAIN), $p));
    }

    // 自动化扫描 UA 拦截
    $bad_ua = ['sqlmap', 'nmap', 'dirbuster', 'nikto', 'zgrab', 'python-requests', 'go-http-client', 'java/', 'curl/', 'wget', 'masscan'];
    if (!$is_bot && !empty($ua)) {
        foreach ($bad_ua as $b) {
            if (stripos($ua, $b) !== false) sba_execute_block(sprintf(__('自动化扫描: %s', SBA_TEXT_DOMAIN), $b));
        }
    }

    if (sba_scan_malicious_payload()) sba_execute_block(__('恶意载荷注入（命令/SQL/XSS/文件包含）', SBA_TEXT_DOMAIN));
}

// ==================== 动态规则引擎 ====================
add_action('init', 'sba_security_engine', 5);
function sba_security_engine() {
    $ip = sba_get_ip();
    if (sba_is_ip_whitelisted($ip)) return;

    $raw_uri = $_SERVER['REQUEST_URI'] ?? '';
    $uri = sba_normalize_uri($raw_uri);
    $rest_route = sba_normalize_uri($_GET['rest_route'] ?? '');
    $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
    $action = $_REQUEST['action'] ?? '';
    $is_bot = sba_is_search_engine();
    $is_logged_in = is_user_logged_in();

    if ((defined('DOING_AJAX') && DOING_AJAX) || strpos($raw_uri, 'admin-ajax.php') !== false) {
        if (strpos($_POST['action'] ?? '', 'sba_ios_') === 0) return;
    }

    // wp-login.php 物理封锁
    $script_name = $_SERVER['SCRIPT_NAME'] ?? '';
    if (strpos($raw_uri, 'wp-login.php') !== false || strpos($script_name, 'wp-login.php') !== false || strpos($raw_uri, 'wp-signup.php') !== false) {
        if ($is_logged_in) {
            if ($action === 'logout') return;
            wp_redirect(admin_url());
            exit;
        }
        $allowed = ['rp', 'resetpass', 'logout', 'postpass', 'checkemail'];
        if (!in_array($action, $allowed)) sba_execute_block(__('物理封锁：入口禁用', SBA_TEXT_DOMAIN));
        return;
    }

    if (is_admin() && !$is_logged_in) sba_execute_block(__('物理封锁：未经授权', SBA_TEXT_DOMAIN));

    $legit = ['register', 'lostpassword', 'retrievepassword', 'rp', 'resetpass', 'postpass', 'checkemail'];
    if (in_array($action, $legit)) {
        $qs = $_SERVER['QUERY_STRING'] ?? '';
        if (!empty($qs)) {
            if (preg_match('/(template|theme|paged|setup|gshst)=?/i', $qs) && !isset($_GET['reauth'])) sba_execute_block(__('非法扫描参数拦截', SBA_TEXT_DOMAIN));
            if (preg_match('/&[^=]+(&|$)/', '&' . $qs) && !isset($_GET['reauth'])) sba_execute_block(__('异常 URL 参数', SBA_TEXT_DOMAIN));
        }
    }

    // 非登录用户的数据探测
    if (!$is_logged_in && !$is_bot) {
        $qs_enum = $_SERVER['QUERY_STRING'] ?? '';
        if (isset($_GET['author']) || strpos($uri, 'author=') !== false ||
            preg_match('#/wp/v2/(users|posts|pages|comments|media|types|taxonomies|statuses|settings|themes|plugins|blocks|block-types|block-renderer|search|categories|tags|font-families|font-faces)#i', $uri . $rest_route)) {
            sba_execute_block(__('数据探测: 敏感信息/内容抓取', SBA_TEXT_DOMAIN));
        }
        if (preg_match('/filter\[author\]\s*=/i', $qs_enum)) sba_execute_block(__('探测: filter注入', SBA_TEXT_DOMAIN));
        if (preg_match('/filter\[orderby\]\s*=/i', $qs_enum)) sba_execute_block(__('探测: orderby注入', SBA_TEXT_DOMAIN));
        if (isset($_GET['context']) && $_GET['context'] === 'edit') sba_execute_block(__('REST限制: 非法上下文', SBA_TEXT_DOMAIN));
        if (isset($_GET['per_page']) && (int)$_GET['per_page'] > 50) sba_execute_block(__('REST限制: 分页超限', SBA_TEXT_DOMAIN));
        if (isset($_GET['offset']) && (int)$_GET['offset'] > 200) sba_execute_block(__('REST限制: 偏移超限', SBA_TEXT_DOMAIN));
        if (strpos($uri . $rest_route, '/oembed/1.0/proxy') !== false) sba_execute_block(__('SSRF探测: OEmbed代理', SBA_TEXT_DOMAIN));

        $scan_patterns = ['/.well-known' => '.well-known', '/wp-json/yoast' => 'yoast', '/wp-json/acf' => 'acf', '/wp-json/tribe' => 'tribe', '/wp-json/woocommerce' => 'woo'];
        foreach ($scan_patterns as $p => $label) {
            if (strpos($uri . $rest_route, $p) !== false) sba_execute_block(sprintf(__('扫描: %s', SBA_TEXT_DOMAIN), $label));
        }
    }

    // 速率限制
    $limit = (int)sba_get_option('auto_block_limit', 0);
    if ($limit > 0 && !$is_logged_in && !$is_bot && !in_array($ip, ['127.0.0.1', '::1'])) {
        $is_browser = preg_match('/Mozilla\/|Chrome\/|Firefox\/|Safari\/|Edge\/|Opera\/|MSIE/', $ua);
        $scraper_paths = sba_get_option('scraper_paths', 'feed=|rest_route=');
        $cur_limit = preg_match('/' . str_replace('/', '\/', $scraper_paths) . '/i', $uri) ? max(5, floor($limit / 3)) : $limit;
        if (sba_get_option('enable_cookie_check', 1) && !sba_has_valid_cookie() && !$is_browser) $cur_limit = max(5, floor($cur_limit / 2));
        if (sba_check_rate_limit($ip, $cur_limit)) sba_execute_block(__('访问速率异常', SBA_TEXT_DOMAIN));
        if (sba_get_option('enable_cookie_check', 1) && !sba_has_valid_cookie() && $_SERVER['REQUEST_METHOD'] === 'GET') sba_set_human_cookie();
    }
}

// ==================== AJAX 统计补丁 ====================
function sba_generate_heartbeat_token($offset = 0) {
    $ip = sba_get_ip();
    $hour = date('YmdH', strtotime("$offset hour"));
    return hash_hmac('sha256', $ip . $hour, NONCE_KEY . SBA_HEARTBEAT_SALT);
}
add_action('wp_footer', 'sba_heartbeat_script');
function sba_heartbeat_script() {
    if (is_admin() || sba_get_option('enable_ajax_patch', 0) != 1) return;
    if (defined('SBA_TRACKED') && SBA_TRACKED) return;
    $token = sba_generate_heartbeat_token();
    ?>
    <script id="sba-ajax-patch">
    (function() {
        setTimeout(function() {
            var xhr = new XMLHttpRequest();
            xhr.open('POST', '<?php echo admin_url('admin-ajax.php'); ?>', true);
            xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
            xhr.send('action=sba_heartbeat&token=<?php echo esc_js($token); ?>');
        }, 2000);
    })();
    </script>
    <?php
}
add_action('wp_ajax_sba_heartbeat', 'sba_ajax_heartbeat');
add_action('wp_ajax_nopriv_sba_heartbeat', 'sba_ajax_heartbeat');
function sba_ajax_heartbeat() {
    $token = $_POST['token'] ?? '';
    $valid_now = sba_generate_heartbeat_token(0);
    $valid_prev = sba_generate_heartbeat_token(-1);
    if (empty($token) || (!hash_equals($valid_now, $token) && !hash_equals($valid_prev, $token))) {
        wp_send_json_error('Invalid token', 403);
        return;
    }
    if (defined('SBA_TRACKED') && SBA_TRACKED) wp_send_json_success();
    sba_inc_pv();
    wp_send_json_success();
}

// ==================== REST API 输出净化 ====================
add_action('rest_api_init', function() {
    add_filter('rest_prepare_post', 'sba_clean_rest_output', 10, 3);
    add_filter('rest_prepare_page', 'sba_clean_rest_output', 10, 3);
    add_filter('rest_prepare_comment', 'sba_clean_comment_output', 10, 3);
    add_filter('rest_post_dispatch', 'sba_rest_post_dispatch', 10, 3);
});
function sba_clean_rest_output($response, $post, $request) {
    if (!is_user_logged_in()) {
        $data = $response->get_data();
        $data['author'] = 0;
        foreach (['guid', 'content', 'title', 'excerpt'] as $field) {
            if (isset($data[$field]['rendered'])) $data[$field]['rendered'] = sba_mask_internal_ips($data[$field]['rendered']);
        }
        $response->set_data($data);
    }
    return $response;
}
function sba_clean_comment_output($response, $comment, $request) {
    if (!is_user_logged_in()) {
        $data = $response->get_data();
        $data['author'] = 0;
        $data['author_name'] = __('匿名访客', SBA_TEXT_DOMAIN);
        if (isset($data['content']['rendered'])) $data['content']['rendered'] = sba_mask_internal_ips($data['content']['rendered']);
        $response->set_data($data);
    }
    return $response;
}
function sba_rest_post_dispatch($response, $rest_server, $request) {
    if (!is_user_logged_in() && $response->get_status() === 403) {
        $route = $request->get_route();
        if (strpos($route, '/wp/v2/posts/') !== false && isset($request['password'])) return new WP_REST_Response(null, 404);
    }
    return $response;
}
function sba_mask_internal_ips($text) {
    $home = home_url();
    $host = parse_url($home, PHP_URL_HOST);
    $text = preg_replace('#https?://((127\.\d+\.\d+\.\d+)|(10\.\d+\.\d+\.\d+)|(172\.(1[6-9]|2[0-9]|3[0-1])\.\d+\.\d+)|(192\.168\.\d+\.\d+))(:\d+)?(/|$)#i', $home . '/', $text);
    $text = preg_replace('#https?://localhost(:\d+)?(/|$)#i', $home . '/', $text);
    $text = preg_replace('#//(127\.\d+\.\d+\.\d+|10\.\d+\.\d+\.\d+|172\.(1[6-9]|2[0-9]|3[0-1])\.\d+\.\d+|192\.168\.\d+\.\d+)(:\d+)?(/|$)#i', '//' . $host . '/', $text);
    return $text;
}
add_action('template_redirect', function() {
    if (is_author() || isset($_GET['author'])) { wp_redirect(home_url(), 301); exit; }
});

// ==================== 登录防护 ====================
add_action('wp_login_failed', 'sba_limit_login_trigger');
add_filter('wp_login_errors', 'sba_limit_login_check_only', 10, 2);
function sba_limit_login_trigger() {
    $ip = sba_get_ip();
    if (sba_is_ip_whitelisted($ip)) return;
    $attempts = (int)get_transient('sba_login_fail_' . md5($ip)) + 1;
    set_transient('sba_login_fail_' . md5($ip), $attempts, 3600);
    if ($attempts >= 5) {
        set_transient('sba_temp_block_' . $ip, 1, 900);
        sba_execute_block(__('登录失败次数过多 (暴力破解防护)', SBA_TEXT_DOMAIN));
    }
}
function sba_limit_login_check_only($errors, $redirect_to) {
    $ip = sba_get_ip();
    if (get_transient('sba_temp_block_' . $ip)) sba_execute_block(__('您的 IP 处于临时封禁期，请 15 分钟后再试。', SBA_TEXT_DOMAIN));
    return $errors;
}
add_action('init', 'sba_check_temp_block', 0);
function sba_check_temp_block() {
    $ip = sba_get_ip();
    if (get_transient('sba_temp_block_' . $ip)) {
        status_header(403);
        wp_die(__('尝试次数太多，请稍后再试。', SBA_TEXT_DOMAIN), 403);
    }
}

// ==================== IP 归属地查询 ====================
if (!class_exists('SBA_Fallback_XdbSearcher')) {
    class SBA_Fallback_XdbSearcher {
        const HeaderInfoLength = 256;
        const VectorIndexRows = 256;
        const VectorIndexCols = 256;
        const VectorIndexSize = 8;
        const SegmentIndexSize = 14;
        private $buffer, $vectorIndex;
        public static function loadContentFromFile($path) { return file_get_contents($path) ?: null; }
        public static function newWithBuffer($cBuff) {
            $self = new self();
            $self->buffer = $cBuff;
            $self->vectorIndex = substr($cBuff, self::HeaderInfoLength, self::VectorIndexRows * self::VectorIndexCols * self::VectorIndexSize);
            return $self;
        }
        public function search($ip) {
            if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) return null;
            $ipNum = sprintf('%u', ip2long($ip));
            if ($ipNum === false) return null;
            $il0 = ($ipNum >> 24) & 0xFF;
            $il1 = ($ipNum >> 16) & 0xFF;
            $idx = $il0 * self::VectorIndexCols * self::VectorIndexSize + $il1 * self::VectorIndexSize;
            $sPtr = unpack('V', substr($this->vectorIndex, $idx, 4))[1];
            $ePtr = unpack('V', substr($this->vectorIndex, $idx + 4, 4))[1];
            $l = 0; $h = ($ePtr - $sPtr) / self::SegmentIndexSize;
            while ($l <= $h) {
                $m = ($l + $h) >> 1;
                $p = $sPtr + $m * self::SegmentIndexSize;
                $startIp = unpack('V', substr($this->buffer, $p, 4))[1];
                if ($ipNum < $startIp) $h = $m - 1;
                else {
                    $endIp = unpack('V', substr($this->buffer, $p + 4, 4))[1];
                    if ($ipNum > $endIp) $l = $m + 1;
                    else {
                        $dataLen = unpack('v', substr($this->buffer, $p + 8, 2))[1];
                        $dataPtr = unpack('V', substr($this->buffer, $p + 10, 4))[1];
                        return substr($this->buffer, $dataPtr, $dataLen);
                    }
                }
            }
            return null;
        }
    }
}
class SBA_IP_Searcher {
    private static $instance = null;
    private $searcher_v4 = null, $searcher_v6 = null;
    private static $cache = [];
    public static function get_instance() {
        if (self::$instance === null) self::$instance = new self();
        return self::$instance;
    }
    private function __construct() {}
    private function load_searchers() {
        if ($this->searcher_v4 === null && file_exists(SBA_IP_V4_FILE) && filesize(SBA_IP_V4_FILE) > 0) {
            $content = SBA_USE_OFFICIAL ? \ip2region\xdb\Util::loadContentFromFile(SBA_IP_V4_FILE) : SBA_Fallback_XdbSearcher::loadContentFromFile(SBA_IP_V4_FILE);
            if ($content) {
                if (SBA_USE_OFFICIAL) $this->searcher_v4 = \ip2region\xdb\Searcher::newWithBuffer(\ip2region\xdb\IPv4::default(), $content);
                else $this->searcher_v4 = SBA_Fallback_XdbSearcher::newWithBuffer($content);
            }
        }
        if (SBA_USE_OFFICIAL && $this->searcher_v6 === null && file_exists(SBA_IP_V6_FILE) && filesize(SBA_IP_V6_FILE) > 0) {
            $content = \ip2region\xdb\Util::loadContentFromFile(SBA_IP_V6_FILE);
            if ($content) $this->searcher_v6 = \ip2region\xdb\Searcher::newWithBuffer(\ip2region\xdb\IPv6::default(), $content);
        }
    }
    public function search($ip) {
        if (isset(self::$cache[$ip])) return self::$cache[$ip];
        $transient = 'sba_geo_' . md5($ip);
        $cached = get_transient($transient);
        if ($cached !== false) {
            self::$cache[$ip] = $cached;
            return $cached;
        }
        $this->load_searchers();
        $result = __('未知', SBA_TEXT_DOMAIN);
        try {
            if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) && $this->searcher_v4) {
                $region = $this->searcher_v4->search($ip);
                if ($region) $result = implode('·', array_filter(explode('|', $region), fn($v) => $v !== '' && $v !== '0'));
            } elseif (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) && $this->searcher_v6) {
                $region = $this->searcher_v6->search($ip);
                if ($region) $result = implode('·', array_filter(explode('|', $region), fn($v) => $v !== '' && $v !== '0'));
            }
        } catch (Exception $e) { error_log("SBA IP 查询异常 ($ip): " . $e->getMessage()); }
        self::$cache[$ip] = $result;
        set_transient($transient, $result, DAY_IN_SECONDS);
        return $result;
    }
}

// ==================== AJAX 归属地和轨迹加载 ====================
add_action('wp_ajax_sba_get_geo', 'sba_ajax_get_geo');
function sba_ajax_get_geo() {
    $ips = (array)$_POST['ips'];
    $searcher = SBA_IP_Searcher::get_instance();
    $results = [];
    foreach ($ips as $ip) $results[$ip] = $searcher->search($ip);
    wp_send_json_success($results);
}
add_action('wp_ajax_sba_load_tracks', 'sba_ajax_load_tracks');
function sba_ajax_load_tracks() {
    global $wpdb;
    $p = max(1, (int)($_POST['page'] ?? 1));
    $per = 50;
    $off = ($p - 1) * $per;
    $searcher = SBA_IP_Searcher::get_instance();
    $latest = $wpdb->get_var("SELECT MAX(visit_date) FROM {$wpdb->prefix}dis_stats") ?: current_time('Y-m-d');
    $total = sba_get_pv($latest);
    if ($total == 0) $total = $wpdb->get_var($wpdb->prepare("SELECT COUNT(*) FROM {$wpdb->prefix}dis_stats WHERE visit_date = %s", $latest));
    $rows = $wpdb->get_results($wpdb->prepare("SELECT ip, url, pv, last_visit FROM {$wpdb->prefix}dis_stats WHERE visit_date = %s ORDER BY last_visit DESC LIMIT %d, %d", $latest, $off, $per));
    $html = '';
    if ($rows) {
        foreach ($rows as $r) {
            $geo = $searcher->search($r->ip);
            $display = current_user_can('manage_options') ? esc_html($r->ip) : sba_mask_ip($r->ip);
            $html .= "<tr><td>" . date('H:i', strtotime($r->last_visit)) . "</td><td><code>{$display}</code></td><td><small>" . esc_html($geo) . "</small></td><td><div class='sba-cell-wrap'><small>" . esc_html($r->url) . "</small></div></td><td><b>{$r->pv}</b></td></tr>";
        }
    } else {
        $html = '<tr><td colspan="5">' . __('暂无更多记录', SBA_TEXT_DOMAIN) . '</td></tr>';
    }
    wp_send_json_success(['html' => $html, 'pages' => ceil($total / $per), 'total' => $total, 'date' => $latest]);
}
add_action('wp_ajax_sba_load_blocked_logs', 'sba_ajax_load_blocked_logs');
function sba_ajax_load_blocked_logs() {
    global $wpdb;
    $p = max(1, (int)($_POST['page'] ?? 1));
    $per = 15;
    $off = ($p - 1) * $per;
    $today = current_time('Y-m-d');
    $total = sba_get_blocked($today);
    if ($total == 0) $total = $wpdb->get_var("SELECT COUNT(*) FROM {$wpdb->prefix}sba_blocked_log WHERE DATE(block_time) = CURDATE()");
    $rows = $wpdb->get_results($wpdb->prepare("SELECT * FROM {$wpdb->prefix}sba_blocked_log WHERE DATE(block_time) = CURDATE() ORDER BY block_time DESC LIMIT %d, %d", $off, $per));
    $html = '';
    if ($rows) {
        foreach ($rows as $b) {
            $display = current_user_can('manage_options') ? esc_html($b->ip) : sba_mask_ip($b->ip);

            $translated_reason = __($b->reason, SBA_TEXT_DOMAIN);
            $html .= "<tr>
                <td>" . date('m-d H:i', strtotime($b->block_time)) . "</td>
                <td><code>{$display}</code></td>
                <td class='sba-cell-wrap' style='color:#d63638;'>" . esc_html($translated_reason) . " ⚡ " . esc_html($b->target_url) . "</td>
            </tr>";
        }
    } else {
        $html = '<tr><td colspan="3">' . __('暂无拦截记录', SBA_TEXT_DOMAIN) . '</td></tr>';
    }
    wp_send_json_success(['html' => $html, 'pages' => ceil($total / $per), 'total' => $total]);
}
add_action('wp_ajax_sba_get_threat_ranking', 'sba_ajax_get_threat_ranking');
function sba_ajax_get_threat_ranking() {
    if (!current_user_can('manage_options')) wp_send_json_error(__('权限不足', SBA_TEXT_DOMAIN));
    global $wpdb;
    $page = max(1, (int)($_POST['page'] ?? 1));
    $per = 30;
    $off = ($page - 1) * $per;
    $total = $wpdb->get_var("SELECT COUNT(*) FROM {$wpdb->prefix}sba_threat_summary WHERE total_blocks > 0");
    if (!$total) wp_send_json_success(['html' => '<tr><td colspan="5" style="text-align:center;">' . __('暂无威胁数据', SBA_TEXT_DOMAIN) . '</td></tr>', 'has_next' => false, 'total' => 0]);
    $ranking = $wpdb->get_results($wpdb->prepare("SELECT ip, total_blocks, last_block_time FROM {$wpdb->prefix}sba_threat_summary WHERE total_blocks > 0 ORDER BY CAST(total_blocks AS UNSIGNED) DESC LIMIT %d, %d", $off, $per + 1));
    $has_next = count($ranking) > $per;
    if ($has_next) array_pop($ranking);
    $html = '';
    $rank = $off + 1;
    foreach ($ranking as $r) {
        $html .= "<tr><td><strong>#$rank</strong></td><td><code>" . esc_html($r->ip) . "</code></td><td style='color:#d63638;'><strong>" . number_format((int)$r->total_blocks) . "</strong></td><td>" . date('Y-m-d H:i:s', strtotime($r->last_block_time)) . "</td><td><button class='button sba-ban-ip-btn' data-ip='" . esc_attr($r->ip) . "'>" . __('永久封禁', SBA_TEXT_DOMAIN) . "</button></td></tr>";
        $rank++;
    }
    wp_send_json_success(['html' => $html, 'has_next' => $has_next, 'total' => (int)$total, 'current_page' => $page]);
}
add_action('wp_ajax_sba_sync_threat_ranking', 'sba_ajax_sync_threat_ranking');
function sba_ajax_sync_threat_ranking() {
    if (!current_user_can('manage_options')) wp_send_json_error('Permission denied');
    global $wpdb;
    $wpdb->query("TRUNCATE TABLE {$wpdb->prefix}sba_threat_summary");
    $wpdb->query("INSERT INTO {$wpdb->prefix}sba_threat_summary (ip, total_blocks, last_block_time)
        SELECT ip, COUNT(*), MAX(block_time)
        FROM {$wpdb->prefix}sba_blocked_log
        WHERE ip IS NOT NULL AND ip != ''
        GROUP BY ip
        ON DUPLICATE KEY UPDATE total_blocks = VALUES(total_blocks), last_block_time = VALUES(last_block_time)");
    $count = $wpdb->get_var("SELECT COUNT(*) FROM {$wpdb->prefix}sba_threat_summary");
    if ($count) wp_send_json_success(['message' => sprintf(__('历史数据对账完成！共同步 %d 条记录', SBA_TEXT_DOMAIN), $count)]);
    else wp_send_json_error(__('对账失败，请检查数据库。', SBA_TEXT_DOMAIN));
}
add_action('wp_ajax_sba_ban_ip', 'sba_ajax_ban_ip');
function sba_ajax_ban_ip() {
    if (!current_user_can('manage_options')) wp_send_json_error(__('权限不足', SBA_TEXT_DOMAIN));
    $ip = sanitize_text_field($_POST['ip']);
    if (!filter_var($ip, FILTER_VALIDATE_IP)) wp_send_json_error(__('无效的 IP 地址', SBA_TEXT_DOMAIN));
    $whitelist = array_filter(explode("\n", sba_get_option('ip_whitelist', '')));
    if (in_array($ip, $whitelist)) wp_send_json_error(__('此 IP 在白名单中，无法封禁', SBA_TEXT_DOMAIN));
    $ban_list = get_option('sba_permanent_ban_list', []);
    if (!in_array($ip, $ban_list)) {
        $ban_list[] = $ip;
        update_option('sba_permanent_ban_list', $ban_list);
    }
    sba_execute_block(sprintf(__('管理员手动封禁 IP: %s', SBA_TEXT_DOMAIN), $ip));
    wp_send_json_success(['message' => sprintf(__('IP %s 已被永久封禁', SBA_TEXT_DOMAIN), $ip), 'ban_list_html' => sba_generate_ban_list_html()]);
}
add_action('wp_ajax_sba_unban_ip', 'sba_ajax_unban_ip');
function sba_ajax_unban_ip() {
    if (!current_user_can('manage_options')) wp_send_json_error(__('权限不足', SBA_TEXT_DOMAIN));
    $ip = sanitize_text_field($_POST['ip']);
    $ban_list = get_option('sba_permanent_ban_list', []);
    $key = array_search($ip, $ban_list);
    if ($key !== false) {
        unset($ban_list[$key]);
        update_option('sba_permanent_ban_list', array_values($ban_list));
        wp_send_json_success(['message' => sprintf(__('IP %s 已解除封禁', SBA_TEXT_DOMAIN), $ip), 'ban_list_html' => sba_generate_ban_list_html()]);
    } else {
        wp_send_json_error(__('未在封禁列表中找到该 IP', SBA_TEXT_DOMAIN));
    }
}
function sba_generate_ban_list_html() {
    $ban_list = get_option('sba_permanent_ban_list', []);
    if (empty($ban_list)) return '<p>' . __('暂无手动封禁的 IP。', SBA_TEXT_DOMAIN) . '</p>';
    $html = '<div class="sba-scroll-x"><table class="sba-table"><thead><tr><th>' . __('IP 地址', SBA_TEXT_DOMAIN) . '</th><th>' . __('操作', SBA_TEXT_DOMAIN) . '</th></tr></thead><tbody>';
    foreach ($ban_list as $ip) $html .= '<tr><td><code>' . esc_html($ip) . '</code></td><td><button class="button sba-unban-ip-btn" data-ip="' . esc_attr($ip) . '">' . __('解除封禁', SBA_TEXT_DOMAIN) . '</button></td></tr>';
    $html .= '</tbody></table></div>';
    return $html;
}
add_filter('plugins_loaded', 'sba_permanent_ban_check');
function sba_permanent_ban_check() {
    $ip = sba_get_ip();
    if (in_array($ip, get_option('sba_permanent_ban_list', [])) && !sba_is_ip_whitelisted($ip)) {
        status_header(403);
        wp_die(__('您的 IP 已被永久封禁。如有疑问，请联系管理员。', SBA_TEXT_DOMAIN), 403);
    }
}

// ==================== iOS 登录辅助函数 ====================
function sba_ios_check_rate_limit($ip, $limit = 10) {
    global $wpdb;
    $table = $wpdb->prefix . 'sba_login_failures';
    $row = $wpdb->get_row($wpdb->prepare("SELECT request_count, last_request_time FROM $table WHERE ip = %s", $ip));
    $now = current_time('mysql');
    $now_ts = strtotime($now);
    if (!$row) {
        $wpdb->insert($table, ['ip' => $ip, 'request_count' => 1, 'last_request_time' => $now]);
        return true;
    }
    $diff_hours = ($now_ts - strtotime($row->last_request_time)) / 3600;
    if ($diff_hours >= 1) {
        $wpdb->update($table, ['request_count' => 1, 'last_request_time' => $now], ['ip' => $ip]);
        return true;
    }
    $new = $row->request_count + 1;
    $wpdb->update($table, ['request_count' => $new, 'last_request_time' => $now], ['ip' => $ip]);
    return $new <= $limit;
}
function sba_ios_record_failure($ip, $success = false) {
    global $wpdb;
    $table = $wpdb->prefix . 'sba_login_failures';
    $row = $wpdb->get_row($wpdb->prepare("SELECT * FROM $table WHERE ip = %s", $ip));
    $now = current_time('mysql');
    if ($success) {
        if ($row) $wpdb->delete($table, ['ip' => $ip]);
        return;
    }
    if (!$row) {
        $wpdb->insert($table, ['ip' => $ip, 'failed_count' => 1, 'last_failed_time' => $now, 'request_count' => 1, 'last_request_time' => $now]);
        return 1;
    }
    if ($row->banned_until && strtotime($row->banned_until) > strtotime($now)) return 'banned';
    $new_count = $row->failed_count + 1;
    $banned_until = $new_count >= 6 ? date('Y-m-d H:i:s', strtotime($now . ' +24 hours')) : null;
    if ($banned_until) wp_mail(get_option('admin_email'), '【' . __('安全提醒', SBA_TEXT_DOMAIN) . '】IP被封禁', sprintf(__("IP: %s\n失败次数: %d\n封禁至: %s", SBA_TEXT_DOMAIN), $ip, $new_count, $banned_until));
    $wpdb->update($table, ['failed_count' => $new_count, 'last_failed_time' => $now, 'banned_until' => $banned_until], ['ip' => $ip]);
    return $new_count;
}
function sba_ios_check_ban_and_captcha($ip, $action = '') {
    global $wpdb;
    $row = $wpdb->get_row($wpdb->prepare("SELECT failed_count, banned_until FROM {$wpdb->prefix}sba_login_failures WHERE ip = %s", $ip));
    if (!$row) return ['banned' => false, 'need_captcha' => false];
    if ($row->banned_until && strtotime($row->banned_until) > time()) return ['banned' => true, 'need_captcha' => false];
    $need_captcha = ($row->failed_count >= 3 && $row->failed_count < 6) || in_array($action, ['register', 'forgot']);
    return ['banned' => false, 'need_captcha' => $need_captcha];
}

// ==================== iOS 风格登录面板 ====================
add_action('wp_enqueue_scripts', 'sba_ios_register_scripts');
function sba_ios_register_scripts() {
    wp_register_script('sba-ios-login-js', '', ['jquery'], '1.0', true);
}
add_shortcode('sba_login_box', 'sba_ios_login_shortcode');
function sba_ios_login_shortcode() {
    $message = '';
    $msg_type = '';
    if (isset($_GET['sba_message'])) {
        switch ($_GET['sba_message']) {
            case 'reset_sent': $message = __('密码重置链接已发送到您的邮箱，请查收。', SBA_TEXT_DOMAIN); $msg_type = 'info'; break;
            case 'reset_success': $message = __('密码修改成功，请使用新密码登录。', SBA_TEXT_DOMAIN); $msg_type = 'success'; break;
            case 'activation_success': $message = __('账号激活成功，请登录。', SBA_TEXT_DOMAIN); $msg_type = 'success'; break;
        }
    }
    if (is_user_logged_in()) {
        $user = wp_get_current_user();
        $avatar = get_avatar($user->ID, 80, '', '', ['class' => 'sba-ios-avatar-img']);
        return '<div class="sba-ios-logged-in"><div class="sba-ios-avatar">' . $avatar . '</div><div class="sba-ios-welcome">' . __('欢迎回来', SBA_TEXT_DOMAIN) . '</div><div class="sba-ios-user">' . esc_html($user->display_name) . '</div><div class="sba-ios-links"><a href="' . admin_url() . '">' . __('控制台', SBA_TEXT_DOMAIN) . '</a><a href="' . admin_url('profile.php') . '">' . __('个人资料', SBA_TEXT_DOMAIN) . '</a><a href="' . wp_logout_url(home_url()) . '">' . __('注销', SBA_TEXT_DOMAIN) . '</a></div></div>';
    }
    $nonce = wp_create_nonce('sba_ios_action');
    $msg_html = '';
    if ($message) {
        $color = $msg_type === 'success' ? '#28cd41' : ($msg_type === 'info' ? '#007aff' : '#ff3b30');
        $msg_html = '<div class="sba-ios-global-message" style="text-align:center;margin-bottom:15px;padding:12px;border-radius:12px;background:' . $color . '10;color:' . $color . ';font-size:14px;border:1px solid ' . $color . '20;">' . esc_html($message) . '</div>';
    }
    ob_start();
    ?>
    <div id="sba-ios-login-container" data-nonce="<?php echo esc_attr($nonce); ?>">
        <?php echo $msg_html; ?>
        <div class="sba-ios-card">
            <div class="sba-ios-tabs">
                <button class="sba-ios-tab active" data-tab="login"><?php _e('登录', SBA_TEXT_DOMAIN); ?></button>
                <button class="sba-ios-tab" data-tab="register"><?php _e('注册', SBA_TEXT_DOMAIN); ?></button>
                <button class="sba-ios-tab" data-tab="forgot"><?php _e('忘记密码', SBA_TEXT_DOMAIN); ?></button>
            </div>
            <div id="sba-ios-login-form" class="sba-ios-form active">
                <div class="sba-ios-field"><input type="text" id="sba-ios-login-username" placeholder="<?php esc_attr_e('用户名或邮箱', SBA_TEXT_DOMAIN); ?>"></div>
                <div class="sba-ios-field"><input type="password" id="sba-ios-login-password" placeholder="<?php esc_attr_e('密码', SBA_TEXT_DOMAIN); ?>"></div>
                <div class="sba-ios-field checkbox-field"><label><input type="checkbox" id="sba-ios-login-remember" checked> <?php _e('记住我', SBA_TEXT_DOMAIN); ?></label></div>
                <div id="sba-ios-login-captcha-area" style="display:none;"><div class="sba-ios-field"><input type="text" id="sba-ios-login-captcha" placeholder="<?php esc_attr_e('验证码', SBA_TEXT_DOMAIN); ?>"></div><div id="sba-ios-login-captcha-question"></div></div>
                <div id="sba-ios-login-message" class="sba-ios-message"></div>
                <button id="sba-ios-login-submit" class="sba-ios-button"><?php _e('登录', SBA_TEXT_DOMAIN); ?></button>
            </div>
            <div id="sba-ios-register-form" class="sba-ios-form">
                <div class="sba-ios-field"><input type="text" id="sba-ios-reg-username" placeholder="<?php esc_attr_e('用户名', SBA_TEXT_DOMAIN); ?>"></div>
                <div class="sba-ios-field"><input type="email" id="sba-ios-reg-email" placeholder="<?php esc_attr_e('邮箱', SBA_TEXT_DOMAIN); ?>"></div>
                <div class="sba-ios-field"><input type="password" id="sba-ios-reg-password" placeholder="<?php esc_attr_e('密码', SBA_TEXT_DOMAIN); ?>"></div>
                <div class="sba-ios-field"><input type="password" id="sba-ios-reg-confirm-password" placeholder="<?php esc_attr_e('确认密码', SBA_TEXT_DOMAIN); ?>"></div>
                <div id="sba-ios-reg-captcha-area" style="display:none;"><div class="sba-ios-field"><input type="text" id="sba-ios-reg-captcha" placeholder="<?php esc_attr_e('验证码', SBA_TEXT_DOMAIN); ?>"></div><div id="sba-ios-reg-captcha-question"></div></div>
                <div id="sba-ios-reg-message" class="sba-ios-message"></div>
                <button id="sba-ios-reg-submit" class="sba-ios-button"><?php _e('注册', SBA_TEXT_DOMAIN); ?></button>
            </div>
            <div id="sba-ios-forgot-form" class="sba-ios-form">
                <div class="sba-ios-field"><input type="text" id="sba-ios-forgot-email" placeholder="<?php esc_attr_e('用户名或邮箱', SBA_TEXT_DOMAIN); ?>"></div>
                <div id="sba-ios-forgot-captcha-area" style="display:none;"><div class="sba-ios-field"><input type="text" id="sba-ios-forgot-captcha" placeholder="<?php esc_attr_e('验证码', SBA_TEXT_DOMAIN); ?>"></div><div id="sba-ios-forgot-captcha-question"></div></div>
                <div id="sba-ios-forgot-message" class="sba-ios-message"></div>
                <button id="sba-ios-forgot-submit" class="sba-ios-button"><?php _e('发送重置链接', SBA_TEXT_DOMAIN); ?></button>
            </div>
        </div>
    </div>
    <style>
        #sba-ios-login-container{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;max-width:380px;margin:30px auto;padding:0 16px}
        .sba-ios-card{background:#fff;border-radius:20px;box-shadow:0 8px 28px rgba(0,0,0,.08),0 0 0 1px rgba(0,0,0,.02);overflow:hidden}
        .sba-ios-tabs{display:flex;border-bottom:1px solid #e9ecef;background:#fff}
        .sba-ios-tab{flex:1;text-align:center;padding:16px 0;font-size:17px;font-weight:500;color:#8e8e93;background:none;border:none;cursor:pointer;transition:all .2s ease}
        .sba-ios-tab.active{color:#007aff;border-bottom:2px solid #007aff}
        .sba-ios-form{padding:24px 20px;display:none}
        .sba-ios-form.active{display:block}
        .sba-ios-field{margin-bottom:16px}
        .sba-ios-field input[type="text"],.sba-ios-field input[type="password"],.sba-ios-field input[type="email"]{width:100%;padding:12px 16px;font-size:16px;border:1px solid #c6c6c8;border-radius:12px;background:#fff;transition:border-color .2s;box-sizing:border-box}
        .sba-ios-field input:focus{outline:none;border-color:#007aff}
        .checkbox-field{margin:-8px 0 16px;text-align:left}
        .checkbox-field label{font-size:14px;color:#8e8e93}
        .sba-ios-field input[type="checkbox"]{width:auto;margin-right:6px;vertical-align:middle}
        .sba-ios-button{background:#007aff;color:#fff;border:none;border-radius:12px;padding:12px 20px;font-size:17px;font-weight:600;width:100%;cursor:pointer;transition:opacity .2s}
        .sba-ios-button:hover{opacity:.85}
        .sba-ios-message{margin:12px 0;font-size:14px;text-align:center;color:#ff3b30;min-height:40px}
        .sba-ios-logged-in{background:#fff;border-radius:20px;box-shadow:0 8px 28px rgba(0,0,0,.08);padding:24px 20px;text-align:center;max-width:380px;margin:30px auto}
        .sba-ios-avatar{width:80px;height:80px;border-radius:50%;margin:0 auto 16px;background:#f0f0f0;display:flex;align-items:center;justify-content:center;overflow:hidden}
        .sba-ios-avatar img{width:100%;height:100%;object-fit:cover}
        .sba-ios-welcome{font-size:20px;font-weight:600;margin-bottom:8px}
        .sba-ios-user{font-size:17px;color:#007aff;margin-bottom:24px}
        .sba-ios-links a{display:inline-block;margin:0 12px;color:#007aff;text-decoration:none;font-size:15px}
        .sba-ios-links a:hover{text-decoration:underline}
        @media (max-width:480px){#sba-ios-login-container,.sba-ios-logged-in{margin:20px auto}}
    </style>
    <?php
    $html = ob_get_clean();
    static $script_added = false;
    if (!$script_added) {
        $script_added = true;
        $ajaxurl = admin_url('admin-ajax.php');
        $i18n = [
            'logging_in' => __('登录中...', SBA_TEXT_DOMAIN),
            'registering' => __('注册中...', SBA_TEXT_DOMAIN),
            'sending' => __('发送中...', SBA_TEXT_DOMAIN),
            'password_mismatch' => __('两次输入的密码不一致。', SBA_TEXT_DOMAIN),
            'password_weak' => __('密码必须至少8位，且包含字母和数字。', SBA_TEXT_DOMAIN),
            'captcha_required' => __('请先填写验证码。', SBA_TEXT_DOMAIN),
            'network_error' => __('网络错误，请稍后重试。', SBA_TEXT_DOMAIN),
            'captcha_question' => __('验证码：', SBA_TEXT_DOMAIN),
            'login_success' => __('登录成功', SBA_TEXT_DOMAIN),
            'register_success' => __('注册成功，请查收激活邮件。', SBA_TEXT_DOMAIN),
            'forgot_success' => __('重置链接已发送至您的邮箱。', SBA_TEXT_DOMAIN),
            'banned_message' => __('由于多次失败，您的IP已被封禁24小时。', SBA_TEXT_DOMAIN),
            'rate_limit_message' => __('操作过于频繁，请稍后再试。', SBA_TEXT_DOMAIN),
            'invalid_captcha' => __('验证码错误', SBA_TEXT_DOMAIN),
            'empty_fields' => __('所有字段都不能为空。', SBA_TEXT_DOMAIN),
            'username_exists' => __('用户名已存在。', SBA_TEXT_DOMAIN),
            'email_exists' => __('邮箱已被注册。', SBA_TEXT_DOMAIN),
            'activation_failed' => __('邮件发送失败，请联系管理员。', SBA_TEXT_DOMAIN),
            'user_not_found' => __('用户名或邮箱未注册。', SBA_TEXT_DOMAIN),
            'reset_key_error' => __('无法生成重置链接，请稍后重试。', SBA_TEXT_DOMAIN),
            'reset_mail_failed' => __('邮件发送失败，请联系管理员。', SBA_TEXT_DOMAIN),
        ];
        wp_add_inline_script('sba-ios-login-js', "
            var ajaxurl = '{$ajaxurl}';
            jQuery(document).ready(function($) {
                var nonce = $('#sba-ios-login-container').data('nonce');
                var loginCaptchaShown = false, regCaptchaShown = false, forgotCaptchaShown = false;
                $('.sba-ios-tab').click(function() {
                    var tab = $(this).data('tab');
                    $('.sba-ios-tab').removeClass('active');
                    $(this).addClass('active');
                    $('.sba-ios-form').removeClass('active');
                    $('#sba-ios-' + tab + '-form').addClass('active');
                    $('.sba-ios-message').html('');
                    if (tab === 'login' && !loginCaptchaShown) loginCheckCaptcha();
                    else if (tab === 'register' && !regCaptchaShown) loadRegCaptcha();
                    else if (tab === 'forgot' && !forgotCaptchaShown) loadForgotCaptcha();
                });
                function loadCaptcha(formType, callback, force) {
                    $.post(ajaxurl, { action: 'sba_ios_get_captcha', _ajax_nonce: nonce, force: force ? 1 : 0 }, function(res) {
                        if (res.success) {
                            $('#sba-ios-' + formType + '-captcha-area').show();
                            $('#sba-ios-' + formType + '-captcha-question').html(sbaI18n.captcha_question + res.data.question);
                            if (callback) callback(true);
                            if (formType === 'login') loginCaptchaShown = true;
                            else if (formType === 'reg') regCaptchaShown = true;
                            else if (formType === 'forgot') forgotCaptchaShown = true;
                        } else if (callback) callback(false);
                    });
                }
                var loginNeedCaptcha = false;
                function loginCheckCaptcha() {
                    if (loginCaptchaShown) return;
                    $.post(ajaxurl, { action: 'sba_ios_check_captcha', _ajax_nonce: nonce }, function(res) {
                        if (res.success && res.data.need_captcha) {
                            loginNeedCaptcha = true;
                            loadCaptcha('login');
                        } else {
                            loginNeedCaptcha = false;
                            $('#sba-ios-login-captcha-area').hide();
                            loginCaptchaShown = false;
                        }
                    });
                }
                function loadRegCaptcha() { if (!regCaptchaShown) loadCaptcha('reg', null, true); }
                function loadForgotCaptcha() { if (!forgotCaptchaShown) loadCaptcha('forgot', null, true); }
                $('#sba-ios-login-submit').click(function() {
                    var btn = $(this);
                    btn.prop('disabled', true).text(sbaI18n.logging_in);
                    $.post(ajaxurl, {
                        action: 'sba_ios_login', username: $('#sba-ios-login-username').val(),
                        password: $('#sba-ios-login-password').val(), remember: $('#sba-ios-login-remember').is(':checked') ? 1 : 0,
                        captcha: $('#sba-ios-login-captcha').val(), need_captcha: loginNeedCaptcha ? 1 : 0, _ajax_nonce: nonce
                    }, function(res) {
                        if (res.success) location.reload();
                        else {
                            $('#sba-ios-login-message').html(res.data.message);
                            if (res.data.need_captcha) { loginNeedCaptcha = true; loginCaptchaShown = false; loadCaptcha('login'); }
                            else { $('#sba-ios-login-captcha-area').hide(); loginNeedCaptcha = false; loginCaptchaShown = false; }
                            btn.prop('disabled', false).text(sbaI18n.login);
                        }
                    }).fail(function() { $('#sba-ios-login-message').html(sbaI18n.network_error); btn.prop('disabled', false).text(sbaI18n.login); });
                });
                $('#sba-ios-reg-submit').click(function() {
                    if (!regCaptchaShown) { loadRegCaptcha(); $('#sba-ios-reg-message').html(sbaI18n.captcha_required); return; }
                    var pwd = $('#sba-ios-reg-password').val(), confirm = $('#sba-ios-reg-confirm-password').val();
                    if (pwd !== confirm) return $('#sba-ios-reg-message').html(sbaI18n.password_mismatch);
                    if (pwd.length < 8 || !/[a-zA-Z]/.test(pwd) || !/[0-9]/.test(pwd)) return $('#sba-ios-reg-message').html(sbaI18n.password_weak);
                    var btn = $(this);
                    btn.prop('disabled', true).text(sbaI18n.registering);
                    $.post(ajaxurl, {
                        action: 'sba_ios_register', username: $('#sba-ios-reg-username').val(),
                        email: $('#sba-ios-reg-email').val(), password: pwd,
                        captcha: $('#sba-ios-reg-captcha').val(), need_captcha: 1, _ajax_nonce: nonce
                    }, function(res) {
                        if (res.success) {
                            $('#sba-ios-reg-message').html('<span style=\"color:#28cd41;\">' + res.data.message + '</span>');
                            if (window.history && window.history.replaceState) {
                                var url = new URL(window.location.href);
                                url.searchParams.delete('sba_message');
                                window.history.replaceState({}, document.title, url.toString());
                            }
                            setTimeout(function() { location.reload(); }, 1500);
                        } else {
                            $('#sba-ios-reg-message').html(res.data.message);
                            if (res.data.need_captcha) { regCaptchaShown = false; loadRegCaptcha(); }
                            else $('#sba-ios-reg-captcha-area').hide();
                            btn.prop('disabled', false).text(sbaI18n.register);
                        }
                    }).fail(function() { $('#sba-ios-reg-message').html(sbaI18n.network_error); btn.prop('disabled', false).text(sbaI18n.register); });
                });
                $('#sba-ios-forgot-submit').click(function() {
                    if (!forgotCaptchaShown) { loadForgotCaptcha(); $('#sba-ios-forgot-message').html(sbaI18n.captcha_required); return; }
                    var btn = $(this);
                    btn.prop('disabled', true).text(sbaI18n.sending);
                    $.post(ajaxurl, {
                        action: 'sba_ios_forgot', email: $('#sba-ios-forgot-email').val(),
                        captcha: $('#sba-ios-forgot-captcha').val(), need_captcha: 1, _ajax_nonce: nonce
                    }, function(res) {
                        if (res.success) $('#sba-ios-forgot-message').html('<span style=\"color:#28cd41;\">' + res.data.message + '</span>');
                        else {
                            $('#sba-ios-forgot-message').html(res.data.message);
                            if (res.data.need_captcha) { forgotCaptchaShown = false; loadForgotCaptcha(); }
                            else $('#sba-ios-forgot-captcha-area').hide();
                        }
                        btn.prop('disabled', false).text(sbaI18n.forgot);
                    }).fail(function() { $('#sba-ios-forgot-message').html(sbaI18n.network_error); btn.prop('disabled', false).text(sbaI18n.forgot); });
                });
                loginCheckCaptcha();
                if ($('#sba-ios-register-form').hasClass('active')) loadRegCaptcha();
                if ($('#sba-ios-forgot-form').hasClass('active')) loadForgotCaptcha();
                $('#sba-ios-login-username, #sba-ios-login-password').focus(loginCheckCaptcha);
                if (window.history && window.history.replaceState) {
                    var url = new URL(window.location.href);
                    if (url.searchParams.has('sba_message')) {
                        url.searchParams.delete('sba_message');
                        window.history.replaceState({}, document.title, url.toString());
                    }
                }
            });
        ");
        wp_enqueue_script('sba-ios-login-js');
        wp_localize_script('sba-ios-login-js', 'sbaI18n', $i18n);
    }
    return $html;
}
// iOS 登录 AJAX 处理
add_action('wp_ajax_nopriv_sba_ios_get_captcha', 'sba_ios_ajax_get_captcha');
function sba_ios_ajax_get_captcha() {
    check_ajax_referer('sba_ios_action', '_ajax_nonce');
    $ip = sba_get_ip();
    $force = (int)($_POST['force'] ?? 0);
    $status = sba_ios_check_ban_and_captcha($ip, $force ? 'register' : '');
    if ($status['banned']) wp_send_json_error(['message' => __('您已被封禁24小时，请稍后再试。', SBA_TEXT_DOMAIN)]);
    if (!$status['need_captcha'] && !$force) wp_send_json_error(['message' => __('当前无需验证码', SBA_TEXT_DOMAIN)]);
    $num1 = rand(1,9); $num2 = rand(1,9);
    set_transient('sba_captcha_' . $ip, $num1 + $num2, 300);
    wp_send_json_success(['question' => "$num1 + $num2 = ?"]);
}
add_action('wp_ajax_nopriv_sba_ios_check_captcha', 'sba_ios_ajax_check_captcha');
function sba_ios_ajax_check_captcha() {
    check_ajax_referer('sba_ios_action', '_ajax_nonce');
    $ip = sba_get_ip();
    $status = sba_ios_check_ban_and_captcha($ip);
    if ($status['banned']) wp_send_json_error(['banned' => true]);
    wp_send_json_success(['need_captcha' => $status['need_captcha']]);
}
add_action('wp_ajax_nopriv_sba_ios_login', 'sba_ios_ajax_login');
function sba_ios_ajax_login() {
    check_ajax_referer('sba_ios_action', '_ajax_nonce');
    $ip = sba_get_ip();
    if (!sba_ios_check_rate_limit($ip, 10)) wp_send_json_error(['message' => __('操作过于频繁，请稍后再试。', SBA_TEXT_DOMAIN)]);
    $status = sba_ios_check_ban_and_captcha($ip);
    if ($status['banned']) wp_send_json_error(['message' => __('由于多次失败，您的IP已被封禁24小时。', SBA_TEXT_DOMAIN)]);
    if ((int)$_POST['need_captcha']) {
        $stored = get_transient('sba_captcha_' . $ip);
        if (!$stored || $_POST['captcha'] != $stored) {
            sba_ios_record_failure($ip, false);
            wp_send_json_error(['message' => __('验证码错误', SBA_TEXT_DOMAIN), 'need_captcha' => true]);
        }
        delete_transient('sba_captcha_' . $ip);
    }
    sleep(2);
    $user = wp_signon([
        'user_login' => sanitize_user($_POST['username']),
        'user_password' => $_POST['password'],
        'remember' => (bool)$_POST['remember'],
    ], false);
    if (is_wp_error($user)) {
        $count = sba_ios_record_failure($ip, false);
        wp_send_json_error(['message' => $user->get_error_message(), 'need_captcha' => ($count >= 3 && $count < 6)]);
    }
    $activated = get_user_meta($user->ID, '_activated', true);
    if ($activated !== '' && $activated !== '1') {
        wp_clear_auth_cookie();
        sba_ios_record_failure($ip, false);
        wp_send_json_error(['message' => __('账号尚未激活，请查收激活邮件。', SBA_TEXT_DOMAIN)]);
    }
    sba_ios_record_failure($ip, true);
    wp_set_current_user($user->ID);
    wp_set_auth_cookie($user->ID, (bool)$_POST['remember']);
    wp_send_json_success(['message' => __('登录成功', SBA_TEXT_DOMAIN)]);
}
add_action('wp_ajax_nopriv_sba_ios_register', 'sba_ios_ajax_register');
function sba_ios_ajax_register() {
    check_ajax_referer('sba_ios_action', '_ajax_nonce');
    $ip = sba_get_ip();
    if (!sba_ios_check_rate_limit($ip, 10)) wp_send_json_error(['message' => __('操作过于频繁，请稍后再试。', SBA_TEXT_DOMAIN)]);
    $status = sba_ios_check_ban_and_captcha($ip, 'register');
    if ($status['banned']) wp_send_json_error(['message' => __('由于多次失败，您的IP已被封禁24小时。', SBA_TEXT_DOMAIN)]);
    $stored = get_transient('sba_captcha_' . $ip);
    if (!$stored || $_POST['captcha'] != $stored) {
        sba_ios_record_failure($ip, false);
        wp_send_json_error(['message' => __('验证码错误', SBA_TEXT_DOMAIN), 'need_captcha' => true]);
    }
    delete_transient('sba_captcha_' . $ip);
    $username = sanitize_user($_POST['username']);
    $email = sanitize_email($_POST['email']);
    $password = $_POST['password'];
    if (empty($username) || empty($email) || empty($password)) {
        sba_ios_record_failure($ip, false);
        wp_send_json_error(['message' => __('所有字段都不能为空。', SBA_TEXT_DOMAIN)]);
    }
    if (strlen($password) < 8 || !preg_match('/[a-zA-Z]/', $password) || !preg_match('/[0-9]/', $password)) {
        sba_ios_record_failure($ip, false);
        wp_send_json_error(['message' => __('密码必须至少8位，且包含字母和数字。', SBA_TEXT_DOMAIN)]);
    }
    if (username_exists($username)) {
        sba_ios_record_failure($ip, false);
        wp_send_json_error(['message' => __('用户名已存在。', SBA_TEXT_DOMAIN)]);
    }
    if (email_exists($email)) {
        sba_ios_record_failure($ip, false);
        wp_send_json_error(['message' => __('邮箱已被注册。', SBA_TEXT_DOMAIN)]);
    }
    $user_id = wp_create_user($username, $password, $email);
    if (is_wp_error($user_id)) {
        sba_ios_record_failure($ip, false);
        wp_send_json_error(['message' => $user_id->get_error_message()]);
    }
    $activation_key = wp_generate_password(20, false);
    update_user_meta($user_id, '_activation_key', $activation_key);
    update_user_meta($user_id, '_activated', '0');
    $activation_url = add_query_arg(['action' => 'sba_activate', 'user' => $user_id, 'key' => $activation_key], home_url());
    $subject = sprintf(__('请激活您的账号 - %s', SBA_TEXT_DOMAIN), get_bloginfo('name'));
    $message = sprintf(__("您好 %s,\n\n请点击以下链接激活您的账号（链接24小时内有效）：\n%s\n\n如果没有注册过，请忽略此邮件。", SBA_TEXT_DOMAIN), $username, $activation_url);
    $sent = wp_mail($email, $subject, $message);
    if (!$sent) {
        wp_delete_user($user_id);
        sba_ios_record_failure($ip, false);
        wp_send_json_error(['message' => __('邮件发送失败，请联系管理员。', SBA_TEXT_DOMAIN)]);
    }
    sba_ios_record_failure($ip, true);
    wp_send_json_success(['message' => __('注册成功，请查收激活邮件。', SBA_TEXT_DOMAIN)]);
}
add_action('wp_ajax_nopriv_sba_ios_forgot', 'sba_ios_ajax_forgot');
function sba_ios_ajax_forgot() {
    check_ajax_referer('sba_ios_action', '_ajax_nonce');
    $ip = sba_get_ip();
    if (!sba_ios_check_rate_limit($ip, 10)) wp_send_json_error(['message' => __('操作过于频繁，请稍后再试。', SBA_TEXT_DOMAIN)]);
    $status = sba_ios_check_ban_and_captcha($ip, 'forgot');
    if ($status['banned']) wp_send_json_error(['message' => __('由于多次失败，您的IP已被封禁24小时。', SBA_TEXT_DOMAIN)]);
    $stored = get_transient('sba_captcha_' . $ip);
    if (!$stored || $_POST['captcha'] != $stored) {
        sba_ios_record_failure($ip, false);
        wp_send_json_error(['message' => __('验证码错误', SBA_TEXT_DOMAIN), 'need_captcha' => true]);
    }
    delete_transient('sba_captcha_' . $ip);
    $login = sanitize_text_field($_POST['email']);
    $user = is_email($login) ? get_user_by('email', $login) : get_user_by('login', $login);
    if (!$user) {
        sba_ios_record_failure($ip, false);
        wp_send_json_error(['message' => __('用户名或邮箱未注册。', SBA_TEXT_DOMAIN)]);
    }
    $key = get_password_reset_key($user);
    if (is_wp_error($key)) {
        sba_ios_record_failure($ip, false);
        wp_send_json_error(['message' => __('无法生成重置链接，请稍后重试。', SBA_TEXT_DOMAIN)]);
    }
    $reset_url = network_site_url("wp-login.php?action=rp&key=$key&login=" . rawurlencode($user->user_login), 'login');
    $subject = __('重置密码', SBA_TEXT_DOMAIN);
    $message = sprintf(__("请点击以下链接重置密码（链接24小时内有效）：\n%s", SBA_TEXT_DOMAIN), $reset_url);
    $sent = wp_mail($user->user_email, $subject, $message);
    if ($sent) {
        sba_ios_record_failure($ip, true);
        wp_send_json_success(['message' => __('重置链接已发送至您的邮箱。', SBA_TEXT_DOMAIN)]);
    } else {
        sba_ios_record_failure($ip, false);
        wp_send_json_error(['message' => __('邮件发送失败，请联系管理员。', SBA_TEXT_DOMAIN)]);
    }
}
add_action('init', 'sba_activation_handler');
function sba_activation_handler() {
    if (isset($_GET['action']) && $_GET['action'] === 'sba_activate') {
        $user_id = (int)$_GET['user'];
        $key = sanitize_text_field($_GET['key']);
        $stored_key = get_user_meta($user_id, '_activation_key', true);
        if (!$stored_key || get_user_meta($user_id, '_activated', true) === '1') wp_die(__('激活链接无效或已使用。', SBA_TEXT_DOMAIN), __('激活失败', SBA_TEXT_DOMAIN), ['response' => 400]);
        if ($stored_key === $key) {
            update_user_meta($user_id, '_activated', '1');
            delete_user_meta($user_id, '_activation_key');
            wp_set_current_user($user_id);
            wp_set_auth_cookie($user_id, false);
            wp_redirect(home_url('/?activation=success'));
            exit;
        }
        wp_die(__('激活码不正确。', SBA_TEXT_DOMAIN), __('激活失败', SBA_TEXT_DOMAIN), ['response' => 400]);
    }
}

// ==================== 管理菜单 ====================
add_action('admin_menu', 'sba_admin_menu');
function sba_admin_menu() {
    add_menu_page(__('全行为审计', SBA_TEXT_DOMAIN), __('全行为审计', SBA_TEXT_DOMAIN), 'manage_options', 'sba_audit', 'sba_audit_dashboard', 'dashicons-shield-alt');
    add_submenu_page('sba_audit', __('防御设置', SBA_TEXT_DOMAIN), __('防御设置', SBA_TEXT_DOMAIN), 'manage_options', 'sba_settings', 'sba_settings_page');
    add_submenu_page('sba_audit', __('威胁排行榜', SBA_TEXT_DOMAIN), __('威胁排行榜', SBA_TEXT_DOMAIN), 'manage_options', 'sba_threat_ranking', 'sba_threat_ranking_page');
    add_submenu_page('sba_audit', __('SMTP 邮件', SBA_TEXT_DOMAIN), __('SMTP 邮件', SBA_TEXT_DOMAIN), 'manage_options', 'sba-smtp', 'sba_smtp_page');
}
add_action('admin_init', function() { register_setting('sba_settings_group', 'sba_settings'); });

// ==================== Dashboard 页面 ====================
function sba_audit_dashboard() {
    global $wpdb;
    $latest = $wpdb->get_var("SELECT MAX(visit_date) FROM {$wpdb->prefix}dis_stats") ?: current_time('Y-m-d');
    $sync_lock = 'sba_sync_lock_' . $latest;
    if (false === get_transient($sync_lock)) {
        $real = $wpdb->get_row($wpdb->prepare("SELECT COUNT(DISTINCT ip) as real_uv, SUM(pv) as real_pv FROM {$wpdb->prefix}dis_stats WHERE visit_date = %s", $latest));
        if ($real) {
            if ($real->real_uv > sba_get_uv($latest)) update_option(SBA_PREFIX_UV . $latest, (int)$real->real_uv);
            if ($real->real_pv > sba_get_pv($latest)) update_option(SBA_PREFIX_PV . $latest, (int)$real->real_pv);
        }
        set_transient($sync_lock, 'locked', 300);
    }
    $online = (int)$wpdb->get_var("SELECT COUNT(DISTINCT ip) FROM {$wpdb->prefix}dis_stats WHERE last_visit > DATE_SUB(NOW(), INTERVAL 5 MINUTE)");
    $trend = sba_get_trend_data(30);
    $end_ts = strtotime($latest);
    ?>
    <style>
        .sba-wrap{max-width:1400px;width:100%;margin-top:15px;box-sizing:border-box;padding:0 15px}
        .sba-card{background:#fff;padding:20px;border-radius:12px;margin-bottom:20px;box-shadow:0 4px 15px rgba(0,0,0,0.05);box-sizing:border-box;width:100%;overflow-x:hidden}
        .sba-grid{display:grid;grid-template-columns:1fr 1fr;gap:20px}
        .sba-scroll-x{width:100%;max-width:100%;overflow-x:auto;border:1px solid #eee;border-radius:8px}
        .sba-table{width:100%;border-collapse:collapse;table-layout:auto}
        .sba-table th,.sba-table td{text-align:left;padding:12px 10px;border-bottom:1px solid #f9f9f9;font-size:13px;background:#fff;color:#333;vertical-align:middle}
        .sba-audit-table{table-layout:fixed;min-width:480px}
        .sba-audit-table th:nth-child(1){width:22%}
        .sba-audit-table th:nth-child(2){width:16%}
        .sba-audit-table th:nth-child(3){width:16%}
        .sba-audit-table th:nth-child(4){width:18%}
        .sba-audit-table th:nth-child(5){width:18%}
        .sba-track-table{min-width:700px}
        .col-time{width:80px}
        .col-ip{width:200px}
        .col-geo{width:160px}
        .col-pv{width:60px}
        .sba-blocked-table{min-width:500px}
        .sba-blocked-table th:first-child,.sba-blocked-table td:first-child{width:100px}
        .sba-blocked-table th:nth-child(2),.sba-blocked-table td:nth-child(2){width:150px}
        .sba-cell-wrap{white-space:normal;word-break:break-all;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden;line-height:1.4;font-size:12px}
        .stat-val{font-size:26px;font-weight:bold;display:block;margin-top:5px}
        .stats-row{display:flex;flex-wrap:nowrap;gap:15px;margin-bottom:20px}
        .stats-row .sba-card{flex:1;min-width:0}
        .chart-container{width:100%;height:250px;position:relative}
        .chart-container canvas{max-width:100%;width:100% !important;height:250px !important}
        @media (max-width:1000px){.sba-grid{grid-template-columns:1fr}}
        @media (max-width:768px){
            .sba-wrap{padding:0 10px}
            .sba-card{padding:12px}
            .stats-row{flex-direction:column;gap:10px}
            .stats-row .sba-card{width:100%;padding:10px 12px;text-align:center}
            .stat-val{font-size:20px}
            .sba-table th,.sba-table td{font-size:11px;padding:8px 5px}
            .sba-track-table{min-width:700px}
            .sba-blocked-table{min-width:500px}
            .sba-cell-wrap{-webkit-line-clamp:unset;display:block;overflow:visible}
        }
    </style>
    <div class="wrap sba-wrap">
        <h2><?php printf(__('🚀 SBA 站点行为监控 v%s', SBA_TEXT_DOMAIN), SBA_VERSION); ?></h2>
        <div class="stats-row">
            <div class="sba-card" style="border-left:4px solid #46b450;"><div><?php _e('当前在线:', SBA_TEXT_DOMAIN); ?></div><span class="stat-val" style="color:#46b450;"><?php echo $online; ?></span></div>
            <div class="sba-card" style="border-left:4px solid #2271b1;"><div><?php printf(__('今日 (%s) UV:', SBA_TEXT_DOMAIN), $latest); ?></div><span class="stat-val" style="color:#2271b1;"><?php echo sba_get_uv($latest); ?></span></div>
            <div class="sba-card" style="border-left:4px solid #4fc3f7;"><div><?php printf(__('今日 (%s) PV:', SBA_TEXT_DOMAIN), $latest); ?></div><span class="stat-val" style="color:#4fc3f7;"><?php echo sba_get_pv($latest); ?></span></div>
            <div class="sba-card" style="border-left:4px solid #d63638;"><div><?php printf(__('今日 (%s) 拦截:', SBA_TEXT_DOMAIN), $latest); ?></div><span class="stat-val" style="color:#d63638;"><?php echo sba_get_blocked($latest); ?></span></div>
        </div>
        <div class="sba-grid">
            <div class="sba-card"><h3><?php _e( '📈 30天访问趋势', SBA_TEXT_DOMAIN ); ?></h3><div class="chart-container"><canvas id="sbaChart"></canvas></div></div>
            <div class="sba-card"><h3><?php _e( '📊 50天审计详表', SBA_TEXT_DOMAIN ); ?></h3><div class="sba-scroll-x" style="height:250px;"><table class="sba-table sba-audit-table"><thead><tr><th><?php _e( '日期', SBA_TEXT_DOMAIN ); ?></th><th><?php _e( 'UV (人)', SBA_TEXT_DOMAIN ); ?></th><th><?php _e( 'PV (次)', SBA_TEXT_DOMAIN ); ?></th><th><?php _e( '拦截 (次)', SBA_TEXT_DOMAIN ); ?></th><th><?php _e( '深度', SBA_TEXT_DOMAIN ); ?></th></tr></thead><tbody><?php for ( $i = 0; $i < 50; $i++ ): $d = date( 'Y-m-d', $end_ts - ( $i * 86400 ) ); $u = sba_get_uv( $d ); $p = sba_get_pv( $d ); $b = sba_get_blocked( $d ); ?><tr><td><b><?php echo $d; ?></b></td><td><?php echo $u; ?></td><td><?php echo $p; ?></td><td style="color:#d63638;"><?php echo $b; ?></td><td><code><?php echo ($u > 0) ? round( $p / $u, 1 ) : 0; ?></code></td></tr><?php endfor; ?></tbody></table></div></div>
        </div>
        <div class="sba-card"><h3><?php printf(__('👣 访客轨迹 (%s)', SBA_TEXT_DOMAIN), $latest); ?></h3><div class="sba-scroll-x"><table class="sba-table sba-track-table"><thead><tr><th class="col-time"><?php _e('时间', SBA_TEXT_DOMAIN); ?></th><th class="col-ip"><?php _e('IP', SBA_TEXT_DOMAIN); ?></th><th class="col-geo"><?php _e('归属地', SBA_TEXT_DOMAIN); ?></th><th class="col-url"><?php _e('访问路径', SBA_TEXT_DOMAIN); ?></th><th class="col-pv"><?php _e('PV', SBA_TEXT_DOMAIN); ?></th></tr></thead><tbody id="track-body"></tbody></table></div>
        <div style="margin-top:15px;display:flex;justify-content:space-between;"><div><?php _e('总记录:', SBA_TEXT_DOMAIN); ?> <b id="total-rows">0</b></div><div><button id="prev-page" class="button"><?php _e('◀ 上页', SBA_TEXT_DOMAIN); ?></button> <?php _e('第', SBA_TEXT_DOMAIN); ?> <b id="current-page">1</b> / <b id="total-pages">1</b> <?php _e('页', SBA_TEXT_DOMAIN); ?> <button id="next-page" class="button"><?php _e('下页 ▶', SBA_TEXT_DOMAIN); ?></button></div></div></div>
        <div class="sba-card" style="border-top:3px solid #d63638;"><h3><?php printf(__('🚫 拦截日志 (%s)', SBA_TEXT_DOMAIN), $latest); ?></h3><div class="sba-scroll-x"><table class="sba-table sba-blocked-table"><thead><tr><th><?php _e('时间', SBA_TEXT_DOMAIN); ?></th><th><?php _e('拦截 IP', SBA_TEXT_DOMAIN); ?></th><th><?php _e('原因与目标', SBA_TEXT_DOMAIN); ?></th></tr></thead><tbody id="blocked-log-body"></tbody></table></div>
        <div style="margin-top:15px;display:flex;justify-content:space-between;"><div><?php _e('总记录:', SBA_TEXT_DOMAIN); ?> <b id="blocked-total-rows">0</b></div><div><button id="blocked-prev-page" class="button"><?php _e('◀ 上页', SBA_TEXT_DOMAIN); ?></button> <?php _e('第', SBA_TEXT_DOMAIN); ?> <b id="blocked-current-page">1</b> / <b id="blocked-total-pages">1</b> <?php _e('页', SBA_TEXT_DOMAIN); ?> <button id="blocked-next-page" class="button"><?php _e('下页 ▶', SBA_TEXT_DOMAIN); ?></button></div></div></div>
    </div>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script>
    new Chart(document.getElementById('sbaChart').getContext('2d'), {
        type:'line', data:{ labels:<?php echo json_encode($trend['labels']); ?>, datasets:[
            { label:'UV', data:<?php echo json_encode($trend['uv']); ?>, borderColor:'#2271b1', backgroundColor:'rgba(34,113,177,0.1)', fill:true },
            { label:'PV', data:<?php echo json_encode($trend['pv']); ?>, borderColor:'#4fc3f7', backgroundColor:'rgba(79,195,247,0.1)', fill:true },
            { label:'<?php _e("拦截", SBA_TEXT_DOMAIN); ?>', data:<?php echo json_encode($trend['blocked']); ?>, borderColor:'#d63638', backgroundColor:'rgba(214,54,56,0.1)', borderDash:[5,5], fill:true }
        ]}, options:{ maintainAspectRatio:false, responsive:true, interaction:{ intersect:false, mode:'index' }, scales:{ y:{ beginAtZero:true } } }
    });
    let curP=1,maxP=1;
    function loadTracks(p){fetch(ajaxurl,{method:'POST',body:new URLSearchParams({action:'sba_load_tracks',page:p})}).then(r=>r.json()).then(res=>{if(res.success){document.getElementById('track-body').innerHTML=res.data.html;curP=p;maxP=res.data.pages;document.getElementById('prev-page').disabled=(curP<=1);document.getElementById('next-page').disabled=(curP>=maxP);document.getElementById('current-page').innerText=p;document.getElementById('total-pages').innerText=maxP;document.getElementById('total-rows').innerText=res.data.total;}}).catch(()=>{document.getElementById('track-body').innerHTML='<tr><td colspan="5" style="color:#d63638;">加载失败，请刷新页面重试</td></tr>';});}
    document.getElementById('prev-page').onclick=()=>{if(curP>1)loadTracks(curP-1);};
    document.getElementById('next-page').onclick=()=>{if(curP<maxP)loadTracks(curP+1);};
    loadTracks(1);
    let blockedCurPage=1,blockedMaxPages=1;
    function loadBlockedLogs(p){fetch(ajaxurl,{method:'POST',body:new URLSearchParams({action:'sba_load_blocked_logs',page:p})}).then(r=>r.json()).then(res=>{if(res.success){document.getElementById('blocked-log-body').innerHTML=res.data.html;blockedCurPage=p;blockedMaxPages=res.data.pages;document.getElementById('blocked-prev-page').disabled=(blockedCurPage<=1);document.getElementById('blocked-next-page').disabled=(blockedCurPage>=blockedMaxPages);document.getElementById('blocked-current-page').innerText=p;document.getElementById('blocked-total-pages').innerText=res.data.pages;document.getElementById('blocked-total-rows').innerText=res.data.total;}}).catch(()=>{document.getElementById('blocked-log-body').innerHTML='<tr><td colspan="3" style="color:#d63638;">加载失败，请刷新页面重试</td></tr>';});}
    document.getElementById('blocked-prev-page').onclick=()=>{if(blockedCurPage>1)loadBlockedLogs(blockedCurPage-1);};
    document.getElementById('blocked-next-page').onclick=()=>{if(blockedCurPage<blockedMaxPages)loadBlockedLogs(blockedCurPage+1);};
    loadBlockedLogs(1);
    </script>
    <?php
}

// ==================== 威胁排行榜页面 ====================
function sba_threat_ranking_page() {
    $ban_list = get_option('sba_permanent_ban_list', []);
    ?>
    <div class="wrap sba-wrap">
        <div style="display: flex; justify-content: space-between; align-items: center;">
            <h1><?php _e('🔥 高频威胁排行榜', SBA_TEXT_DOMAIN); ?></h1>
            <button id="sba-sync-btn" class="button button-secondary"><?php _e('🔄 同步历史数据', SBA_TEXT_DOMAIN); ?></button>
        </div>
        <div class="sba-card">
            <h3><?php _e('实时统计', SBA_TEXT_DOMAIN); ?></h3>
            <div class="sba-scroll-x">
                <table class="sba-table">
                    <thead><tr><th><?php _e('排名', SBA_TEXT_DOMAIN); ?></th><th><?php _e('IP 地址', SBA_TEXT_DOMAIN); ?></th><th><?php _e('拦截次数', SBA_TEXT_DOMAIN); ?></th><th><?php _e('最后活动', SBA_TEXT_DOMAIN); ?></th><th><?php _e('操作', SBA_TEXT_DOMAIN); ?></th></tr></thead>
                    <tbody id="threat-ranking-body"><tr><td colspan="5"><?php _e('加载中...', SBA_TEXT_DOMAIN); ?></td></tr></tbody>
                </table>
            </div>
            <div style="margin-top:20px; display:flex; gap:10px; align-items:center;">
                <button id="sba-prev-page" class="button" disabled><?php _e('◀ 上一页', SBA_TEXT_DOMAIN); ?></button>
                <span><?php _e('第', SBA_TEXT_DOMAIN); ?> <b id="sba-current-page-num">1</b> <?php _e('页', SBA_TEXT_DOMAIN); ?></span>
                <button id="sba-next-page" class="button" disabled><?php _e('下一页 ▶', SBA_TEXT_DOMAIN); ?></button>
            </div>
        </div>
        <div class="sba-card" style="margin-top:20px; border-top: 3px solid #333;">
            <h3><?php _e('🚫 永久封禁名单', SBA_TEXT_DOMAIN); ?></h3>
            <div id="sba-permanent-ban-list"><?php echo sba_generate_ban_list_html(); ?></div>
        </div>
    </div>
    <script>
    var sba_i18n = {
        loading: '<?php _e("加载中...", SBA_TEXT_DOMAIN); ?>', loadFailed: '<?php _e("加载失败", SBA_TEXT_DOMAIN); ?>', unknownError: '<?php _e("未知错误", SBA_TEXT_DOMAIN); ?>',
        networkError: '<?php _e("网络错误，请刷新页面重试", SBA_TEXT_DOMAIN); ?>', banConfirm: '<?php _e("确定要永久封禁该 IP 吗？", SBA_TEXT_DOMAIN); ?>',
        unbanConfirm: '<?php _e("确定要解除该 IP 的封禁吗？", SBA_TEXT_DOMAIN); ?>', banning: '<?php _e("封禁中...", SBA_TEXT_DOMAIN); ?>', unbanning: '<?php _e("解封中...", SBA_TEXT_DOMAIN); ?>',
        banFailed: '<?php _e("封禁请求失败", SBA_TEXT_DOMAIN); ?>', unbanFailed: '<?php _e("解封请求失败", SBA_TEXT_DOMAIN); ?>', syncFailed: '<?php _e("同步请求失败", SBA_TEXT_DOMAIN); ?>',
        permanentBan: '<?php _e("永久封禁", SBA_TEXT_DOMAIN); ?>', removeBan: '<?php _e("解除封禁", SBA_TEXT_DOMAIN); ?>', syncing: '<?php _e("同步中...", SBA_TEXT_DOMAIN); ?>',
        syncHistory: '<?php _e("🔄 同步历史数据", SBA_TEXT_DOMAIN); ?>', prevPage: '<?php _e("◀ 上一页", SBA_TEXT_DOMAIN); ?>', nextPage: '<?php _e("下一页 ▶", SBA_TEXT_DOMAIN); ?>',
        page: '<?php _e("第", SBA_TEXT_DOMAIN); ?>', pageOf: '<?php _e("页", SBA_TEXT_DOMAIN); ?>'
    };
    jQuery(document).ready(function($) {
        var currentPage = 1, isLoading = false;
        function loadThreatRanking(page) {
            if (isLoading) return;
            isLoading = true;
            $('#threat-ranking-body').html('<tr><td colspan="5" style="text-align:center;">' + sba_i18n.loading + '</td></tr>');
            $.ajax({ url: ajaxurl, type: 'POST', data: { action: 'sba_get_threat_ranking', page: page }, dataType: 'json',
                success: function(res) {
                    if (res.success) {
                        $('#threat-ranking-body').html(res.data.html);
                        currentPage = page;
                        $('#sba-current-page-num').text(currentPage);
                        $('#sba-prev-page').prop('disabled', currentPage <= 1);
                        $('#sba-next-page').prop('disabled', !res.data.has_next);
                    } else $('#threat-ranking-body').html('<tr><td colspan="5" style="text-align:center;color:#d63638;">' + sba_i18n.loadFailed + ': ' + (res.data || sba_i18n.unknownError) + '</td></tr>');
                    isLoading = false;
                },
                error: function() { $('#threat-ranking-body').html('<tr><td colspan="5" style="text-align:center;color:#d63638;">' + sba_i18n.networkError + '</td></tr>'); isLoading = false; }
            });
        }
        $(document).on('click', '.sba-ban-ip-btn', function() {
            var ip = $(this).data('ip');
            if (!confirm(sba_i18n.banConfirm + ' ' + ip)) return;
            var btn = $(this), original = btn.text();
            btn.prop('disabled', true).text(sba_i18n.banning);
            $.post(ajaxurl, { action: 'sba_ban_ip', ip: ip }, function(res) {
                if (res.success) { alert(res.data.message); if (res.data.ban_list_html) $('#sba-permanent-ban-list').html(res.data.ban_list_html); loadThreatRanking(currentPage); }
                else { alert(res.data); btn.prop('disabled', false).text(original); }
            }, 'json').fail(function() { alert(sba_i18n.banFailed); btn.prop('disabled', false).text(original); });
        });
        $(document).on('click', '.sba-unban-ip-btn', function() {
            var ip = $(this).data('ip');
            if (!confirm(sba_i18n.unbanConfirm + ' ' + ip)) return;
            var btn = $(this), original = btn.text();
            btn.prop('disabled', true).text(sba_i18n.unbanning);
            $.post(ajaxurl, { action: 'sba_unban_ip', ip: ip }, function(res) {
                if (res.success) { alert(res.data.message); if (res.data.ban_list_html) $('#sba-permanent-ban-list').html(res.data.ban_list_html); loadThreatRanking(currentPage); }
                else { alert(res.data); btn.prop('disabled', false).text(original); }
            }, 'json').fail(function() { alert(sba_i18n.unbanFailed); btn.prop('disabled', false).text(original); });
        });
        $('#sba-prev-page').off('click').on('click', function() { if (currentPage > 1 && !isLoading) loadThreatRanking(currentPage - 1); });
        $('#sba-next-page').off('click').on('click', function() { if (!isLoading) loadThreatRanking(currentPage + 1); });
        $('#sba-sync-btn').off('click').on('click', function() {
            var btn = $(this);
            btn.prop('disabled', true).text(sba_i18n.syncing);
            $.post(ajaxurl, { action: 'sba_sync_threat_ranking' }, function(res) {
                if (res.success) alert(res.data.message);
                else alert(res.data || sba_i18n.syncFailed);
                btn.prop('disabled', false).text(sba_i18n.syncHistory);
                loadThreatRanking(1);
            }, 'json').fail(function() { alert(sba_i18n.syncFailed); btn.prop('disabled', false).text(sba_i18n.syncHistory); });
        });
        loadThreatRanking(1);
    });
    </script>
    <?php
}

// ==================== 设置页面 ====================
function sba_settings_page() {
    $opts = get_option('sba_settings');
    ?>
    <div class="wrap sba-wrap">
        <?php settings_errors(); ?>
        <h1><?php _e('🛠️ SBA 防御设置', SBA_TEXT_DOMAIN); ?></h1>
        <div class="sba-card" style="background:#fffbe6;border-left:5px solid #faad14;">
            <h3><?php _e('📖 核心功能配置指南', SBA_TEXT_DOMAIN); ?></h3>
            <p><?php _e('1. <b>性能对账：</b>数据每 10 分钟写库。若觉延迟，按 <code>Ctrl + F5</code> 强制对账。白名单用户豁免所有拦截。', SBA_TEXT_DOMAIN); ?></p>
            <p><?php _e('2. <b>入口保护：</b>系统已自动封锁 wp-login.php 和 wp-admin 目录。请使用 <code>[sba_login_box]</code> 短代码在前台展示登录面板。', SBA_TEXT_DOMAIN); ?></p>
            <p><?php _e('3. <b>IP 信任：</b>看仪表盘 IP。若为 127.0.0.1 或内网 IP，请根据 CDN/代理环境切换至「Nginx」或「Cloudflare」。', SBA_TEXT_DOMAIN); ?></p>
            <p><?php _e('4. <b>AJAX 补丁：</b>无痕访问首页。若「访客轨迹」未增加记录，说明 PHP 被静态缓存截断，此时必须开启。', SBA_TEXT_DOMAIN); ?></p>
            <p><?php _e('5. <b>爬虫防御：</b>「Cookie 校验」识别无状态脚本。内置「蜜罐陷阱」会自动诱捕并封禁扫描页面的恶意爬虫。', SBA_TEXT_DOMAIN); ?></p>
        </div>
        <form method="post" action="options.php">
            <?php settings_fields('sba_settings_group'); ?>
            <div class="sba-grid">
                <div class="sba-card"><h3><?php _e('✅ 信任通道', SBA_TEXT_DOMAIN); ?></h3><table class="form-table">
                    <tr><th><?php _e('用户名白名单', SBA_TEXT_DOMAIN); ?></th><td><input type="text" name="sba_settings[user_whitelist]" value="<?php echo esc_attr($opts['user_whitelist'] ?? ''); ?>" class="regular-text" /><br><small><?php _e('登录此用户时，系统自动信任，不执行拦截逻辑。', SBA_TEXT_DOMAIN); ?></small></td></tr>
                    <tr><th><?php _e('应急密钥', SBA_TEXT_DOMAIN); ?></th><td><input type="text" name="sba_settings[emergency_entrance_key]" value="<?php echo esc_attr(sba_get_option('emergency_entrance_key')); ?>" class="regular-text" placeholder="?sba_key=xxx" /><br><small class="description"><?php _e('访问 <code>域名/?sba_key=密钥</code> 可自动加白名单。', SBA_TEXT_DOMAIN); ?></small></td></tr>
                    <tr><th><?php _e('IP 白名单', SBA_TEXT_DOMAIN); ?></th><td><textarea name="sba_settings[ip_whitelist]" rows="3" style="width:100%"><?php echo esc_textarea($opts['ip_whitelist'] ?? ''); ?></textarea><br><small><?php _e('每行一个 IP。支持 IPv4 和 IPv6。', SBA_TEXT_DOMAIN); ?></small></td></tr>
                </table></div>
                <div class="sba-card"><h3><?php _e('🚫 防御配置', SBA_TEXT_DOMAIN); ?></h3><table class="form-table">
                    <tr><th><?php _e('CC 封禁阈值', SBA_TEXT_DOMAIN); ?></th><td><input type="number" name="sba_settings[auto_block_limit]" value="<?php echo esc_attr($opts['auto_block_limit'] ?? '60'); ?>" /> <?php _e('次/分', SBA_TEXT_DOMAIN); ?><br><small><?php _e('单 IP 每分钟请求超过此值自动封禁（0 为关闭）。', SBA_TEXT_DOMAIN); ?></small></td></tr>
                    <tr><th><?php _e('IP 信任来源', SBA_TEXT_DOMAIN); ?></th><td><select name="sba_settings[ip_source]"><option value="REMOTE_ADDR" <?php selected($opts['ip_source'] ?? '', 'REMOTE_ADDR'); ?>><?php _e('REMOTE_ADDR (标准直连)', SBA_TEXT_DOMAIN); ?></option><option value="HTTP_CF_CONNECTING_IP" <?php selected($opts['ip_source'] ?? '', 'HTTP_CF_CONNECTING_IP'); ?>><?php _e('Cloudflare (CF_IP)', SBA_TEXT_DOMAIN); ?></option><option value="HTTP_X_REAL_IP" <?php selected($opts['ip_source'] ?? '', 'HTTP_X_REAL_IP'); ?>><?php _e('Nginx 转发 (REAL_IP)', SBA_TEXT_DOMAIN); ?></option><option value="HTTP_X_FORWARDED_FOR" <?php selected($opts['ip_source'] ?? '', 'HTTP_X_FORWARDED_FOR'); ?>><?php _e('标准代理 (XFF)', SBA_TEXT_DOMAIN); ?></option></select><br><small><?php _e('根据 CDN 环境选择正确的 IP 来源。', SBA_TEXT_DOMAIN); ?></small></td></tr>
                    <tr><th><?php _e('AJAX 异步统计', SBA_TEXT_DOMAIN); ?></th><td><label><input type="checkbox" name="sba_settings[enable_ajax_patch]" value="1" <?php checked($opts['enable_ajax_patch'] ?? 0, 1); ?> /> <?php _e('启用异步统计（解决静态 HTML 缓存导致的 PV 丢失）', SBA_TEXT_DOMAIN); ?></label></td></tr>
                    <tr><th><?php _e('追加拦截路径', SBA_TEXT_DOMAIN); ?></th><td><input type="text" name="sba_settings[evil_paths]" value="<?php echo esc_attr($opts['evil_paths'] ?? ''); ?>" style="width:100%" placeholder="/test.php, /backup.zip" /></td></tr>
                    <tr><th><?php _e('爬虫特征正则', SBA_TEXT_DOMAIN); ?></th><td><input type="text" name="sba_settings[scraper_paths]" value="<?php echo esc_attr($opts['scraper_paths'] ?? 'feed=|rest_route=|[\?&]m=|\?p='); ?>" style="width:100%" /></td></tr>
                    <tr><th><?php _e('高级策略', SBA_TEXT_DOMAIN); ?></th><td><label><input type="checkbox" name="sba_settings[enable_cookie_check]" value="1" <?php checked($opts['enable_cookie_check'] ?? 1, 1); ?> /> <?php _e('启用 Cookie 身份校验', SBA_TEXT_DOMAIN); ?></label></td></tr>
                    <tr><th><?php _e('拦截重定向', SBA_TEXT_DOMAIN); ?></th><td><input type="text" name="sba_settings[block_target_url]" value="<?php echo esc_attr($opts['block_target_url'] ?? ''); ?>" style="width:100%" placeholder="https://127.0.0.1" /></td></tr>
                </table></div>
            </div>
            <div class="sba-card" style="margin-top:20px;">
                <h3><?php _e('🔒 出站安全（SSRF 防御）', SBA_TEXT_DOMAIN); ?></h3>
                <table class="form-table">
                    <tr><th><?php _e('DNS Rebinding', SBA_TEXT_DOMAIN); ?></th><td><label><input type="checkbox" name="sba_settings[ssrf_prevent_dns_rebind]" value="1" <?php checked($opts['ssrf_prevent_dns_rebind'] ?? 1, 1); ?> /> <?php _e('启用强制 IP 直连 + Host 头校验', SBA_TEXT_DOMAIN); ?></label></td></tr>
                    <tr><th><?php _e('出站 IP 白名单', SBA_TEXT_DOMAIN); ?></th><td><textarea name="sba_settings[outbound_whitelist]" rows="2" style="width:100%;" placeholder="<?php echo esc_attr__("192.168.1.100\n10.0.0.0/8", SBA_TEXT_DOMAIN); ?>"><?php echo esc_textarea($opts['outbound_whitelist'] ?? ''); ?></textarea></td></tr>
                    <tr><th><?php _e('额外黑名单 (CIDR)', SBA_TEXT_DOMAIN); ?></th><td><input type="text" name="sba_settings[ssrf_blacklist]" value="<?php echo esc_attr($opts['ssrf_blacklist'] ?? ''); ?>" style="width:100%;" placeholder="<?php echo esc_attr__("192.0.2.0/24, 203.0.113.0/24", SBA_TEXT_DOMAIN); ?>" /></td></tr>
                </table>
            </div>
            <?php submit_button(); ?>
        </form>
        <div class="sba-card"><h3><?php _e('📁 IP 归属地库 (ip2region xdb) 分片上传', SBA_TEXT_DOMAIN); ?></h3>
            <?php foreach (['v4' => __('IPv4库', SBA_TEXT_DOMAIN), 'v6' => __('IPv6库', SBA_TEXT_DOMAIN)] as $type => $label): ?>
            <div style="margin-bottom:20px;"><p><strong><?php echo $label; ?></strong> <?php echo file_exists(constant("SBA_IP_" . strtoupper($type) . "_FILE")) ? '<span style="color:green;">✓ ' . __('已上传', SBA_TEXT_DOMAIN) . ' (' . size_format(filesize(constant("SBA_IP_" . strtoupper($type) . "_FILE"))) . ')</span>' : '<span style="color:red;">✗ ' . __('未上传', SBA_TEXT_DOMAIN) . '</span>'; ?></p>
            <div><input type="file" id="sba-ip-<?php echo $type; ?>-file" accept=".xdb"><button id="sba-upload-<?php echo $type; ?>-btn" class="button button-primary"><?php _e('上传', SBA_TEXT_DOMAIN); ?> <?php echo $label; ?></button><button id="sba-cancel-upload-<?php echo $type; ?>-btn" class="button button-secondary" style="display:none;"><?php _e('取消上传', SBA_TEXT_DOMAIN); ?></button></div>
            <div id="sba-upload-<?php echo $type; ?>-progress" style="display:none;margin-top:10px;"><div style="background:#f0f0f0;height:20px;border-radius:10px;overflow:hidden;width:100%;max-width:400px;"><div id="sba-upload-<?php echo $type; ?>-bar" style="background:#2271b1;width:0%;height:100%;transition:width 0.3s;text-align:center;color:#fff;line-height:20px;font-size:12px;">0%</div></div><div id="sba-upload-<?php echo $type; ?>-status" style="margin-top:5px;font-size:12px;color:#555;"></div></div></div>
            <?php if ($type === 'v4') echo '<hr style="margin:20px 0;">'; endforeach; ?>
        </div>
        <?php sba_environment_panel(); ?>
    </div>
    <?php
    sba_upload_script();
}
function sba_environment_panel() {
    ?>
    <div class="sba-card" style="margin-top:20px;"><h3><?php _e('⚙️ 服务器环境检测', SBA_TEXT_DOMAIN); ?></h3><table class="widefat" style="width:auto;"><tr><th><?php _e('PHP 版本', SBA_TEXT_DOMAIN); ?></th><td><?php echo PHP_VERSION; ?></td><th>upload_max_filesize</th><td><?php echo ini_get('upload_max_filesize'); ?></td></tr><tr><th>post_max_size</th><td><?php echo ini_get('post_max_size'); ?></td><th>memory_limit</th><td><?php echo ini_get('memory_limit'); ?></td></tr><tr><th>max_execution_time</th><td><?php echo ini_get('max_execution_time'); ?> <?php _e('秒', SBA_TEXT_DOMAIN); ?></td><th>cURL</th><td><?php echo extension_loaded('curl') ? '✓' : '✗'; ?></td></tr></table><p class="description"><?php _e('若需上传大文件（超过 10MB），建议将 <code>upload_max_filesize</code> 和 <code>post_max_size</code> 调至至少 64M。', SBA_TEXT_DOMAIN); ?></p></div>
    <?php
}
// 分片上传脚本与 AJAX
function sba_upload_script() {
    ?>
    <script>
    jQuery(document).ready(function($) {
        if (typeof ajaxurl === 'undefined') { var ajaxurl = '<?php echo admin_url('admin-ajax.php'); ?>'; }
        function createUploader(type, fileInputId, uploadBtnId, cancelBtnId, progressDivId, barId, statusId) {
            let currentFile = null, isUploading = false, chunkSize = <?php echo SBA_CHUNK_SIZE_INITIAL; ?>, minChunkSize = <?php echo SBA_MIN_CHUNK_SIZE; ?>, maxChunkSize = <?php echo SBA_MAX_CHUNK_SIZE; ?>, consecutiveSuccess = 0, uploadedParts = [], maxRetries = 5, nonce = '<?php echo wp_create_nonce('sba_upload_xdb'); ?>';
            function sleep(ms){return new Promise(resolve=>setTimeout(resolve,ms));}
            async function uploadChunkWithRetry(formData, start, attempt=1){return new Promise((resolve,reject)=>{const xhr=new XMLHttpRequest();xhr.open('POST',ajaxurl,true);xhr.timeout=60000;xhr.onload=function(){if(xhr.status===200){try{const res=JSON.parse(xhr.responseText);if(res.success){consecutiveSuccess++;if(consecutiveSuccess>=3&&chunkSize<maxChunkSize){chunkSize=Math.min(chunkSize*2,maxChunkSize);$('#'+statusId).append(`<br><small><?php _e('网络良好，分片大小提升至', SBA_TEXT_DOMAIN); ?> ${(chunkSize/1024/1024).toFixed(1)}MB</small>`);consecutiveSuccess=0;}resolve(res);}else reject(new Error(res.data||'<?php _e('上传失败', SBA_TEXT_DOMAIN); ?>'));}catch(e){reject(e);}}else if(xhr.status===413){chunkSize=Math.max(chunkSize/2,minChunkSize);$('#'+statusId).html(`<span style="color:#d63638;"><?php _e('单片过大，已降低至', SBA_TEXT_DOMAIN); ?> ${(chunkSize/1024/1024).toFixed(1)}MB，<?php _e('重试中...', SBA_TEXT_DOMAIN); ?></span>`);reject(new Error('Chunk too large'));}else reject(new Error(`HTTP ${xhr.status}`));};xhr.onerror=()=>reject(new Error('<?php _e('网络错误', SBA_TEXT_DOMAIN); ?>'));xhr.ontimeout=()=>reject(new Error('<?php _e('上传超时', SBA_TEXT_DOMAIN); ?>'));xhr.send(formData);});}
            async function uploadChunkWithBackoff(formData,start,end){let delay=1000;for(let attempt=1;attempt<=maxRetries;attempt++){try{return await uploadChunkWithRetry(formData,start,attempt);}catch(error){if(attempt===maxRetries)throw error;const wait=delay*Math.pow(2,attempt-1);$('#'+statusId).html(`<span style="color:#d63638;"><?php _e('区间', SBA_TEXT_DOMAIN); ?> ${start}-${end} <?php _e('上传失败，', SBA_TEXT_DOMAIN); ?> ${wait/1000} <?php _e('秒后重试', SBA_TEXT_DOMAIN); ?> (${attempt}/${maxRetries})...</span>`);await sleep(wait);}}}
            function mergeIntervals(intervals){if(intervals.length===0)return[];intervals.sort((a,b)=>a.start-b.start);let merged=[intervals[0]];for(let i=1;i<intervals.length;i++){let last=merged[merged.length-1],curr=intervals[i];if(curr.start<=last.end)last.end=Math.max(last.end,curr.end);else merged.push(curr);}return merged;}
            function getRemainingIntervals(fileSize,uploaded){let merged=mergeIntervals(uploaded),remaining=[],cursor=0;for(let i=0;i<merged.length;i++){if(cursor<merged[i].start)remaining.push({start:cursor,end:merged[i].start});cursor=merged[i].end;}if(cursor<fileSize)remaining.push({start:cursor,end:fileSize});return remaining;}
            async function getUploadedParts(filename,fileSize){return new Promise((resolve,reject)=>{$.post(ajaxurl,{action:'sba_upload_xdb_status',type:type,filename:filename,file_size:fileSize,_wpnonce:nonce},function(res){if(res.success)resolve(res.data.parts||[]);else reject(new Error(res.data));},'json').fail(()=>reject(new Error('<?php _e('查询状态失败', SBA_TEXT_DOMAIN); ?>')));});}
            async function cancelUpload(filename,fileSize){return new Promise((resolve,reject)=>{$.post(ajaxurl,{action:'sba_upload_xdb_cancel',type:type,filename:filename,file_size:fileSize,_wpnonce:nonce},function(res){if(res.success)resolve();else reject(new Error(res.data));},'json').fail(()=>reject(new Error('<?php _e('中断请求失败', SBA_TEXT_DOMAIN); ?>')));});}
            async function uploadFileInChunks(file){currentFile=file;isUploading=true;$('#'+cancelBtnId).show();try{const uploaded=await getUploadedParts(file.name,file.size);uploadedParts=uploaded;let remainingIntervals=getRemainingIntervals(file.size,uploadedParts);const totalBytes=file.size;let uploadedBytes=uploadedParts.reduce((sum,p)=>sum+(p.end-p.start),0);let initialPercent=Math.round((uploadedBytes/totalBytes)*100);$('#'+progressDivId).show();$('#'+barId).css('width',initialPercent+'%').text(initialPercent+'%');$('#'+statusId).html(`<?php _e('准备上传，动态分片大小', SBA_TEXT_DOMAIN); ?> ${(chunkSize/1024/1024).toFixed(1)}MB，<?php _e('剩余', SBA_TEXT_DOMAIN); ?> ${remainingIntervals.length} <?php _e('个区间', SBA_TEXT_DOMAIN); ?>`);
                for(let interval of remainingIntervals){if(!isUploading)break;let start=interval.start;while(start<interval.end&&isUploading){let chunkEnd=Math.min(start+chunkSize,interval.end);const chunk=file.slice(start,chunkEnd);const formData=new FormData();formData.append('action','sba_upload_xdb_chunk');formData.append('file_chunk',chunk);formData.append('type',type);formData.append('filename',file.name);formData.append('start',start);formData.append('end',chunkEnd);formData.append('file_size',file.size);formData.append('_wpnonce',nonce);try{const response=await uploadChunkWithBackoff(formData,start,chunkEnd);if(response&&response.message==='<?php _e('上传并合并完成', SBA_TEXT_DOMAIN); ?>'){isUploading=false;$('#'+statusId).html('<span style=\"color:#46b450;\">✓ <?php _e('上传成功，正在刷新页面...', SBA_TEXT_DOMAIN); ?></span>');setTimeout(()=>location.reload(),1500);return;}uploadedParts.push({start:start,end:chunkEnd});uploadedParts=mergeIntervals(uploadedParts);const uploadedNow=uploadedParts.reduce((sum,p)=>sum+(p.end-p.start),0);const percent=Math.round((uploadedNow/totalBytes)*100);$('#'+barId).css('width',percent+'%').text(percent+'%');$('#'+statusId).text(`<?php _e('区间', SBA_TEXT_DOMAIN); ?> ${start}-${chunkEnd} <?php _e('上传成功', SBA_TEXT_DOMAIN); ?> (${percent}%)`);start=chunkEnd;}catch(error){throw new Error(`<?php _e('上传失败:', SBA_TEXT_DOMAIN); ?> ${error.message}`);}}}
                if(isUploading){const finalParts=await getUploadedParts(file.name,file.size);if(finalParts.length===0){$('#'+statusId).html('<span style=\"color:#46b450;\">✓ <?php _e('上传成功，正在刷新页面...', SBA_TEXT_DOMAIN); ?></span>');setTimeout(()=>location.reload(),1500);return;}const finalMerged=mergeIntervals(finalParts);const totalCovered=finalMerged.reduce((sum,p)=>sum+(p.end-p.start),0);if(totalCovered>=file.size){$('#'+statusId).html('<span style=\"color:#46b450;\">✓ <?php _e('上传成功，正在刷新页面...', SBA_TEXT_DOMAIN); ?></span>');setTimeout(()=>location.reload(),1500);}else throw new Error('<?php _e('上传未完全完成', SBA_TEXT_DOMAIN); ?>');}}catch(error){$('#'+statusId).html(`<span style=\"color:#d63638;\">✗ <?php _e('上传失败：', SBA_TEXT_DOMAIN); ?> ${error.message}</span>`);setTimeout(()=>$('#'+progressDivId).hide(),3000);}finally{isUploading=false;$('#'+cancelBtnId).hide();}}
            $('#'+uploadBtnId).click(function(){const file=document.getElementById(fileInputId).files[0];if(!file){alert('<?php _e('请选择文件', SBA_TEXT_DOMAIN); ?>');return;}if(!file.name.endsWith('.xdb')){alert('<?php _e('只允许 .xdb 格式的文件', SBA_TEXT_DOMAIN); ?>');return;}uploadFileInChunks(file);});
            $('#'+cancelBtnId).click(async function(){if(!currentFile||!isUploading)return;if(confirm('<?php _e('确定要中断上传并清理已上传的临时文件吗？', SBA_TEXT_DOMAIN); ?>')){isUploading=false;$('#'+statusId).html('<?php _e('正在中断并清理临时文件...', SBA_TEXT_DOMAIN); ?>');try{await cancelUpload(currentFile.name,currentFile.size);$('#'+statusId).html('<?php _e('已中断上传，临时文件已清理', SBA_TEXT_DOMAIN); ?>');setTimeout(()=>$('#'+progressDivId).hide(),2000);}catch(error){$('#'+statusId).html(`<?php _e('中断失败：', SBA_TEXT_DOMAIN); ?> ${error.message}`);}$('#'+cancelBtnId).hide();}});
        }
        createUploader('v4','sba-ip-v4-file','sba-upload-v4-btn','sba-cancel-upload-v4-btn','sba-upload-v4-progress','sba-upload-v4-bar','sba-upload-v4-status');
        createUploader('v6','sba-ip-v6-file','sba-upload-v6-btn','sba-cancel-upload-v6-btn','sba-upload-v6-progress','sba-upload-v6-bar','sba-upload-v6-status');
    });
    </script>
    <?php
}
add_action('wp_ajax_sba_upload_xdb_chunk', 'sba_ajax_upload_chunk');
add_action('wp_ajax_sba_upload_xdb_status', 'sba_ajax_upload_status');
add_action('wp_ajax_sba_upload_xdb_cancel', 'sba_ajax_upload_cancel');
function sba_ajax_upload_chunk() {
    if (!current_user_can('manage_options') || !wp_verify_nonce($_POST['_wpnonce'], 'sba_upload_xdb')) wp_send_json_error();
    $type = sanitize_text_field($_POST['type']);
    $filename = sanitize_file_name($_POST['filename']);
    $start = (int)$_POST['start'];
    $end = (int)$_POST['end'];
    $size = (int)$_POST['file_size'];
    $temp_dir = SBA_IP_DATA_DIR . 'upload_temp';
    if (!is_dir($temp_dir)) wp_mkdir_p($temp_dir);
    $task_id = md5($type . $filename . $size . get_current_user_id());
    $part_file = "$temp_dir/{$task_id}_{$start}_{$end}.part";
    if (!move_uploaded_file($_FILES['file_chunk']['tmp_name'], $part_file)) wp_send_json_error();
    $meta_file = "$temp_dir/{$task_id}_meta.json";
    $meta = file_exists($meta_file) ? json_decode(file_get_contents($meta_file), true) : ['filename' => $filename, 'file_size' => $size, 'type' => $type, 'parts' => []];
    $meta['parts'][] = ['start' => $start, 'end' => $end];
    $meta['parts'] = array_unique($meta['parts'], SORT_REGULAR);
    file_put_contents($meta_file, json_encode($meta));
    if (sba_is_range_covered($meta['parts'], $size)) {
        $final = $type === 'v4' ? SBA_IP_V4_FILE : SBA_IP_V6_FILE;
        $handle = fopen($final, 'wb');
        usort($meta['parts'], fn($a,$b) => $a['start'] - $b['start']);
        foreach ($meta['parts'] as $part) {
            $p = fopen("$temp_dir/{$task_id}_{$part['start']}_{$part['end']}.part", 'rb');
            fseek($handle, $part['start']);
            stream_copy_to_stream($p, $handle);
            fclose($p);
            unlink("$temp_dir/{$task_id}_{$part['start']}_{$part['end']}.part");
        }
        fclose($handle);
        unlink($meta_file);
        @rmdir($temp_dir);
        sba_clear_trend_cache();
        wp_send_json_success(['message' => __('上传并合并完成', SBA_TEXT_DOMAIN)]);
    }
    wp_send_json_success(['message' => __('分片接收成功', SBA_TEXT_DOMAIN)]);
}
function sba_ajax_upload_status() {
    if (!current_user_can('manage_options') || !wp_verify_nonce($_POST['_wpnonce'], 'sba_upload_xdb')) wp_send_json_error();
    $temp_dir = SBA_IP_DATA_DIR . 'upload_temp';
    $task_id = md5($_POST['type'] . sanitize_file_name($_POST['filename']) . (int)$_POST['file_size'] . get_current_user_id());
    $meta_file = "$temp_dir/{$task_id}_meta.json";
    $meta = file_exists($meta_file) ? json_decode(file_get_contents($meta_file), true) : [];
    wp_send_json_success(['parts' => $meta['parts'] ?? []]);
}
function sba_ajax_upload_cancel() {
    if (!current_user_can('manage_options') || !wp_verify_nonce($_POST['_wpnonce'], 'sba_upload_xdb')) wp_send_json_error();
    $temp_dir = SBA_IP_DATA_DIR . 'upload_temp';
    $task_id = md5($_POST['type'] . sanitize_file_name($_POST['filename']) . (int)$_POST['file_size'] . get_current_user_id());
    foreach (glob("$temp_dir/{$task_id}_*") as $f) @unlink($f);
    wp_send_json_success();
}
function sba_is_range_covered($parts, $size) {
    if (empty($parts)) return false;
    usort($parts, fn($a,$b) => $a['start'] - $b['start']);
    $covered = 0;
    foreach ($parts as $p) {
        if ($p['start'] > $covered) return false;
        $covered = max($covered, $p['end']);
    }
    return $covered >= $size;
}

// ==================== SMTP 邮件设置 ====================
function sba_smtp_page() {
    $opts = get_option('sba_smtp_settings', []);
    if (isset($_POST['smtp_save']) && check_admin_referer('sba_smtp_save')) {
        $new = [
            'smtp_host' => sanitize_text_field($_POST['smtp_host']),
            'smtp_port' => (int)$_POST['smtp_port'],
            'smtp_encryption' => sanitize_text_field($_POST['smtp_encryption']),
            'smtp_auth' => isset($_POST['smtp_auth']) ? 1 : 0,
            'smtp_username' => sanitize_text_field($_POST['smtp_username']),
            'smtp_password' => sanitize_text_field($_POST['smtp_password']),
            'from_email' => sanitize_email($_POST['from_email']),
            'from_name' => sanitize_text_field($_POST['from_name']),
        ];
        update_option('sba_smtp_settings', $new);
        echo '<div class="updated"><p>' . __('设置已保存。', SBA_TEXT_DOMAIN) . '</p></div>';
        $opts = $new;
    }
    if (isset($_POST['test_email']) && check_admin_referer('sba_smtp_save')) {
        $to = sanitize_email($_POST['test_to']);
        if ($to) {
            global $phpmailer;
            $result = wp_mail($to, sprintf(__('SMTP 测试邮件 - %s', SBA_TEXT_DOMAIN), get_bloginfo('name')), __('这是一封测试邮件，确认您的 SMTP 配置正确。', SBA_TEXT_DOMAIN));
            if ($result) echo '<div class="updated"><p>' . sprintf(__('测试邮件已发送到 %s，请检查收件箱。', SBA_TEXT_DOMAIN), esc_html($to)) . '</p></div>';
            else echo '<div class="error"><p>' . sprintf(__('测试邮件发送失败：%s', SBA_TEXT_DOMAIN), isset($phpmailer) ? $phpmailer->ErrorInfo : __('未知错误', SBA_TEXT_DOMAIN)) . '</p></div>';
        } else echo '<div class="error"><p>' . __('请输入有效的测试邮箱地址。', SBA_TEXT_DOMAIN) . '</p></div>';
    }
    ?>
    <div class="wrap"><h1><?php _e('SMTP 邮件设置', SBA_TEXT_DOMAIN); ?></h1>
        <form method="post"><?php wp_nonce_field('sba_smtp_save'); ?>
            <table class="form-table">
                <tr><th><label for="smtp_host"><?php _e('SMTP 主机', SBA_TEXT_DOMAIN); ?></label></th><td><input type="text" id="smtp_host" name="smtp_host" value="<?php echo esc_attr($opts['smtp_host'] ?? ''); ?>" class="regular-text" placeholder="<?php _e('例如：smtp.gmail.com', SBA_TEXT_DOMAIN); ?>"></td></tr>
                <tr><th><label for="smtp_port"><?php _e('端口', SBA_TEXT_DOMAIN); ?></label></th><td><input type="number" id="smtp_port" name="smtp_port" value="<?php echo esc_attr($opts['smtp_port'] ?? '587'); ?>" class="small-text"> <?php _e('常用：587 (TLS) 或 465 (SSL)', SBA_TEXT_DOMAIN); ?></td></tr>
                <tr><th><label for="smtp_encryption"><?php _e('加密方式', SBA_TEXT_DOMAIN); ?></label></th><td><select id="smtp_encryption" name="smtp_encryption"><option value="none" <?php selected($opts['smtp_encryption'] ?? '', 'none'); ?>><?php _e('无', SBA_TEXT_DOMAIN); ?></option><option value="tls" <?php selected($opts['smtp_encryption'] ?? '', 'tls'); ?>><?php _e('TLS', SBA_TEXT_DOMAIN); ?></option><option value="ssl" <?php selected($opts['smtp_encryption'] ?? '', 'ssl'); ?>><?php _e('SSL', SBA_TEXT_DOMAIN); ?></option></select></td></tr>
                <tr><th><label for="smtp_auth"><?php _e('启用认证', SBA_TEXT_DOMAIN); ?></label></th><td><input type="checkbox" id="smtp_auth" name="smtp_auth" value="1" <?php checked($opts['smtp_auth'] ?? 1, 1); ?>> <?php _e('通常需要勾选', SBA_TEXT_DOMAIN); ?></td></tr>
                <tr><th><label for="smtp_username"><?php _e('用户名', SBA_TEXT_DOMAIN); ?></label></th><td><input type="text" id="smtp_username" name="smtp_username" value="<?php echo esc_attr($opts['smtp_username'] ?? ''); ?>" class="regular-text"></td></tr>
                <tr><th><label for="smtp_password"><?php _e('密码', SBA_TEXT_DOMAIN); ?></label></th><td><input type="password" id="smtp_password" name="smtp_password" value="<?php echo esc_attr($opts['smtp_password'] ?? ''); ?>" class="regular-text"></td></tr>
                <tr><th><label for="from_email"><?php _e('发件人邮箱', SBA_TEXT_DOMAIN); ?></label></th><td><input type="email" id="from_email" name="from_email" value="<?php echo esc_attr($opts['from_email'] ?? ''); ?>" class="regular-text" placeholder="<?php _e('留空则使用 WordPress 默认', SBA_TEXT_DOMAIN); ?>"></td></tr>
                <tr><th><label for="from_name"><?php _e('发件人名称', SBA_TEXT_DOMAIN); ?></label></th><td><input type="text" id="from_name" name="from_name" value="<?php echo esc_attr($opts['from_name'] ?? ''); ?>" class="regular-text" placeholder="<?php _e('例如：网站名称', SBA_TEXT_DOMAIN); ?>"></td></tr>
            </table>
            <?php submit_button(__('保存设置', SBA_TEXT_DOMAIN), 'primary', 'smtp_save'); ?>
        </form>
        <hr>
        <h2><?php _e('测试邮件发送', SBA_TEXT_DOMAIN); ?></h2>
        <form method="post"><?php wp_nonce_field('sba_smtp_save'); ?>
            <table class="form-table"><tr><th><label for="test_to"><?php _e('接收测试邮箱', SBA_TEXT_DOMAIN); ?></label></th><td><input type="email" id="test_to" name="test_to" class="regular-text" placeholder="your@email.com"></td></tr></table>
            <?php submit_button(__('发送测试邮件', SBA_TEXT_DOMAIN), 'secondary', 'test_email'); ?>
        </form>
    </div>
    <?php
}
add_action('phpmailer_init', 'sba_smtp_phpmailer_init');
function sba_smtp_phpmailer_init($phpmailer) {
    $opts = get_option('sba_smtp_settings', []);
    if (empty($opts['smtp_host'])) return;
    $phpmailer->isSMTP();
    $phpmailer->Host = $opts['smtp_host'];
    $phpmailer->Port = (int)$opts['smtp_port'];
    $phpmailer->SMTPAuth = (bool)$opts['smtp_auth'];
    $enc = strtolower($opts['smtp_encryption'] ?? '');
    if ($enc === 'tls') $phpmailer->SMTPSecure = PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_STARTTLS;
    elseif ($enc === 'ssl') $phpmailer->SMTPSecure = PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_SMTPS;
    else $phpmailer->SMTPSecure = false;
    if (!empty($opts['smtp_username']) && !empty($opts['smtp_password'])) {
        $phpmailer->Username = $opts['smtp_username'];
        $phpmailer->Password = $opts['smtp_password'];
    }
    $from_email = !empty($opts['from_email']) ? $opts['from_email'] : get_option('admin_email');
    $from_name = !empty($opts['from_name']) ? $opts['from_name'] : get_bloginfo('name');
    $phpmailer->setFrom($from_email, $from_name);
}

// ==================== 短代码 ====================
add_shortcode('sba_stats', function() {
    global $wpdb;
    $online = (int)$wpdb->get_var("SELECT COUNT(DISTINCT ip) FROM {$wpdb->prefix}dis_stats WHERE last_visit > DATE_SUB(NOW(), INTERVAL 5 MINUTE)");
    $latest = $wpdb->get_var("SELECT MAX(visit_date) FROM {$wpdb->prefix}dis_stats") ?: current_time('Y-m-d');
    $uv = sba_get_uv($latest);
    $pv = sba_get_pv($latest);
    return "<div class='sba-sidebar-card' style='padding:15px;background:#fff;border:1px solid #e5e7eb;border-radius:12px;box-shadow:0 1px 3px rgba(0,0,0,0.1);font-family:monospace;font-size:13px;line-height:2;'>
        <div style='display:flex;justify-content:space-between;border-bottom:1px solid #f3f4f6;padding-bottom:5px;margin-bottom:5px;'><span>● " . __('当前在线', SBA_TEXT_DOMAIN) . "</span><strong style='color:#10b981;'>{$online}</strong></div>
        <div style='display:flex;justify-content:space-between;border-bottom:1px solid #f3f4f6;padding-bottom:5px;margin-bottom:5px;'><span>📈 " . __('今日访客', SBA_TEXT_DOMAIN) . "</span><strong style='color:#3b82f6;'>{$uv}</strong></div>
        <div style='display:flex;justify-content:space-between;'><span>🔥 " . __('累积浏览', SBA_TEXT_DOMAIN) . "</span><strong style='color:#8b5cf6;'>{$pv}</strong></div>
    </div>";
});
add_filter('widget_text', 'do_shortcode');
add_action('wp_logout', function() { wp_redirect(home_url()); exit; });

// ==================== SSRF 防御 ====================
add_filter('pre_http_request', 'sba_outbound_ssrf_filter', 10, 3);
function sba_outbound_ssrf_filter($preempt, $args, $url) {
    $parts = parse_url($url);
    $scheme = strtolower($parts['scheme'] ?? '');
    $host = strtolower($parts['host'] ?? '');
    if (empty($host) || $host === 'localhost' || $host === '127.0.0.1' || $host === '::1') return $preempt;
    if (!in_array($scheme, ['http', 'https'])) {
        sba_ssrf_log_and_block("非法协议: $scheme", $url);
        return new WP_Error('sba_ssrf_blocked', __('🛡️ SBA 系统安全限制：仅允许 HTTP/HTTPS 协议。', SBA_TEXT_DOMAIN));
    }
    $ips = sba_get_dns_records($host);
    $whitelist = array_filter(array_map('trim', explode("\n", sba_get_option('outbound_whitelist', ''))));
    $blacklist = array_merge(['127.0.0.0/8', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '169.254.169.254', '::1', 'fc00::/7', 'fe80::/10', '0.0.0.0'], array_filter(array_map('trim', explode(',', sba_get_option('ssrf_blacklist', '')))));
    foreach ($ips as $ip) {
        if (sba_ip_in_cidr_list($ip, $whitelist)) continue;
        if (sba_ip_in_cidr_list($ip, $blacklist)) {
            sba_ssrf_log_and_block("禁止访问内网/敏感 IP: $ip", $url);
            return new WP_Error('sba_ssrf_blocked', __('🛡️ SBA 系统安全限制：禁止访问内部网络资源。', SBA_TEXT_DOMAIN));
        }
    }
    if (sba_get_option('ssrf_prevent_dns_rebind', 1)) {
        static $depth = 0;
        if ($depth < 2) {
            $depth++;
            $args['headers']['Host'] = $parts['host'];
            $result = wp_remote_request(str_replace("//{$parts['host']}", "//{$ips[0]}", $url), $args);
            $depth--;
            return $result;
        }
    }
    return $preempt;
}
function sba_get_dns_records($host) {
    static $cache = [];
    if (isset($cache[$host])) return $cache[$host];
    $ips = [];
    $records = @dns_get_record($host, DNS_A | DNS_AAAA);
    if (is_array($records)) {
        foreach ($records as $rec) {
            if ($rec['type'] === 'A') $ips[] = $rec['ip'];
            elseif ($rec['type'] === 'AAAA') $ips[] = $rec['ipv6'];
        }
    }
    if (empty($ips)) {
        $ip = gethostbyname($host);
        if ($ip !== $host && filter_var($ip, FILTER_VALIDATE_IP)) $ips[] = $ip;
    }
    $cache[$host] = array_unique($ips);
    return $cache[$host];
}
function sba_ip_in_cidr_list($ip, $list) {
    foreach ($list as $range) {
        if (strpos($range, '/') === false) { if ($ip === $range) return true; continue; }
        list($subnet, $mask) = explode('/', $range);
        if (strpos($ip, ':') !== false) {
            $ip_bin = inet_pton($ip);
            $subnet_bin = inet_pton($subnet);
            if ($ip_bin && $subnet_bin) {
                $mask_hex = str_pad(str_repeat('f', ceil($mask / 4)), 32, '0');
                $mask_bin = hex2bin($mask_hex);
                if (($ip_bin & $mask_bin) === ($subnet_bin & $mask_bin)) return true;
            }
        } else {
            $mask_long = -1 << (32 - $mask);
            if ((ip2long($ip) & $mask_long) === (ip2long($subnet) & $mask_long)) return true;
        }
    }
    return false;
}
function sba_ssrf_log_and_block($reason, $url) {
    global $wpdb;
    $ip = sba_get_ip();
    $wpdb->insert($wpdb->prefix . 'sba_blocked_log', ['ip' => $ip, 'reason' => 'SSRF: ' . $reason, 'target_url' => $url]);
    $wpdb->query($wpdb->prepare("INSERT INTO {$wpdb->prefix}sba_threat_summary (ip, total_blocks, last_block_time) VALUES (%s, 1, NOW()) ON DUPLICATE KEY UPDATE total_blocks = total_blocks + 1, last_block_time = NOW()", $ip));
    sba_inc_blocked();
    error_log("[SBA SSRF Blocked] $reason | URL: $url | Requester IP: " . $ip);
}
add_action('wp_footer', 'sba_whitelist_notice');
function sba_whitelist_notice() {
    if (isset($_GET['sba_msg']) && $_GET['sba_msg'] === 'whitelisted') {
        echo '<script>
            (function() {
                var msg = "' . esc_js(__('✅ 您的 IP 已成功加入白名单，拦截已解除。', SBA_TEXT_DOMAIN)) . '";
                var showAlert = function() {
                    alert(msg);
                    if (window.history && window.history.replaceState) {
                        var url = new URL(window.location.href);
                        url.searchParams.delete("sba_msg");
                        window.history.replaceState({}, document.title, url.toString());
                    }
                };
                if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", showAlert);
                else showAlert();
            })();
        </script>';
    }
}