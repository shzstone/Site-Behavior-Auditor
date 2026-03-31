<?php
/**
 * Plugin Name: 综合安全套件 (Site Behavior Auditor + Login Box + SMTP)
 * Description: 集成站点全行为审计、iOS风格登录/注册/忘记密码面板（简码: sba_login_box）和SMTP邮件配置。IP归属地使用 ip2region xdb 内存查询（支持 IPv4/IPv6），分片上传库文件，并提供高级爬虫防御（阶梯限制、Cookie校验、诱饵陷阱）。
 * Version: 2.1.6
 * Author: Stone
 */

if ( ! defined( 'ABSPATH' ) ) exit;

/* ================= 常量定义 ================= */
define( 'SBA_VERSION', '2.1.6' );
define( 'SBA_IP_DATA_DIR', WP_CONTENT_DIR . '/uploads/sba_ip_data/' );
define( 'SBA_IP_V4_FILE', SBA_IP_DATA_DIR . 'ip2region_v4.xdb' );
define( 'SBA_IP_V6_FILE', SBA_IP_DATA_DIR . 'ip2region_v6.xdb' );
define( 'SBA_CHUNK_SIZE_INITIAL', 2 * 1024 * 1024 );
define( 'SBA_MIN_CHUNK_SIZE', 512 * 1024 );
define( 'SBA_MAX_CHUNK_SIZE', 10 * 1024 * 1024 );

/* ================= 检测官方类库 ================= */
$sba_official_lib_path = plugin_dir_path( __FILE__ ) . 'lib/ip2region/xdb/Searcher.class.php';
if ( file_exists( $sba_official_lib_path ) ) {
    require_once $sba_official_lib_path;
    define( 'SBA_USE_OFFICIAL', true );
} else {
    define( 'SBA_USE_OFFICIAL', false );
}

/* ================= 后台提醒：官方类库缺失 ================= */
add_action( 'admin_notices', 'sba_official_lib_missing_notice' );
function sba_official_lib_missing_notice() {
    if ( ! defined( 'SBA_USE_OFFICIAL' ) || SBA_USE_OFFICIAL ) {
        return;
    }
    $screen = get_current_screen();
    if ( $screen && strpos( $screen->id, 'sba_' ) === false && strpos( $screen->id, 'toplevel_page_sba_audit' ) === false ) {
        return;
    }
    echo '<div class="notice notice-warning is-dismissible"><p>';
    echo '⚠️ <strong>SBA 安全套件</strong>：未检测到官方 ip2region 类库，已自动降级为内置简化版（仅支持 IPv4 查询）。如需完整 IPv6 支持，请将官方类库放置于 <code>' . esc_html( plugin_dir_path( __FILE__ ) . 'lib/ip2region/xdb/Searcher.class.php' ) . '</code>。';
    echo '</p></div>';
}

/* ================= 创建目录 ================= */
register_activation_hook( __FILE__, 'sba_create_dirs' );
function sba_create_dirs() {
    if ( ! file_exists( SBA_IP_DATA_DIR ) ) {
        wp_mkdir_p( SBA_IP_DATA_DIR );
    }
    $htaccess = SBA_IP_DATA_DIR . '.htaccess';
    if ( ! file_exists( $htaccess ) ) {
        file_put_contents( $htaccess, "Deny from all\n" );
    }
}

/* ================= 数据库表创建与升级 ================= */
register_activation_hook( __FILE__, 'sba_combined_activate' );
function sba_combined_activate() {
    global $wpdb;
    $charset_collate = $wpdb->get_charset_collate();

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

    $sql[] = "CREATE TABLE IF NOT EXISTS {$wpdb->prefix}sba_blocked_log (
        id BIGINT AUTO_INCREMENT PRIMARY KEY,
        ip VARCHAR(45),
        reason VARCHAR(100),
        target_url TEXT,
        block_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    ) $charset_collate;";

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

    $installed_version = get_option( 'sba_version', '0' );
    if ( version_compare( $installed_version, '2.0', '<' ) ) {
        $wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}sba_ip_data" );
        delete_option( 'sba_geo_v1' );
        update_option( 'sba_version', SBA_VERSION );
    }

    if ( ! wp_next_scheduled( 'sba_daily_cleanup' ) ) {
        wp_schedule_event( time(), 'daily', 'sba_daily_cleanup' );
    }

    $defaults = [
        'auto_block_limit'      => '60',
        'login_slug'            => '',
        'evil_paths'            => '',
        'block_target_url'      => '',
        'user_whitelist'        => '',
        'ip_whitelist'          => '',
        'scraper_paths'         => 'feed=|rest_route=|[\?&]m=|\?p=',
        'enable_cookie_check'   => 1,
    ];
    $current = get_option( 'sba_settings' );
    if ( empty( $current ) ) {
        update_option( 'sba_settings', $defaults );
    } else {
        $updated = false;
        foreach ( $defaults as $key => $val ) {
            if ( ! isset( $current[ $key ] ) ) {
                $current[ $key ] = $val;
                $updated = true;
            }
        }
        if ( $updated ) {
            update_option( 'sba_settings', $current );
        }
    }
}

/* ================= 每日清理 ================= */
add_action( 'sba_daily_cleanup', 'sba_cleanup_old_data' );
function sba_cleanup_old_data() {
    global $wpdb;
    $wpdb->query( "DELETE FROM {$wpdb->prefix}dis_stats WHERE visit_date < DATE_SUB(NOW(), INTERVAL 30 DAY)" );
    $wpdb->query( "DELETE FROM {$wpdb->prefix}sba_blocked_log WHERE block_time < DATE_SUB(NOW(), INTERVAL 7 DAY)" );
    $wpdb->query( "DELETE FROM {$wpdb->prefix}sba_login_failures WHERE last_failed_time < DATE_SUB(NOW(), INTERVAL 30 DAY)" );
}

/* ================= 通用工具函数 ================= */
function sba_combined_get_ip() {
    $ip = $_SERVER['HTTP_CF_CONNECTING_IP'] ?? $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'];
    return filter_var( trim( explode( ',', $ip )[0] ), FILTER_VALIDATE_IP ) ?: '0.0.0.0';
}

function sba_audit_get_opt( $k, $d = '' ) {
    $o = get_option( 'sba_settings' );
    return ( isset( $o[ $k ] ) && $o[ $k ] !== '' ) ? $o[ $k ] : $d;
}

/* ================= 内置降级 IP 查询类（简化版，仅 IPv4） ================= */
if ( ! class_exists( 'SBA_Fallback_XdbSearcher' ) ) {
    class SBA_Fallback_XdbSearcher
    {
        const HeaderInfoLength = 256;
        const VectorIndexRows = 256;
        const VectorIndexCols = 256;
        const VectorIndexSize = 8;
        const SegmentIndexSize = 14;

        private $buffer = null;
        private $vectorIndex = null;

        public static function loadContentFromFile( $xdbPath ) {
            $content = file_get_contents( $xdbPath );
            return $content === false ? null : $content;
        }

        public static function newWithBuffer( $cBuff ) {
            $searcher = new self();
            $searcher->buffer = $cBuff;
            $searcher->vectorIndex = substr( $cBuff, self::HeaderInfoLength, self::VectorIndexRows * self::VectorIndexCols * self::VectorIndexSize );
            return $searcher;
        }

        public function search( $ip ) {
            if ( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) === false ) {
                return null;
            }
            $ipNum = ip2long( $ip );
            if ( $ipNum === false ) return null;
            $ipNum = sprintf( '%u', $ipNum );

            $il0 = ( $ipNum >> 24 ) & 0xFF;
            $il1 = ( $ipNum >> 16 ) & 0xFF;
            $idx = $il0 * self::VectorIndexCols * self::VectorIndexSize + $il1 * self::VectorIndexSize;
            $sPtr = unpack( 'V', substr( $this->vectorIndex, $idx, 4 ) )[1];
            $ePtr = unpack( 'V', substr( $this->vectorIndex, $idx + 4, 4 ) )[1];

            $l = 0;
            $h = ( $ePtr - $sPtr ) / self::SegmentIndexSize;
            while ( $l <= $h ) {
                $m = ( $l + $h ) >> 1;
                $p = $sPtr + $m * self::SegmentIndexSize;
                $startIp = unpack( 'V', substr( $this->buffer, $p, 4 ) )[1];
                if ( $ipNum < $startIp ) {
                    $h = $m - 1;
                } else {
                    $endIp = unpack( 'V', substr( $this->buffer, $p + 4, 4 ) )[1];
                    if ( $ipNum > $endIp ) {
                        $l = $m + 1;
                    } else {
                        $dataLen = unpack( 'v', substr( $this->buffer, $p + 8, 2 ) )[1];
                        $dataPtr = unpack( 'V', substr( $this->buffer, $p + 10, 4 ) )[1];
                        return substr( $this->buffer, $dataPtr, $dataLen );
                    }
                }
            }
            return null;
        }
    }
}

/* ================= IP 归属地查询类（统一接口，自动选择官方或降级） ================= */
class SBA_IP_Searcher {
    private static $instance = null;
    private $searcher_v4 = null;
    private $searcher_v6 = null;
    private static $ip_cache = [];

    private function __construct() {
        $this->load_searcher();
    }

    public static function get_instance() {
        if ( self::$instance === null ) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    private function load_searcher() {
        if ( SBA_USE_OFFICIAL ) {
            // 使用官方类库（支持 IPv4 和 IPv6）
            if ( file_exists( SBA_IP_V4_FILE ) && filesize( SBA_IP_V4_FILE ) > 0 ) {
                try {
                    $cBuff = \ip2region\xdb\Util::loadContentFromFile( SBA_IP_V4_FILE );
                    if ( $cBuff ) {
                        $this->searcher_v4 = \ip2region\xdb\Searcher::newWithBuffer( \ip2region\xdb\IPv4::default(), $cBuff );
                    }
                } catch ( Exception $e ) {
                    error_log( "SBA: IPv4 库加载失败: " . $e->getMessage() );
                }
            }
            if ( file_exists( SBA_IP_V6_FILE ) && filesize( SBA_IP_V6_FILE ) > 0 ) {
                try {
                    $cBuff = \ip2region\xdb\Util::loadContentFromFile( SBA_IP_V6_FILE );
                    if ( $cBuff ) {
                        $this->searcher_v6 = \ip2region\xdb\Searcher::newWithBuffer( \ip2region\xdb\IPv6::default(), $cBuff );
                    }
                } catch ( Exception $e ) {
                    error_log( "SBA: IPv6 库加载失败: " . $e->getMessage() );
                }
            }
        } else {
            // 降级：使用内置简化版（仅 IPv4）
            if ( file_exists( SBA_IP_V4_FILE ) && filesize( SBA_IP_V4_FILE ) > 0 ) {
                $cBuff = SBA_Fallback_XdbSearcher::loadContentFromFile( SBA_IP_V4_FILE );
                if ( $cBuff ) {
                    $this->searcher_v4 = SBA_Fallback_XdbSearcher::newWithBuffer( $cBuff );
                }
            }
        }
    }

    public function search( $ip ) {
        if ( isset( self::$ip_cache[ $ip ] ) ) {
            return self::$ip_cache[ $ip ];
        }

        $result = '未知';
        $is_v4 = filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 );
        $is_v6 = filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 );

        try {
            if ( $is_v4 && $this->searcher_v4 ) {
                $region = $this->searcher_v4->search( $ip );
                if ( $region !== null && $region !== '' ) {
                    $result = $this->format_region( $region );
                }
            } elseif ( $is_v6 && $this->searcher_v6 ) {
                $region = $this->searcher_v6->search( $ip );
                if ( $region !== null && $region !== '' ) {
                    $result = $this->format_region( $region );
                } elseif ( $is_v6 && !$this->searcher_v6 ) {
                    $result = 'IPv6库未上传或官方类库缺失';
                }
            }
        } catch ( Exception $e ) {
            error_log( "SBA IP 查询异常 ($ip): " . $e->getMessage() );
            $result = '查询失败';
        }

        self::$ip_cache[ $ip ] = $result;
        return $result;
    }

    private function format_region( $region ) {
        $parts = explode( '|', $region );
        $parts = array_filter( $parts, function( $v ) {
            return $v !== '' && $v !== '0';
        });
        return implode( '·', $parts );
    }
}

/* ================= Cookie 校验函数 ================= */
function sba_set_human_cookie( $ip ) {
    $cookie_name = 'sba_human';
    $value = hash_hmac( 'sha256', $ip, wp_salt() );
    setcookie( $cookie_name, $value, time() + 3600, COOKIEPATH, COOKIE_DOMAIN, false, true );
}

function sba_has_valid_cookie( $ip ) {
    $cookie_name = 'sba_human';
    if ( ! isset( $_COOKIE[ $cookie_name ] ) ) {
        return false;
    }
    $expected = hash_hmac( 'sha256', $ip, wp_salt() );
    return hash_equals( $expected, $_COOKIE[ $cookie_name ] );
}

/* ================= CC 频率限制（使用 Transient） ================= */
function sba_check_cc_limit( $ip, $limit ) {
    if ( $limit <= 0 ) return false;
    $key = 'sba_cc_' . $ip;
    $count = get_transient( $key );
    if ( $count === false ) {
        set_transient( $key, 1, 60 );
        return false;
    }
    if ( $count >= $limit ) {
        return true;
    }
    set_transient( $key, $count + 1, 60 );
    return false;
}

/* ================= 拦截执行 ================= */
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

/* ================= 主拦截逻辑（包含三层防御） ================= */
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

    // ========== 诱饵陷阱检测（最高优先级） ==========
    foreach ( $_GET as $key => $val ) {
        if ( strpos( $key, 'sba_trap_' ) === 0 ) {
            $trap_key = $key;
            if ( get_transient( 'sba_trap_' . $trap_key ) ) {
                $ip = sba_combined_get_ip();
                // 快速累加失败次数至封禁阈值
                for ( $i = 0; $i < 6; $i++ ) {
                    sba_ios_record_failure( $ip, false );
                }
                sba_audit_execute_block( '蜜罐陷阱触发' );
            }
            delete_transient( 'sba_trap_' . $trap_key );
            break;
        }
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

    // Gate 钥匙（使用 Transient）
    $stored_slug = sba_audit_get_opt( 'login_slug', '' );
    $internal_params = ['interim-login', 'auth-check', 'wp_scrape_key', 'wp_scrape_nonce'];
    foreach ($internal_params as $param) {
        if (isset($_GET[$param])) {
            return;
        }
    }
    if ( ! empty( $stored_slug ) && $is_login_page && empty( $current_action ) ) {
        if ( isset( $_GET['gate'] ) && ! empty( $_GET['gate'] ) ) {
            $provided_gate = $_GET['gate'];
            $salt_fixed = defined( 'NONCE_SALT' ) ? NONCE_SALT : 'sba_fallback_salt';
            $expected_token_fixed = hash_hmac( 'sha256', $stored_slug, $salt_fixed );
            $provided_token_fixed = hash_hmac( 'sha256', $provided_gate, $salt_fixed );
            if ( hash_equals( $expected_token_fixed, $provided_token_fixed ) ) {
                $token = wp_generate_password( 20, false );
                set_transient( 'sba_gate_token_' . $ip, $token, 1800 );
                $redirect_url = remove_query_arg( 'gate' );
                wp_redirect( $redirect_url );
                exit;
            } else {
                sba_audit_execute_block( "Gate 钥匙错误或已失效" );
            }
        }
        if ( $_SERVER['REQUEST_METHOD'] !== 'POST' ) {
            if ( ! get_transient( 'sba_gate_token_' . $ip ) ) {
                sba_audit_execute_block( "Gate 钥匙错误或已失效" );
            }
            return;
        }
        $stored_token = get_transient( 'sba_gate_token_' . $ip );
        if ( ! $stored_token ) {
            $stored_token = wp_generate_password( 20, false );
            set_transient( 'sba_gate_token_' . $ip, $stored_token, 1800 );
        }
        $expected_token = hash_hmac( 'sha256', $stored_slug, $stored_token );
        $provided_token = $_POST['sba_gate_token'] ?? '';
        if ( ! hash_equals( $expected_token, $provided_token ) ) {
            sba_audit_execute_block( "Gate 钥匙错误或已失效" );
        }
    }

    // ========== 三层防御：阶梯限制 + Cookie 校验 ==========
    $limit = (int) sba_audit_get_opt( 'auto_block_limit', 0 );
    if ( $limit > 0 && ! is_user_logged_in() ) {
        if ( ! ( $ip === '127.0.0.1' || $ip === '::1' ) ) {
            $is_browser = preg_match( '/Mozilla\/|Chrome\/|Firefox\/|Safari\/|Edge\/|Opera\/|MSIE/', $ua );
            $scraper_paths = sba_audit_get_opt( 'scraper_paths', 'feed=|rest_route=|[\?&]m=|\?p=' );
            $is_scraper_path = preg_match( '/' . str_replace( '/', '\/', $scraper_paths ) . '/i', $_SERVER['REQUEST_URI'] );
            $current_limit = $is_scraper_path ? max( 5, floor( $limit / 3 ) ) : $limit;

            $cookie_check_enabled = (bool) sba_audit_get_opt( 'enable_cookie_check', 1 );
            if ( $cookie_check_enabled && ! sba_has_valid_cookie( $ip ) && ! $is_browser ) {
                $current_limit = max( 5, floor( $current_limit / 2 ) );
            }

            if ( sba_check_cc_limit( $ip, $current_limit ) ) {
                $reason = $is_scraper_path ? "采集器高频抓取" : "频率超限 (CC风险)";
                sba_audit_execute_block( $reason );
            }

            if ( $cookie_check_enabled && ! sba_has_valid_cookie( $ip ) && $_SERVER['REQUEST_METHOD'] === 'GET' ) {
                sba_set_human_cookie( $ip );
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

/* ================= 诱饵陷阱输出 ================= */
add_action( 'wp_footer', 'sba_output_honeypot_link' );
function sba_output_honeypot_link() {
    if ( is_admin() || is_user_logged_in() ) {
        return;
    }
    $trap_param = 'sba_trap_' . substr( md5( wp_salt() . time() ), 0, 8 );
    set_transient( 'sba_trap_' . $trap_param, 1, 3600 );
    echo '<a href="' . home_url( '/?' . $trap_param . '=1' ) . '" style="display:none; visibility:hidden;" rel="nofollow">.</a>';
}

/* ================= 其余原有功能（作者重定向、登录表单令牌、归属地AJAX、轨迹、拦截日志等） ================= */
add_action( 'template_redirect', function() {
    if ( is_author() || isset( $_GET['author'] ) ) {
        wp_redirect( home_url(), 301 );
        exit;
    }
} );

add_action( 'login_form', function() {
    $stored_slug = sba_audit_get_opt( 'login_slug', '' );
    if ( ! empty( $stored_slug ) ) {
        $ip = sba_combined_get_ip();
        $token = get_transient( 'sba_gate_token_' . $ip );
        if ( $token ) {
            $expected_token = hash_hmac( 'sha256', $stored_slug, $token );
            echo '<input type="hidden" name="sba_gate_token" value="' . esc_attr( $expected_token ) . '" />';
        }
    }
} );

add_action( 'wp_login', function() {
    $ip = sba_combined_get_ip();
    delete_transient( 'sba_gate_token_' . $ip );
} );
add_action( 'wp_logout', function() {
    $ip = sba_combined_get_ip();
    delete_transient( 'sba_gate_token_' . $ip );
} );

// AJAX 归属地解析
add_action( 'wp_ajax_sba_get_geo', 'sba_audit_ajax_geo' );
function sba_audit_ajax_geo() {
    $ips = (array) $_POST['ips'];
    $searcher = SBA_IP_Searcher::get_instance();
    $results = [];
    foreach ( $ips as $ip ) {
        $results[ $ip ] = $searcher->search( $ip );
    }
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

add_action( 'wp_ajax_sba_load_blocked_logs', 'sba_audit_ajax_blocked_logs' );
function sba_audit_ajax_blocked_logs() {
    global $wpdb;
    $p = intval( $_POST['page'] ?? 1 );
    $per = 15;
    $off = ( $p - 1 ) * $per;
    $total = $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->prefix}sba_blocked_log WHERE DATE(block_time) = CURDATE()" );
    $pages = ceil( $total / $per );
    $rows = $wpdb->get_results( $wpdb->prepare(
        "SELECT * FROM {$wpdb->prefix}sba_blocked_log WHERE DATE(block_time) = CURDATE() ORDER BY block_time DESC LIMIT %d, %d",
        $off, $per
    ) );
    $html = '';
    if ( $rows ) {
        foreach ( $rows as $b ) {
            $html .= "<tr>
                <td>" . date( 'm-d H:i', strtotime( $b->block_time ) ) . "</td>
                <td><code>" . esc_html( $b->ip ) . "</code></td>
                <td class='sba-cell-wrap' style='color:#d63638;'>" . esc_html( $b->reason ) . " ⚡ " . esc_html( $b->target_url ) . "</td>
            </tr>";
        }
    } else {
        $html = '<tr><td colspan="3">暂无拦截记录</td></tr>';
    }
    wp_send_json_success( [ 'html' => $html, 'pages' => $pages, 'total' => $total ] );
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
        return sba_ios_logged_in_html( $user, wp_logout_url( home_url() ) );
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

// AJAX 验证码
add_action( 'wp_ajax_nopriv_sba_ios_get_captcha', 'sba_ios_ajax_get_captcha' );
function sba_ios_ajax_get_captcha() {
    check_ajax_referer( 'sba_ios_action', '_ajax_nonce' );
    $ip = sba_combined_get_ip();
    $force = isset($_POST['force']) ? (int)$_POST['force'] : 0;
    $status = $force ? [ 'banned' => false, 'need_captcha' => true ] : sba_ios_check_ban_and_captcha( $ip );
    if ( $status['banned'] ) wp_send_json_error( [ 'message' => '您已被封禁24小时，请稍后再试。' ] );
    if ( ! $status['need_captcha'] ) wp_send_json_error( [ 'message' => '当前无需验证码' ] );
    $num1 = rand( 1, 9 );
    $num2 = rand( 1, 9 );
    $answer = $num1 + $num2;
    set_transient( 'sba_captcha_' . $ip, $answer, 300 );
    wp_send_json_success( [ 'question' => "验证码：$num1 + $num2 = ?", 'answer' => $answer ] );
}
add_action( 'wp_ajax_nopriv_sba_ios_check_captcha', 'sba_ios_ajax_check_captcha' );
function sba_ios_ajax_check_captcha() {
    check_ajax_referer( 'sba_ios_action', '_ajax_nonce' );
    $ip = sba_combined_get_ip();
    $status = sba_ios_check_ban_and_captcha( $ip );
    if ( $status['banned'] ) wp_send_json_error( [ 'banned' => true ] );
    wp_send_json_success( [ 'need_captcha' => $status['need_captcha'] ] );
}
add_action( 'wp_ajax_nopriv_sba_ios_login', 'sba_ios_ajax_login' );
function sba_ios_ajax_login() {
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
        $stored_answer = get_transient( 'sba_captcha_' . $ip );
        if ( ! $stored_answer || $provided_captcha != $stored_answer ) {
            sba_ios_record_failure( $ip, false );
            wp_send_json_error( [ 'message' => '验证码错误', 'need_captcha' => true ] );
        }
        delete_transient( 'sba_captcha_' . $ip );
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
add_action( 'wp_ajax_nopriv_sba_ios_register', 'sba_ios_ajax_register' );
function sba_ios_ajax_register() {
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
        $stored_answer = get_transient( 'sba_captcha_' . $ip );
        if ( ! $stored_answer || $provided_captcha != $stored_answer ) {
            sba_ios_record_failure( $ip, false );
            wp_send_json_error( [ 'message' => '验证码错误', 'need_captcha' => true ] );
        }
        delete_transient( 'sba_captcha_' . $ip );
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
add_action( 'wp_ajax_nopriv_sba_ios_forgot', 'sba_ios_ajax_forgot' );
function sba_ios_ajax_forgot() {
    check_ajax_referer( 'sba_ios_action', '_ajax_nonce' );
    $ip = sba_combined_get_ip();
    if ( ! sba_ios_check_rate_limit( $ip, 10 ) ) wp_send_json_error( [ 'message' => '操作过于频繁，请稍后再试。' ] );
    $status = sba_ios_check_ban_and_captcha( $ip, 'forgot' );
    if ( $status['banned'] ) wp_send_json_error( [ 'message' => '由于多次失败，您的IP已被封禁24小时。' ] );
    $login_or_email = sanitize_text_field( $_POST['email'] );
    $provided_captcha = sanitize_text_field( $_POST['captcha'] );
    $need_captcha = (int) $_POST['need_captcha'];
    if ( $need_captcha ) {
        $stored_answer = get_transient( 'sba_captcha_' . $ip );
        if ( ! $stored_answer || $provided_captcha != $stored_answer ) {
            sba_ios_record_failure( $ip, false );
            wp_send_json_error( [ 'message' => '验证码错误', 'need_captcha' => true ] );
        }
        delete_transient( 'sba_captcha_' . $ip );
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

/* ================= SMTP 模块 ================= */
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

/* ================= 环境检测面板（显示关键配置） ================= */
function sba_environment_panel() {
    $max_upload = ini_get( 'upload_max_filesize' );
    $post_max = ini_get( 'post_max_size' );
    $memory_limit = ini_get( 'memory_limit' );
    $max_execution = ini_get( 'max_execution_time' );
    $php_version = PHP_VERSION;
    $curl_enabled = extension_loaded( 'curl' ) ? '✓' : '✗';
    ?>
    <div class="sba-card" style="margin-top:20px;">
        <h3>⚙️ 服务器环境检测</h3>
        <table class="widefat" style="width: auto;">
            <tr>
                <th>PHP 版本</th>
                <td><?php echo esc_html( $php_version ); ?></td>
            </tr>
            <tr>
                <th>upload_max_filesize</th>
                <td><?php echo esc_html( $max_upload ); ?></td>
            </tr>
            <tr>
                <th>post_max_size</th>
                <td><?php echo esc_html( $post_max ); ?></td>
            </tr>
            <tr>
                <th>memory_limit</th>
                <td><?php echo esc_html( $memory_limit ); ?></td>
            </tr>
            <tr>
                <th>max_execution_time</th>
                <td><?php echo esc_html( $max_execution ); ?> 秒</td>
            </tr>
            <tr>
                <th>cURL 扩展</th>
                <td><?php echo $curl_enabled; ?></td>
            </tr>
        </table>
        <p class="description">若需上传大文件（超过 10MB），建议将 <code>upload_max_filesize</code> 和 <code>post_max_size</code> 调至至少 64M。</p>
    </div>
    <?php
}

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
    ?>
    <style>
        .sba-wrap { max-width: 1400px; margin-top: 15px; }
        .sba-card { background:#fff; padding:20px; border-radius:12px; margin-bottom:20px; box-shadow:0 4px 15px rgba(0,0,0,0.05); }
        .sba-grid { display:grid; grid-template-columns: 1fr 1fr; gap:20px; }
        @media (max-width: 1000px) { .sba-grid { grid-template-columns: 1fr; } }
        .sba-scroll-x { width: 100%; overflow-x: auto; border: 1px solid #eee; border-radius:8px; }
        .sba-table { width: 100%; min-width: 850px; border-collapse: collapse; table-layout: fixed; }
        .sba-table th, .sba-table td { text-align: left; padding: 12px 10px; border-bottom: 1px solid #f9f9f9; font-size: 13px; background-color: #fff; color: #333; vertical-align: middle; }
        .sba-table td code { font-size: inherit; background: none; padding: 0; color: inherit; }
        .col-time { width: 80px; }
        .col-ip { width: 240px; min-width: 200px; max-width: 280px; word-break: keep-all; }
        .col-geo { width: 180px; }
        .col-pv { width: 70px; }
        .sba-table tbody tr td:first-child, .sba-table thead tr th:first-child { width: 100px; }
        .sba-table tbody tr td:nth-child(2), .sba-table thead tr th:nth-child(2) { width: 240px; word-break: keep-all; }
        .sba-cell-wrap { white-space: normal; word-break: break-all; display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden; line-height: 1.4; font-size: 12px; }
        .stat-val { font-size: 26px; font-weight: bold; display: block; margin-top: 5px; }
		@media (max-width: 768px) {
			.sba-card .sba-table {
				min-width: 680px;
				table-layout: auto;
			}
			.sba-card .sba-table th,
			.sba-card .sba-table td {
				font-size: 12px;
				padding: 8px 6px;
				white-space: normal;
				word-break: break-word;
			}
			.sba-grid .sba-card:first-child .sba-table {
				table-layout: fixed;
				min-width: 500px;
			}
			.sba-grid .sba-card:first-child .sba-table th,
			.sba-grid .sba-card:first-child .sba-table td {
				width: 25%;
				padding-left: 4px;
				padding-right: 4px;
			}
			.sba-card:not(.sba-blocked-card) .sba-table {
				table-layout: auto;
			}
			.sba-card:not(.sba-blocked-card) .sba-table th:first-child,
			.sba-card:not(.sba-blocked-card) .sba-table td:first-child {
				width: auto;
				min-width: 70px;
			}
			.sba-card:not(.sba-blocked-card) .sba-table th:nth-child(2),
			.sba-card:not(.sba-blocked-card) .sba-table td:nth-child(2) {
				width: auto;
				min-width: 60px;
			}
			.sba-card:not(.sba-blocked-card) .sba-table th:nth-child(3),
			.sba-card:not(.sba-blocked-card) .sba-table td:nth-child(3) {
				width: auto;
				min-width: 60px;
			}
			.sba-card:not(.sba-blocked-card) .sba-table th:nth-child(4),
			.sba-card:not(.sba-blocked-card) .sba-table td:nth-child(4) {
				width: auto;
				min-width: 90px;
				white-space: normal;
			}
			.sba-blocked-card .sba-table th:first-child,
			.sba-blocked-card .sba-table td:first-child {
				width: 90px;
			}
			.sba-blocked-card .sba-table th:nth-child(2),
			.sba-blocked-card .sba-table td:nth-child(2) {
				width: 180px;
			}
			.sba-blocked-card .sba-table th:nth-child(3),
			.sba-blocked-card .sba-table td:nth-child(3) {
				width: auto;
				min-width: 150px;
			}
			.sba-blocked-card .sba-cell-wrap {
				-webkit-line-clamp: unset !important;
				display: block !important;
				overflow: visible !important;
				white-space: normal !important;
				word-break: break-word !important;
				line-height: 1.4;
			}
		}
    </style>
    <div class="wrap sba-wrap">
        <h2>🚀 SBA 站点行为监控 v<?php echo SBA_VERSION; ?></h2>
        <div style="display:flex; gap:15px; margin-bottom:20px; flex-wrap:wrap;">
            <div class="sba-card" style="flex:1; border-left:4px solid #46b450;">当前在线: <span class="stat-val" style="color:#46b450;"><?php echo $online ?: 0; ?></span></div>
            <div class="sba-card" style="flex:1; border-left:4px solid #2271b1;">今日 (<?php echo $latest_date; ?>) UV: <span class="stat-val" style="color:#2271b1;"><?php echo $today_stat->uv ?: 0; ?></span></div>
            <div class="sba-card" style="flex:1; border-left:4px solid #4fc3f7;">今日 (<?php echo $latest_date; ?>) PV: <span class="stat-val" style="color:#4fc3f7;"><?php echo $today_stat->pv ?: 0; ?></span></div>
        </div>
		<div class="sba-grid">
			<div class="sba-card"><h3>📈 30天访问趋势</h3><div style="height:250px;"><canvas id="sbaChart10"></canvas></div></div>
			<div class="sba-card"><h3>📊 50天审计详表</h3>
				<div class="sba-scroll-x" style="height:250px;">
					<table class="sba-table" style="min-width:400px;">
						<thead>
							 <tr>
								<th>日期</th>
								<th>UV (人)</th>
								<th>PV (次)</th>
								<th>深度</th>
							</tr>
						</thead>
						<tbody>
						<?php for ( $j = 0; $j < 50; $j++ ): 
							$d = date( 'Y-m-d', $latest_ts - ( $j * 86400 ) ); 
							$u = isset( $history_50[ $d ] ) ? $history_50[ $d ]->uv : 0; 
							$p = isset( $history_50[ $d ] ) ? $history_50[ $d ]->pv : 0; ?>
							<tr>
								<td><b><?php echo $d; ?></b></td>
								<td><?php echo $u; ?></td>
								<td><?php echo $p; ?></td>
								<td><code><?php echo round( $p / max( 1, $u ), 1 ); ?></code></td>
							</tr>
						<?php endfor; ?>
						</tbody>
					</table>
				</div>
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
            <h3>🚫 拦截日志 (<?php echo $latest_date; ?>)</h3>
            <div class="sba-scroll-x"><table class="sba-table"><thead><tr><th width="100">时间</th><th width="150">拦截 IP</th><th>原因与目标</th></tr></thead><tbody id="blocked-log-body"></tbody></table></div>
            <div style="margin-top:15px; display:flex; justify-content: space-between;">
                <div>总记录: <b id="blocked-total-rows">0</b></div>
                <div><button id="blocked-prev-page" class="button">上页</button> 第 <b id="blocked-current-page">1</b> / <b id="blocked-total-pages">1</b> 页 <button id="blocked-next-page" class="button">下页</button></div>
            </div>
        </div>
        <?php sba_environment_panel(); ?>
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
    var blockedCurPage = 1, blockedMaxPages = 1;
    function loadBlockedLogs(page) {
        fetch(ajaxurl, { method: 'POST', body: new URLSearchParams({action:'sba_load_blocked_logs', page:page}) }).then(r => r.json()).then(res => {
            if(res.success) {
                document.getElementById('blocked-log-body').innerHTML = res.data.html;
                blockedCurPage = page;
                blockedMaxPages = res.data.pages;
                document.getElementById('blocked-current-page').innerText = page;
                document.getElementById('blocked-total-pages').innerText = res.data.pages;
                document.getElementById('blocked-total-rows').innerText = res.data.total;
            }
        });
    }
    document.getElementById('blocked-prev-page').onclick = () => { if(blockedCurPage > 1) loadBlockedLogs(blockedCurPage - 1); };
    document.getElementById('blocked-next-page').onclick = () => { if(blockedCurPage < blockedMaxPages) loadBlockedLogs(blockedCurPage + 1); };
    loadBlockedLogs(1);
    </script>
    <?php
}

function sba_audit_render_settings() {
    $opts = get_option( 'sba_settings' );
    ?>
    <div class="wrap sba-wrap">
	    <?php settings_errors(); ?>
        <h1>🛠️ SBA 防御设置</h1>
        <div class="sba-card" style="background:#fffbe6; border-left:5px solid #faad14;">
            <h3>📖 使用说明</h3>
            <p>1. <b>防误杀：</b> 填入用户名后，登录时将免疫所有频率拦截和路径检测。</p>
            <p>2. <b>Gate 钥匙：</b> 设置后，访问 <code>wp-login.php?gate=钥匙</code> 可开启登录入口（地址栏自动去除参数）。此后登录表单通过隐藏字段提交令牌，退出后令牌失效。</p>
            <p>3. <b>指纹库：</b> 自动识别 <code>sqlmap, curl, wget, python</code> 等 UA 特征并阻断。</p>
            <p>4. <b>归属地：</b> 使用 ip2region xdb 内存查询。请通过下方按钮上传 IPv4 和 IPv6 的 xdb 文件（支持分片上传、断点续传）。</p>
            <p>5. <b>爬虫防御：</b> 启用阶梯限制和 Cookie 校验可有效识别采集器，蜜罐陷阱触发即封禁。</p>
        </div>
        <form method="post" action="options.php">
            <?php settings_fields( 'sba_settings_group' ); ?>
            <div class="sba-grid">
                <div class="sba-card">
                    <h3>✅ 信任通道</h3>
                    <table class="form-table">
                         <tr><th>用户名白名单</th><td><input type="text" name="sba_settings[user_whitelist]" value="<?php echo esc_attr( $opts['user_whitelist'] ?? '' ); ?>" class="regular-text" /><br><small>登录此用户时，系统自动信任，不执行拦截逻辑。</small></td></tr>
                         <tr><th>IP 白名单</th><td><textarea name="sba_settings[ip_whitelist]" rows="3" style="width:100%"><?php echo esc_textarea( $opts['ip_whitelist'] ?? '' ); ?></textarea><br><small>每行一个 IP。</small></td></tr>
                    </table>
                </div>
                <div class="sba-card">
                    <h3>🚫 防御配置</h3>
                    <table class="form-table">
                         <tr><th>CC 封禁阈值</th><td><input type="number" name="sba_settings[auto_block_limit]" value="<?php echo esc_attr( $opts['auto_block_limit'] ?? '60' ); ?>" /> 次/分<br><small>单 IP 每分钟请求超过此值自动封禁（0 为关闭）。</small></td></tr>
                         <tr><th>Gate 钥匙</th><td><input type="text" name="sba_settings[login_slug]" value="<?php echo esc_attr( $opts['login_slug'] ?? '' ); ?>" /><br><small>保护登录入口。访问 <code>wp-login.php?gate=钥匙</code> 开启入口，之后自动隐藏。</small></td></tr>
                         <tr><th>追加拦截路径</th><td><input type="text" name="sba_settings[evil_paths]" value="<?php echo esc_attr( $opts['evil_paths'] ?? '' ); ?>" style="width:100%" placeholder="/test.php, /backup.zip" /><br><small>逗号分隔。内置已含 .env/.git 等，此处用于扩充。</small></td></tr>
                         <tr><th>爬虫特征路径 (正则)</th><td><input type="text" name="sba_settings[scraper_paths]" value="<?php echo esc_attr( $opts['scraper_paths'] ?? 'feed=|rest_route=|[\?&]m=|\?p=' ); ?>" style="width:100%" /><br><small>正则表达式，匹配的 URL 将使用更严格的频率限制（默认阈值的 1/3）。</small></td></tr>
                         <tr><th>Cookie 校验</th><td><label><input type="checkbox" name="sba_settings[enable_cookie_check]" value="1" <?php checked( $opts['enable_cookie_check'] ?? 1, 1 ); ?> /> 启用 Cookie 校验（无有效 Cookie 且非浏览器的请求将受到更严格限制）</label></td></tr>
                         <tr><th>拦截重定向 URL</th><td><input type="text" name="sba_settings[block_target_url]" value="<?php echo esc_attr( $opts['block_target_url'] ?? '' ); ?>" style="width:100%" placeholder="https://127.0.0.1" /><br><small>拦截后将对方跳转至此页面（留空则显示默认 403 页面）。</small></td></tr>
                    </table>
                    <?php submit_button( '保存核心配置' ); ?>
                </div>
            </div>
        </form>

        <div class="sba-card">
            <h3>📁 IP 归属地库 (ip2region xdb) 分片上传</h3>
            <div style="margin-bottom:20px;">
                <p><strong>IPv4 库</strong> <?php if ( file_exists( SBA_IP_V4_FILE ) ) : ?><span style="color:green;">✓ 已上传 (<?php echo size_format( filesize( SBA_IP_V4_FILE ) ); ?>)</span><?php else : ?><span style="color:red;">✗ 未上传</span><?php endif; ?></p>
                <div id="upload-v4-area">
                    <input type="file" id="sba-ip-v4-file" accept=".xdb">
                    <button id="sba-upload-v4-btn" class="button button-primary">上传 IPv4 库</button>
                    <button id="sba-cancel-upload-v4-btn" class="button button-secondary" style="display:none;">取消上传</button>
                    <div id="sba-upload-v4-progress" style="display:none; margin-top:10px;">
                        <div style="background:#f0f0f0; height:20px; border-radius:10px; overflow:hidden; width:100%; max-width:400px;">
                            <div id="sba-upload-v4-bar" style="background:#2271b1; width:0%; height:100%; transition:width 0.3s; text-align:center; color:#fff; line-height:20px; font-size:12px;">0%</div>
                        </div>
                        <div id="sba-upload-v4-status" style="margin-top:5px; font-size:12px; color:#555;"></div>
                    </div>
                </div>
                <hr style="margin:20px 0;">
                <p><strong>IPv6 库</strong> <?php if ( file_exists( SBA_IP_V6_FILE ) ) : ?><span style="color:green;">✓ 已上传 (<?php echo size_format( filesize( SBA_IP_V6_FILE ) ); ?>)</span><?php else : ?><span style="color:red;">✗ 未上传</span><?php endif; ?></p>
                <div id="upload-v6-area">
                    <input type="file" id="sba-ip-v6-file" accept=".xdb">
                    <button id="sba-upload-v6-btn" class="button button-primary">上传 IPv6 库</button>
                    <button id="sba-cancel-upload-v6-btn" class="button button-secondary" style="display:none;">取消上传</button>
                    <div id="sba-upload-v6-progress" style="display:none; margin-top:10px;">
                        <div style="background:#f0f0f0; height:20px; border-radius:10px; overflow:hidden; width:100%; max-width:400px;">
                            <div id="sba-upload-v6-bar" style="background:#2271b1; width:0%; height:100%; transition:width 0.3s; text-align:center; color:#fff; line-height:20px; font-size:12px;">0%</div>
                        </div>
                        <div id="sba-upload-v6-status" style="margin-top:5px; font-size:12px; color:#555;"></div>
                    </div>
                </div>
            </div>
        </div>
        <?php sba_environment_panel(); ?>
    </div>
    <?php
}

/* ================= 分片上传 AJAX 处理 ================= */
add_action( 'wp_ajax_sba_upload_xdb_chunk', 'sba_ajax_upload_xdb_chunk' );
add_action( 'wp_ajax_sba_upload_xdb_status', 'sba_ajax_upload_xdb_status' );
add_action( 'wp_ajax_sba_upload_xdb_cancel', 'sba_ajax_upload_xdb_cancel' );

function sba_ajax_upload_xdb_chunk() {
    if ( ! current_user_can( 'manage_options' ) ) wp_send_json_error( '无权限' );
    if ( ! wp_verify_nonce( $_POST['_wpnonce'], 'sba_upload_xdb' ) ) wp_send_json_error( '无效请求' );
    $type = sanitize_text_field( $_POST['type'] );
    $filename = sanitize_file_name( $_POST['filename'] );
    $start = intval( $_POST['start'] );
    $end = intval( $_POST['end'] );
    $file_size = intval( $_POST['file_size'] );
    if ( ! in_array( $type, [ 'v4', 'v6' ] ) ) wp_send_json_error( '无效类型' );
    if ( empty( $filename ) || $start < 0 || $end <= $start || ! isset( $_FILES['file_chunk'] ) ) wp_send_json_error( '参数错误' );
    $chunk = $_FILES['file_chunk'];
    if ( $chunk['error'] !== UPLOAD_ERR_OK ) wp_send_json_error( '分片上传错误' );
    $temp_dir = SBA_IP_DATA_DIR . 'upload_temp';
    if ( ! is_dir( $temp_dir ) ) wp_mkdir_p( $temp_dir );
    $task_id = md5( $type . $filename . $file_size . get_current_user_id() );
    $part_file = $temp_dir . '/' . $task_id . '_' . $start . '_' . $end . '.part';
    if ( ! move_uploaded_file( $chunk['tmp_name'], $part_file ) ) wp_send_json_error( '保存分片失败' );
    $meta_file = $temp_dir . '/' . $task_id . '_meta.json';
    $meta = file_exists( $meta_file ) ? json_decode( file_get_contents( $meta_file ), true ) : [];
    $meta['filename'] = $filename;
    $meta['file_size'] = $file_size;
    $meta['type'] = $type;
    if ( ! isset( $meta['parts'] ) ) $meta['parts'] = [];
    $meta['parts'][] = [ 'start' => $start, 'end' => $end ];
    $meta['parts'] = array_unique( $meta['parts'], SORT_REGULAR );
    file_put_contents( $meta_file, json_encode( $meta ) );
    $covered = sba_is_range_fully_covered( $meta['parts'], $file_size );
    if ( $covered ) {
        $final_file = ( $type === 'v4' ) ? SBA_IP_V4_FILE : SBA_IP_V6_FILE;
        $handle = fopen( $final_file, 'wb' );
        if ( ! $handle ) wp_send_json_error( '无法创建最终文件，请检查目录权限' );
        usort( $meta['parts'], function($a, $b) { return $a['start'] - $b['start']; } );
        foreach ( $meta['parts'] as $part ) {
            $part_path = $temp_dir . '/' . $task_id . '_' . $part['start'] . '_' . $part['end'] . '.part';
            if ( ! file_exists( $part_path ) ) {
                fclose( $handle );
                @unlink( $final_file );
                wp_send_json_error( '分片文件丢失，合并失败' );
            }
            fseek( $handle, $part['start'] );
            $part_handle = fopen( $part_path, 'rb' );
            while ( ! feof( $part_handle ) ) {
                fwrite( $handle, fread( $part_handle, 4096 ) );
            }
            fclose( $part_handle );
            unlink( $part_path );
        }
        fclose( $handle );
        unlink( $meta_file );
        @rmdir( $temp_dir );
        wp_send_json_success( [ 'message' => '上传并合并完成' ] );
    } else {
        wp_send_json_success( [ 'message' => '分片接收成功' ] );
    }
}

function sba_ajax_upload_xdb_status() {
    if ( ! current_user_can( 'manage_options' ) ) wp_send_json_error( '无权限' );
    if ( ! wp_verify_nonce( $_POST['_wpnonce'], 'sba_upload_xdb' ) ) wp_send_json_error( '无效请求' );
    $type = sanitize_text_field( $_POST['type'] );
    $filename = sanitize_file_name( $_POST['filename'] );
    $file_size = intval( $_POST['file_size'] );
    $temp_dir = SBA_IP_DATA_DIR . 'upload_temp';
    $task_id = md5( $type . $filename . $file_size . get_current_user_id() );
    $meta_file = $temp_dir . '/' . $task_id . '_meta.json';
    if ( file_exists( $meta_file ) ) {
        $meta = json_decode( file_get_contents( $meta_file ), true );
        wp_send_json_success( [ 'parts' => $meta['parts'] ] );
    } else {
        wp_send_json_success( [ 'parts' => [] ] );
    }
}

function sba_ajax_upload_xdb_cancel() {
    if ( ! current_user_can( 'manage_options' ) ) wp_send_json_error( '无权限' );
    if ( ! wp_verify_nonce( $_POST['_wpnonce'], 'sba_upload_xdb' ) ) wp_send_json_error( '无效请求' );
    $type = sanitize_text_field( $_POST['type'] );
    $filename = sanitize_file_name( $_POST['filename'] );
    $file_size = intval( $_POST['file_size'] );
    $temp_dir = SBA_IP_DATA_DIR . 'upload_temp';
    $task_id = md5( $type . $filename . $file_size . get_current_user_id() );
    $pattern = $temp_dir . '/' . $task_id . '_*';
    foreach ( glob( $pattern ) as $file ) @unlink( $file );
    @unlink( $temp_dir . '/' . $task_id . '_meta.json' );
    wp_send_json_success( [ 'message' => '已中断并清理临时文件' ] );
}

function sba_is_range_fully_covered( $parts, $size ) {
    if ( empty( $parts ) ) return false;
    usort( $parts, function($a, $b) { return $a['start'] - $b['start']; } );
    $covered = 0;
    foreach ( $parts as $part ) {
        if ( $part['start'] > $covered ) return false;
        $covered = max( $covered, $part['end'] );
    }
    return $covered >= $size;
}

/* ================= 分片上传前端脚本 ================= */
add_action( 'admin_footer', 'sba_upload_script' );
function sba_upload_script() {
    if ( ! isset( $_GET['page'] ) || $_GET['page'] !== 'sba_settings' ) return;
    ?>
    <script>
    jQuery(document).ready(function($) {
        if (typeof ajaxurl === 'undefined') {
            var ajaxurl = '<?php echo admin_url('admin-ajax.php'); ?>';
        }

        function createUploader(type, fileInputId, uploadBtnId, cancelBtnId, progressDivId, barId, statusId) {
            let currentFile = null;
            let isUploading = false;
            let chunkSize = <?php echo SBA_CHUNK_SIZE_INITIAL; ?>;
            const minChunkSize = <?php echo SBA_MIN_CHUNK_SIZE; ?>;
            const maxChunkSize = <?php echo SBA_MAX_CHUNK_SIZE; ?>;
            let consecutiveSuccess = 0;
            let uploadedParts = [];
            let maxRetries = 5;
            let nonce = '<?php echo wp_create_nonce( 'sba_upload_xdb' ); ?>';

            function sleep(ms) { return new Promise(resolve => setTimeout(resolve, ms)); }

            async function uploadChunkWithRetry(formData, start, attempt = 1) {
                return new Promise((resolve, reject) => {
                    const xhr = new XMLHttpRequest();
                    xhr.open('POST', ajaxurl, true);
                    xhr.timeout = 60000;
                    xhr.onload = function() {
                        if (xhr.status === 200) {
                            try {
                                const res = JSON.parse(xhr.responseText);
                                if (res.success) {
                                    consecutiveSuccess++;
                                    if (consecutiveSuccess >= 3 && chunkSize < maxChunkSize) {
                                        chunkSize = Math.min(chunkSize * 2, maxChunkSize);
                                        $('#' + statusId).append(`<br><small>网络良好，分片大小提升至 ${(chunkSize/1024/1024).toFixed(1)}MB</small>`);
                                        consecutiveSuccess = 0;
                                    }
                                    resolve(res);
                                } else {
                                    reject(new Error(res.data || '上传失败'));
                                }
                            } catch(e) { reject(e); }
                        } else if (xhr.status === 413) {
                            chunkSize = Math.max(chunkSize / 2, minChunkSize);
                            $('#' + statusId).html(`<span style="color:#d63638;">单片过大，已降低至 ${(chunkSize/1024/1024).toFixed(1)}MB，重试中...</span>`);
                            reject(new Error('Chunk too large'));
                        } else {
                            reject(new Error(`HTTP ${xhr.status}`));
                        }
                    };
                    xhr.onerror = () => reject(new Error('网络错误'));
                    xhr.ontimeout = () => reject(new Error('上传超时'));
                    xhr.send(formData);
                });
            }

            async function uploadChunkWithBackoff(formData, start, end) {
                let delay = 1000;
                for (let attempt = 1; attempt <= maxRetries; attempt++) {
                    try {
                        return await uploadChunkWithRetry(formData, start, attempt);
                    } catch (error) {
                        if (attempt === maxRetries) throw error;
                        const wait = delay * Math.pow(2, attempt - 1);
                        $('#' + statusId).html(`<span style="color:#d63638;">区间 ${start}-${end} 上传失败，${wait/1000}秒后重试 (${attempt}/${maxRetries})...</span>`);
                        await sleep(wait);
                    }
                }
            }

            function mergeIntervals(intervals) {
                if (intervals.length === 0) return [];
                intervals.sort((a, b) => a.start - b.start);
                let merged = [intervals[0]];
                for (let i = 1; i < intervals.length; i++) {
                    let last = merged[merged.length - 1];
                    let curr = intervals[i];
                    if (curr.start <= last.end) {
                        last.end = Math.max(last.end, curr.end);
                    } else {
                        merged.push(curr);
                    }
                }
                return merged;
            }

            function getRemainingIntervals(fileSize, uploaded) {
                let merged = mergeIntervals(uploaded);
                let remaining = [];
                let cursor = 0;
                for (let i = 0; i < merged.length; i++) {
                    if (cursor < merged[i].start) {
                        remaining.push({ start: cursor, end: merged[i].start });
                    }
                    cursor = merged[i].end;
                }
                if (cursor < fileSize) {
                    remaining.push({ start: cursor, end: fileSize });
                }
                return remaining;
            }

            async function getUploadedParts(filename, fileSize) {
                return new Promise((resolve, reject) => {
                    $.post(ajaxurl, {
                        action: 'sba_upload_xdb_status',
                        type: type,
                        filename: filename,
                        file_size: fileSize,
                        _wpnonce: nonce
                    }, function(res) {
                        if (res.success) resolve(res.data.parts || []);
                        else reject(new Error(res.data));
                    }, 'json').fail(() => reject(new Error('查询状态失败')));
                });
            }

            async function cancelUpload(filename, fileSize) {
                return new Promise((resolve, reject) => {
                    $.post(ajaxurl, {
                        action: 'sba_upload_xdb_cancel',
                        type: type,
                        filename: filename,
                        file_size: fileSize,
                        _wpnonce: nonce
                    }, function(res) {
                        if (res.success) resolve();
                        else reject(new Error(res.data));
                    }, 'json').fail(() => reject(new Error('中断请求失败')));
                });
            }

            async function uploadFileInChunks(file) {
                currentFile = file;
                isUploading = true;
                $('#' + cancelBtnId).show();
                try {
                    const uploaded = await getUploadedParts(file.name, file.size);
                    uploadedParts = uploaded;
                    let remainingIntervals = getRemainingIntervals(file.size, uploadedParts);
                    const totalBytes = file.size;
                    let uploadedBytes = uploadedParts.reduce((sum, p) => sum + (p.end - p.start), 0);
                    let initialPercent = Math.round((uploadedBytes / totalBytes) * 100);
                    $('#' + progressDivId).show();
                    $('#' + barId).css('width', initialPercent + '%').text(initialPercent + '%');
                    $('#' + statusId).html(`准备上传，动态分片大小 ${(chunkSize/1024/1024).toFixed(1)}MB，剩余 ${remainingIntervals.length} 个区间`);
                    
                    for (let interval of remainingIntervals) {
                        if (!isUploading) break;
                        let start = interval.start;
                        while (start < interval.end && isUploading) {
                            let chunkEnd = Math.min(start + chunkSize, interval.end);
                            const chunk = file.slice(start, chunkEnd);
                            const formData = new FormData();
                            formData.append('action', 'sba_upload_xdb_chunk');
                            formData.append('file_chunk', chunk);
                            formData.append('type', type);
                            formData.append('filename', file.name);
                            formData.append('start', start);
                            formData.append('end', chunkEnd);
                            formData.append('file_size', file.size);
                            formData.append('_wpnonce', nonce);
                            try {
                                const response = await uploadChunkWithBackoff(formData, start, chunkEnd);
                                if (response && response.message === '上传并合并完成') {
                                    isUploading = false;
                                    $('#' + statusId).html('<span style="color:#46b450;">✓ 上传成功，正在刷新页面...</span>');
                                    setTimeout(() => location.reload(), 1500);
                                    return;
                                }
                                uploadedParts.push({ start: start, end: chunkEnd });
                                uploadedParts = mergeIntervals(uploadedParts);
                                const uploadedNow = uploadedParts.reduce((sum, p) => sum + (p.end - p.start), 0);
                                const percent = Math.round((uploadedNow / totalBytes) * 100);
                                $('#' + barId).css('width', percent + '%').text(percent + '%');
                                $('#' + statusId).text(`区间 ${start}-${chunkEnd} 上传成功 (${percent}%)`);
                                start = chunkEnd;
                            } catch (error) {
                                throw new Error(`上传失败: ${error.message}`);
                            }
                        }
                    }
                    
                    if (isUploading) {
                        const finalParts = await getUploadedParts(file.name, file.size);
                        if (finalParts.length === 0) {
                            $('#' + statusId).html('<span style="color:#46b450;">✓ 上传成功，正在刷新页面...</span>');
                            setTimeout(() => location.reload(), 1500);
                            return;
                        }
                        const finalMerged = mergeIntervals(finalParts);
                        const totalCovered = finalMerged.reduce((sum, p) => sum + (p.end - p.start), 0);
                        if (totalCovered >= file.size) {
                            $('#' + statusId).html('<span style="color:#46b450;">✓ 上传成功，正在刷新页面...</span>');
                            setTimeout(() => location.reload(), 1500);
                        } else {
                            throw new Error('上传未完全完成');
                        }
                    }
                } catch (error) {
                    $('#' + statusId).html(`<span style="color:#d63638;">✗ 上传失败：${error.message}</span>`);
                    setTimeout(() => $('#' + progressDivId).hide(), 3000);
                } finally {
                    isUploading = false;
                    $('#' + cancelBtnId).hide();
                }
            }

            $('#' + uploadBtnId).click(function() {
                const fileInput = document.getElementById(fileInputId);
                const file = fileInput.files[0];
                if (!file) { alert('请选择文件'); return; }
                if (!file.name.endsWith('.xdb')) { alert('只允许 .xdb 格式的文件'); return; }
                uploadFileInChunks(file);
            });
            $('#' + cancelBtnId).click(async function() {
                if (!currentFile || !isUploading) return;
                if (confirm('确定要中断上传并清理已上传的临时文件吗？')) {
                    isUploading = false;
                    $('#' + statusId).html('正在中断并清理临时文件...');
                    try {
                        await cancelUpload(currentFile.name, currentFile.size);
                        $('#' + statusId).html('已中断上传，临时文件已清理');
                        setTimeout(() => $('#' + progressDivId).hide(), 2000);
                    } catch (error) {
                        $('#' + statusId).html(`中断失败：${error.message}`);
                    }
                    $('#' + cancelBtnId).hide();
                }
            });
        }

        createUploader('v4', 'sba-ip-v4-file', 'sba-upload-v4-btn', 'sba-cancel-upload-v4-btn',
                       'sba-upload-v4-progress', 'sba-upload-v4-bar', 'sba-upload-v4-status');
        createUploader('v6', 'sba-ip-v6-file', 'sba-upload-v6-btn', 'sba-cancel-upload-v6-btn',
                       'sba-upload-v6-progress', 'sba-upload-v6-bar', 'sba-upload-v6-status');
    });
    </script>
    <?php
}

/* ================= SMTP 邮件设置页面 ================= */
function sba_smtp_settings_page() {
    $opts = get_option( 'sba_smtp_settings', array() );
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
                 <tr><th><label for="smtp_host">SMTP 主机</label></th><td><input type="text" id="smtp_host" name="smtp_host" value="<?php echo esc_attr( $opts['smtp_host'] ?? '' ); ?>" class="regular-text" placeholder="例如：smtp.gmail.com" /></td></tr>
                 <tr><th><label for="smtp_port">端口</label></th><td><input type="number" id="smtp_port" name="smtp_port" value="<?php echo esc_attr( $opts['smtp_port'] ?? '587' ); ?>" class="small-text" /> 常用：587 (TLS) 或 465 (SSL)</td></tr>
                 <tr><th><label for="smtp_encryption">加密方式</label></th><td><select id="smtp_encryption" name="smtp_encryption"><option value="none" <?php selected( $opts['smtp_encryption'] ?? '', 'none' ); ?>>无</option><option value="tls" <?php selected( $opts['smtp_encryption'] ?? '', 'tls' ); ?>>TLS</option><option value="ssl" <?php selected( $opts['smtp_encryption'] ?? '', 'ssl' ); ?>>SSL</option></select></td></tr>
                 <tr><th><label for="smtp_auth">启用认证</label></th><td><input type="checkbox" id="smtp_auth" name="smtp_auth" value="1" <?php checked( $opts['smtp_auth'] ?? 1, 1 ); ?> /> 通常需要勾选</td></tr>
                 <tr><th><label for="smtp_username">用户名</label></th><td><input type="text" id="smtp_username" name="smtp_username" value="<?php echo esc_attr( $opts['smtp_username'] ?? '' ); ?>" class="regular-text" /></td></tr>
                 <tr><th><label for="smtp_password">密码</label></th><td><input type="password" id="smtp_password" name="smtp_password" value="<?php echo esc_attr( $opts['smtp_password'] ?? '' ); ?>" class="regular-text" /></td></tr>
                 <tr><th><label for="from_email">发件人邮箱</label></th><td><input type="email" id="from_email" name="from_email" value="<?php echo esc_attr( $opts['from_email'] ?? '' ); ?>" class="regular-text" placeholder="留空则使用 WordPress 默认" /></td></tr>
                 <tr><th><label for="from_name">发件人名称</label></th><td><input type="text" id="from_name" name="from_name" value="<?php echo esc_attr( $opts['from_name'] ?? '' ); ?>" class="regular-text" placeholder="例如：网站名称" /></td></tr>
            </table>
            <?php submit_button( '保存设置', 'primary', 'smtp_save' ); ?>
        </form>
        <hr />
        <h2>测试邮件发送</h2>
        <form method="post" action="">
            <?php wp_nonce_field( 'sba_smtp_save' ); ?>
            <table class="form-table"><tr><th><label for="test_to">接收测试邮箱</label></th><td><input type="email" id="test_to" name="test_to" class="regular-text" placeholder="your@email.com" /></td></tr></table>
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

add_action( 'wp_logout', function() {
    wp_redirect( home_url() );
    exit;
} );
