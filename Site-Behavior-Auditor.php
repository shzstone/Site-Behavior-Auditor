<?php
/**
 * Plugin Name: 综合安全套件 (Site Behavior Auditor + Login Box + SMTP)
 * Description: 集成站点全行为审计、iOS风格登录/注册/忘记密码面板（简码: sba_login_box）和SMTP邮件配置。IP归属地使用 ip2region xdb 内存查询，支持分片上传大文件。
 * Version: 2.0
 * Author: Stone
 */

if ( ! defined( 'ABSPATH' ) ) exit;

/* ================= 常量定义 ================= */
define( 'SBA_VERSION', '2.1' );
define( 'SBA_IP_DATA_DIR', WP_CONTENT_DIR . '/uploads/sba_ip_data/' );
define( 'SBA_IP_V4_FILE', SBA_IP_DATA_DIR . 'ip2region_v4.xdb' );
define( 'SBA_IP_V6_FILE', SBA_IP_DATA_DIR . 'ip2region_v6.xdb' );
define( 'SBA_CHUNK_SIZE', 2 * 1024 * 1024 ); // 2MB 分片大小

/* ================= 创建目录 ================= */
register_activation_hook( __FILE__, 'sba_create_dirs' );
function sba_create_dirs() {
    if ( ! file_exists( SBA_IP_DATA_DIR ) ) {
        wp_mkdir_p( SBA_IP_DATA_DIR );
    }
    // 确保 .htaccess 禁止直接访问
    $htaccess = SBA_IP_DATA_DIR . '.htaccess';
    if ( ! file_exists( $htaccess ) ) {
        file_put_contents( $htaccess, "Deny from all\n" );
    }
}

/* ================= 数据库表创建 ================= */
register_activation_hook( __FILE__, 'sba_combined_activate' );
function sba_combined_activate() {
    global $wpdb;
    $charset_collate = $wpdb->get_charset_collate();

    // 审计统计表（不再包含 IP 库表）
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

    // 拦截日志表
    $sql[] = "CREATE TABLE IF NOT EXISTS {$wpdb->prefix}sba_blocked_log (
        id BIGINT AUTO_INCREMENT PRIMARY KEY,
        ip VARCHAR(45),
        reason VARCHAR(100),
        target_url TEXT,
        block_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    ) $charset_collate;";

    // 登录失败记录表（保留用于封禁逻辑）
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

    // 安排每日清理任务
    if ( ! wp_next_scheduled( 'sba_daily_cleanup' ) ) {
        wp_schedule_event( time(), 'daily', 'sba_daily_cleanup' );
    }
}

/* ================= 每日清理 ================= */
add_action( 'sba_daily_cleanup', 'sba_cleanup_old_data' );
function sba_cleanup_old_data() {
    global $wpdb;
    // 保留最近30天的访问统计
    $wpdb->query( "DELETE FROM {$wpdb->prefix}dis_stats WHERE visit_date < DATE_SUB(NOW(), INTERVAL 30 DAY)" );
    // 保留最近7天的拦截日志
    $wpdb->query( "DELETE FROM {$wpdb->prefix}sba_blocked_log WHERE block_time < DATE_SUB(NOW(), INTERVAL 7 DAY)" );
    // 清理过期的登录失败记录（超过30天未活动）
    $wpdb->query( "DELETE FROM {$wpdb->prefix}sba_login_failures WHERE last_failed_time < DATE_SUB(NOW(), INTERVAL 30 DAY)" );
}

/* ================= 分片上传相关函数 ================= */
// 清理旧的分片文件
function sba_cleanup_orphaned_chunks() {
    $chunk_pattern = SBA_IP_DATA_DIR . 'chunk_*_*';
    foreach ( glob( $chunk_pattern ) as $chunk_file ) {
        if ( file_exists( $chunk_file ) && ( time() - filemtime( $chunk_file ) > 86400 ) ) {
            @unlink( $chunk_file );
        }
    }
}

// 每日清理任务
if ( ! wp_next_scheduled( 'sba_cleanup_chunks_daily' ) ) {
    wp_schedule_event( time(), 'daily', 'sba_cleanup_chunks_daily' );
}
add_action( 'sba_cleanup_chunks_daily', 'sba_cleanup_orphaned_chunks' );

/* ================= 通用工具函数 ================= */
function sba_combined_get_ip() {
    $ip = $_SERVER['HTTP_CF_CONNECTING_IP'] ?? $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'];
    return filter_var( trim( explode( ',', $ip )[0] ), FILTER_VALIDATE_IP ) ?: '0.0.0.0';
}

function sba_audit_get_opt( $k, $d = '' ) {
    $o = get_option( 'sba_settings' );
    return ( isset( $o[ $k ] ) && $o[ $k ] !== '' ) ? $o[ $k ] : $d;
}

/* ================= 完整的 IP 归属地查询类（基于 ip2region xdb） ================= */
if ( ! class_exists( 'XdbSearcher' ) ) {
    /**
     * ip2region xdb searcher class (完整支持 IPv4 和 IPv6)
     * 基于官方库完整实现
     */
    class XdbSearcher
    {
        const HeaderInfoLength = 256;
        const VectorIndexRows = 256;
        const VectorIndexCols = 256;
        const VectorIndexSize = 8;
        const IPv4_SEGMENT_SIZE = 14;  // 4+4+2+4
        const IPv6_SEGMENT_SIZE = 38;  // 16+16+2+4

        private $buffer = null;
        private $headerInfo = null;
        private $vectorIndex = null;
        private $version = null; // 'v4' 或 'v6'

        public static function loadContentFromFile($xdbPath) {
            $content = file_get_contents($xdbPath);
            if ($content === false) {
                return null;
            }
            return $content;
        }

        public static function newWithBuffer($cBuff, $version = 'v4') {
            $searcher = new self();
            $searcher->buffer = $cBuff;
            $searcher->headerInfo = substr($cBuff, 0, self::HeaderInfoLength);
            $searcher->vectorIndex = substr($cBuff, self::HeaderInfoLength, 
                self::VectorIndexRows * self::VectorIndexCols * self::VectorIndexSize);
            $searcher->version = $version;
            
            // 解析头部信息验证版本
            if (strlen($cBuff) >= self::HeaderInfoLength) {
                $version_byte = ord(substr($cBuff, 16, 1));
                if ($version_byte == 6) {
                    $searcher->version = 'v6';
                } elseif ($version_byte == 4) {
                    $searcher->version = 'v4';
                }
            }
            
            return $searcher;
        }

        public function search($ip) {
            if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                return $this->searchIPv4($ip);
            } elseif (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                return $this->searchIPv6($ip);
            }
            return null;
        }

        private function searchIPv4($ip) {
            $ipNum = ip2long($ip);
            if ($ipNum === false) return null;
            
            // 处理 32 位有符号整数溢出
            if (PHP_INT_SIZE === 4 && $ipNum < 0) {
                $ipNum = sprintf('%u', $ipNum);
            }
            
            return $this->searchByIpNum($ipNum, self::IPv4_SEGMENT_SIZE);
        }

        private function searchIPv6($ip) {
            $ipBin = inet_pton($ip);
            if ($ipBin === false) return null;
            
            // 将 IPv6 地址转为十六进制字符串用于比较
            $ipHex = bin2hex($ipBin);
            
            // 使用完整的 IPv6 搜索逻辑
            return $this->searchIPv6ByHex($ipHex);
        }

        private function searchIPv6ByHex($ipHex) {
            if (strlen($ipHex) !== 32) {
                return null; // 无效的 IPv6 十六进制表示
            }
            
            $il0 = hexdec(substr($ipHex, 0, 2));
            $il1 = hexdec(substr($ipHex, 2, 2));
            
            $idx = $il0 * self::VectorIndexCols * self::VectorIndexSize + $il1 * self::VectorIndexSize;
            
            if (strlen($this->vectorIndex) < $idx + 8) {
                return null;
            }
            
            $sPtr = unpack('V', substr($this->vectorIndex, $idx, 4))[1];
            $ePtr = unpack('V', substr($this->vectorIndex, $idx + 4, 4))[1];

            if ($sPtr === 0 || $ePtr === 0) {
                return null;
            }

            $l = 0;
            $h = ($ePtr - $sPtr) / self::IPv6_SEGMENT_SIZE;
            
            while ($l <= $h) {
                $m = (int)(($l + $h) / 2);
                $p = $sPtr + $m * self::IPv6_SEGMENT_SIZE;
                
                if ($p + 32 > strlen($this->buffer)) {
                    break;
                }
                
                $startIpHex = bin2hex(substr($this->buffer, $p, 16));
                $endIpHex = bin2hex(substr($this->buffer, $p + 16, 16));
                
                if ($ipHex < $startIpHex) {
                    $h = $m - 1;
                } elseif ($ipHex > $endIpHex) {
                    $l = $m + 1;
                } else {
                    if ($p + 36 > strlen($this->buffer)) {
                        return null;
                    }
                    
                    $dataLen = unpack('v', substr($this->buffer, $p + 32, 2))[1];
                    $dataPtr = unpack('V', substr($this->buffer, $p + 34, 4))[1];
                    
                    if ($dataPtr + $dataLen > strlen($this->buffer)) {
                        return null;
                    }
                    
                    return substr($this->buffer, $dataPtr, $dataLen);
                }
            }
            
            return null;
        }

        private function searchByIpNum($ipNum, $segmentSize) {
            $il0 = ($ipNum >> 24) & 0xFF;
            $il1 = ($ipNum >> 16) & 0xFF;
            $idx = $il0 * self::VectorIndexCols * self::VectorIndexSize + $il1 * self::VectorIndexSize;
            
            if (strlen($this->vectorIndex) < $idx + 8) {
                return null;
            }
            
            $sPtr = unpack('V', substr($this->vectorIndex, $idx, 4))[1];
            $ePtr = unpack('V', substr($this->vectorIndex, $idx + 4, 4))[1];

            if ($sPtr === 0 || $ePtr === 0) {
                return null;
            }

            $l = 0;
            $h = ($ePtr - $sPtr) / $segmentSize;
            
            while ($l <= $h) {
                $m = (int)(($l + $h) / 2);
                $p = $sPtr + $m * $segmentSize;
                
                if ($p + 8 > strlen($this->buffer)) {
                    break;
                }
                
                $startIp = unpack('V', substr($this->buffer, $p, 4))[1];
                if ($ipNum < $startIp) {
                    $h = $m - 1;
                } else {
                    if ($p + 8 > strlen($this->buffer)) {
                        return null;
                    }
                    
                    $endIp = unpack('V', substr($this->buffer, $p + 4, 4))[1];
                    if ($ipNum > $endIp) {
                        $l = $m + 1;
                    } else {
                        if ($p + 14 > strlen($this->buffer)) {
                            return null;
                        }
                        
                        $dataLen = unpack('v', substr($this->buffer, $p + 8, 2))[1];
                        $dataPtr = unpack('V', substr($this->buffer, $p + 10, 4))[1];
                        
                        if ($dataPtr + $dataLen > strlen($this->buffer)) {
                            return null;
                        }
                        
                        return substr($this->buffer, $dataPtr, $dataLen);
                    }
                }
            }
            
            return null;
        }
        
        public function getVersion() {
            return $this->version;
        }
    }
}

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
        // 加载 IPv4 库
        if ( file_exists( SBA_IP_V4_FILE ) ) {
            $cBuff = XdbSearcher::loadContentFromFile( SBA_IP_V4_FILE );
            if ( $cBuff ) {
                $this->searcher_v4 = XdbSearcher::newWithBuffer( $cBuff, 'v4' );
            }
        }
        // 加载 IPv6 库
        if ( file_exists( SBA_IP_V6_FILE ) ) {
            $cBuff = XdbSearcher::loadContentFromFile( SBA_IP_V6_FILE );
            if ( $cBuff ) {
                $this->searcher_v6 = XdbSearcher::newWithBuffer( $cBuff, 'v6' );
            }
        }
    }

    public function search( $ip ) {
        // 请求内缓存
        if ( isset( self::$ip_cache[ $ip ] ) ) {
            return self::$ip_cache[ $ip ];
        }

        $result = '未知';
        $is_v4 = filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 );
        $is_v6 = filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 );

        if ( $is_v4 && $this->searcher_v4 ) {
            $region = $this->searcher_v4->search( $ip );
            if ( $region ) {
                $result = $this->format_region( $region );
            }
        } elseif ( $is_v6 && $this->searcher_v6 ) {
            $region = $this->searcher_v6->search( $ip );
            if ( $region ) {
                $result = $this->format_region( $region );
            } else {
                // 如果 IPv6 查询失败，尝试降级到 IPv4 查询（对于 IPv4 映射的 IPv6 地址）
                if ( strpos( $ip, '::ffff:' ) === 0 ) {
                    $ipv4 = substr( $ip, 7 );
                    $region = $this->searcher_v4 ? $this->searcher_v4->search( $ipv4 ) : null;
                    if ( $region ) {
                        $result = $this->format_region( $region ) . ' (IPv4-mapped)';
                    }
                }
            }
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
    
    public function reload_searcher() {
        $this->searcher_v4 = null;
        $this->searcher_v6 = null;
        $this->load_searcher();
    }
}

/* ================= 站点行为审计模块 ================= */
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

// CC 频率限制（使用 Transient）
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

    // Gate 钥匙（使用 Transient 替代 Session）
    $stored_slug = sba_audit_get_opt( 'login_slug', '' );
    $internal_params = ['interim-login', 'auth-check', 'wp_scrape_key', 'wp_scrape_nonce'];
    foreach ($internal_params as $param) {
        if (isset($_GET[$param])) {
            return;
        }
    }
    if ( ! empty( $stored_slug ) && $is_login_page && empty( $current_action ) ) {
        // 1. 检查 URL 中的 gate 参数
        if ( isset( $_GET['gate'] ) && ! empty( $_GET['gate'] ) ) {
            $provided_gate = $_GET['gate'];
            $salt_fixed = defined( 'NONCE_SALT' ) ? NONCE_SALT : 'sba_fallback_salt';
            $expected_token_fixed = hash_hmac( 'sha256', $stored_slug, $salt_fixed );
            $provided_token_fixed = hash_hmac( 'sha256', $provided_gate, $salt_fixed );

            if ( hash_equals( $expected_token_fixed, $provided_token_fixed ) ) {
                // 生成临时令牌，存入 Transient
                $token = wp_generate_password( 20, false );
                set_transient( 'sba_gate_token_' . $ip, $token, 1800 );
                $redirect_url = remove_query_arg( 'gate' );
                wp_redirect( $redirect_url );
                exit;
            } else {
                sba_audit_execute_block( "Gate 钥匙错误或已失效" );
            }
        }

        // 2. 页面加载时检查令牌是否存在
        if ( $_SERVER['REQUEST_METHOD'] !== 'POST' ) {
            if ( ! get_transient( 'sba_gate_token_' . $ip ) ) {
                sba_audit_execute_block( "Gate 钥匙错误或已失效" );
            }
            return;
        }

        // 3. POST 请求验证隐藏字段
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

    // CC 频率限制（仅对非浏览器且未登录的请求进行限制）
    $limit = (int) sba_audit_get_opt( 'auto_block_limit', 0 );
    if ( $limit > 0 ) {
        if ( is_user_logged_in() ) {
            // 已登录用户不限制
        } else {
            $ip = sba_combined_get_ip();
            if ( $ip === '127.0.0.1' || $ip === '::1' ) {
                // 本地不限制
            } else {
                $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
                $is_browser = preg_match( '/Mozilla\/|Chrome\/|Firefox\/|Safari\/|Edge\/|Opera\/|MSIE/', $ua );
                if ( ! $is_browser ) {
                    if ( sba_check_cc_limit( $ip, $limit ) ) {
                        sba_audit_execute_block( "频率超限 (CC风险)" );
                    }
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
    if ( ! empty( $stored_slug ) ) {
        $ip = sba_combined_get_ip();
        $token = get_transient( 'sba_gate_token_' . $ip );
        if ( $token ) {
            $expected_token = hash_hmac( 'sha256', $stored_slug, $token );
            echo '<input type="hidden" name="sba_gate_token" value="' . esc_attr( $expected_token ) . '" />';
        }
    }
} );

// 登录/退出时销毁令牌
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
        "SELECT * FROM {$wpdb->prefix}sba_blocked_log 
         WHERE DATE(block_time) = CURDATE() 
         ORDER BY block_time DESC LIMIT %d, %d",
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

/* ================= 分片上传功能模块 ================= */
// AJAX 分片上传处理
add_action( 'wp_ajax_sba_upload_ip_file_chunk', 'sba_ajax_upload_ip_file_chunk' );
add_action( 'wp_ajax_nopriv_sba_upload_ip_file_chunk', 'sba_ajax_upload_ip_file_chunk' );

function sba_ajax_upload_ip_file_chunk() {
    if ( ! current_user_can( 'manage_options' ) ) {
        wp_send_json_error( '无权限' );
    }
    
    check_ajax_referer( 'sba_upload_action', '_ajax_nonce' );
    
    $chunk_index = intval( $_POST['chunk_index'] );
    $total_chunks = intval( $_POST['total_chunks'] );
    $file_type = sanitize_text_field( $_POST['file_type'] ); // 'v4' 或 'v6'
    $file_name = sanitize_text_field( $_POST['file_name'] );
    
    // 验证文件类型
    if ( ! in_array( $file_type, ['v4', 'v6'] ) ) {
        wp_send_json_error( '无效的文件类型' );
    }
    
    // 验证文件名
    if ( ! preg_match('/\.xdb$/i', $file_name) ) {
        wp_send_json_error( '仅支持 .xdb 格式文件' );
    }
    
    // 目标文件名
    $target_file = ( $file_type === 'v4' ) ? SBA_IP_V4_FILE : SBA_IP_V6_FILE;
    
    // 确保目录存在
    if ( ! file_exists( SBA_IP_DATA_DIR ) ) {
        wp_mkdir_p( SBA_IP_DATA_DIR );
    }
    
    // 处理上传的文件块
    if ( ! isset( $_FILES['chunk'] ) || $_FILES['chunk']['error'] !== UPLOAD_ERR_OK ) {
        wp_send_json_error( '上传失败: 文件块错误' );
    }
    
    $temp_chunk = $_FILES['chunk']['tmp_name'];
    $chunk_size = $_FILES['chunk']['size'];
    
    // 验证分片大小
    if ( $chunk_size > SBA_CHUNK_SIZE * 1.1 ) { // 允许10%的误差
        wp_send_json_error( '分片大小超过限制' );
    }
    
    $chunk_path = SBA_IP_DATA_DIR . 'chunk_' . $file_type . '_' . $chunk_index;
    
    // 移动分片到临时位置
    if ( ! move_uploaded_file( $temp_chunk, $chunk_path ) ) {
        wp_send_json_error( '保存分片失败' );
    }
    
    // 验证分片文件
    if ( ! file_exists( $chunk_path ) || filesize( $chunk_path ) !== $chunk_size ) {
        @unlink( $chunk_path );
        wp_send_json_error( '分片验证失败' );
    }
    
    // 如果是最后一个分片，合并文件
    if ( $chunk_index === $total_chunks - 1 ) {
        $success = sba_merge_ip_file_chunks( $file_type, $total_chunks, $target_file );
        if ( $success ) {
            // 重新加载 IP 搜索器
            $searcher = SBA_IP_Searcher::get_instance();
            $searcher->reload_searcher();
            
            wp_send_json_success( [
                'message' => 'IP库文件上传完成',
                'file_size' => size_format( filesize( $target_file ) ),
                'file_path' => $target_file
            ] );
        } else {
            wp_send_json_error( '文件合并失败' );
        }
    } else {
        wp_send_json_success( [
            'message' => "分片 {$chunk_index}/{$total_chunks} 上传成功",
            'next_chunk' => $chunk_index + 1,
            'progress' => round( ( $chunk_index + 1 ) / $total_chunks * 100, 2 )
        ] );
    }
}

// 合并分片文件
function sba_merge_ip_file_chunks( $file_type, $total_chunks, $target_file ) {
    $fp = @fopen( $target_file, 'wb' );
    if ( ! $fp ) {
        return false;
    }
    
    $success = true;
    
    for ( $i = 0; $i < $total_chunks; $i++ ) {
        $chunk_path = SBA_IP_DATA_DIR . 'chunk_' . $file_type . '_' . $i;
        if ( ! file_exists( $chunk_path ) ) {
            $success = false;
            break;
        }
        
        $chunk_data = @file_get_contents( $chunk_path );
        if ( $chunk_data === false ) {
            $success = false;
            break;
        }
        
        if ( @fwrite( $fp, $chunk_data ) === false ) {
            $success = false;
            break;
        }
        
        @unlink( $chunk_path ); // 删除临时分片
    }
    
    @fclose( $fp );
    
    // 如果合并失败，删除不完整的文件
    if ( ! $success && file_exists( $target_file ) ) {
        @unlink( $target_file );
    }
    
    return $success && file_exists( $target_file );
}

// AJAX 获取上传状态
add_action( 'wp_ajax_sba_get_upload_status', 'sba_ajax_get_upload_status' );
function sba_ajax_get_upload_status() {
    if ( ! current_user_can( 'manage_options' ) ) {
        wp_send_json_error( '无权限' );
    }
    
    check_ajax_referer( 'sba_upload_action', '_ajax_nonce' );
    
    $file_type = sanitize_text_field( $_POST['file_type'] );
    $chunks_uploaded = 0;
    $total_size = 0;
    
    for ( $i = 0; $i < 1000; $i++ ) { // 假设最多1000个分片
        $chunk_path = SBA_IP_DATA_DIR . 'chunk_' . $file_type . '_' . $i;
        if ( file_exists( $chunk_path ) ) {
            $chunks_uploaded++;
            $total_size += filesize( $chunk_path );
        } else {
            break;
        }
    }
    
    wp_send_json_success( [
        'chunks_uploaded' => $chunks_uploaded,
        'total_size' => size_format( $total_size )
    ] );
}

// AJAX 取消上传
add_action( 'wp_ajax_sba_cancel_upload', 'sba_ajax_cancel_upload' );
function sba_ajax_cancel_upload() {
    if ( ! current_user_can( 'manage_options' ) ) {
        wp_send_json_error( '无权限' );
    }
    
    check_ajax_referer( 'sba_upload_action', '_ajax_nonce' );
    
    $file_type = sanitize_text_field( $_POST['file_type'] );
    $deleted_count = 0;
    
    // 删除所有临时分片
    for ( $i = 0; $i < 1000; $i++ ) {
        $chunk_path = SBA_IP_DATA_DIR . 'chunk_' . $file_type . '_' . $i;
        if ( file_exists( $chunk_path ) ) {
            if ( @unlink( $chunk_path ) ) {
                $deleted_count++;
            }
        }
    }
    
    wp_send_json_success( [ 
        'message' => '上传已取消',
        'deleted_chunks' => $deleted_count
    ] );
}

// AJAX 验证 IP 数据库文件
add_action( 'wp_ajax_sba_validate_ip_file', 'sba_ajax_validate_ip_file' );
function sba_ajax_validate_ip_file() {
    if ( ! current_user_can( 'manage_options' ) ) {
        wp_send_json_error( '无权限' );
    }
    
    check_ajax_referer( 'sba_upload_action', '_ajax_nonce' );
    
    $file_type = sanitize_text_field( $_POST['file_type'] );
    $target_file = ( $file_type === 'v4' ) ? SBA_IP_V4_FILE : SBA_IP_V6_FILE;
    
    if ( ! file_exists( $target_file ) ) {
        wp_send_json_error( '文件不存在' );
    }
    
    // 尝试加载文件验证
    $cBuff = XdbSearcher::loadContentFromFile( $target_file );
    if ( ! $cBuff ) {
        wp_send_json_error( '文件加载失败' );
    }
    
    // 验证文件头部
    if ( strlen( $cBuff ) < 256 ) { // HeaderInfoLength
        wp_send_json_error( '文件格式无效' );
    }
    
    $version_byte = ord( substr( $cBuff, 16, 1 ) );
    $expected_version = ( $file_type === 'v4' ) ? 4 : 6;
    
    if ( $version_byte != $expected_version ) {
        wp_send_json_error( "文件版本不匹配，期望 IPv{$expected_version} 但找到 IPv{$version_byte}" );
    }
    
    // 测试查询
    $searcher = XdbSearcher::newWithBuffer( $cBuff, $file_type );
    $test_ip = ( $file_type === 'v4' ) ? '8.8.8.8' : '2001:4860:4860::8888';
    $result = $searcher->search( $test_ip );
    
    wp_send_json_success( [
        'message' => 'IP数据库文件验证通过',
        'file_size' => size_format( filesize( $target_file ) ),
        'test_query' => $result ?: '无结果',
        'version' => $version_byte
    ] );
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

// AJAX 获取验证码（使用 Transient）
add_action( 'wp_ajax_nopriv_sba_ios_get_captcha', 'sba_ios_ajax_get_captcha' );
function sba_ios_ajax_get_captcha() {
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
    set_transient( 'sba_captcha_' . $ip, $answer, 300 );
    wp_send_json_success( [ 'question' => "验证码：$num1 + $num2 = ?", 'answer' => $answer ] );
}

// AJAX 检查是否需要验证码
add_action( 'wp_ajax_nopriv_sba_ios_check_captcha', 'sba_ios_ajax_check_captcha' );
function sba_ios_ajax_check_captcha() {
    check_ajax_referer( 'sba_ios_action', '_ajax_nonce' );
    $ip = sba_combined_get_ip();
    $status = sba_ios_check_ban_and_captcha( $ip );
    if ( $status['banned'] ) wp_send_json_error( [ 'banned' => true ] );
    wp_send_json_success( [ 'need_captcha' => $status['need_captcha'] ] );
}

// AJAX 登录处理
add_action( 'wp_ajax_nopriv_sba_ios_login', 'sba_ios_ajax_login' );
function sba_ios_ajax_login() {
    check_ajax_referer( 'sba_ios_action', '_ajax_nonce' );
    $ip = sba_combined_get_ip();
    if ( ! sba_ios_check_rate_limit( $ip, 10 ) ) wp_send_json_error( [ 'message' => '操作过于频繁，请稍后再试。' ] );
    $status = sba_ios_check_ban_and_captcha( $ip );
    if ( $status['banned'] ) wp_send_json_error( [ 'message' => '由于多次失败，您的IP已被封禁24小时。' ] );

    $username =sanitize_user( $_POST['username'] );
    $password = $_POST['password'];
    $remember = ! empty( $_POST['remember'] );
    $captcha  = sanitize_text_field( $_POST['captcha'] );
    $need_captcha = ! empty( $_POST['need_captcha'] );

    if ( empty( $username ) || empty( $password ) ) {
        wp_send_json_error( [ 'message' => '请填写用户名和密码。' ] );
    }

    if ( $need_captcha ) {
        $expected = get_transient( 'sba_captcha_' . $ip );
        if ( $expected === false || $captcha != $expected ) {
            sba_ios_record_failure( $ip );
            delete_transient( 'sba_captcha_' . $ip );
            wp_send_json_error( [ 'message' => '验证码不正确。', 'need_captcha' => true ] );
        }
        delete_transient( 'sba_captcha_' . $ip );
    }

    $user = wp_authenticate( $username, $password );
    if ( is_wp_error( $user ) ) {
        $count = sba_ios_record_failure( $ip );
        if ( $count === 'banned' ) {
            wp_send_json_error( [ 'message' => '由于多次失败，您的IP已被封禁24小时。' ] );
        }
        $msg = '用户名或密码不正确';
        if ( $count >= 3 ) $msg .= '，请填写验证码';
        wp_send_json_error( [ 'message' => $msg, 'need_captcha' => ( $count >= 3 ) ] );
    }

    // 检查用户是否已激活
    $activated = get_user_meta( $user->ID, '_activated', true );
    if ( $activated !== '1' ) {
        wp_send_json_error( [ 'message' => '账户未激活，请检查您的邮箱激活链接。' ] );
    }

    wp_set_current_user( $user->ID, $user->user_login );
    wp_set_auth_cookie( $user->ID, $remember );
    do_action( 'wp_login', $user->user_login, $user );
    sba_ios_record_failure( $ip, true );
    wp_send_json_success( [ 'message' => '登录成功，正在跳转...' ] );
}

// AJAX 注册处理
add_action( 'wp_ajax_nopriv_sba_ios_register', 'sba_ios_ajax_register' );
function sba_ios_ajax_register() {
    check_ajax_referer( 'sba_ios_action', '_ajax_nonce' );
    $ip = sba_combined_get_ip();
    if ( ! sba_ios_check_rate_limit( $ip, 5 ) ) wp_send_json_error( [ 'message' => '操作过于频繁，请稍后再试。' ] );
    $status = sba_ios_check_ban_and_captcha( $ip, 'register' );
    if ( $status['banned'] ) wp_send_json_error( [ 'message' => '由于多次失败，您的IP已被封禁24小时。' ] );

    $username = sanitize_user( $_POST['username'] );
    $email    = sanitize_email( $_POST['email'] );
    $password = $_POST['password'];
    $captcha  = sanitize_text_field( $_POST['captcha'] );
    $need_captcha = ! empty( $_POST['need_captcha'] );

    if ( empty( $username ) || empty( $email ) || empty( $password ) ) {
        wp_send_json_error( [ 'message' => '请填写完整信息。' ] );
    }

    if ( $need_captcha ) {
        $expected = get_transient( 'sba_captcha_' . $ip );
        if ( $expected === false || $captcha != $expected ) {
            delete_transient( 'sba_captcha_' . $ip );
            wp_send_json_error( [ 'message' => '验证码不正确。', 'need_captcha' => true ] );
        }
        delete_transient( 'sba_captcha_' . $ip );
    }

    if ( ! is_email( $email ) ) wp_send_json_error( [ 'message' => '邮箱格式不正确。' ] );
    if ( username_exists( $username ) ) wp_send_json_error( [ 'message' => '用户名已存在。' ] );
    if ( email_exists( $email ) ) wp_send_json_error( [ 'message' => '邮箱已被注册。' ] );

    if ( strlen( $password ) < 8 ) wp_send_json_error( [ 'message' => '密码长度至少8位。' ] );
    if ( ! preg_match( '/[a-zA-Z]/', $password ) || ! preg_match( '/[0-9]/', $password ) ) {
        wp_send_json_error( [ 'message' => '密码必须包含字母和数字。' ] );
    }

    $user_id = wp_create_user( $username, $password, $email );
    if ( is_wp_error( $user_id ) ) {
        wp_send_json_error( [ 'message' => '注册失败：' . $user_id->get_error_message() ] );
    }

    // 生成激活链接
    $activation_key = wp_generate_password( 20, false );
    update_user_meta( $user_id, '_activation_key', $activation_key );
    update_user_meta( $user_id, '_activated', '0' );

    $activate_link = add_query_arg( [
        'action' => 'sba_activate',
        'user'   => $user_id,
        'key'    => $activation_key
    ], home_url( '/' ) );

    $subject = '请激活您的账户';
    $message = sprintf( '请点击以下链接激活您的账户：%s', $activate_link );
    wp_mail( $email, $subject, $message );

    wp_send_json_success( [ 'message' => '注册成功！请查收邮件激活账户。' ] );
}

// AJAX 忘记密码处理
add_action( 'wp_ajax_nopriv_sba_ios_forgot', 'sba_ios_ajax_forgot' );
function sba_ios_ajax_forgot() {
    check_ajax_referer( 'sba_ios_action', '_ajax_nonce' );
    $ip = sba_combined_get_ip();
    if ( ! sba_ios_check_rate_limit( $ip, 5 ) ) wp_send_json_error( [ 'message' => '操作过于频繁，请稍后再试。' ] );
    $status = sba_ios_check_ban_and_captcha( $ip, 'forgot' );
    if ( $status['banned'] ) wp_send_json_error( [ 'message' => '由于多次失败，您的IP已被封禁24小时。' ] );

    $login = sanitize_text_field( $_POST['email'] );
    $captcha = sanitize_text_field( $_POST['captcha'] );
    $need_captcha = ! empty( $_POST['need_captcha'] );

    if ( empty( $login ) ) {
        wp_send_json_error( [ 'message' => '请填写用户名或邮箱。' ] );
    }

    if ( $need_captcha ) {
        $expected = get_transient( 'sba_captcha_' . $ip );
        if ( $expected === false || $captcha != $expected ) {
            delete_transient( 'sba_captcha_' . $ip );
            wp_send_json_error( [ 'message' => '验证码不正确。', 'need_captcha' => true ] );
        }
        delete_transient( 'sba_captcha_' . $ip );
    }

    $user_data = get_user_by( is_email( $login ) ? 'email' : 'login', $login );
    if ( ! $user_data ) {
        wp_send_json_error( [ 'message' => '用户不存在。' ] );
    }

    $key = get_password_reset_key( $user_data );
    if ( is_wp_error( $key ) ) {
        wp_send_json_error( [ 'message' => '生成重置密钥失败。' ] );
    }

    $reset_link = network_site_url( "wp-login.php?action=rp&key=$key&login=" . rawurlencode( $user_data->user_login ), 'login' );
    $subject = '重置密码';
    $message = "请点击以下链接重置您的密码：\n$reset_link";
    wp_mail( $user_data->user_email, $subject, $message );

    wp_send_json_success( [ 'message' => '重置链接已发送到您的邮箱。' ] );
}

/* ================= SMTP 邮件配置模块 ================= */
function sba_smtp_init( $phpmailer ) {
    $smtp_enabled = sba_audit_get_opt( 'smtp_enabled', '0' );
    if ( $smtp_enabled !== '1' ) return;

    $phpmailer->isSMTP();
    $phpmailer->Host       = sba_audit_get_opt( 'smtp_host', '' );
    $phpmailer->SMTPAuth   = true;
    $phpmailer->Port       = (int) sba_audit_get_opt( 'smtp_port', '465' );
    $phpmailer->SMTPSecure = sba_audit_get_opt( 'smtp_secure', 'ssl' );
    $phpmailer->Username   = sba_audit_get_opt( 'smtp_user', '' );
    $phpmailer->Password   = sba_audit_get_opt( 'smtp_pass', '' );
    $phpmailer->From       = sba_audit_get_opt( 'smtp_from', '' );
    $phpmailer->FromName   = sba_audit_get_opt( 'smtp_from_name', get_bloginfo( 'name' ) );

    if ( empty( $phpmailer->From ) ) {
        $phpmailer->From = $phpmailer->Username;
    }
}
add_action( 'phpmailer_init', 'sba_smtp_init' );

/* ================= 设置页面 ================= */
add_action( 'admin_menu', 'sba_audit_add_menu' );
function sba_audit_add_menu() {
    add_menu_page(
        '综合安全套件',
        'SBA',
        'manage_options',
        'sba-audit',
        'sba_audit_render_settings',
        'dashicons-shield',
        80
    );
    add_submenu_page(
        'sba-audit',
        'IP库上传',
        'IP库上传',
        'manage_options',
        'sba-ip-upload',
        'sba_render_ip_upload_page'
    );
}

function sba_audit_render_settings() {
    if ( ! current_user_can( 'manage_options' ) ) {
        wp_die( '权限不足' );
    }

    if ( isset( $_POST['sba_settings_nonce'] ) && wp_verify_nonce( $_POST['sba_settings_nonce'], 'sba_save_settings' ) ) {
        $settings = [];
        $fields = [
            'login_slug', 'block_target_url', 'ip_whitelist', 'user_whitelist', 'evil_paths',
            'auto_block_limit', 'smtp_enabled', 'smtp_host', 'smtp_port', 'smtp_secure',
            'smtp_user', 'smtp_pass', 'smtp_from', 'smtp_from_name'
        ];
        foreach ( $fields as $field ) {
            $settings[ $field ] = isset( $_POST[ $field ] ) ? sanitize_text_field( $_POST[ $field ] ) : '';
        }
        update_option( 'sba_settings', $settings );
        echo '<div class="notice notice-success"><p>设置已保存</p></div>';
    }

    $settings = get_option( 'sba_settings', [] );
    $login_slug = $settings['login_slug'] ?? '';
    $block_target_url = $settings['block_target_url'] ?? '';
    $ip_whitelist = $settings['ip_whitelist'] ?? '';
    $user_whitelist = $settings['user_whitelist'] ?? '';
    $evil_paths = $settings['evil_paths'] ?? '';
    $auto_block_limit = $settings['auto_block_limit'] ?? 0;
    $smtp_enabled = $settings['smtp_enabled'] ?? '0';
    $smtp_host = $settings['smtp_host'] ?? '';
    $smtp_port = $settings['smtp_port'] ?? '465';
    $smtp_secure = $settings['smtp_secure'] ?? 'ssl';
    $smtp_user = $settings['smtp_user'] ?? '';
    $smtp_pass = $settings['smtp_pass'] ?? '';
    $smtp_from = $settings['smtp_from'] ?? '';
    $smtp_from_name = $settings['smtp_from_name'] ?? get_bloginfo( 'name' );

    // 检查IP库文件状态
    $ip_v4_exists = file_exists( SBA_IP_V4_FILE );
    $ip_v6_exists = file_exists( SBA_IP_V6_FILE );
    $ip_v4_size = $ip_v4_exists ? size_format( filesize( SBA_IP_V4_FILE ) ) : '未上传';
    $ip_v6_size = $ip_v6_exists ? size_format( filesize( SBA_IP_V6_FILE ) ) : '未上传';
    ?>
    <div class="wrap">
        <h1>综合安全套件设置</h1>
        
        <div id="poststuff">
            <div id="post-body" class="metabox-holder columns-2">
                <div id="post-body-content">
                    <div class="postbox">
                        <h2 class="hndle">站点行为审计</h2>
                        <div class="inside">
                            <form method="post">
                                <?php wp_nonce_field( 'sba_save_settings', 'sba_settings_nonce' ); ?>
                                
                                <table class="form-table">
                                    <tr>
                                        <th scope="row"><label for="login_slug">隐藏登录地址别名</label></th>
                                        <td>
                                            <input type="text" id="login_slug" name="login_slug" value="<?php echo esc_attr( $login_slug ); ?>" class="regular-text" />
                                            <p class="description">设置后必须通过 <?php echo esc_url( home_url( '/wp-login.php?gate=' . $login_slug ) ); ?> 访问登录页</p>
                                        </td>
                                    </tr>
                                    <tr>
                                        <th scope="row"><label for="block_target_url">拦截后跳转地址</label></th>
                                        <td>
                                            <input type="url" id="block_target_url" name="block_target_url" value="<?php echo esc_attr( $block_target_url ); ?>" class="regular-text" />
                                            <p class="description">留空则显示拦截页面</p>
                                        </td>
                                    </tr>
                                    <tr>
                                        <th scope="row"><label for="ip_whitelist">IP白名单</label></th>
                                        <td>
                                            <textarea id="ip_whitelist" name="ip_whitelist" rows="3" class="large-text"><?php echo esc_textarea( $ip_whitelist ); ?></textarea>
                                            <p class="description">每行一个IP或IP段，支持CIDR格式</p>
                                        </td>
                                    </tr>
                                    <tr>
                                        <th scope="row"><label for="user_whitelist">用户白名单</label></th>
                                        <td>
                                            <textarea id="user_whitelist" name="user_whitelist" rows="3" class="large-text"><?php echo esc_textarea( $user_whitelist ); ?></textarea>
                                            <p class="description">每行一个用户名</p>
                                        </td>
                                    </tr>
                                    <tr>
                                        <th scope="row"><label for="evil_paths">自定义拦截路径</label></th>
                                        <td>
                                            <textarea id="evil_paths" name="evil_paths" rows="3" class="large-text"><?php echo esc_textarea( $evil_paths ); ?></textarea>
                                            <p class="description">每行一个路径，如: /admin.php, /backup.zip</p>
                                        </td>
                                    </tr>
                                    <tr>
                                        <th scope="row"><label for="auto_block_limit">CC攻击限制频率</label></th>
                                        <td>
                                            <input type="number" id="auto_block_limit" name="auto_block_limit" value="<?php echo esc_attr( $auto_block_limit ); ?>" class="small-text" min="0" />
                                            <p class="description">同一IP每分钟最大请求数，0为不限制（非浏览器UA）</p>
                                        </td>
                                    </tr>
                                </table>
                                
                                <h3>SMTP邮件设置</h3>
                                <table class="form-table">
                                    <tr>
                                        <th scope="row"><label for="smtp_enabled">启用SMTP</label></th>
                                        <td>
                                            <input type="checkbox" id="smtp_enabled" name="smtp_enabled" value="1" <?php checked( $smtp_enabled, '1' ); ?> />
                                            <label for="smtp_enabled">使用SMTP发送邮件</label>
                                        </td>
                                    </tr>
                                    <tr>
                                        <th scope="row"><label for="smtp_host">SMTP服务器</label></th>
                                        <td>
                                            <input type="text" id="smtp_host" name="smtp_host" value="<?php echo esc_attr( $smtp_host ); ?>" class="regular-text" />
                                        </td>
                                    </tr>
                                    <tr>
                                        <th scope="row"><label for="smtp_port">SMTP端口</label></th>
                                        <td>
                                            <input type="number" id="smtp_port" name="smtp_port" value="<?php echo esc_attr( $smtp_port ); ?>" class="small-text" min="1" max="65535" />
                                        </td>
                                    </tr>
                                    <tr>
                                        <th scope="row"><label for="smtp_secure">加密方式</label></th>
                                        <td>
                                            <select id="smtp_secure" name="smtp_secure">
                                                <option value="ssl" <?php selected( $smtp_secure, 'ssl' ); ?>>SSL</option>
                                                <option value="tls" <?php selected( $smtp_secure, 'tls' ); ?>>TLS</option>
                                                <option value="" <?php selected( $smtp_secure, '' ); ?>>无</option>
                                            </select>
                                        </td>
                                    </tr>
                                    <tr>
                                        <th scope="row"><label for="smtp_user">SMTP用户名</label></th>
                                        <td>
                                            <input type="text" id="smtp_user" name="smtp_user" value="<?php echo esc_attr( $smtp_user ); ?>" class="regular-text" />
                                        </td>
                                    </tr>
                                    <tr>
                                        <th scope="row"><label for="smtp_pass">SMTP密码</label></th>
                                        <td>
                                            <input type="password" id="smtp_pass" name="smtp_pass" value="<?php echo esc_attr( $smtp_pass ); ?>" class="regular-text" />
                                        </td>
                                    </tr>
                                    <tr>
                                        <th scope="row"><label for="smtp_from">发件人邮箱</label></th>
                                        <td>
                                            <input type="email" id="smtp_from" name="smtp_from" value="<?php echo esc_attr( $smtp_from ); ?>" class="regular-text" />
                                        </td>
                                    </tr>
                                    <tr>
                                        <th scope="row"><label for="smtp_from_name">发件人名称</label></th>
                                        <td>
                                            <input type="text" id="smtp_from_name" name="smtp_from_name" value="<?php echo esc_attr( $smtp_from_name ); ?>" class="regular-text" />
                                        </td>
                                    </tr>
                                </table>
                                
                                <p class="submit">
                                    <button type="submit" class="button button-primary">保存设置</button>
                                </p>
                            </form>
                        </div>
                    </div>
                    
                    <div class="postbox">
                        <h2 class="hndle">IP归属地数据库状态</h2>
                        <div class="inside">
                            <table class="widefat">
                                <thead>
                                    <tr>
                                        <th>数据库类型</th>
                                        <th>状态</th>
                                        <th>文件大小</th>
                                        <th>最后修改</th>
                                        <th>操作</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <tr>
                                        <td><strong>IPv4 数据库</strong></td>
                                        <td>
                                            <?php if ( $ip_v4_exists ): ?>
                                                <span style="color:#46b450;">✓ 已上传</span>
                                            <?php else: ?>
                                                <span style="color:#d63638;">✗ 未上传</span>
                                            <?php endif; ?>
                                        </td>
                                        <td><?php echo esc_html( $ip_v4_size ); ?></td>
                                        <td>
                                            <?php if ( $ip_v4_exists ): ?>
                                                <?php echo date( 'Y-m-d H:i:s', filemtime( SBA_IP_V4_FILE ) ); ?>
                                            <?php else: ?>
                                                -
                                            <?php endif; ?>
                                        </td>
                                        <td>
                                            <button class="button button-small sba-validate-ip-file" data-type="v4">验证</button>
                                            <button class="button button-small sba-upload-ip-file" data-type="v4">上传/更新</button>
                                        </td>
                                    </tr>
                                    <tr>
                                        <td><strong>IPv6 数据库</strong></td>
                                        <td>
                                            <?php if ( $ip_v6_exists ): ?>
                                                <span style="color:#46b450;">✓ 已上传</span>
                                            <?php else: ?>
                                                <span style="color:#d63638;">✗ 未上传</span>
                                            <?php endif; ?>
                                        </td>
                                        <td><?php echo esc_html( $ip_v6_size ); ?></td>
                                        <td>
                                            <?php if ( $ip_v6_exists ): ?>
                                                <?php echo date( 'Y-m-d H:i:s', filemtime( SBA_IP_V6_FILE ) ); ?>
                                            <?php else: ?>
                                                -
                                            <?php endif; ?>
                                        </td>
                                        <td>
                                            <button class="button button-small sba-validate-ip-file" data-type="v6">验证</button>
                                            <button class="button button-small sba-upload-ip-file" data-type="v6">上传/更新</button>
                                        </td>
                                    </tr>
                                </tbody>
                            </table>
                            
                            <div id="sba-upload-container" style="margin-top: 20px; display: none;">
                                <div id="sba-upload-progress" style="background: #f0f0f0; height: 20px; border-radius: 10px; overflow: hidden; width: 100%; max-width: 400px;">
                                    <div id="sba-upload-progress-bar" style="background: #2271b1; width: 0%; height: 100%; transition: width 0.3s; text-align: center; color: #fff; line-height: 20px; font-size: 12px;">0%</div>
                                </div>
                                <div id="sba-upload-status" style="margin-top: 5px; font-size: 12px; color: #555;"></div>
                                <button id="sba-cancel-upload" class="button button-small button-danger" style="display: none; margin-top: 10px;">取消上传</button>
                            </div>
                            
                            <div id="sba-validation-result" style="margin-top: 20px;"></div>
                        </div>
                    </div>
                    
                    <div class="postbox">
                        <h2 class="hndle">访客轨迹</h2>
                        <div class="inside">
                            <div id="sba-tracks-container">
                                <div class="tablenav top">
                                    <div class="alignleft">
                                        <label>按日期筛选：</label>
                                        <input type="date" id="sba-tracks-date" value="<?php echo date( 'Y-m-d' ); ?>" />
                                    </div>
                                    <div class="tablenav-pages">
                                        <span id="sba-tracks-pagination"></span>
                                    </div>
                                </div>
                                <table class="wp-list-table widefat fixed striped">
                                    <thead>
                                        <tr>
                                            <th width="80">时间</th>
                                            <th width="150">IP</th>
                                            <th width="150">归属地</th>
                                            <th>访问页面</th>
                                            <th width="60">PV</th>
                                        </tr>
                                    </thead>
                                    <tbody id="sba-tracks-body">
                                        <tr><td colspan="5">加载中...</td></tr>
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                    
                    <div class="postbox">
                        <h2 class="hndle">拦截日志</h2>
                        <div class="inside">
                            <div id="sba-blocked-container">
                                <div class="tablenav top">
                                    <div class="tablenav-pages">
                                        <span id="sba-blocked-pagination"></span>
                                    </div>
                                </div>
                                <table class="wp-list-table widefat fixed striped">
                                    <thead>
                                        <tr>
                                            <th width="120">时间</th>
                                            <th width="150">IP</th>
                                            <th>拦截原因与URL</th>
                                        </tr>
                                    </thead>
                                    <tbody id="sba-blocked-body">
                                        <tr><td colspan="3">加载中...</td></tr>
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div id="postbox-container-1" class="postbox-container">
                    <div class="postbox">
                        <h2 class="hndle">系统信息</h2>
                        <div class="inside">
                            <ul>
                                <li>插件版本: <?php echo SBA_VERSION; ?></li>
                                <li>数据库表: <?php
                                    global $wpdb;
                                    $tables = ['dis_stats', 'sba_blocked_log', 'sba_login_failures'];
                                    $missing = [];
                                    foreach ( $tables as $table ) {
                                        if ( $wpdb->get_var( "SHOW TABLES LIKE '{$wpdb->prefix}{$table}'" ) !== $wpdb->prefix . $table ) {
                                            $missing[] = $table;
                                        }
                                    }
                                    echo empty( $missing ) ? '完整' : '缺失: ' . implode( ', ', $missing );
                                ?></li>
                                <li>PHP版本: <?php echo PHP_VERSION; ?></li>
                                <li>WordPress版本: <?php echo get_bloginfo( 'version' ); ?></li>
                                <li>IP获取方式: <?php echo sba_combined_get_ip(); ?></li>
                                <li>内存限制: <?php echo ini_get( 'memory_limit' ); ?></li>
                                <li>执行时间: <?php echo ini_get( 'max_execution_time' ); ?>秒</li>
                            </ul>
                        </div>
                    </div>
                    
                    <div class="postbox">
                        <h2 class="hndle">使用说明</h2>
                        <div class="inside">
                            <ol>
                                <li><strong>隐藏登录地址</strong>: 设置别名后，必须通过带gate参数的URL访问登录页</li>
                                <li><strong>IP白名单</strong>: 被拦截的用户可以手动添加到此列表</li>
                                <li><strong>CC攻击防护</strong>: 自动拦截高频请求的爬虫和扫描器</li>
                                <li><strong>IP归属地</strong>: 需要上传 ip2region 的 xdb 格式数据库文件</li>
                                <li><strong>SMTP设置</strong>: 用于发送激活邮件、重置密码邮件等</li>
                                <li><strong>登录简码</strong>: 在任意页面使用 [sba_login_box] 显示登录表单</li>
                            </ol>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <style>
            .sba-cell-wrap { max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
            .sba-cell-wrap small { word-break: break-all; }
        </style>
        
        <script>
        jQuery(document).ready(function($) {
            var sba_ajax = {
                url: '<?php echo admin_url( "admin-ajax.php" ); ?>',
                nonce: '<?php echo wp_create_nonce( "sba_audit_action" ); ?>',
                upload_nonce: '<?php echo wp_create_nonce( "sba_upload_action" ); ?>'
            };
            
            var currentUpload = {
                type: null,
                file: null,
                totalChunks: 0,
                currentChunk: 0,
                cancelled: false
            };
            
            // IP数据库验证
            $('.sba-validate-ip-file').click(function(e) {
                e.preventDefault();
                var type = $(this).data('type');
                var $result = $('#sba-validation-result');
                $result.html('<p style="color:#666;">验证中...</p>');
                
                $.post(sba_ajax.url, {
                    action: 'sba_validate_ip_file',
                    file_type: type,
                    _ajax_nonce: sba_ajax.upload_nonce
                }, function(response) {
                    if (response.success) {
                        $result.html('<div style="background:#f0fff0; border:1px solid #46b450; padding:10px; border-radius:4px;">' +
                            '<p style="color:#46b450; font-weight:bold;">✓ ' + response.data.message + '</p>' +
                            '<p>文件大小: ' + response.data.file_size + '</p>' +
                            '<p>版本: IPv' + response.data.version + '</p>' +
                            '<p>测试查询(8.8.8.8): ' + (response.data.test_query || '无结果') + '</p>' +
                            '</div>');
                    } else {
                        $result.html('<div style="background:#ffeaea; border:1px solid #d63638; padding:10px; border-radius:4px;">' +
                            '<p style="color:#d63638; font-weight:bold;">✗ 验证失败</p>' +
                            '<p>' + (response.data || '未知错误') + '</p>' +
                            '</div>');
                    }
                }).fail(function() {
                    $result.html('<div style="background:#ffeaea; border:1px solid #d63638; padding:10px; border-radius:4px;">' +
                        '<p style="color:#d63638; font-weight:bold;">网络错误</p>' +
                        '</div>');
                });
            });
            
            // IP数据库上传
            $('.sba-upload-ip-file').click(function(e) {
                e.preventDefault();
                currentUpload.type = $(this).data('type');
                
                var $input = $('<input type="file" accept=".xdb" style="display:none;">');
                $('body').append($input);
                
                $input.on('change', function(e) {
                    var file =e.target.files[0];
                    if (!file) return;
                    
                    if (!file.name.toLowerCase().endsWith('.xdb')) {
                        alert('请选择.xdb格式的文件');
                        return;
                    }
                    
                    // 检查文件大小
                    if (file.size > 1024 * 1024 * 1024) { // 1GB
                        if (!confirm('文件较大，上传可能需要较长时间，是否继续？')) {
                            return;
                        }
                    }
                    
                    currentUpload.file = file;
                    currentUpload.totalChunks = Math.ceil(file.size / <?php echo SBA_CHUNK_SIZE; ?>);
                    currentUpload.currentChunk = 0;
                    currentUpload.cancelled = false;
                    
                    $('#sba-upload-container').show();
                    $('#sba-upload-progress-bar').css('width', '0%').text('0%');
                    $('#sba-upload-status').html('准备上传...');
                    $('#sba-cancel-upload').show();
                    
                    // 开始上传
                    uploadNextChunk();
                });
                
                $input.click();
            });
            
            // 取消上传
            $('#sba-cancel-upload').click(function() {
                if (!confirm('确定要取消上传吗？')) return;
                
                currentUpload.cancelled = true;
                $.post(sba_ajax.url, {
                    action: 'sba_cancel_upload',
                    file_type: currentUpload.type,
                    _ajax_nonce: sba_ajax.upload_nonce
                });
                
                $('#sba-upload-status').html('<span style="color:#d63638;">上传已取消</span>');
                $('#sba-cancel-upload').hide();
            });
            
            // 上传分片函数
            function uploadNextChunk() {
                if (currentUpload.cancelled) return;
                
                var start = currentUpload.currentChunk * <?php echo SBA_CHUNK_SIZE; ?>;
                var end = Math.min(start + <?php echo SBA_CHUNK_SIZE; ?>, currentUpload.file.size);
                var chunk = currentUpload.file.slice(start, end);
                
                var formData = new FormData();
                formData.append('action', 'sba_upload_ip_file_chunk');
                formData.append('_ajax_nonce', sba_ajax.upload_nonce);
                formData.append('chunk_index', currentUpload.currentChunk);
                formData.append('total_chunks', currentUpload.totalChunks);
                formData.append('file_type', currentUpload.type);
                formData.append('file_name', currentUpload.file.name);
                formData.append('chunk', chunk);
                
                // 显示上传进度
                var progress = ((currentUpload.currentChunk) / currentUpload.totalChunks * 100).toFixed(1);
                $('#sba-upload-progress-bar').css('width', progress + '%').text(progress + '%');
                $('#sba-upload-status').html('上传中: ' + (currentUpload.currentChunk + 1) + '/' + currentUpload.totalChunks + ' (' + progress + '%)');
                
                $.ajax({
                    url: sba_ajax.url,
                    type: 'POST',
                    data: formData,
                    processData: false,
                    contentType: false,
                    timeout: 300000, // 5分钟超时
                    success: function(response) {
                        if (currentUpload.cancelled) return;
                        
                        if (response.success) {
                            currentUpload.currentChunk++;
                            
                            if (currentUpload.currentChunk < currentUpload.totalChunks) {
                                // 继续上传下一个分片
                                uploadNextChunk();
                            } else {
                                // 上传完成
                                $('#sba-upload-progress-bar').css('width', '100%').text('100%');
                                $('#sba-upload-status').html('<span style="color:#46b450;">✓ 上传完成！</span> ' + response.data.message);
                                $('#sba-cancel-upload').hide();
                                
                                // 3秒后刷新页面
                                setTimeout(function() {
                                    location.reload();
                                }, 3000);
                            }
                        } else {
                            $('#sba-upload-status').html('<span style="color:#d63638;">✗ 上传失败: ' + (response.data || '未知错误') + '</span>');
                        }
                    },
                    error: function(xhr, status, error) {
                        if (currentUpload.cancelled) return;
                        
                        if (status === 'timeout') {
                            $('#sba-upload-status').html('<span style="color:#d63638;">✗ 上传超时，请重试</span>');
                        } else {
                            $('#sba-upload-status').html('<span style="color:#d63638;">✗ 网络错误: ' + error + '</span>');
                        }
                    }
                });
            }
            
            // 加载访客轨迹
            var tracksPage = 1;
            var tracksTotalPages = 1;
            var tracksDate = $('#sba-tracks-date').val();
            
            function loadTracks(page) {
                $.post(sba_ajax.url, {
                    action: 'sba_load_tracks',
                    page: page,
                    date: tracksDate,
                    _ajax_nonce: sba_ajax.nonce
                }, function(response) {
                    if (response.success) {
                        $('#sba-tracks-body').html(response.data.html);
                        tracksPage = response.data.page;
                        tracksTotalPages = response.data.pages;
                        
                        // 更新分页
                        var pagination = '';
                        if (tracksTotalPages > 1) {
                            pagination = '第 ';
                            for (var i = 1; i <= tracksTotalPages; i++) {
                                if (i === tracksPage) {
                                    pagination += '<strong>' + i + '</strong> ';
                                } else {
                                    pagination += '<a href="#" class="sba-tracks-page" data-page="' + i + '">' + i + '</a> ';
                                }
                            }
                            pagination += ' 页，共 ' + response.data.total + ' 条记录';
                        } else {
                            pagination = '共 ' + response.data.total + ' 条记录';
                        }
                        $('#sba-tracks-pagination').html(pagination);
                        
                        // 加载归属地信息
                        var ips = [];
                        $('.geo-tag').each(function() {
                            ips.push($(this).data('ip'));
                        });
                        
                        if (ips.length > 0) {
                            $.post(sba_ajax.url, {
                                action: 'sba_get_geo',
                                ips: ips,
                                _ajax_nonce: sba_ajax.nonce
                            }, function(geoResponse) {
                                if (geoResponse.success) {
                                    $.each(geoResponse.data, function(ip, location) {
                                        $('.geo-tag[data-ip="' + ip + '"]').text(location);
                                    });
                                }
                            });
                        }
                    }
                });
            }
            
            // 日期筛选
            $('#sba-tracks-date').change(function() {
                tracksDate = $(this).val();
                loadTracks(1);
            });
            
            // 分页点击
            $(document).on('click', '.sba-tracks-page', function(e) {
                e.preventDefault();
                var page = $(this).data('page');
                loadTracks(page);
            });
            
            // 加载拦截日志
            var blockedPage = 1;
            var blockedTotalPages = 1;
            
            function loadBlockedLogs(page) {
                $.post(sba_ajax.url, {
                    action: 'sba_load_blocked_logs',
                    page: page,
                    _ajax_nonce: sba_ajax.nonce
                }, function(response) {
                    if (response.success) {
                        $('#sba-blocked-body').html(response.data.html);
                        blockedPage = response.data.page;
                        blockedTotalPages = response.data.pages;
                        
                        // 更新分页
                        var pagination = '';
                        if (blockedTotalPages > 1) {
                            pagination = '第 ';
                            for (var i = 1; i <= blockedTotalPages; i++) {
                                if (i === blockedPage) {
                                    pagination += '<strong>' + i + '</strong> ';
                                } else {
                                    pagination += '<a href="#" class="sba-blocked-page" data-page="' + i + '">' + i + '</a> ';
                                }
                            }
                            pagination += ' 页，共 ' + response.data.total + ' 条记录';
                        } else {
                            pagination = '共 ' + response.data.total + ' 条记录';
                        }
                        $('#sba-blocked-pagination').html(pagination);
                    }
                });
            }
            
            // 拦截日志分页点击
            $(document).on('click', '.sba-blocked-page', function(e) {
                e.preventDefault();
                var page = $(this).data('page');
                loadBlockedLogs(page);
            });
            
            // 初始化加载
            loadTracks(1);
            loadBlockedLogs(1);
            
            // 自动刷新访客轨迹（每30秒）
            setInterval(function() {
                if ($('#sba-tracks-container').is(':visible')) {
                    loadTracks(tracksPage);
                }
            }, 30000);
        });
        </script>
    </div>
    <?php
}

function sba_render_ip_upload_page() {
    if ( ! current_user_can( 'manage_options' ) ) {
        wp_die( '权限不足' );
    }
    ?>
    <div class="wrap">
        <h1>IP归属地数据库管理</h1>
        
        <div class="notice notice-info">
            <p>ip2region 数据库文件可以从以下地址获取：</p>
            <ul>
                <li>IPv4数据库: <a href="https://github.com/lionsoul2014/ip2region/raw/master/data/ip2region_v4.xdb" target="_blank">https://github.com/lionsoul2014/ip2region/raw/master/data/ip2region_v4.xdb</a></li>
                <li>IPv6数据库: 需要自行转换或购买</li>
            </ul>
        </div>
        
        <div class="postbox">
            <h2 class="hndle">IPv4 数据库</h2>
            <div class="inside">
                <div class="sba-upload-area" data-type="v4">
                    <h3>上传 IPv4 数据库</h3>
                    <p>选择 ip2region_v4.xdb 文件进行上传</p>
                    <input type="file" class="sba-upload-input" data-type="v4" accept=".xdb">
                    <button class="button button-primary sba-start-upload" data-type="v4">开始上传</button>
                    <div class="sba-upload-progress" data-type="v4" style="display:none; margin-top: 10px;">
                        <div class="progress-bar" style="height: 20px; background: #f0f0f0; border-radius: 10px; overflow: hidden;">
                            <div class="progress" style="height: 100%; width: 0%; background: #2271b1; transition: width 0.3s;"></div>
                        </div>
                        <div class="progress-text" style="margin-top: 5px; font-size: 12px;"></div>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="postbox">
            <h2 class="hndle">IPv6 数据库</h2>
            <div class="inside">
                <div class="sba-upload-area" data-type="v6">
                    <h3>上传 IPv6 数据库</h3>
                    <p>选择 ip2region_v6.xdb 文件进行上传</p>
                    <input type="file" class="sba-upload-input" data-type="v6" accept=".xdb">
                    <button class="button button-primary sba-start-upload" data-type="v6">开始上传</button>
                    <div class="sba-upload-progress" data-type="v6" style="display:none; margin-top: 10px;">
                        <div class="progress-bar" style="height: 20px; background: #f0f0f0; border-radius: 10px; overflow: hidden;">
                            <div class="progress" style="height: 100%; width: 0%; background: #2271b1; transition: width 0.3s;"></div>
                        </div>
                        <div class="progress-text" style="margin-top: 5px; font-size: 12px;"></div>
                    </div>
                </div>
            </div>
        </div>
        
        <script>
        jQuery(document).ready(function($) {
            var sba_ajax = {
                url: '<?php echo admin_url( "admin-ajax.php" ); ?>',
                upload_nonce: '<?php echo wp_create_nonce( "sba_upload_action" ); ?>'
            };
            
            var uploads = {};
            
            $('.sba-start-upload').click(function() {
                var type = $(this).data('type');
                var $input = $('.sba-upload-input[data-type="' + type + '"]');
                var file = $input[0].files[0];
                
                if (!file) {
                    alert('请选择文件');
                    return;
                }
                
                if (!file.name.toLowerCase().endsWith('.xdb')) {
                    alert('请选择.xdb格式的文件');
                    return;
                }
                
                // 初始化上传状态
                uploads[type] = {
                    file: file,
                    totalChunks: Math.ceil(file.size / <?php echo SBA_CHUNK_SIZE; ?>),
                    currentChunk: 0,
                    cancelled: false
                };
                
                var $progress = $('.sba-upload-progress[data-type="' + type + '"]');
                var $progressBar = $progress.find('.progress');
                var $progressText = $progress.find('.progress-text');
                
                $progress.show();
                $progressBar.css('width', '0%');
                $progressText.text('准备上传...');
                
                // 开始上传
                uploadChunk(type);
            });
            
            function uploadChunk(type) {
                if (!uploads[type] || uploads[type].cancelled) return;
                
                var upload = uploads[type];
                var start = upload.currentChunk * <?php echo SBA_CHUNK_SIZE; ?>;
                var end = Math.min(start + <?php echo SBA_CHUNK_SIZE; ?>, upload.file.size);
                var chunk = upload.file.slice(start, end);
                
                var formData = new FormData();
                formData.append('action', 'sba_upload_ip_file_chunk');
                formData.append('_ajax_nonce', sba_ajax.upload_nonce);
                formData.append('chunk_index', upload.currentChunk);
                formData.append('total_chunks', upload.totalChunks);
                formData.append('file_type', type);
                formData.append('file_name', upload.file.name);
                formData.append('chunk', chunk);
                
                var progress = ((upload.currentChunk) / upload.totalChunks * 100).toFixed(1);
                var $progress = $('.sba-upload-progress[data-type="' + type + '"]');
                var $progressBar = $progress.find('.progress');
                var $progressText = $progress.find('.progress-text');
                
                $progressBar.css('width', progress + '%');
                $progressText.text('上传中: ' + (upload.currentChunk + 1) + '/' + upload.totalChunks + ' (' + progress + '%)');
                
                $.ajax({
                    url: sba_ajax.url,
                    type: 'POST',
                    data: formData,
                    processData: false,
                    contentType: false,
                    timeout: 300000,
                    success: function(response) {
                        if (!uploads[type] || uploads[type].cancelled) return;
                        
                        if (response.success) {
                            uploads[type].currentChunk++;
                            
                            if (uploads[type].currentChunk < uploads[type].totalChunks) {
                                uploadChunk(type);
                            } else {
                                $progressBar.css('width', '100%');
                                $progressText.html('<span style="color:#46b450;">✓ 上传完成！</span> ' + response.data.message);
                                
                                // 3秒后刷新页面
                                setTimeout(function() {
                                    location.reload();
                                }, 3000);
                            }
                        } else {
                            $progressText.html('<span style="color:#d63638;">✗ 上传失败: ' + (response.data || '未知错误') + '</span>');
                        }
                    },
                    error: function(xhr, status, error) {
                        if (!uploads[type] || uploads[type].cancelled) return;
                        
                        $progressText.html('<span style="color:#d63638;">✗ 上传错误: ' + error + '</span>');
                    }
                });
            }
        });
        </script>
    </div>
    <?php
}

// 清理旧的上传分片
function sba_cleanup_upload_chunks() {
    $chunks = glob( SBA_IP_DATA_DIR . 'chunk_*' );
    foreach ( $chunks as $chunk ) {
        if ( file_exists( $chunk ) && ( time() - filemtime( $chunk ) > 86400 ) ) {
            @unlink( $chunk );
        }
    }
}
add_action( 'init', 'sba_cleanup_upload_chunks' );

// 在插件停用时清理
register_deactivation_hook( __FILE__, 'sba_combined_deactivate' );
function sba_combined_deactivate() {
    wp_clear_scheduled_hook( 'sba_daily_cleanup' );
    wp_clear_scheduled_hook( 'sba_cleanup_chunks_daily' );
    
    // 清理上传分片
    sba_cleanup_upload_chunks();
}
?>
