<?php
if (!defined('ABSPATH')) { exit; }

/**
 * ماژول: قفل کامل XML-RPC + بستن Pingback/Trackback + Rate Limit
 * - بستن کامل xmlrpc.php (پیش‌فرض) با امکان لیست سفید IP/CIDR و محدودسازی نرخ
 * - حذف کامل متدهای pingback و trackback
 * - مسدودسازی دسترسی به /xmlrpc.php و /wp-trackback.php و /trackback/
 * - جلوگیری از ارسال Pingback خروجی (pre_ping)
 * - ثبت رویدادها: xmlrpc_block, xmlrpc_rate_limit, trackback_block, pingback_block
 *
 * گزینه‌ها (Options):
 *  - rsp_xmlrpc_disable        (bool)   پیش‌فرض 1 (قفل کامل)
 *  - rsp_xmlrpc_rate_limit     (int)    پیش‌فرض 20 درخواست در پنجره
 *  - rsp_xmlrpc_window         (int)    پیش‌فرض 60 ثانیه
 *  - rsp_xmlrpc_whitelist      (string) هر خط یک IP یا CIDR (IPv4/IPv6)
 *  - rsp_xmlrpc_restrict       (bool)   اگر 1 باشد فقط متدهای مشخص مجازند
 *  - rsp_xmlrpc_allowed_methods(string) لیست متدهای مجاز (هر خط یک متد، مثال: wp.getUsersBlogs)
 */
class RSP_Module_XMLRPC implements RSP_Module_Interface {

    public function init() {
        // در اول چرخه درخواست تصمیم‌گیری کن
        add_action('init', [$this, 'maybe_block_early'], 0);

        // هسته: فعال/غیرفعال بودن XML-RPC
        add_filter('xmlrpc_enabled', [$this, 'filter_enabled']);
        add_filter('xmlrpc_methods', [$this, 'filter_methods']);

        // بلاک Trackback ها در وردپرس
        add_action('template_redirect', [$this, 'block_trackback_endpoints'], 0);
        add_filter('pre_ping',          [$this, 'block_outgoing_pingbacks']);
    }

    /* ===================== Early blocker ===================== */
    public function maybe_block_early() {
        $path = isset($_SERVER['REQUEST_URI']) ? (string) parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH) : '';
        if ($path === '') return;

        // 1) بلاک xmlrpc.php (با لیست سفید + rate limit)
        if ($this->is_xmlrpc_path($path)) {
            if (!$this->is_xmlrpc_allowed()) {
                if ($this->rate_limit_exceeded()) {
                    do_action('rsp_activity_log','xmlrpc_rate_limit', [ 'ip' => $this->ip() ]);
                    return $this->deny(429, __('تعداد درخواست‌های XML‑RPC زیاد است. بعداً تلاش کنید.', 'ready-secure-pro'));
                }
                do_action('rsp_activity_log','xmlrpc_block', [ 'ip' => $this->ip(), 'path' => $path ]);
                return $this->deny(403, __('دسترسی به XML‑RPC غیرفعال است.', 'ready-secure-pro'));
            }
        }

        // 2) بلاک wp-trackback.php یا /trackback/
        if ($this->is_trackback_path($path)) {
            do_action('rsp_activity_log','trackback_block', [ 'ip' => $this->ip(), 'path' => $path ]);
            return $this->deny(403, __('Trackback/Pingback غیرفعال است.', 'ready-secure-pro'));
        }
    }

    /* ===================== Core toggles ===================== */
    public function filter_enabled($enabled) {
        // اگر مسیر فعلی xmlrpc است و اجازه نداریم، false برگردان
        if ($this->is_xmlrpc_request()) {
            if (!$this->is_xmlrpc_allowed()) return false;
        }
        // در سایر درخواست‌ها از گزینهٔ کلی تبعیت کن
        if (get_option('rsp_xmlrpc_disable', 1)) return false;
        return $enabled;
    }

    public function filter_methods($methods) {
        // حذف کامل متدهای pingback
        unset($methods['pingback.ping']);
        unset($methods['pingback.extensions.getPingbacks']);

        // اگر restrict فعال است، تنها لیست سفید اجازه دارد
        if (get_option('rsp_xmlrpc_restrict', 0)) {
            $allowed = $this->allowed_methods_list();
            if (!empty($allowed)) {
                $filtered = [];
                foreach ($methods as $name => $cb) {
                    if (in_array($name, $allowed, true)) $filtered[$name] = $cb;
                }
                return $filtered;
            }
        }
        return $methods;
    }

    /* ===================== Trackbacks/Pingbacks ===================== */
    public function block_trackback_endpoints() {
        $path = isset($_SERVER['REQUEST_URI']) ? (string) parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH) : '';
        if ($this->is_trackback_path($path)) {
            do_action('rsp_activity_log','trackback_block', [ 'ip' => $this->ip(), 'path' => $path ]);
            return $this->deny(403, __('Trackback/Pingback غیرفعال است.', 'ready-secure-pro'));
        }
    }

    /** جلوگیری از ارسال pingback های خروجی */
    public function block_outgoing_pingbacks(&$links) {
        if (!is_array($links)) return;
        // همه لینک‌ها را حذف کن تا pingback ارسال نشود
        $count = count($links);
        if ($count > 0) {
            $links = [];
            do_action('rsp_activity_log','pingback_block', [ 'count' => $count ]);
        }
    }

    /* ===================== Helpers ===================== */
    private function is_xmlrpc_path($path) {
        return (stripos($path, '/xmlrpc.php') !== false);
    }

    private function is_trackback_path($path) {
        if ($path === '') return false;
        if (stripos($path, '/wp-trackback.php') !== false) return true;
        if (substr($path, -11) === '/trackback/' || stripos($path, '/trackback/') !== false) return true;
        return false;
    }

    private function is_xmlrpc_request() {
        if (defined('XMLRPC_REQUEST') && XMLRPC_REQUEST) return true;
        $path = isset($_SERVER['REQUEST_URI']) ? (string) parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH) : '';
        return $this->is_xmlrpc_path($path);
    }

    private function is_xmlrpc_allowed() {
        // اگر به‌طور کلی غیرفعال است، فقط با لیست سفید اجازه ده
        $disabled = get_option('rsp_xmlrpc_disable', 1);
        if (!$disabled) return true; // قفل نیست

        $ip = $this->ip();
        // لیست سفید IP/CIDR
        $raw = (string) get_option('rsp_xmlrpc_whitelist', '');
        $lines = array_filter(array_map('trim', preg_split('/\r?\n/', $raw)));
        foreach ($lines as $rule) {
            if ($this->ip_match($ip, $rule)) return true;
        }

        // اجازه بر اساس User-Agent (قابل‌گسترش با فیلتر)
        $ua = isset($_SERVER['HTTP_USER_AGENT']) ? (string) $_SERVER['HTTP_USER_AGENT'] : '';
        $ua_allow = apply_filters('rsp_xmlrpc_allow_ua', []);
        foreach ((array)$ua_allow as $sig) { if ($sig && stripos($ua, $sig) !== false) return true; }

        return false;
    }

    private function allowed_methods_list() {
        $raw = (string) get_option('rsp_xmlrpc_allowed_methods', "wp.getUsersBlogs\nsystem.listMethods\nsystem.getCapabilities");
        $list = array_filter(array_map('trim', preg_split('/\r?\n/', $raw)));
        return array_values(array_unique($list));
    }

    private function rate_limit_exceeded() {
        $limit = max(10, (int) get_option('rsp_xmlrpc_rate_limit', 20));
        $win   = max(10, (int) get_option('rsp_xmlrpc_window', 60));
        $bucket= (int) floor(time() / $win);
        $ip    = $this->ip();
        $key   = 'rsp_xmlrpc_rl_' . md5($ip.'|'.$bucket);
        $count = (int) get_transient($key);
        $count++;
        set_transient($key, $count, $win);
        return ($count > $limit);
    }

    private function ip() {
        return function_exists('rsp_client_ip') ? rsp_client_ip() : (isset($_SERVER['REMOTE_ADDR'])? $_SERVER['REMOTE_ADDR'] : '');
    }

    private function ip_match($ip, $rule) {
        if (!is_string($ip) || !is_string($rule) || $ip === '' || $rule === '') return false;
        if (strcasecmp($ip, $rule) === 0) return true; // exact
        if (strpos($rule, '/') === false) return false; // CIDR only (wildcard پشتیبانی نمی‌شود اینجا)
        if (!function_exists('inet_pton')) return false;
        list($subnet, $mask) = explode('/', $rule, 2);
        $mask = (int) $mask;
        $ip_bin = @inet_pton($ip); $net_bin = @inet_pton($subnet);
        if ($ip_bin === false || $net_bin === false) return false;
        $len = strlen($ip_bin);
        $bytes = intdiv($mask, 8); $bits = $mask % 8;
        if ($bytes > $len) $bytes = $len;
        if (strncmp($ip_bin, $net_bin, $bytes) !== 0) return false;
        if ($bits === 0) return true;
        $mask_byte = (0xFF00 >> $bits) & 0xFF;
        return ((ord($ip_bin[$bytes]) & $mask_byte) === (ord($net_bin[$bytes]) & $mask_byte));
    }

    private function deny($status, $msg) {
        if (!headers_sent()) { status_header((int)$status); nocache_headers(); }
        wp_die( esc_html($msg), (int)$status );
    }
}
