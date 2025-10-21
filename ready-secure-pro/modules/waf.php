<?php
if (!defined('ABSPATH')) { exit; }

/**
 * Ready Secure Pro - WAF
 * v2.4.1
 * - تنظیمات روی صفحه‌ی صحیح rsp_settings_waf
 * - پنل همیشه نمایش داده می‌شود؛ اجرای فایروال فقط وقتی فعال است
 * - پشتیبانی Whitelist (IP/CIDR یا User-Agent)
 * - Rate-limit جدا برای login/xmlrpc/rest
 * - کاهش False-Positive با بررسی نوع محتوا و سقف اندازه بدنۀ درخواست
 */
class RSP_Module_WAF implements RSP_Module_Interface
{
    public function init() {
        // پنل تنظیمات همیشه حاضر باشد
        add_action('admin_init', [$this, 'settings']);

        // اجرای WAF فقط هنگام فعال‌بودن
        if (get_option('rsp_waf_enable', 1)) {
            add_action('init', [$this, 'inspect'], 0);
        }
    }

    /* ---------------- Settings UI ---------------- */

    public function settings() {
        // گروه تنظیمات اختصاصی این تب (سازگار با class-admin.php)
        register_setting('rsp_settings_waf', 'rsp_waf_enable', [
            'type' => 'boolean', 'default' => 1,
            'sanitize_callback' => function($v){ return in_array($v, [1,'1','on','true',true], true) ? 1 : 0; }
        ]);
        register_setting('rsp_settings_waf', 'rsp_waf_rate_window', [
            'type' => 'integer', 'default' => 60, 'sanitize_callback' => 'absint'
        ]);
        register_setting('rsp_settings_waf', 'rsp_waf_rate_limit', [
            'type' => 'integer', 'default' => 40, 'sanitize_callback' => 'absint'
        ]);
        register_setting('rsp_settings_waf', 'rsp_waf_whitelist', [
            'type' => 'string', 'default' => '', 'sanitize_callback' => 'wp_kses_post'
        ]);

        // سکشن روی صفحه صحیح
        add_settings_section(
            'rsp_waf_section',
            __('فایروال برنامه (WAF)', 'ready-secure-pro'),
            function () {
                echo '<p>' . esc_html__('تشخیص الگوهای رایج XSS/SQLi/LFI و محدودسازی نرخ درخواست مسیرهای حساس. برای کاهش خطای مثبت کاذب می‌توانید IP/CIDR یا بخشی از User-Agent را whitelist کنید (هر خط یک مورد).', 'ready-secure-pro') . '</p>';
            },
            'rsp_settings_waf'
        );

        // فیلد: فعال‌سازی
        add_settings_field(
            'rsp_waf_enable',
            __('فعال باشد؟', 'ready-secure-pro'),
            function () {
                $v = get_option('rsp_waf_enable', 1);
                echo '<label><input type="checkbox" name="rsp_waf_enable" value="1" ' . checked($v, 1, false) . '> ' .
                     esc_html__('فعال‌سازی WAF', 'ready-secure-pro') . '</label>';
            },
            'rsp_settings_waf',
            'rsp_waf_section'
        );

        // فیلد: پنجره زمانی ریت‌لیمیت
        add_settings_field(
            'rsp_waf_rate_window',
            __('پنجره زمانی (ثانیه)', 'ready-secure-pro'),
            function () {
                $v = (int) get_option('rsp_waf_rate_window', 60);
                echo '<input type="number" min="10" step="10" name="rsp_waf_rate_window" value="' . esc_attr($v) . '">';
                echo '<p class="description">' . esc_html__('مثلاً 60 ثانیه', 'ready-secure-pro') . '</p>';
            },
            'rsp_settings_waf',
            'rsp_waf_section'
        );

        // فیلد: سقف درخواست در هر پنجره
        add_settings_field(
            'rsp_waf_rate_limit',
            __('حداکثر درخواست در پنجره', 'ready-secure-pro'),
            function () {
                $v = (int) get_option('rsp_waf_rate_limit', 40);
                echo '<input type="number" min="5" step="5" name="rsp_waf_rate_limit" value="' . esc_attr($v) . '">';
                echo '<p class="description">' . esc_html__('اگر از CDN/پراکسی استفاده می‌کنید، مقادیر منطقی‌تری انتخاب کنید.', 'ready-secure-pro') . '</p>';
            },
            'rsp_settings_waf',
            'rsp_waf_section'
        );

        // فیلد: whitelist
        add_settings_field(
            'rsp_waf_whitelist',
            __('Whitelist IP/User-Agent', 'ready-secure-pro'),
            function () {
                $v = (string) get_option('rsp_waf_whitelist', '');
                echo '<textarea name="rsp_waf_whitelist" rows="4" style="width:100%;max-width:640px;">' . esc_textarea($v) . '</textarea>';
                echo '<p class="description">' .
                     esc_html__('هر خط یک مورد: 1) IP مثل 192.0.2.10  2) CIDR مثل 203.0.113.0/24  3) عبارت User-Agent مثل "Googlebot".', 'ready-secure-pro') .
                     '</p>';
            },
            'rsp_settings_waf',
            'rsp_waf_section'
        );
    }

    /* ---------------- Core WAF logic ---------------- */

    private function ip() {
        if (function_exists('rsp_client_ip')) return rsp_client_ip();
        return isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '';
    }

    /** بررسی در لیست سفید: IP یا CIDR یا UA substring */
    private function is_whitelisted() {
        $list = (string) get_option('rsp_waf_whitelist', '');
        if ($list === '') return false;

        $ip = $this->ip();
        $ua = isset($_SERVER['HTTP_USER_AGENT']) ? (string) $_SERVER['HTTP_USER_AGENT'] : '';

        foreach (preg_split('/\r?\n/', $list) as $ln) {
            $ln = trim($ln);
            if ($ln === '') continue;

            // اول: CIDR یا IP
            if (filter_var($ln, FILTER_VALIDATE_IP)) {
                if (strcasecmp($ln, $ip) === 0) return true;
                continue;
            }
            if (strpos($ln, '/') !== false && function_exists('rsp_ip_in_cidr')) {
                if (rsp_ip_in_cidr($ip, $ln)) return true;
                continue;
            }

            // بعد: User-Agent substring (حساس‌نبودن به حروف)
            if ($ua && stripos($ua, $ln) !== false) return true;
        }
        return false;
    }

    private function deny($why = 'waf') {
        status_header(403);
        header('X-RSP-Block: waf');
        do_action('rsp_activity_log', 'waf_block', [
            'ip'  => $this->ip(),
            'why' => $why,
            'uri' => isset($_SERVER['REQUEST_URI']) ? substr((string)$_SERVER['REQUEST_URI'], 0, 300) : '',
        ]);
        exit;
    }

    private function rate_key($ip, $bucket, $route) {
        return 'rsp_waf_rate_' . md5($ip . '|' . $bucket . '|' . $route);
    }

    /** تشخیص مسیر حساس: login/xmlrpc/rest */
    private function route_kind() {
        $uri  = isset($_SERVER['REQUEST_URI']) ? (string) $_SERVER['REQUEST_URI'] : '';
        $path = $uri ? (string) parse_url($uri, PHP_URL_PATH) : '';
        $qs   = isset($_SERVER['QUERY_STRING']) ? (string) $_SERVER['QUERY_STRING'] : '';

        // custom login slug
        $slug = trim((string) get_option('rsp_login_slug', 'manager'));
        $login_custom = '/' . ltrim($slug, '/') . '/';

        if ($path && (stripos($path, 'wp-login.php') !== false || $path === $login_custom || rtrim($path, '/') === rtrim($login_custom, '/'))) {
            return 'login';
        }
        if ($path && stripos($path, 'xmlrpc.php') !== false) {
            return 'xmlrpc';
        }
        if ($qs && stripos($qs, 'rest_route=') !== false) {
            return 'rest';
        }
        return '';
    }

    /** بررسی الگوهای خطرناک با محدودیت اندازه و نوع محتوا */
    private function match_suspicious($haystack) {
        // الگوها محتاطانه انتخاب شده‌اند
        $patterns = [
            '/<\s*script\b/i',
            '/onerror\s*=/i',
            '/onload\s*=/i',
            '/union\s+select/i',
            '/sleep\s*\(/i',
            '/load_file\s*\(/i',
            '/benchmark\s*\(/i',
            '/\.\.\/\.\.\//i',       // traversal
        ];
        foreach ($patterns as $re) {
            if (@preg_match($re, $haystack)) {
                return $re;
            }
        }
        return false;
    }

    public function inspect() {
        if (is_user_logged_in() && current_user_can('manage_options')) return;
        if ($this->is_whitelisted()) return;

        $uri  = isset($_SERVER['REQUEST_URI'])  ? (string) $_SERVER['REQUEST_URI']  : '';
        $qs   = isset($_SERVER['QUERY_STRING']) ? (string) $_SERVER['QUERY_STRING'] : '';
        $body = '';

        // فقط با نوع محتوای قابل‌تحلیل و سقف حجم منطقی
        $ctype = isset($_SERVER['CONTENT_TYPE']) ? strtolower((string)$_SERVER['CONTENT_TYPE']) : '';
        $len   = isset($_SERVER['CONTENT_LENGTH']) ? (int) $_SERVER['CONTENT_LENGTH'] : 0;
        if ($len > 0 && $len <= 65536 && ($ctype === '' || strpos($ctype, 'application/x-www-form-urlencoded') !== false || strpos($ctype, 'application/json') !== false)) {
            $raw = @file_get_contents('php://input');
            if (is_string($raw)) $body = substr($raw, 0, 65536);
        }

        // 1) الگوهای خطرناک
        $hay = $uri . ' ' . $qs . ' ' . $body;
        $hit = $this->match_suspicious($hay);
        if ($hit !== false) {
            $this->deny('pattern');
        }

        // 2) Rate-limit روی مسیرهای حساس
        $route = $this->route_kind();
        if ($route !== '') {
            $ip  = $this->ip();
            $win = max(10, (int) get_option('rsp_waf_rate_window', 60));
            $lim = max(5,  (int) get_option('rsp_waf_rate_limit', 40));

            $bucket = 'b' . intdiv(time(), $win);
            $key    = $this->rate_key($ip, $bucket, $route);

            $n = (int) get_transient($key);
            $n++;
            set_transient($key, $n, $win);
            if ($n > $lim) {
                $this->deny('rate-limit:' . $route);
            }
        }
    }
}
