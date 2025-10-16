<?php
if (!defined('ABSPATH')) { exit; }

/**
 * ماژول: فایروال سبک (WAF) + محدودسازی نرخ درخواست
 * - بازرسی ورودی‌ها برای الگوهای رایج SQLi/XSS/LFI/RCE
 * - Rate Limit برای مسیرهای حساس (wp-login.php, xmlrpc.php, admin-ajax.php, REST)
 * - لیست سفید IP و مسیرها با فیلترها
 * - ثبت رویدادها در لاگ مرکزی (waf_block, rate_limit)
 *
 * گزینه‌ها (Options)
 *  - rsp_waf_enabled      (bool)
 *  - rsp_waf_rate_limit   (int)  تعداد درخواست مجاز در پنجره برای کلاینت ناشناس
 *  - rsp_waf_window       (int)  طول پنجره بر حسب ثانیه
 */
class RSP_Module_WAF implements RSP_Module_Interface {

    public function init() {
        // بازرسی خیلی زود انجام شود
        add_action('init', [$this, 'inspect'], 0);
    }

    /** اجرای WAF */
    public function inspect() {
        if (!get_option('rsp_waf_enabled', 1)) return;

        // نادیده گرفتن درخواست‌های ادمین لاگین‌کرده برای جلوگیری از تداخل مدیریتی
        if (is_user_logged_in() && current_user_can('manage_options')) return;

        $ip  = $this->client_ip();
        $uri = isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '';
        $ua  = isset($_SERVER['HTTP_USER_AGENT']) ? substr($_SERVER['HTTP_USER_AGENT'], 0, 190) : '';

        // لیست سفید IP از گزینه BruteForce (در صورت استفاده) + فیلتر سفارشی
        if ($this->is_ip_whitelisted($ip)) return;

        // مسیرهای مجاز از طریق فیلتر (مثلاً وبهوک‌ها)
        $allow_paths = apply_filters('rsp_waf_allow_paths', [ '/wp-cron.php' ]);
        foreach ((array)$allow_paths as $p) { if (strpos($uri, $p) !== false) return; }

        // محدودسازی نرخ برای ناشناس‌ها روی مسیرهای حساس
        if (!$this->is_logged_in_request()) {
            if ($this->is_rate_limited_target($uri)) {
                if ($this->rate_limit_exceeded($ip)) {
                    do_action('rsp_activity_log','rate_limit',[ 'ip'=>$ip, 'uri'=>esc_url_raw($uri), 'ua'=>$ua ]);
                    return $this->deny(429, __('درخواست‌های بسیار زیاد. بعداً تلاش کنید.', 'ready-secure-pro'));
                }
            }
        }

        // اسکن محتوای درخواست برای الگوهای مخرب
        $haystack = $this->make_haystack();
        if ($this->matches_attack($haystack)) {
            do_action('rsp_activity_log','waf_block',[ 'ip'=>$ip, 'uri'=>esc_url_raw($uri), 'ua'=>$ua ]);
            return $this->deny(403, __('دسترسی به دلیل محتوای درخواست مشکوک محدود شد.', 'ready-secure-pro'));
        }
    }

    /**
     * ساخت رشتهٔ بازرسی از URL, Query, Body (با محدودیت اندازه)
     */
    private function make_haystack() {
        $max = 100000; // 100KB کافی است
        $url  = isset($_SERVER['REQUEST_URI']) ? (string)$_SERVER['REQUEST_URI'] : '';
        $q    = isset($_SERVER['QUERY_STRING']) ? (string)$_SERVER['QUERY_STRING'] : '';
        $body = '';
        // فقط برای متدهای دارای بادی
        $method = isset($_SERVER['REQUEST_METHOD']) ? strtoupper($_SERVER['REQUEST_METHOD']) : 'GET';
        if (in_array($method, ['POST','PUT','PATCH'], true)) {
            $raw = @file_get_contents('php://input');
            if (is_string($raw)) $body = substr($raw, 0, $max);
        }
        // نرمال‌سازی: lower + urldecode محافظه‌کارانه
        $mix = strtolower($url.' '.$q.' '.$body);
        $mix = preg_replace('/%([0-9a-f]{2})/i', function($m){
            $c = chr(hexdec($m[1]));
            return ctype_print($c) ? $c : $m[0];
        }, $mix);
        return $mix;
    }

    /** آیا مقصد نیازمند RateLimit است؟ */
    private function is_rate_limited_target($uri) {
        $targets = apply_filters('rsp_waf_rate_targets', [
            'wp-login.php',
            'xmlrpc.php',
            'admin-ajax.php',
            '/wp-json/',
        ]);
        foreach ((array)$targets as $t) {
            if (strpos($uri, $t) !== false) return true;
        }
        return false;
    }

    /** Rate Limit بر اساس IP و پنجرهٔ زمانی */
    private function rate_limit_exceeded($ip) {
        $limit = max(30, (int) get_option('rsp_waf_rate_limit', 120));
        $win   = max(10, (int) get_option('rsp_waf_window', 60));
        $bucket= (int) floor(time() / $win);
        $key   = 'rsp_waf_rl_' . md5($ip.'|'.$bucket);
        $count = (int) get_transient($key);
        $count++;
        set_transient($key, $count, $win);
        return ($count > $limit);
    }

    /** تشخیص حملات رایج */
    private function matches_attack($mix) {
        // الگوها: SQLi / XSS / LFI / RCE / Path traversal / header injection
        $patterns = [
            // SQLi
            'union select', '/*!union*/select', ' or 1=1', "' or '1'='1", ' information_schema ', 'load_file(', 'into outfile', 'sleep(', 'benchmark(',
            // XSS
            '<script', '%3cscript', ' onerror=', ' onload=', 'javascript:', 'data:text/html',
            // LFI / traversal
            '../', '..%2f', '%2e%2e/', 'etc/passwd', 'proc/self/environ',
            // RCE vectors
            'php://input', 'php://filter', 'expect://', 'system(', 'exec(', 'shell_exec(', 'passthru(', 'popen(', 'proc_open(',
            // header split
            "\r\n", '%0d%0a',
        ];
        foreach ($patterns as $p) {
            if ($p === "\r\n") { if (strpos($mix, "\r\n") !== false) return true; continue; }
            if (strpos($mix, $p) !== false) return true;
        }
        // regex برای الگوهای فشرده/ encoded
        $regexes = [
            '/(<\\/?)[a-z0-9\\-]+\\s+on[a-z]+=/i',                // any on*=
            '/%3c[a-z0-9]+%20on[a-z]+%3d/i',                           // url-encoded on*
            '/%00|\\x00|\\u0000/i',                                  // null byte
            '/(?:\n|\r)content-\w+:/i',                             // header injection
        ];
        foreach ($regexes as $re) { if (preg_match($re, $mix)) return true; }
        return false;
    }

    /** پاسخ امن */
    private function deny($status = 403, $msg = '') {
        if (!headers_sent()) { status_header($status); nocache_headers(); }
        if ($msg === '') $msg = ($status === 429) ? __('تعداد درخواست زیاد است.', 'ready-secure-pro') : __('دسترسی غیرمجاز.', 'ready-secure-pro');
        wp_die( esc_html($msg), $status );
    }

    /** ابزارها */
    private function client_ip() { return function_exists('rsp_client_ip') ? rsp_client_ip() : (isset($_SERVER['REMOTE_ADDR'])? $_SERVER['REMOTE_ADDR'] : ''); }
    private function is_logged_in_request() { return is_user_logged_in(); }

    private function is_ip_whitelisted($ip) {
        // از گزینهٔ whitelist ماژول BruteForce نیز استفاده می‌کنیم
        $opt = (string) get_option('rsp_bruteforce_whitelist', '');
        $list = array_filter(array_map('trim', preg_split('/\r?\n/', $opt)));
        $allow_ips = apply_filters('rsp_waf_ip_whitelist', $list);
        return in_array($ip, (array)$allow_ips, true);
    }
}
