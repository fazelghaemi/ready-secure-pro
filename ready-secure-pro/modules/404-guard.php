<?php
if (!defined('ABSPATH')) { exit; }

/**
 * ماژول: مسدودسازی هوشمند خطای 404 (Smart 404 Guard)
 * - شمارش 404های تکراری بر اساس IP و پنجره زمانی
 * - وزن‌دهی بیشتر به مسیرهای مشکوک (.env, phpmyadmin, wp-config.php, .git, backup.zip, …)
 * - قفل موقت IP پس از عبور از آستانه و بازگردانی 403
 * - لیست سفید IP/CIDR و فهرست مسیرهای چشم‌پوشی
 * - ثبت رویدادها: 404_hit (نمونه‌ای)، 404_lockout
 *
 * گزینه‌ها (Options)
 *  - rsp_404_enable        (bool)   پیش‌فرض: 1
 *  - rsp_404_threshold     (int)    آستانه امتیاز 404 در پنجره—پیش‌فرض: 12
 *  - rsp_404_window        (int)    طول پنجره بر حسب ثانیه—پیش‌فرض: 120
 *  - rsp_404_lock_minutes  (int)    مدت قفل موقت—پیش‌فرض: 30 دقیقه
 *  - rsp_404_whitelist     (string) لیست IP/CIDR/Wildcard؛ هر خط یک مورد (مثال: 1.2.3.* یا 10.0.0.0/8)
 *  - rsp_404_ignore_paths  (string) فهرست مسیرهایی که نباید شمرده شوند؛ هر خط یک پیشوند مسیر (مثال: /ads.txt)
 */
class RSP_Module_404_Guard implements RSP_Module_Interface {

    public function init() {
        add_action('init',               [$this, 'maybe_block_early'], 0);
        add_action('template_redirect',  [$this, 'on_template_redirect'], 9999);
    }

    /* ====================== Early deny if locked ====================== */
    public function maybe_block_early() {
        if (!$this->enabled()) return;
        $ip = $this->ip();
        if ($this->is_whitelisted($ip)) return;
        if ($this->is_locked($ip)) {
            return $this->deny(403, __('دسترسی شما به دلیل درخواست‌های نامعتبر موقتاً محدود شده است.', 'ready-secure-pro'));
        }
    }

    /* ====================== Count on 404 ====================== */
    public function on_template_redirect() {
        if (!$this->enabled()) return;
        if (!is_404()) return;

        $ip = $this->ip();
        if ($this->is_whitelisted($ip)) return; // چشم‌پوشی برای لیست سفید

        $path = isset($_SERVER['REQUEST_URI']) ? (string) parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH) : '';
        if ($this->is_ignored_path($path)) return;

        $score = 1 + $this->suspicious_weight($path);
        $count = $this->bump_bucket($ip, $score);

        // هر 5 رخداد یک‌بار لاگ نمونه‌ای بزنیم تا لاگ حجیم نشود
        if (($count % 5) === 0) {
            do_action('rsp_activity_log', '404_hit', [ 'ip' => $ip, 'path' => $path, 'score' => $score, 'count' => (int)$count ]);
        }

        $threshold = max(3, (int) get_option('rsp_404_threshold', 12));
        if ($count > $threshold) {
            $minutes = max(5, (int) get_option('rsp_404_lock_minutes', 30));
            $this->lock_ip($ip, $minutes);
            do_action('rsp_activity_log', '404_lockout', [ 'ip' => $ip, 'minutes' => $minutes, 'last_path' => $path, 'count' => (int)$count ]);
            return $this->deny(403, __('به دلیل درخواست‌های 404 مکرر، دسترسی شما موقتاً محدود شد.', 'ready-secure-pro'));
        }
    }

    /* ====================== Core helpers ====================== */
    private function enabled(){ return (bool) get_option('rsp_404_enable', 1); }

    private function ip() {
        return function_exists('rsp_client_ip') ? rsp_client_ip() : (isset($_SERVER['REMOTE_ADDR'])? $_SERVER['REMOTE_ADDR'] : '');
    }

    private function is_locked($ip){ return (bool) get_transient($this->lock_key($ip)); }
    private function lock_ip($ip, $minutes){ set_transient($this->lock_key($ip), 1, $minutes * MINUTE_IN_SECONDS); }
    private function lock_key($ip){ return 'rsp_404_lock_' . md5($ip); }

    /** شمارندهٔ پنجره‌ای بر اساس IP */
    private function bump_bucket($ip, $delta){
        $win = max(10, (int) get_option('rsp_404_window', 120));
        $bucket = (int) floor(time() / $win);
        $key = 'rsp_404_bkt_' . md5($ip.'|'.$bucket);
        $count = (int) get_transient($key);
        $count += (int) $delta;
        set_transient($key, $count, $win);
        return $count;
    }

    /** وزن‌دهی به مسیرهای مشکوک */
    private function suspicious_weight($path){
        $w = 0; $p = strtolower((string)$path);
        $patterns = apply_filters('rsp_404_sensitive_patterns', [
            '.env', 'phpmyadmin', 'pma', 'wp-config.php', '.git', '.svn', '.hg', 'vendor/', 'composer.json', 'id_rsa', 'ssh',
            'backup', 'bak', '.zip', '.tar', '.gz', '.7z', 'webshell', 'wso', 'r57', 'c99', 'eval(', 'base64,', 'wp-admin.php',
        ]);
        foreach ((array)$patterns as $sig){ if ($sig && strpos($p, strtolower($sig)) !== false) $w++; }
        // مسیرهای بکاپ/اکسپورت رایج
        if (preg_match('/\.(sql|dump|old|swp|save)$/i', $p)) $w++;
        return min($w, 5); // سقف وزن برای جلوگیری از جهش زیاد
    }

    /** لیست سفید IP: exact, wildcard*, CIDR (IPv4/IPv6) */
    private function is_whitelisted($ip){
        // از لیست سفید BruteForce نیز ارث‌بری کنیم
        $raw_bf = (string) get_option('rsp_bruteforce_whitelist', '');
        $raw_own= (string) get_option('rsp_404_whitelist', '');
        $lines = array_merge(
            array_filter(array_map('trim', preg_split('/\r?\n/', $raw_bf))),
            array_filter(array_map('trim', preg_split('/\r?\n/', $raw_own)))
        );
        $list = apply_filters('rsp_404_whitelist_ips', $lines);
        foreach ((array)$list as $rule){ if ($this->ip_match($ip, $rule)) return true; }
        return false;
    }

    private function ip_match($ip, $rule){
        if (!is_string($ip) || !is_string($rule) || $ip === '' || $rule === '') return false;
        // exact
        if (strcasecmp($ip, $rule) === 0) return true;
        // wildcard tail 1.2.3.* یا 2001:db8:*
        if (substr($rule, -1) === '*') { $prefix = substr($rule, 0, -1); return stripos($ip, $prefix) === 0; }
        // CIDR (IPv4/IPv6)
        if (function_exists('rsp_ip_in_cidr')) return rsp_ip_in_cidr($ip, $rule);
        // fallback ساده
        return false;
    }

    /** آیا مسیر باید از شمارش مستثنا شود؟ */
    private function is_ignored_path($path){
        $path = (string)$path;
        $raw = (string) get_option('rsp_404_ignore_paths', "/favicon.ico\n/robots.txt\n/.well-known\n/sitemap.xml\n/sitemap_index.xml");
        $list = apply_filters('rsp_404_ignore_paths', array_filter(array_map('trim', preg_split('/\r?\n/', $raw))));
        foreach ((array)$list as $prefix){ if ($prefix !== '' && stripos($path, $prefix) === 0) return true; }
        return false;
    }

    /** پاسخ امن */
    private function deny($status, $msg){
        if (!headers_sent()) { status_header((int)$status); nocache_headers(); }
        wp_die( esc_html($msg), (int)$status );
    }
}
