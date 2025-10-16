<?php
if (!defined('ABSPATH')) { exit; }

/**
 * ماژول: محافظت در برابر حملات Brute‑Force
 * - شمارش تلاش‌های ناموفق ورود بر اساس IP (و کاربر)
 * - قفل موقت پس از عبور از آستانه
 * - لیست سفید IP (پشتیبانی از IPv4، IPv6، wildcard پسوندی و CIDR ساده برای IPv4)
 * - ثبت رویدادها: login_failed, lockout, login_success
 *
 * گزینه‌ها (Options)
 *  - rsp_bruteforce_max           (int)    سقف تلاش ناموفق
 *  - rsp_bruteforce_lock_minutes  (int)    مدت قفل موقت (دقیقه)
 *  - rsp_bruteforce_whitelist     (string) لیست IP (هر خط یک مقدار؛ پشتیبانی از 1.2.3.* و 10.0.0.0/8)
 */
class RSP_Module_BruteForce implements RSP_Module_Interface {

    private $prefix = 'rsp_bf_';

    public function init() {
        add_filter('wp_authenticate_user', [$this, 'check_lock'], 99, 2);
        add_action('wp_login_failed',       [$this, 'on_failed']);
        add_action('wp_login',              [$this, 'on_success'], 10, 2);
    }

    /** بررسی قفل پیش از ورود */
    public function check_lock($user, $password) {
        // اگر قبلاً خطا هست، همان را برگردان
        if (is_wp_error($user)) return $user;

        $ip = $this->client_ip();
        if ($this->is_whitelisted($ip)) return $user;

        $state = $this->get_state($ip);
        if ($state['locked']) {
            $min = max(1, (int) get_option('rsp_bruteforce_lock_minutes', 15));
            return new WP_Error('rsp_locked', sprintf(__('به دلیل تلاش‌های ناموفق متعدد، دسترسی شما برای %d دقیقه محدود شد.', 'ready-secure-pro'), $min));
        }
        return $user;
    }

    /** افزایش شمارنده در صورت شکست ورود */
    public function on_failed($username) {
        $ip = $this->client_ip();
        if ($this->is_whitelisted($ip)) return;

        $max     = max(1, (int) get_option('rsp_bruteforce_max', 5));
        $minutes = max(1, (int) get_option('rsp_bruteforce_lock_minutes', 15));

        $state = $this->get_state($ip);
        $state['count']++;

        if ($state['count'] >= $max) {
            $state['locked'] = true;
            $this->set_state($ip, $state, $minutes * MINUTE_IN_SECONDS);
            do_action('rsp_activity_log', 'lockout', [
                'ip'       => $ip,
                'username' => sanitize_user($username),
                'minutes'  => $minutes,
                'count'    => (int) $state['count'],
            ]);
        } else {
            $this->set_state($ip, $state, 2 * HOUR_IN_SECONDS); // شمارنده با انقضا 2 ساعت
        }

        do_action('rsp_activity_log', 'login_failed', [
            'ip'       => $ip,
            'username' => sanitize_user($username),
            'count'    => (int) $state['count'],
        ]);

        // یک تأخیر کوچک تصادفی برای کند کردن حملات رباتی (در حدود 120-300ms)
        $us = rand(120, 300) * 1000; // میکروثانیه
        usleep($us);
    }

    /** پاک‌سازی شمارنده پس از ورود موفق */
    public function on_success($login, $user) {
        $ip = $this->client_ip();
        $this->clear_state($ip);
        do_action('rsp_activity_log', 'login_success', [
            'ip'       => $ip,
            'username' => sanitize_user($login),
            'uid'      => (int) $user->ID,
        ]);
    }

    /* =================== ابزار داخلی =================== */

    private function client_ip() {
        return function_exists('rsp_client_ip') ? rsp_client_ip() : (isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '0.0.0.0');
    }

    private function key($ip) { return $this->prefix . md5($ip); }

    private function get_state($ip) {
        $d = get_transient($this->key($ip));
        if (!is_array($d)) $d = ['count' => 0, 'locked' => false];
        return $d;
    }

    private function set_state($ip, $state, $ttl) { set_transient($this->key($ip), $state, (int) $ttl); }

    private function clear_state($ip) { delete_transient($this->key($ip)); }

    /** بررسی عضویت IP در لیست سفید (Exact, Wildcard*, CIDR IPv4) */
    private function is_whitelisted($ip) {
        $raw = (string) get_option('rsp_bruteforce_whitelist', '');
        if ($raw === '') return false;
        $lines = preg_split('/\r?\n/', $raw);
        foreach ($lines as $line) {
            $pat = trim($line);
            if ($pat === '') continue;
            if ($this->ip_match($ip, $pat)) return true;
        }
        return false;
    }

    private function ip_match($ip, $pat) {
        // exact
        if (strcasecmp($ip, $pat) === 0) return true;
        // wildcard tail: 1.2.3.*  یا 2001:db8::* (پوشش ساده—شروع با پیشوند)
        if (substr($pat, -1) === '*') {
            $prefix = substr($pat, 0, -1);
            return stripos($ip, $prefix) === 0;
        }
        // CIDR فقط IPv4 (ساده)
        if (strpos($pat, '/') !== false && filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            list($net, $mask) = explode('/', $pat, 2);
            $mask = (int) $mask;
            if ($mask < 0 || $mask > 32) return false;
            if (!filter_var($net, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) return false;
            $ip_long  = ip2long($ip);
            $net_long = ip2long($net);
            $mask_long= -1 << (32 - $mask);
            $net_net  = $net_long & $mask_long;
            $ip_net   = $ip_long & $mask_long;
            return ($ip_net === $net_net);
        }
        return false;
    }
}
