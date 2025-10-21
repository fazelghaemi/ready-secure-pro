<?php
if (!defined('ABSPATH')) { exit; }

/**
 * Ready Secure Pro — Brute Force Protector
 * v2.5.0
 * - UI کامل روی صفحه rsp_settings_bf
 * - قفل IP پس از n تلاش ناموفق در بازه‌ی زمانی (از lock_minutes برای پنجره و مدت قفل استفاده می‌کنیم)
 * - Whitelist: IP/CIDR
 * - پاک‌سازی شمارنده در ورود موفق
 */
if (!interface_exists('RSP_Module_Interface')) {
    interface RSP_Module_Interface { public function init(); }
}

class RSP_Module_Brute_Force implements RSP_Module_Interface
{
    public function init() {
        // UI تنظیمات همیشه حاضر
        add_action('admin_init', [$this, 'settings']);

        if ((int) get_option('rsp_bf_enable', 1) === 1) {
            // قبل از احراز هویت بررسی قفل
            add_filter('authenticate', [$this, 'block_if_locked'], 5, 3);
            // ثبت شکست
            add_action('wp_login_failed', [$this, 'on_login_failed'], 10, 1);
            // پاک‌سازی روی ورود موفق
            add_action('wp_login',       [$this, 'on_login_success'], 10, 2);
        }
    }

    /* ================== Settings UI ================== */

    public function settings() {
        // این گزینه‌ها قبلاً در class-admin.php ثبت شده‌اند؛ اینجا فقط سکشن/فیلدها را می‌سازیم
        add_settings_section(
            'rsp_bf_section',
            __('محافظت در برابر Brute Force', 'ready-secure-pro'),
            function () {
                echo '<p>' . esc_html__('محدودسازی تلاش‌های ورود ناموفق بر اساس IP؛ برای مدیران و IPهای لیست سفید اعمال نمی‌شود.', 'ready-secure-pro') . '</p>';
            },
            'rsp_settings_bf'
        );

        add_settings_field(
            'rsp_bf_enable',
            __('فعال باشد؟', 'ready-secure-pro'),
            function () {
                $v = (int) get_option('rsp_bf_enable', 1);
                echo '<label><input type="checkbox" name="rsp_bf_enable" value="1" '. checked($v, 1, false) .'> ' .
                     esc_html__('فعال‌سازی محافظ Brute Force', 'ready-secure-pro') . '</label>';
            },
            'rsp_settings_bf',
            'rsp_bf_section'
        );

        add_settings_field(
            'rsp_bf_max',
            __('حداکثر تلاش ناموفق (قبل از قفل)', 'ready-secure-pro'),
            function () {
                $v = (int) get_option('rsp_bf_max', 5);
                echo '<input type="number" min="1" step="1" name="rsp_bf_max" value="'. esc_attr($v) .'">';
                echo '<p class="description">'. esc_html__('مثال: 5 تلاش ناموفق → قفل IP', 'ready-secure-pro') .'</p>';
            },
            'rsp_settings_bf',
            'rsp_bf_section'
        );

        add_settings_field(
            'rsp_bf_lock_min',
            __('مدت قفل و پنجره شمارش (دقیقه)', 'ready-secure-pro'),
            function () {
                $v = (int) get_option('rsp_bf_lock_min', 15);
                echo '<input type="number" min="5" step="5" name="rsp_bf_lock_min" value="'. esc_attr($v) .'">';
                echo '<p class="description">'. esc_html__('در این مدت هم شمارش انجام می‌شود و هم قفل اعمال می‌گردد.', 'ready-secure-pro') .'</p>';
            },
            'rsp_settings_bf',
            'rsp_bf_section'
        );

        add_settings_field(
            'rsp_bf_whitelist',
            __('Whitelist IP/CIDR', 'ready-secure-pro'),
            function () {
                $v = (string) get_option('rsp_bf_whitelist', '');
                echo '<textarea name="rsp_bf_whitelist" rows="4" style="width:100%;max-width:640px;">'. esc_textarea($v) .'</textarea>';
                echo '<p class="description">'. esc_html__('هر خط یک مورد: 1) IP مثل 192.0.2.10  2) CIDR مثل 203.0.113.0/24', 'ready-secure-pro') .'</p>';
            },
            'rsp_settings_bf',
            'rsp_bf_section'
        );
    }

    /* ================== Core Logic ================== */

    private function ip() {
        if (function_exists('rsp_client_ip')) return rsp_client_ip();
        return isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '';
    }

    private function is_whitelisted($ip) {
        $list = (string) get_option('rsp_bf_whitelist', '');
        if ($list === '') return false;
        foreach (preg_split('/\r?\n/', $list) as $ln) {
            $ln = trim($ln);
            if ($ln === '') continue;
            if (filter_var($ln, FILTER_VALIDATE_IP)) {
                if (strcasecmp($ln, $ip) === 0) return true;
                continue;
            }
            if (strpos($ln, '/') !== false && function_exists('rsp_ip_in_cidr')) {
                if (rsp_ip_in_cidr($ip, $ln)) return true;
            }
        }
        return false;
    }

    private function key_fail($ip)  { return 'rsp_bf_fail_'  . md5($ip); }
    private function key_lock($ip)  { return 'rsp_bf_lock_'  . md5($ip); }

    /** اگر IP قفل است، جلوی احراز هویت را بگیر */
    public function block_if_locked($user, $username, $password) {
        if (is_user_logged_in() && current_user_can('manage_options')) return $user;

        $ip = $this->ip();
        if (!$ip || $this->is_whitelisted($ip)) return $user;

        $lock_key = $this->key_lock($ip);
        if (get_transient($lock_key)) {
            return new WP_Error(
                'rsp_bf_locked',
                sprintf(
                    /* translators: %s = minutes */
                    esc_html__('به‌دلیل تلاش‌های مکرر ناموفق، دسترسی موقتاً مسدود شد. چند دقیقهٔ دیگر تلاش کنید.', 'ready-secure-pro')
                )
            );
        }
        return $user;
    }

    /** در شکست ورود، شمارنده را افزایش بده و در صورت عبور از آستانه، قفل کن */
    public function on_login_failed($username) {
        $ip = $this->ip();
        if (!$ip || $this->is_whitelisted($ip)) return;

        $max   = max(1,  (int) get_option('rsp_bf_max', 5));
        $mins  = max(5,  (int) get_option('rsp_bf_lock_min', 15));
        $ttl   = $mins * MINUTE_IN_SECONDS;

        $fail_key = $this->key_fail($ip);
        $n = (int) get_transient($fail_key);
        $n++;
        set_transient($fail_key, $n, $ttl);

        if ($n >= $max) {
            set_transient($this->key_lock($ip), 1, $ttl);
            do_action('rsp_activity_log', 'bf_lock', [
                'ip' => $ip, 'username' => $username, 'count' => $n, 'minutes' => $mins
            ]);
        } else {
            do_action('rsp_activity_log', 'bf_fail', [
                'ip' => $ip, 'username' => $username, 'count' => $n
            ]);
        }
    }

    /** روی ورود موفق، شمارنده را پاک کن */
    public function on_login_success($user_login, $user) {
        $ip = $this->ip();
        if ($ip) {
            delete_transient($this->key_fail($ip));
        }
    }
}