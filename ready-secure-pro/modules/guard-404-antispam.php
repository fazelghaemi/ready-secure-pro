<?php
if (!defined('ABSPATH')) { exit; }

/**
 * Ready Secure Pro - Smart 404 Guard + AntiSpam
 * v2.4.2
 * - نمایش/ذخیره‌سازی فیلدها روی صفحه‌ی صحیح: rsp_settings_404_antispam
 * - قفل IP پس از تکرار 404های مشکوک در پنجرهٔ زمانی تعیین‌شده
 * - ضداسپم دیدگاه: Honeypot + حداقل زمان ارسال + محدودیت لینک
 * - استایل فرانت‌اند اختصاصی برای پنهان‌کردن Honeypot
 * - ثبت لاگ با do_action('rsp_activity_log', ...)
 */
if (!interface_exists('RSP_Module_Interface')) {
    interface RSP_Module_Interface { public function init(); }
}

class RSP_Module_Guard_404_AntiSpam implements RSP_Module_Interface
{
    public function init() {
        // UI تنظیمات (همیشه)
        add_action('admin_init', [$this, 'settings']);

        // اجرای گارد 404
        if ((int) get_option('rsp_404_enable', 1) === 1) {
            add_action('init',              [$this, 'maybe_block_locked_ip'], 1);
            add_action('template_redirect', [$this, 'count_404_and_lock'], 99);
        }

        // اجرای ضداسپم دیدگاه‌ها
        if ((int) get_option('rsp_antispam_enable', 1) === 1) {
            add_action('wp_enqueue_scripts',           [$this, 'enqueue_front_styles']);
            add_action('comment_form_after_fields',    [$this, 'output_honeypot']);
            add_action('comment_form_logged_in_after', [$this, 'output_honeypot']);
            add_filter('preprocess_comment',           [$this, 'check_comment_spam']);
        }
    }

    /* ---------------------- Settings UI ---------------------- */

    public function settings() {
        // سکشن گارد 404
        add_settings_section(
            'rsp_404_section',
            __('گارد 404', 'ready-secure-pro'),
            function () {
                echo '<p>' . esc_html__(
                    'IP پس از تکرار 404های مشکوک در بازهٔ زمانی مشخص، به‌صورت موقت قفل می‌شود.',
                    'ready-secure-pro'
                ) . '</p>';
            },
            'rsp_settings_404_antispam'
        );

        // فیلدهای گارد 404
        add_settings_field(
            'rsp_404_enable',
            __('فعال باشد؟', 'ready-secure-pro'),
            function () {
                $v = (int) get_option('rsp_404_enable', 1);
                echo '<label><input type="checkbox" name="rsp_404_enable" value="1" '. checked($v, 1, false) .'> ' .
                     esc_html__('فعال‌سازی گارد 404', 'ready-secure-pro') . '</label>';
            },
            'rsp_settings_404_antispam',
            'rsp_404_section'
        );

        add_settings_field(
            'rsp_404_threshold',
            __('حد آستانهٔ 404 (تعداد)', 'ready-secure-pro'),
            function () {
                $v = (int) get_option('rsp_404_threshold', 12);
                echo '<input type="number" min="3" step="1" name="rsp_404_threshold" value="'. esc_attr($v) .'">';
                echo '<p class="description">'. esc_html__('مثال: 12 خطای 404 در پنجرهٔ زمانی → قفل IP', 'ready-secure-pro') .'</p>';
            },
            'rsp_settings_404_antispam',
            'rsp_404_section'
        );

        add_settings_field(
            'rsp_404_window',
            __('پنجرهٔ زمانی (ثانیه)', 'ready-secure-pro'),
            function () {
                $v = (int) get_option('rsp_404_window', 120);
                echo '<input type="number" min="30" step="30" name="rsp_404_window" value="'. esc_attr($v) .'">';
            },
            'rsp_settings_404_antispam',
            'rsp_404_section'
        );

        add_settings_field(
            'rsp_404_lock_minutes',
            __('مدت قفل IP (دقیقه)', 'ready-secure-pro'),
            function () {
                $v = (int) get_option('rsp_404_lock_minutes', 30);
                echo '<input type="number" min="5" step="5" name="rsp_404_lock_minutes" value="'. esc_attr($v) .'">';
            },
            'rsp_settings_404_antispam',
            'rsp_404_section'
        );

        // سکشن ضداسپم دیدگاه‌ها
        add_settings_section(
            'rsp_antispam_section',
            __('ضداسپم دیدگاه‌ها', 'ready-secure-pro'),
            function () {
                echo '<p>' . esc_html__(
                    'کاهش اسپم با Honeypot مخفی، حداقل زمان ارسال فرم و محدودیت لینک‌ها.',
                    'ready-secure-pro'
                ) . '</p>';
            },
            'rsp_settings_404_antispam'
        );

        // فیلدهای ضداسپم
        add_settings_field(
            'rsp_antispam_enable',
            __('فعال باشد؟', 'ready-secure-pro'),
            function () {
                $v = (int) get_option('rsp_antispam_enable', 1);
                echo '<label><input type="checkbox" name="rsp_antispam_enable" value="1" '. checked($v, 1, false) .'> ' .
                     esc_html__('فعال‌سازی ضداسپم دیدگاه‌ها', 'ready-secure-pro') . '</label>';
            },
            'rsp_settings_404_antispam',
            'rsp_antispam_section'
        );

        add_settings_field(
            'rsp_antispam_min_secs',
            __('حداقل زمان ارسال (ثانیه)', 'ready-secure-pro'),
            function () {
                $v = (int) get_option('rsp_antispam_min_secs', 8);
                echo '<input type="number" min="3" step="1" name="rsp_antispam_min_secs" value="'. esc_attr($v) .'">';
                echo '<p class="description">'. esc_html__('ارسال سریع‌تر از این مقدار → مشکوک به ربات', 'ready-secure-pro') .'</p>';
            },
            'rsp_settings_404_antispam',
            'rsp_antispam_section'
        );

        add_settings_field(
            'rsp_antispam_max_links',
            __('حداکثر لینک مجاز در دیدگاه', 'ready-secure-pro'),
            function () {
                $v = (int) get_option('rsp_antispam_max_links', 2);
                echo '<input type="number" min="0" step="1" name="rsp_antispam_max_links" value="'. esc_attr($v) .'">';
            },
            'rsp_settings_404_antispam',
            'rsp_antispam_section'
        );
    }

    /* ---------------------- Guard 404 Logic ---------------------- */

    private function client_ip() {
        $keys = ['HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'REMOTE_ADDR'];
        foreach ($keys as $k) {
            if (!empty($_SERVER[$k])) {
                $v = trim((string) $_SERVER[$k]);
                if ($k === 'HTTP_X_FORWARDED_FOR' && strpos($v, ',') !== false) {
                    $v = trim(explode(',', $v)[0]);
                }
                if (filter_var($v, FILTER_VALIDATE_IP)) {
                    return $v;
                }
            }
        }
        return '';
    }

    /** اگر IP قفل است، سریع 403 بده (مدیران مستثنی) */
    public function maybe_block_locked_ip() {
        if (is_user_logged_in() && current_user_can('manage_options')) {
            return;
        }
        $ip = $this->client_ip();
        if (!$ip) return;

        $key = 'rsp_404_block_' . md5($ip);
        if (get_transient($key)) {
            status_header(403);
            header('X-RSP-Block: smart-404');
            do_action('rsp_activity_log', 'smart_404_blocked_request', ['ip' => $ip]);
            exit;
        }
    }

    /** شمارش 404ها و قفل IP */
    public function count_404_and_lock() {
        if (!is_404()) return;

        $ip = $this->client_ip();
        if (!$ip) return;

        $th     = max(3,  (int) get_option('rsp_404_threshold', 12));
        $win    = max(30, (int) get_option('rsp_404_window', 120));
        $lock_m = max(5,  (int) get_option('rsp_404_lock_minutes', 30));

        // سازگاری با intdiv برای PHP < 7
        if (!function_exists('intdiv')) {
            function rsp_intdiv($a, $b) { return ($a - ($a % $b)) / $b; }
            $bucket = 'b' . rsp_intdiv(time(), $win);
        } else {
            $bucket = 'b' . intdiv(time(), $win);
        }
        
        $key    = 'rsp_404_cnt_' . md5($ip . '|' . $bucket);

        $n = (int) get_transient($key);
        $n++;
        set_transient($key, $n, $win);

        if ($n >= $th) {
            // قفل کن
            $blk = 'rsp_404_block_' . md5($ip);
            set_transient($blk, 1, $lock_m * MINUTE_IN_SECONDS);

            do_action('rsp_activity_log', 'smart_404_lock', [
                'ip'      => $ip,
                'count'   => $n,
                'window'  => $win,
                'minutes' => $lock_m,
                'uri'     => isset($_SERVER['REQUEST_URI']) ? substr((string)$_SERVER['REQUEST_URI'], 0, 300) : ''
            ]);

            status_header(403);
            header('X-RSP-Block: smart-404');
            exit;
        }
    }

    /* ---------------------- Anti-Spam Logic ---------------------- */

    /** استایل فرانت‌اند برای مخفی کردن Honeypot */
    public function enqueue_front_styles() {
        // هندل بدون فایل با استایل inline
        wp_register_style('rsp-frontend', false);
        wp_enqueue_style('rsp-frontend');
        $css = '.rsp-hp{position:absolute !important;left:-999em !important;opacity:0 !important;visibility:hidden !important;height:0 !important;}' .
               '.rsp-hp input{display:none !important;}';
        wp_add_inline_style('rsp-frontend', $css);
    }

    /** افزودن فیلدهای مخفی به فرم دیدگاه */
    public function output_honeypot() {
        $ts = time();
        echo '<div class="rsp-hp" aria-hidden="true">';
        echo '<label for="rsp_hp">'. esc_html__('این فیلد را خالی بگذارید', 'ready-secure-pro') .'</label>';
        echo '<input type="text" name="rsp_hp" id="rsp_hp" tabindex="-1" autocomplete="off" />';
        echo '</div>';
        echo '<input type="hidden" name="rsp_ts" value="'. esc_attr($ts) .'" />';
    }

    /** بررسی قبل از ذخیرهٔ دیدگاه */
    public function check_comment_spam($commentdata) {
        if (is_user_logged_in() && current_user_can('moderate_comments')) {
            return $commentdata;
        }

        $hp = isset($_POST['rsp_hp']) ? (string) $_POST['rsp_hp'] : '';
        $ts = isset($_POST['rsp_ts']) ? (int) $_POST['rsp_ts'] : 0;

        $min_secs  = max(3, (int) get_option('rsp_antispam_min_secs', 8));
        $max_links = max(0, (int) get_option('rsp_antispam_max_links', 2));

        // Honeypot باید خالی باشد
        if ($hp !== '') {
            wp_die(
                esc_html__('ارسال شما مشکوک تشخیص داده شد (Honeypot).', 'ready-secure-pro'),
                esc_html__('خطا', 'ready-secure-pro'),
                ['response' => 403]
            );
        }

        // حداقل زمان
        if ($ts > 0 && (time() - $ts) < $min_secs) {
            wp_die(
                esc_html__('ارسال بسیار سریع بود. لطفاً مجدد تلاش کنید.', 'ready-secure-pro'),
                esc_html__('خیلی سریع!', 'ready-secure-pro'),
                ['response' => 429]
            );
        }

        // محدودیت لینک‌ها
        if ($max_links >= 0) {
            $content = isset($commentdata['comment_content']) ? (string)$commentdata['comment_content'] : '';
            $links = 0;
            if ($content !== '') {
                $links += preg_match_all('~https?://~i', $content);
                $links += preg_match_all('~<\s*a\b~i', $content);
            }
            if ($links > $max_links) {
                wp_die(
                    esc_html__('تعداد لینک‌های موجود در دیدگاه بیش از حد مجاز است.', 'ready-secure-pro'),
                    esc_html__('لینک‌های زیاد', 'ready-secure-pro'),
                    ['response' => 403]
                );
            }
        }

        do_action('rsp_activity_log', 'antispam_pass', [
            'ip' => isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '',
            'len'=> isset($commentdata['comment_content']) ? strlen((string)$commentdata['comment_content']) : 0
        ]);
        return $commentdata;
    }
}