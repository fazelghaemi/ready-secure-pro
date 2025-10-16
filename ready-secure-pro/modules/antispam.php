<?php
if (!defined('ABSPATH')) { exit; }

/**
 * ماژول: ضد اسپم دیدگاه‌ها (Anti‑Spam)
 * - فیلد هانی‌پات مخفی
 * - بررسی حداقل زمان بین بارگذاری فرم و ارسال (min seconds)
 * - بررسی nonce اختصاصی
 * - ثبت بلاک‌ها در لاگ مرکزی
 *
 * گزینه‌ها (Options):
 *  - rsp_antispam_enable (bool)
 *  - rsp_antispam_min_seconds (int)
 *  - rsp_antispam_honeypot (bool)
 */
class RSP_Module_AntiSpam implements RSP_Module_Interface {

    public function init() {
        add_action('init', [$this, 'maybe_boot']);
    }

    public function maybe_boot() {
        if (!get_option('rsp_antispam_enable', 1)) return;

        // افزودن فیلد هانی‌پات به فرم دیدگاه
        add_filter('comment_form_default_fields', [$this, 'inject_honeypot_field']);
        add_action('comment_form_after_fields',    [$this, 'inject_hidden_fields']);
        add_action('comment_form_logged_in_after', [$this, 'inject_hidden_fields']);

        // اعتبارسنجی قبل از ثبت دیدگاه
        add_filter('preprocess_comment', [$this, 'validate_comment']);
    }

    /** فیلد هانی‌پات (برای کاربران مهمان؛ برای لاگین‌شده‌ها هم در inject_hidden_fields پوشش داریم) */
    public function inject_honeypot_field($fields) {
        if (!get_option('rsp_antispam_honeypot', 1)) return $fields;
        $hp_html = '<p class="comment-form-rsp-hp" style="position:absolute !important; left:-9999px; top:auto; width:1px; height:1px; overflow:hidden;">'
                 . '<label for="rsp_hp">' . esc_html__('فیلد خالی (پر نکنید)', 'ready-secure-pro') . '</label>'
                 . '<input type="text" name="rsp_hp" id="rsp_hp" value="" autocomplete="off" tabindex="-1" />'
                 . '</p>';
        // در آرایهٔ فیلدهای پیش‌فرض درج می‌کنیم تا نزدیک ابتدای فرم بیاید
        $fields['rsp_hp'] = $hp_html;
        return $fields;
    }

    /** فیلدهای پنهان مشترک: Nonce + Timestamp */
    public function inject_hidden_fields() {
        $nonce = wp_create_nonce('rsp_antispam');
        $ts_server = time(); // fallback در صورت غیرفعال بودن JS
        echo '<input type="hidden" name="rsp_as_nonce" value="' . esc_attr($nonce) . '" />';
        echo '<input type="hidden" name="rsp_ts" id="rsp_ts" value="' . esc_attr($ts_server) . '" />';
        // تعیین timestamp واقعی در لحظهٔ بارگذاری صفحه با JS
        echo '<script>(function(){var e=document.getElementById("rsp_ts");if(e){e.value=Math.floor(Date.now()/1000).toString();}})();</script>';
    }

    /** اعتبارسنجی پیش از ثبت دیدگاه */
    public function validate_comment($commentdata) {
        // اگر کاربر توانایی مدیریت دیدگاه دارد، عبور (برای ادمین‌ها و مدیران محتوایی)
        if (is_user_logged_in() && current_user_can('moderate_comments')) {
            return $commentdata;
        }

        // Comment type بررسی — اسپم عموماً برای نوع "comment" است؛ اما بگذاریم برای همه اعمال شود
        $type = isset($commentdata['comment_type']) ? $commentdata['comment_type'] : '';

        // 1) Nonce
        if (!isset($_POST['rsp_as_nonce']) || !wp_verify_nonce($_POST['rsp_as_nonce'], 'rsp_antispam')) {
            $this->deny(__('ارسال نامعتبر (کد امنیتی نامعتبر).', 'ready-secure-pro'), 'nonce');
        }

        // 2) Honeypot
        if (get_option('rsp_antispam_honeypot', 1)) {
            $hp = isset($_POST['rsp_hp']) ? trim((string) $_POST['rsp_hp']) : '';
            if ($hp !== '') {
                $this->log_block('honeypot', $commentdata);
                $this->deny(__('ارسال مسدود شد (شناسایی ربات).', 'ready-secure-pro'), 'honeypot');
            }
        }

        // 3) حداقل زمان بین بارگذاری و ارسال
        $min = max(0, (int) get_option('rsp_antispam_min_seconds', 5));
        if ($min > 0) {
            $ts = isset($_POST['rsp_ts']) ? (int) $_POST['rsp_ts'] : 0;
            $now = time();
            if ($ts <= 0 || ($now - $ts) < $min) {
                $this->log_block('min_seconds', $commentdata, [ 'delta' => $now - $ts, 'required' => $min ]);
                $this->deny(sprintf(__('لطفاً کمی صبر کنید و سپس ارسال کنید (حداقل %d ثانیه).', 'ready-secure-pro'), $min), 'min_seconds');
            }
        }

        return $commentdata; // مجاز
    }

    /** مسدودسازی با پاسخ امن */
    private function deny($msg, $reason = '') {
        if (!headers_sent()) { status_header(403); nocache_headers(); }
        wp_die( esc_html($msg), 403 );
    }

    /** ثبت در لاگ مرکزی */
    private function log_block($reason, $commentdata, $extra = []) {
        $payload = array_merge([
            'ip'   => function_exists('rsp_client_ip') ? rsp_client_ip() : (isset($_SERVER['REMOTE_ADDR'])? $_SERVER['REMOTE_ADDR'] : ''),
            'ua'   => isset($_SERVER['HTTP_USER_AGENT']) ? substr($_SERVER['HTTP_USER_AGENT'], 0, 190) : '',
            'post' => isset($commentdata['comment_post_ID']) ? (int)$commentdata['comment_post_ID'] : 0,
            'type' => isset($commentdata['comment_type']) ? $commentdata['comment_type'] : '',
        ], $extra);
        do_action('rsp_activity_log', 'antispam_block', array_merge(['reason'=>$reason], $payload));
    }
}
