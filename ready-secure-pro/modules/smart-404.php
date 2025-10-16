<?php
if (!defined('ABSPATH')) { exit; }

/**
 * ماژول: مسدودسازی هوشمند 404
 * - شمارش رگباری درخواست‌های 404 در یک پنجره زمانی per-IP
 * - در صورت عبور از آستانه، IP برای مدت مشخص مسدود می‌شود
 * - رویدادها در لاگ مرکزی ثبت می‌گردند
 *
 * گزینه‌ها (Options)
 *  - rsp_404_enable           (bool)   فعال/غیرفعال
 *  - rsp_404_threshold        (int)    حداکثر مجاز 404 در پنجره
 *  - rsp_404_window           (int)    طول پنجره بر حسب ثانیه (پیش‌فرض 300)
 *  - rsp_404_block_minutes    (int)    مدت مسدودسازی بر حسب دقیقه
 */
class RSP_Module_Smart_404 implements RSP_Module_Interface {

    public function init() {
        // اگر IP مسدود باشد، خیلی زود پاسخ بدهیم
        add_action('init', [$this, 'maybe_block_now'], 0);
        // پس از تشخیص 404، شمارش و احتمالاً بلاک
        add_action('template_redirect', [$this, 'maybe_count_404'], 9999);
    }

    /** بررسی و بلاک فوری در ابتدای چرخه */
    public function maybe_block_now() {
        if (!get_option('rsp_404_enable', 1)) return;
        if (is_admin()) return; // بخش ادمین را مسدود نکن

        $ip = rsp_client_ip();
        if ($this->is_blocked($ip)) {
            $this->deny_now(__('دسترسی شما به دلیل خطاهای 404 مکرر، موقتاً محدود شده است.', 'ready-secure-pro'));
        }
    }

    /** اگر این درخواست 404 است، شمارش کن و در صورت نیاز بلاک کن */
    public function maybe_count_404() {
        if (!get_option('rsp_404_enable', 1)) return;
        if (is_admin()) return;

        // فقط زمانی عمل کن که وردپرس تشخیص 404 داده باشد
        if (!is_404()) return;

        $ip = rsp_client_ip();
        if ($this->is_blocked($ip)) return $this->deny_now();

        // آدرس‌های مجاز (برای جلوگیری از false-positive)
        $uri = isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '';
        $allow = apply_filters('rsp_smart_404_allow', [
            '/robots.txt',
            '/favicon.ico',
        ]);
        foreach ((array)$allow as $a) {
            if (strpos($uri, $a) !== false) return; // صرف نظر کن
        }

        $win      = max(30, (int) get_option('rsp_404_window', 300));
        $limit    = max(1,  (int) get_option('rsp_404_threshold', 20));
        $blockMin = max(1,  (int) get_option('rsp_404_block_minutes', 60));

        $bucket = floor(time() / $win);
        $key    = $this->k_count($ip, $bucket);
        $count  = (int) get_transient($key);
        $count++;
        set_transient($key, $count, $win);

        // ثبت لاگ هر رخداد 404 برای این ماژول
        do_action('rsp_activity_log', '404_count', [
            'ip'   => $ip,
            'uri'  => esc_url_raw($uri),
            'ua'   => isset($_SERVER['HTTP_USER_AGENT']) ? substr($_SERVER['HTTP_USER_AGENT'], 0, 190) : '',
            'bucket' => (int)$bucket,
            'count'  => (int)$count,
        ]);

        if ($count > $limit) {
            // بلاک موقت
            $this->block_ip($ip, $blockMin);
            do_action('rsp_activity_log', '404_block', [
                'ip'      => $ip,
                'minutes' => $blockMin,
                'uri'     => esc_url_raw($uri),
                'count'   => (int)$count,
            ]);
            $this->deny_now(__('دسترسی شما به دلیل خطاهای 404 مکرر، موقتاً محدود شده است.', 'ready-secure-pro'));
        }
    }

    /**
     * آیا IP مسدود است؟
     */
    private function is_blocked($ip) {
        return (bool) get_transient($this->k_block($ip));
    }

    /**
     * اعمال بلاک برای مدت مشخص
     */
    private function block_ip($ip, $minutes) {
        set_transient($this->k_block($ip), 1, absint($minutes) * MINUTE_IN_SECONDS);
    }

    /**
     * پاسخ 403 و خروج
     */
    private function deny_now($msg = '') {
        if (!headers_sent()) {
            status_header(403);
            nocache_headers();
        }
        if ($msg === '') $msg = __('دسترسی غیرمجاز.', 'ready-secure-pro');
        wp_die( esc_html($msg), 403 );
    }

    /** کلیدها */
    private function k_block($ip)  { return 'rsp_404_block_' . md5($ip); }
    private function k_count($ip, $bucket) { return 'rsp_404_cnt_' . md5($ip.'|'.$bucket); }
}
