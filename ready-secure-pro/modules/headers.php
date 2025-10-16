<?php
if (!defined('ABSPATH')) { exit; }

/**
 * ماژول: هدرهای امنیتی مدرن
 * - HSTS (فقط روی HTTPS)
 * - CSP (Report-Only یا Enforce از طریق گزینه‌ها)
 * - Referrer-Policy, X-Content-Type-Options, X-Frame-Options (یا frame-ancestors در CSP),
 *   Permissions-Policy, Cross-Origin-* (COOP/COEP/CORP), X-Permitted-Cross-Domain-Policies, X-Download-Options, X-XSS-Protection
 * - قابل گسترش با فیلترها و بدون تداخل با سایر افزونه‌ها (ارسال فقط اگر هنوز هدر ارسال نشده باشد)
 *
 * گزینه‌ها (Options)
 *  - rsp_headers_hsts  (bool)
 *  - rsp_headers_mode  (string: 'report-only' | 'enforce')
 *  - rsp_headers_csp   (string)
 */
class RSP_Module_Headers implements RSP_Module_Interface {

    public function init() {
        // روی send_headers ثبت می‌کنیم تا هم در فرانت و هم ادمین اعمال شود
        add_action('send_headers', [$this, 'apply_headers'], 20, 1);
    }

    /**
     * اِعمال هدرها با رعایت ایمنی
     */
    public function apply_headers($wp) {
        // امکان خاموش‌کردن برای برخی درخواست‌ها
        $enabled = apply_filters('rsp_headers_enable_for_request', true, $wp);
        if (!$enabled) return;

        // 1) HSTS
        if (get_option('rsp_headers_hsts', 1) && is_ssl()) {
            $hsts = apply_filters('rsp_headers_hsts_value', 'max-age=31536000; includeSubDomains; preload');
            $this->send_once('Strict-Transport-Security', $hsts);
        }

        // 2) CSP (enforce یا report-only)
        $csp = trim((string) get_option('rsp_headers_csp', "default-src 'self'; img-src 'self' data:;"));
        $csp = apply_filters('rsp_headers_csp_value', $csp);
        if ($csp !== '') {
            $mode = (string) get_option('rsp_headers_mode', 'report-only');
            if ($mode === 'enforce') {
                $this->send_once('Content-Security-Policy', $csp);
            } else {
                $this->send_once('Content-Security-Policy-Report-Only', $csp);
            }
        }

        // 3) Referrer-Policy (ایمن ولی سازگار)
        $this->send_once('Referrer-Policy', apply_filters('rsp_headers_referrer', 'strict-origin-when-cross-origin'));

        // 4) X-Content-Type-Options
        $this->send_once('X-Content-Type-Options', 'nosniff');

        // 5) X-Frame-Options — فقط اگر در CSP، frame-ancestors نیامده باشد (برای سازگاری مرورگرهای قدیمی)
        if (stripos($csp, 'frame-ancestors') === false) {
            $this->send_once('X-Frame-Options', 'SAMEORIGIN');
        }

        // 6) Permissions-Policy — حداقل‌گرای ایمن؛ قابل گسترش با فیلتر
        $pp = apply_filters('rsp_headers_permissions_policy', 'accelerometer=(), autoplay=(), camera=(), display-capture=(), encrypted-media=(), fullscreen=(self), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), midi=(), payment=(), usb=()');
        $this->send_once('Permissions-Policy', $pp);

        // 7) CORP/COOP/COEP — مقادیر محافظه‌کارانه تا سایت‌ها دچار مشکل نشوند
        $this->send_once('Cross-Origin-Opener-Policy', apply_filters('rsp_headers_coop', 'same-origin'));
        $this->send_once('Cross-Origin-Resource-Policy', apply_filters('rsp_headers_corp', 'same-origin'));
        // COEP: credentialless نسبتاً سازگارتر از require-corp است
        $this->send_once('Cross-Origin-Embedder-Policy', apply_filters('rsp_headers_coep', 'credentialless'));

        // 8) هدرهای تکمیلی
        $this->send_once('X-Permitted-Cross-Domain-Policies', 'none');
        $this->send_once('X-Download-Options', 'noopen'); // برای IE/Edge قدیمی
        $this->send_once('X-XSS-Protection', '0'); // غیرفعال تا با CSP تداخل نکند

        // 9) امکان افزودن هدرهای سفارشی توسط مدیر/کدنویس
        $extra = (array) apply_filters('rsp_headers_extra', []);
        foreach ($extra as $name => $val) {
            if (is_string($name) && is_string($val)) $this->send_once($name, $val);
        }
    }

    /**
     * ارسال هدر فقط اگر قبلاً ارسال نشده باشد
     */
    private function send_once($name, $value) {
        if (headers_sent()) return;
        if (!is_string($name) || $name === '' || !is_string($value)) return;
        // اگر هدر با همین نام قبلاً ست شده باشد، دوباره نفرست
        foreach (headers_list() as $h) {
            if (stripos($h, $name . ':') === 0) return;
        }
        header($name . ': ' . $value, true);
    }
}
