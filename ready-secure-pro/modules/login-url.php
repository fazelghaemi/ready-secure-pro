<?php
if (!defined('ABSPATH')) { exit; }

/**
 * ماژول: امنیت کامل ورود (Login URL سفارشی + مسدودسازی wp-login.php)
 * - اسلاگ سفارشی برای صفحه ورود (گزینه: rsp_login_slug؛ پیش‌فرض: manager)
 * - رندر ورود از مسیر مجازی /{slug}/ بدون برهم‌زدن منطق اصلی وردپرس (require wp-login.php)
 * - مسدودسازی دسترسی مستقیم به wp-login.php (به‌جز اکشن‌های ضروری: logout, lostpassword, resetpass, postpass, rp)
 * - یکسان‌سازی لینک‌های ورود (فیلترهای login_url / site_url / network_site_url)
 */
class RSP_Module_Login_Url implements RSP_Module_Interface {

    public function init() {
        add_filter('query_vars',                 [$this, 'register_query_var']);
        add_action('template_redirect',         [$this, 'maybe_render_custom_login'], 0);
        add_action('init',                      [$this, 'block_wp_login_direct'], 1);
        add_filter('login_url',                 [$this, 'filter_login_url'], 10, 3);
        add_filter('site_url',                  [$this, 'filter_site_url'], 10, 3);
        add_filter('network_site_url',          [$this, 'filter_site_url'], 10, 3);
    }

    /** ثبت query var مربوط به ری‌رایت */
    public function register_query_var($vars) {
        $vars[] = 'rsp_custom_login';
        return $vars;
    }

    /** آدرس ورود سفارشی */
    private function login_slug() {
        $slug = trim((string) get_option('rsp_login_slug', 'manager'));
        $slug = ltrim($slug, '/');
        $slug = $slug === '' ? 'manager' : $slug;
        return $slug;
    }

    /** URL کامل ورود سفارشی */
    private function login_url_custom() {
        $slug = $this->login_slug();
        return home_url('/' . $slug . '/');
    }

    /** رندر صفحه ورود وقتی /{slug}/ درخواست شده است */
    public function maybe_render_custom_login() {
        if (get_query_var('rsp_custom_login') !== '1') return;

        // صفحه‌ی ورود اصلی وردپرس را در همین درخواست رندر کن
        if (!defined('DONOTCACHEPAGE')) define('DONOTCACHEPAGE', true);
        if (!headers_sent()) {
            nocache_headers();
            header('X-RSP-Login: custom');
            header('Referrer-Policy: no-referrer');
            header('X-Frame-Options: SAMEORIGIN');
        }

        // اطمینان از این‌که توابع و محیط وردپرس آماده‌اند
        global $pagenow; $pagenow = 'wp-login.php';
        $login_php = ABSPATH . 'wp-login.php';
        if (file_exists($login_php)) {
            require $login_php; // این فایل خروجی صفحه ورود را مدیریت می‌کند
            exit;
        }
        // اگر به هر دلیل موجود نبود
        wp_die(__('فایل ورود وردپرس یافت نشد.', 'ready-secure-pro'), 500);
    }

    /** مسدودسازی دسترسی مستقیم به wp-login.php و هدایت به اسلاگ سفارشی */
    public function block_wp_login_direct() {
        // اگر اسلاگ برابر wp-login.php است، کاری نکن
        $slug = $this->login_slug();
        if ($slug === 'wp-login.php') return;

        $uri  = isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '';
        $path = parse_url($uri, PHP_URL_PATH);
        if (!$path) return;

        // فقط وقتی wp-login.php مستقیماً خواسته شده
        if (stripos($path, '/wp-login.php') === false) return;

        // اکشن‌های مجاز که باید از مسیر اصلی عبور کنند
        $allowed = apply_filters('rsp_login_allowed_actions', [
            'logout', 'lostpassword', 'retrievepassword', 'resetpass', 'rp', 'postpass'
        ]);
        $action = isset($_REQUEST['action']) ? strtolower((string) $_REQUEST['action']) : '';

        if (!in_array($action, (array)$allowed, true)) {
            // هدایت به آدرس سفارشی
            $to = $this->login_url_custom();
            if (!headers_sent()) {
                wp_safe_redirect($to, 302);
                exit;
            } else {
                echo '<meta http-equiv="refresh" content="0;url='.esc_url($to).'">';
                exit;
            }
        }
    }

    /** یکسان‌سازی خروجی فیلتر login_url */
    public function filter_login_url($login_url, $redirect, $force_reauth) {
        $url = $this->login_url_custom();
        $args = [];
        if (!empty($redirect))  $args['redirect_to'] = $redirect;
        if (!empty($force_reauth)) $args['reauth'] = '1';
        if (!empty($args)) $url = add_query_arg($args, $url);
        return $url;
    }

    /** جایگزینی wp-login.php در site_url / network_site_url */
    public function filter_site_url($url, $path, $scheme) {
        if (!is_string($url)) return $url;
        // اگر خروجی شامل wp-login.php بود، با اسلاگ سفارشی جایگزین کن
        if (strpos($url, 'wp-login.php') !== false) {
            $url = $this->login_url_custom();
        }
        return $url;
    }
}
