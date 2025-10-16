<?php
if (!defined('ABSPATH')) { exit; }

/**
 * ماژول: هاردنینگ پیشرفته وردپرس
 * - غیرفعال‌سازی ویرایشگر فایل‌ها در پیشخوان
 * - کاهش نشت اطلاعات (حذف ژنراتور/ورژن از HTML و آدرس فایل‌ها)
 * - حذف اسکریپت/استایل ایموجی و oEmbed/REST discovery از <head>
 * - خطای ورود عمومی (بدون لو دادن نام کاربری/علت)
 * - جلوگیری از Enumerate نویسندگان (?author=1) و بستن آرشیو نویسنده برای مهمان‌ها
 * - مسدودسازی فایل‌های پیش‌فرض حساس (readme.html, license.txt, wp-config-sample.php)
 * - محدودسازی REST برای کاربران مهمان (حذف endpointهای users)
 * - غیرفعال‌سازی XML-RPC و pingback
 */
class RSP_Module_Hardening implements RSP_Module_Interface {

    public function init() {
        // ثابت‌ها خیلی زود تعریف شوند
        add_action('init', [$this, 'define_constants'], 1);

        // حذف موارد غیرضروری از هد
        add_action('init', [$this, 'clean_head'], 3);

        // نسخه‌ها و ژنراتور
        add_filter('the_generator', '__return_empty_string', 99);
        add_filter('style_loader_src',  [$this, 'strip_ver_query'], 99);
        add_filter('script_loader_src', [$this, 'strip_ver_query'], 99);

        // خطای ورود یکسان
        add_filter('login_errors', [$this, 'generic_login_error']);

        // جلوگیری از enumerate نویسنده
        add_action('init',               [$this, 'block_author_enum'], 2);
        add_action('template_redirect',  [$this, 'restrict_author_archives']);

        // مسدودسازی فایل‌های عمومی حساس
        add_action('template_redirect', [$this, 'block_public_files'], 0);

        // REST: حذف endpoint های کاربران برای مهمان‌ها
        add_filter('rest_endpoints', [$this, 'lockdown_rest_for_guests']);

        // XML-RPC و pingback
        add_filter('xmlrpc_enabled', '__return_false');
        add_filter('xmlrpc_methods',  [$this, 'remove_pingback_method']);

        // خاموش کردن ایموجی‌ها بطور کامل
        add_action('init', [$this, 'disable_emojis']);

        // کاهش نویز و جلوگیری از افشای نسخه در پاسخ‌ها
        add_filter('rest_pre_serve_request', [$this, 'rest_headers_hardening'], 10, 4);
    }

    /** تعریف ثابت‌های هاردنینگ */
    public function define_constants() {
        if (!defined('DISALLOW_FILE_EDIT')) define('DISALLOW_FILE_EDIT', true);
        // توجه: DISALLOW_FILE_MODS آپدیت‌ها را هم می‌بندد؛ به‌صورت پیش‌فرض فعال نکنیم
    }

    /** پاکسازی head: لینک‌ها و اسکریپت‌های غیرضروری */
    public function clean_head() {
        remove_action('wp_head', 'wp_generator');
        remove_action('wp_head', 'wlwmanifest_link');
        remove_action('wp_head', 'rsd_link');
        remove_action('wp_head', 'wp_shortlink_wp_head');
        remove_action('wp_head', 'rest_output_link_wp_head');
        remove_action('template_redirect', 'rest_output_link_header', 11);
        remove_action('wp_head', 'wp_oembed_add_discovery_links');
    }

    /** حذف پارامتر ver= از src اسکریپت/استایل‌ها برای کاهش fingerprint */
    public function strip_ver_query($src) {
        if (strpos($src, 'ver=') !== false) {
            $src = remove_query_arg('ver', $src);
        }
        return $src;
    }

    /** پیام ورود عمومی */
    public function generic_login_error() {
        return __('ورود ناموفق بود. لطفاً نام کاربری یا گذرواژه را بررسی کنید.', 'ready-secure-pro');
    }

    /** جلوگیری از enumerate نویسنده از طریق ?author=1 */
    public function block_author_enum() {
        if (is_admin()) return;
        if (!isset($_GET['author'])) return;
        if (is_user_logged_in() && current_user_can('list_users')) return; // مدیران نیاز دارند
        $auth = $_GET['author'];
        if (is_numeric($auth)) {
            // ثبت رویداد و بلاک
            do_action('rsp_activity_log', 'hardening_author_enum', [ 'ip' => function_exists('rsp_client_ip')? rsp_client_ip() : '', 'author' => (int)$auth ]);
            $this->deny_404();
        }
    }

    /** محدود کردن آرشیو نویسندگان برای مهمان‌ها */
    public function restrict_author_archives() {
        if (!is_author()) return;
        if (is_user_logged_in() && current_user_can('edit_posts')) return; // برای نویسندگان/مدیران باز باشد
        // به صفحه اصلی هدایت کن یا 404 بده — 404 امن‌تر است
        $this->deny_404();
    }

    /** مسدودسازی دسترسی مستقیم به فایل‌های عمومی حساس */
    public function block_public_files() {
        $path = isset($_SERVER['REQUEST_URI']) ? (string) parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH) : '';
        if ($path === '') return;
        $deny = [ '/readme.html', '/license.txt', '/wp-config-sample.php' ];
        foreach ($deny as $p) {
            if (stripos($path, $p) !== false) {
                do_action('rsp_activity_log', 'hardening_public_file', [ 'path' => $path ]);
                $this->deny_404();
            }
        }
    }

    /** حذف endpoint های کاربر از REST برای مهمان‌ها */
    public function lockdown_rest_for_guests($endpoints) {
        if (is_user_logged_in()) return $endpoints;
        unset($endpoints['/wp/v2/users']);
        foreach (array_keys($endpoints) as $key) {
            if (strpos($key, '/wp/v2/users/') === 0) unset($endpoints[$key]);
        }
        return $endpoints;
    }

    /** حذف متد pingback از XML-RPC (اگر به هر دلیل xmlrpc فعال بود) */
    public function remove_pingback_method($methods) {
        unset($methods['pingback.ping']);
        unset($methods['pingback.extensions.getPingbacks']);
        return $methods;
    }

    /** غیرفعال‌سازی کامل ایموجی‌ها */
    public function disable_emojis() {
        remove_action('wp_head', 'print_emoji_detection_script', 7);
        remove_action('admin_print_scripts', 'print_emoji_detection_script');
        remove_action('wp_print_styles', 'print_emoji_styles');
        remove_action('admin_print_styles', 'print_emoji_styles');
        remove_filter('the_content_feed', 'wp_staticize_emoji');
        remove_filter('comment_text_rss', 'wp_staticize_emoji');
        remove_filter('wp_mail', 'wp_staticize_emoji_for_email');
        add_filter('emoji_svg_url', '__return_false');
    }

    /** سخت‌گیری روی هدرهای REST (حذف X-WP-Total و نسخه) */
    public function rest_headers_hardening($served, $result, $request, $server) {
        if (!headers_sent()) {
            header_remove('X-Powered-By');
            header_remove('X-Pingback');
        }
        return $served;
    }

    /** خروج 404 امن */
    private function deny_404() {
        if (!headers_sent()) { status_header(404); nocache_headers(); }
        wp_die( __('صفحه مورد نظر یافت نشد.', 'ready-secure-pro'), 404 );
    }
}