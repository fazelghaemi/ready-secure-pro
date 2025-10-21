<?php
/**
 * Plugin Name: Ready Secure Pro
 * Description: مجموعه ابزارهای امنیت وردپرس (WAF سبک، گارد 404، ضداسپم دیدگاه، تغییر آدرس ورود، File Guard، هاردنینگ)
 * Version:     2.4.4
 * Author:      Ready Studio
 * Text Domain: ready-secure-pro
 */

if (!defined('ABSPATH')) { exit; }

/* -------------------------------------------------
 * ثابت‌ها
 * ------------------------------------------------- */
if (!defined('RSP_VERSION')) define('RSP_VERSION', '2.4.4');
if (!defined('RSP_PATH'))    define('RSP_PATH', plugin_dir_path(__FILE__));
if (!defined('RSP_URL'))     define('RSP_URL',  plugin_dir_url(__FILE__));

/* -------------------------------------------------
 * سازگاری: Interface عمومی ماژول‌ها (اگر از قبل نیست)
 * ------------------------------------------------- */
if (!interface_exists('RSP_Module_Interface')) {
    interface RSP_Module_Interface { public function init(); }
}

/* -------------------------------------------------
 * Helperهای ضروری
 * [اصلاح] تعاریف تکراری توابع از اینجا حذف شد.
 * ------------------------------------------------- */
 // توابع rsp_client_ip و rsp_ip_in_cidr اکنون فقط در helpers.php تعریف می‌شوند.

/* -------------------------------------------------
 * بارگذاری فایل با بررسی وجود
 * ------------------------------------------------- */
function rsp_require($relpath) {
    $abs = RSP_PATH . ltrim($relpath, '/');
    if (file_exists($abs)) { require_once $abs; return true; }
    return false;
}

/* -------------------------------------------------
 * فعال‌سازی/غیرفعال‌سازی
 * ------------------------------------------------- */
register_activation_hook(__FILE__, function () {
    // جدول لاگ ساده (درصورت نبود)
    global $wpdb;
    $t = $wpdb->prefix . 'rsp_logs';
    $charset = $wpdb->get_charset_collate();
    $sql = "CREATE TABLE IF NOT EXISTS $t (
        id BIGINT unsigned NOT NULL AUTO_INCREMENT,
        ts DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        type VARCHAR(64) NOT NULL,
        ip   VARCHAR(64) NULL,
        detail LONGTEXT NULL,
        PRIMARY KEY (id),
        KEY type_idx (type)
    ) $charset;";
    require_once ABSPATH . 'wp-admin/includes/upgrade.php';
    dbDelta($sql);

    // فلش قوانین بازنویسی (برای اسلاگ ورود سفارشی)
    flush_rewrite_rules(false);
});
register_deactivation_hook(__FILE__, function () {
    flush_rewrite_rules(false);
});

/* -------------------------------------------------
 * بوت‌استرپ افزونه
 * ------------------------------------------------- */
add_action('plugins_loaded', function () {

    // بارگذاری Helper ها (حاوی توابع اصلی مثل rsp_client_ip)
    rsp_require('includes/helpers.php');

    // استایل/اسکریپت مدیریت و صفحه تنظیمات
    rsp_require('includes/class-admin.php');

    // ماژول‌ها: هر کدام اگر وجود داشتند، لود و init شوند
    $modules = [
        'modules/file-guard.php'          => 'RSP_Module_File_Guard',
        'modules/waf.php'                 => 'RSP_Module_WAF',
        'modules/guard-404-antispam.php'  => 'RSP_Module_Guard_404_AntiSpam',
        'modules/rest-guard.php'          => 'RSP_Module_REST_Guard',
        'modules/hardening.php'           => 'RSP_Module_Hardening',
        'modules/brute-force.php'         => 'RSP_Module_Brute_Force',
        'modules/login-url.php'           => 'RSP_Module_Login_Url',
        'modules/xmlrpc.php'              => 'RSP_Module_XMLRPC',
        'modules/activity-log.php'        => 'RSP_Module_Activity_Log',
    ];

    // لود کلاس ادمین
    if (class_exists('RSP_Admin')) {
        $GLOBALS['rsp_admin'] = new RSP_Admin();
        if (method_exists($GLOBALS['rsp_admin'], 'init')) {
            $GLOBALS['rsp_admin']->init();
        }
    }

    // لود و راه‌اندازی ماژول‌ها
    foreach ($modules as $file => $class) {
        rsp_require($file);
        if (class_exists($class)) {
            try {
                $obj = new $class();
                if ($obj instanceof RSP_Module_Interface) {
                    $obj->init();
                } elseif (method_exists($obj,'init')) {
                    $obj->init();
                }
            } catch (Exception $e) {
                // در صورت خطا، فقط لاگ بزن و ادامه بده
                if (function_exists('rsp_activity_log_write')) {
                     rsp_activity_log_write('module_init_error', [
                         'module' => $class, 'error' => $e->getMessage()
                     ]);
                }
            }
        }
    }
});

/* -------------------------------------------------
 * هاردنینگ هدرها (HSTS فقط روی HTTPS)
 * ------------------------------------------------- */
add_action('send_headers', function () {
    // اطمینان از وجود تابع قبل از فراخوانی
    if (!function_exists('rsp_send_header_once')) {
         return; // اگر helpers.php لود نشده باشد، کاری نکن
    }

    // HSTS فقط در HTTPS
    if (get_option('rsp_headers_hsts', 1) && is_ssl()) {
        rsp_send_header_once('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
    }

    // سایر هدرهای سبک
    rsp_send_header_once('Referrer-Policy', esc_attr(get_option('rsp_headers_referrer', 'no-referrer')));
    rsp_send_header_once('X-Frame-Options', 'SAMEORIGIN');
    rsp_send_header_once('X-Content-Type-Options', 'nosniff');
}, 11);