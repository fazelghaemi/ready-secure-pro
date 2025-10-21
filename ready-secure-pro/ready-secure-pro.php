<?php
/**
 * Plugin Name: Ready Secure Pro
 * Description: مجموعه ابزارهای امنیت وردپرس (WAF سبک، گارد 404، ضداسپم دیدگاه، تغییر آدرس ورود، File Guard، هاردنینگ)
 * Version:     2.4.5
 * Author:      Ready Studio
 * Text Domain: ready-secure-pro
 */

if (!defined('ABSPATH')) { exit; }

/* -------------------------------------------------
 * ثابت‌ها
 * ------------------------------------------------- */
if (!defined('RSP_VERSION')) define('RSP_VERSION', '2.4.5');
if (!defined('RSP_PATH'))    define('RSP_PATH', plugin_dir_path(__FILE__));
if (!defined('RSP_URL'))     define('RSP_URL',  plugin_dir_url(__FILE__));

/* -------------------------------------------------
 * سازگاری: Interface عمومی ماژول‌ها (اگر از قبل نیست)
 * ------------------------------------------------- */
if (!interface_exists('RSP_Module_Interface')) {
    interface RSP_Module_Interface { public function init(); }
}

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
 * بوت‌استرپ افزونه با بارگذاری شرطی
 * ------------------------------------------------- */
add_action('plugins_loaded', function () {

    // بارگذاری Helper ها (حاوی توابع اصلی) - همیشه لازم است
    rsp_require('includes/helpers.php');

    // بارگذاری کلاس ادمین (فقط در بخش مدیریت)
    if (is_admin()) {
        rsp_require('includes/class-admin.php');
        if (class_exists('RSP_Admin')) {
            // init() کلاس ادمین، هوک init وردپرس را برای بارگذاری ترجمه قلاب می‌کند
            (new RSP_Admin())->init();
        }
    }

    // --- ماژول‌های حیاتی که تقریباً همیشه لازمند ---

    // WAF: باید خیلی زود اجرا شود (قبل از بقیه)
    if (rsp_require('modules/waf.php') && class_exists('RSP_Module_WAF')) {
        // init() این کلاس، خودش بررسی می‌کند که آیا WAF فعال است یا نه
        // و اگر فعال بود، به هوک init وردپرس با اولویت 0 قلاب می‌شود
        (new RSP_Module_WAF())->init();
    }

    // Hardening: هدرها و بلاک مسیرهای حساس
    if (rsp_require('modules/hardening.php') && class_exists('RSP_Module_Hardening')) {
        // init() این کلاس به init و send_headers قلاب می‌شود
        (new RSP_Module_Hardening())->init();
    }

    // File Guard: نوشتن htaccess. و فیلتر آپلود
    if (rsp_require('modules/file-guard.php') && class_exists('RSP_Module_File_Guard')) {
        // init() این کلاس به init و wp_handle_upload_prefilter قلاب می‌شود
        (new RSP_Module_File_Guard())->init();
    }

    // --- ماژول‌هایی که فقط در شرایط خاص لازمند ---

    // گارد 404 و ضد اسپم
    if (rsp_require('modules/guard-404-antispam.php') && class_exists('RSP_Module_Guard_404_AntiSpam')) {
        // init() این کلاس خودش بررسی می‌کند کدام بخش فعال است و به هوک‌های لازم (template_redirect, preprocess_comment و ...) قلاب می‌شود
        (new RSP_Module_Guard_404_AntiSpam())->init();
    }

    // لاگ فعالیت‌ها (فقط برای هرس کردن لاگ)
    if (rsp_require('modules/activity-log.php') && class_exists('RSP_Module_Activity_Log')) {
        // init() این کلاس به init وردپرس قلاب می‌شود تا گاهی لاگ‌ها را هرس کند
        (new RSP_Module_Activity_Log())->init();
    }

    // --- هوک init: برای ماژول‌هایی که به state وردپرس نیاز دارند ---
    add_action('init', function() {

        // ماژول آدرس ورود سفارشی
        if (rsp_require('modules/login-url.php') && class_exists('RSP_Module_Login_Url')) {
            // init() این کلاس قوانین بازنویسی و فیلترها را اضافه می‌کند
            (new RSP_Module_Login_Url())->init();
        }

        // ماژول Brute Force (قلاب به authenticate و wp_login_failed)
        if (rsp_require('modules/brute-force.php') && class_exists('RSP_Module_Brute_Force')) {
            // init() این کلاس خودش بررسی می‌کند که آیا فعال است یا نه
            // و اگر فعال بود، به هوک‌های مربوط به ورود قلاب می‌شود
            (new RSP_Module_Brute_Force())->init();
        }

        // ماژول XML-RPC
        if (rsp_require('modules/xmlrpc.php') && class_exists('RSP_Module_XMLRPC')) {
            // init() این کلاس فیلترهای xmlrpc_enabled و ... را اضافه می‌کند
            (new RSP_Module_XMLRPC())->init();
        }

    }, 5); // اولویت کمتر (زودتر اجرا شود)

    // --- هوک rest_api_init: فقط برای ماژول REST Guard ---
    add_action('rest_api_init', function() {
        if (rsp_require('modules/rest-guard.php') && class_exists('RSP_Module_REST_Guard')) {
            // init() این کلاس فقط به rest_api_init قلاب شده بود، می‌توان مستقیما guard را اجرا کرد
            // یا همچنان از init استفاده کرد که خودش به rest_api_init قلاب شود (کد فعلی از init استفاده کرده)
            $rest_guard = new RSP_Module_REST_Guard();
            // چون خود init() ماژول به rest_api_init قلاب می‌شود، نیازی نیست اینجا دوباره قلاب کنیم.
            // فقط باید مطمئن شویم کلاس لود شده و تنظیماتش ثبت شده.
            // ثبت تنظیمات آن در هوک admin_init خودش انجام می‌شود.
            // اجرای منطق گارد آن هم توسط قلاب خودش در init() انجام می‌شود.
            // پس فقط لود کردن فایل کافی است، اما برای اطمینان init() را صدا می‌زنیم.
             $rest_guard->init();
        }
    }, 5); // اولویت کمتر (زودتر اجرا شود)

});

/* -------------------------------------------------
 * هاردنینگ هدرها (توسط ماژول Hardening انجام می‌شود)
 * [اصلاح] این بخش حذف شد چون ماژول Hardening خودش این کار را در init() انجام می‌دهد
 * ------------------------------------------------- */
// add_action('send_headers', function () { ... }); // <-- حذف شد