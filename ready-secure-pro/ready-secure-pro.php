<?php
/**
 * Plugin Name: Ready Secure Pro
 * Description: سویت امنیتی ماژولار وردپرس با هویت بصری Ready Studio — حفاظت از محتوا، فایروال و حفاظت از فایل‌ها، امنیت کامل ورود (Login URL/2FA/Brute-Force)، مسدودسازی هوشمند 404، اسکن بدافزار، هاردنینگ، کاهش اسپم دیدگاه‌ها و هدرهای امنیتی.
 * Version: 2.2.0
 * Author: Ready Studio
 * Text Domain: ready-secure-pro
 * Domain Path: /languages
 */

if ( ! defined('ABSPATH') ) { exit; }

/**
 * ثوابت عمومی
 */
define('RSP_VERSION', '2.2.0');
define('RSP_PATH', plugin_dir_path(__FILE__));
define('RSP_URL',  plugin_dir_url(__FILE__));

/**
 * بارگذاری ترجمه‌ها
 */
add_action('init', function () {
    load_plugin_textdomain('ready-secure-pro', false, dirname(plugin_basename(__FILE__)) . '/languages/');
});

/**
 * اتولودر ساده برای کلاس‌های داخلی (پیشوند RSP_)
 */
spl_autoload_register(function ($class) {
    if (strpos($class, 'RSP_') !== 0) return;
    $file = 'includes/class-' . strtolower(str_replace('RSP_', '', $class)) . '.php';
    $path = RSP_PATH . $file;
    if (file_exists($path)) require_once $path;
});

/** فایل‌های کمکی و هستهٔ پنل ادمین */
if (file_exists(RSP_PATH . 'includes/helpers.php'))                require_once RSP_PATH . 'includes/helpers.php';
if (file_exists(RSP_PATH . 'includes/class-admin.php'))            require_once RSP_PATH . 'includes/class-admin.php';
if (file_exists(RSP_PATH . 'includes/class-module-interface.php')) require_once RSP_PATH . 'includes/class-module-interface.php';

/**
 * ماژول‌ها — هرکدام مشروط بارگذاری می‌شوند تا در صورت نبود فایل Fatal رخ ندهد
 * نام‌گذاری ماژول‌های جدید مطابق فیچرلیست: content-protect, smart-404, antispam, file-guard
 */
$__rsp_modules_files = [
    // ورود و دسترسی
    'modules/login-url.php',        // تغییر آدرس ورود (مثلاً /manager)
    'modules/bruteforce.php',       // قفل Brute-Force
    'modules/two-factor.php',       // TOTP 2FA

    // هدرها و هاردنینگ
    'modules/headers.php',          // HSTS/CSP/COOP/COEP/CORP/…
    'modules/hardening.php',        // غیرفعال‌سازی ویرایشگر، پنهان‌سازی نسخه، ضد enumeration
    'modules/rest-guard.php',       // محدودسازی REST API برای ناشناس‌ها
    'modules/xmlrpc.php',           // غیرفعال‌سازی XML-RPC

    // فایروال/حفاظت فایل و لاگ‌ها
    'modules/waf.php',              // WAF سبک + Rate Limit
    'modules/file-guard.php',       // ← جدید: محافظت از فایل‌ها (uploads .htaccess / اسکن PHP)
    'modules/activity-log.php',     // لاگ مرکزی رویدادها
    'modules/fs-permissions.php',   // اسکن سطح دسترسی فایل/پوشه

    // 404 هوشمند و آنتی‌اسپم
    'modules/smart-404.php',        // ← جدید: مسدودسازی هوشمند IP بر اساس رگبار 404
    'modules/antispam.php',         // ← جدید: هانی‌پات/تأخیر ارسال/Nonce برای دیدگاه‌ها

    // یکپارچگی/بدافزار
    'modules/integrity.php',        // چکسام هسته
    'modules/malware.php',          // ← جدید: اسکنر بدافزار (رَپِر برای کلاس اسکن)

    // اسکنرها (کلاس‌ها)
    'modules/scanners/class-rsp-malware-scanner.php',
];
foreach ($__rsp_modules_files as $__f) {
    $__p = RSP_PATH . $__f;
    if (file_exists($__p)) require_once $__p;
}

/**
 * بوت: پنل ادمین + راه‌اندازی تمام ماژول‌های موجود
 */
add_action('plugins_loaded', function () {
    if (class_exists('RSP_Admin')) {
        (new RSP_Admin())->init();
    }

    $classes = [
        // ورود
        'RSP_Module_Login_Url',
        'RSP_Module_BruteForce',
        'RSP_Module_Two_Factor',

        // هاردنینگ/هدرها
        'RSP_Module_Headers',
        'RSP_Module_Hardening',
        'RSP_Module_Rest_Guard',
        'RSP_Module_Xmlrpc',

        // فایروال/فایل/لاگ
        'RSP_Module_WAF',
        'RSP_Module_File_Guard',    // جدید
        'RSP_Module_Activity_Log',
        'RSP_Module_FS_Permissions',

        // 404/اسپم
        'RSP_Module_Smart_404',     // جدید
        'RSP_Module_AntiSpam',      // جدید

        // یکپارچگی/بدافزار
        'RSP_Module_Integrity',
        'RSP_Module_Malware',       // جدید
    ];

    foreach ($classes as $cls) {
        if (class_exists($cls)) {
            try { (new $cls())->init(); } catch (\Throwable $e) {
                if (function_exists('error_log')) error_log('[Ready Secure Pro] Module boot error: ' . $cls . ' → ' . $e->getMessage());
            }
        }
    }
});

/**
 * اکتیویشن: پیش‌فرض‌های امن و ری‌رایت برای اسلاگ ورود
 */
register_activation_hook(__FILE__, function () {
    // ورود
    add_option('rsp_login_slug', 'manager');
    add_option('rsp_bruteforce_max', 5);
    add_option('rsp_bruteforce_lock_minutes', 15);
    add_option('rsp_bruteforce_whitelist', '');
    add_option('rsp_2fa_enforce_role', ''); // مثال: administrator

    // هدرها
    add_option('rsp_headers_hsts', 1);
    add_option('rsp_headers_mode', 'report-only');
    add_option('rsp_headers_csp', "default-src 'self'; img-src 'self' data:;");

    // WAF / Rate limit
    add_option('rsp_waf_enabled', 1);
    add_option('rsp_waf_rate_limit', 120); // تعداد درخواست در پنجره
    add_option('rsp_waf_window', 60);      // طول پنجره ثانیه

    // محافظت از فایل‌ها (uploads)
    add_option('rsp_file_guard_disable_php_uploads', 1);
    add_option('rsp_file_guard_auto_index', 1); // index.html در دایرکتوری‌های حساس

    // 404 هوشمند
    add_option('rsp_404_enable', 1);
    add_option('rsp_404_threshold', 20);        // حداکثر 404 در پنجره
    add_option('rsp_404_window', 300);          // پنجره 5 دقیقه‌ای
    add_option('rsp_404_block_minutes', 60);    // قفل 60 دقیقه

    // آنتی‌اسپم دیدگاه‌ها
    add_option('rsp_antispam_enable', 1);
    add_option('rsp_antispam_min_seconds', 5);  // حداقل زمان بین load و submit
    add_option('rsp_antispam_honeypot', 1);

    // حفاظت از محتوا (فرانت)
    add_option('rsp_content_protect_enable', 1); // منع راست‌کلیک/کپی/دِرَگ تصویر

    // ری‌رایت اسلاگ ورود
    $slug = get_option('rsp_login_slug', 'manager');
    add_rewrite_tag('%rsp_custom_login%', '1');
    add_rewrite_rule('^' . preg_quote($slug, '/') . '/?$', 'index.php?rsp_custom_login=1', 'top');

    flush_rewrite_rules();
});

/**
 * دی‌اکتیویشن: فقط فلش ری‌رایت
 */
register_deactivation_hook(__FILE__, function () {
    flush_rewrite_rules();
});