<?php
/**
 * Plugin Name: Ready Secure Pro
 * Description: مجموعه ابزارهای امنیت وردپرس (WAF سبک، گارد 404، ضداسپم دیدگاه، تغییر آدرس ورود، File Guard، هاردنینگ و اسکن‌ها)
 * Version:     2.4.3
 * Author:      Ready Studio
 * Text Domain: ready-secure-pro
 */

if (!defined('ABSPATH')) { exit; }

/* -------------------------------------------------
 * ثابت‌ها
 * ------------------------------------------------- */
if (!defined('RSP_VERSION')) define('RSP_VERSION', '2.4.3');
if (!defined('RSP_PATH'))    define('RSP_PATH', plugin_dir_path(__FILE__));
if (!defined('RSP_URL'))     define('RSP_URL',  plugin_dir_url(__FILE__));

/* -------------------------------------------------
 * سازگاری: Interface عمومی ماژول‌ها (اگر از قبل نیست)
 * ------------------------------------------------- */
if (!interface_exists('RSP_Module_Interface')) {
    interface RSP_Module_Interface { public function init(); }
}

/* -------------------------------------------------
 * Helperهای ضروری (اگر در جای دیگر تعریف نشده‌اند)
 * ------------------------------------------------- */
if (!function_exists('rsp_client_ip')) {
    function rsp_client_ip() {
        $keys = ['HTTP_CF_CONNECTING_IP','HTTP_X_FORWARDED_FOR','HTTP_X_REAL_IP','REMOTE_ADDR'];
        foreach ($keys as $k) {
            if (!empty($_SERVER[$k])) {
                $v = trim((string) $_SERVER[$k]);
                if ($k === 'HTTP_X_FORWARDED_FOR' && strpos($v, ',') !== false) {
                    $v = trim(explode(',', $v)[0]);
                }
                if (filter_var($v, FILTER_VALIDATE_IP)) return $v;
            }
        }
        return '';
    }
}
if (!function_exists('rsp_ip_in_cidr')) {
    function rsp_ip_in_cidr($ip, $cidr) {
        if (!$ip || strpos($cidr, '/') === false) return false;
        list($subnet, $mask) = explode('/', $cidr, 2);
        $mask = (int) $mask;
        $ip_long     = ip2long($ip);
        $subnet_long = ip2long($subnet);
        if ($ip_long === false || $subnet_long === false) return false;
        $mask = ~((1 << (32 - $mask)) - 1);
        return (($ip_long & $mask) === ($subnet_long & $mask));
    }
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
 * بوت‌استرپ افزونه
 * ------------------------------------------------- */
add_action('plugins_loaded', function () {

    // [اصلاح ۱] بارگذاری Helper ها برای رفع Fatal Error
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
        
        // [اصلاح ۳] ماژول‌های جامانده اضافه شدند
        'modules/login-url.php'           => 'RSP_Module_Login_Url',
        'modules/xmlrpc.php'              => 'RSP_Module_XMLRPC',
        'modules/activity-log.php'        => 'RSP_Module_Activity_Log',
        
        // [اصلاح ۲] ماژول‌های اسکنر حذف شدند
        // 'modules/integrity.php'           => 'RSP_Module_Integrity',
        // 'modules/malware-scanner.php'     => 'RSP_Module_Malware_Scanner', // مسیر این فایل اشتباه بود
        // 'modules/scanners/class-rsp-malware-scanner.php' => 'RSP_Module_Malware_Scanner', // مسیر صحیح
        // 'modules/fs-permissions.php'      => 'RSP_Module_FS_Permissions',
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
        // مسیر فایل اسکنر بدافزار متفاوت بود، اصلاح شد
        if ($class === 'RSP_Module_Malware_Scanner' && $file === 'modules/malware-scanner.php') {
             $file = 'modules/scanners/class-rsp-malware-scanner.php';
        }

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
                do_action('rsp_activity_log', 'module_init_error', [
                    'module' => $class, 'error' => $e->getMessage()
                ]);
            }
        }
    }
});

/* -------------------------------------------------
 * هاردنینگ هدرها (HSTS فقط روی HTTPS)
 * ------------------------------------------------- */
add_action('send_headers', function () {
    // این توابع اکنون باید بدون خطا کار کنند چون helpers.php لود شده است
    
    // مثال: HSTS فقط در HTTPS
    if (get_option('rsp_headers_hsts', 1) && is_ssl()) {
        // تابع rsp_send_header_once تعریف شده در helpers.php
        if (function_exists('rsp_send_header_once')) {
            rsp_send_header_once('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
        } else {
            header('Strict-Transport-Security: max-age=31536000; includeSubDomains; preload');
        }
    }
    
    if (function_exists('rsp_send_header_once')) {
        rsp_send_header_once('Referrer-Policy', esc_attr(get_option('rsp_headers_referrer', 'no-referrer')));
        rsp_send_header_once('X-Frame-Options', 'SAMEORIGIN');
        rsp_send_header_once('X-Content-Type-Options', 'nosniff');
    } else {
        // Fallback در صورتی که تابع به هر دلیلی لود نشده باشد
        header('Referrer-Policy: ' . esc_attr(get_option('rsp_headers_referrer', 'no-referrer')));
        header('X-Frame-Options: SAMEORIGIN');
        header('X-Content-Type-Options: nosniff');
    }
}, 11);