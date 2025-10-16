<?php
/**
 * Plugin Name: Ready Secure Pro
 * Description: A modular security suite for WordPress by Ready Studio.
 * Version: 2.1.0
 * Author: Ready Studio
 * Text Domain: ready-secure-pro
 * Domain Path: /languages
 */

if (!defined('ABSPATH')) { exit; }

define('RSP_VERSION', '2.1.0');
define('RSP_PATH', plugin_dir_path(__FILE__));
define('RSP_URL', plugin_dir_url(__FILE__));

// Load plugin textdomain for translation
add_action('plugins_loaded', function() {
    load_plugin_textdomain('ready-secure-pro', false, dirname(plugin_basename(__FILE__)) . '/languages/');
});

// Helpers
require_once RSP_PATH . 'includes/helpers.php';

// Core classes
require_once RSP_PATH . 'includes/class-admin.php';
require_once RSP_PATH . 'includes/class-module-interface.php';

// === Modules ===
$modules_to_load = [
    'login-url.php', 'headers.php', 'bruteforce.php', 'xmlrpc.php',
    'hardening.php', 'rest-guard.php', 'activity-log.php', 'fs-permissions.php',
    'waf.php', 'two-factor.php', 'integrity.php',
    'scanners/class-rsp-malware-scanner.php'
];

foreach ($modules_to_load as $module_file) {
    if (file_exists(RSP_PATH . 'modules/' . $module_file)) {
        require_once RSP_PATH . 'modules/' . $module_file;
    }
}

add_action('plugins_loaded', function() {
    (new RSP_Admin())->init();

    $module_classes = [
        'RSP_Module_Login_Url', 'RSP_Module_Headers', 'RSP_Module_BruteForce',
        'RSP_Module_Xmlrpc', 'RSP_Module_Hardening', 'RSP_Module_Rest_Guard',
        'RSP_Module_Activity_Log', 'RSP_Module_FS_Permissions', 'RSP_Module_WAF',
        'RSP_Module_Two_Factor', 'RSP_Module_Integrity', 'RSP_Module_Malware_Scanner'
    ];

    foreach ($module_classes as $cls) {
        if (class_exists($cls) && method_exists($cls, 'init')) {
            (new $cls())->init();
        }
    }
});

// Activation Hook: Create database table and set defaults
register_activation_hook(__FILE__, function() {
    global $wpdb;

    $table_name = $wpdb->prefix . 'rsp_logs';
    $charset_collate = $wpdb->get_charset_collate();

    $sql = "CREATE TABLE $table_name (
        id bigint(20) NOT NULL AUTO_INCREMENT,
        event_type varchar(50) NOT NULL,
        ip_address varchar(100) NOT NULL,
        user_id bigint(20) UNSIGNED DEFAULT 0,
        details text,
        created_at datetime NOT NULL,
        PRIMARY KEY  (id),
        KEY event_type (event_type),
        KEY ip_address (ip_address)
    ) $charset_collate;";

    require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
    dbDelta($sql);

    $defaults = [
        'rsp_login_slug' => 'manager',
        'rsp_headers_hsts' => 1,
        'rsp_bruteforce_max' => 5,
        'rsp_bruteforce_lock_minutes' => 15,
        'rsp_waf_rate_limit' => 120,
        'rsp_waf_window' => 60,
        'rsp_2fa_enforce_role' => ''
    ];

    foreach ($defaults as $key => $value) {
        if (!get_option($key)) {
            update_option($key, $value);
        }
    }

    flush_rewrite_rules();
});

// Deactivation Hook
register_deactivation_hook(__FILE__, function() {
    flush_rewrite_rules();
});