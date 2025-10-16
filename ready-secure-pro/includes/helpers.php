<?php
if (!defined('ABSPATH')) { exit; }

function rsp_client_ip() {
    $keys = ['HTTP_CF_CONNECTING_IP','HTTP_X_REAL_IP','HTTP_X_FORWARDED_FOR','REMOTE_ADDR'];
    foreach ($keys as $k) {
        if (!empty($_SERVER[$k])) {
            $ip = explode(',', $_SERVER[$k])[0];
            return trim($ip);
        }
    }
    return '0.0.0.0';
}

function rsp_option_export() {
    global $wpdb;
    $options = $wpdb->get_results( "SELECT option_name, option_value FROM {$wpdb->options} WHERE option_name LIKE 'rsp_%'", ARRAY_A );
    $out = [];
    foreach ($options as $row) {
        $out[$row['option_name']] = maybe_unserialize($row['option_value']);
    }
    return $out;
}

function rsp_array_get($arr,$key,$default=null){ return isset($arr[$key]) ? $arr[$key] : $default; }
