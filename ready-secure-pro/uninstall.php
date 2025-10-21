<?php
if (!defined('WP_UNINSTALL_PLUGIN')) { exit; }
global $wpdb;
$like = $wpdb->esc_like('rsp_').'%';
$wpdb->query($wpdb->prepare("DELETE FROM {$wpdb->options} WHERE option_name LIKE %s", $like));
$table = $wpdb->prefix.'rsp_logs';
$wpdb->query("DROP TABLE IF EXISTS $table");
