<?php
if (!defined('ABSPATH')) { exit; }

class RSP_Module_Activity_Log implements RSP_Module_Interface {
    public function init() {
        add_action('rsp_activity_log', [$this, 'log_event'], 10, 2);
    }

    /**
     * Logs an event to the custom database table.
     *
     * @param string $type The type of event (e.g., 'login_failed', 'waf_block').
     * @param array  $payload Additional data related to the event.
     */
    public function log_event($type, $payload = []) {
        global $wpdb;
        $table_name = $wpdb->prefix . 'rsp_logs';

        $data = [
            'event_type' => sanitize_key($type),
            'ip_address' => rsp_client_ip(),
            'user_id'    => get_current_user_id(), // Will be 0 for anonymous users
            'details'    => !empty($payload) ? wp_json_encode($payload) : null,
            'created_at' => current_time('mysql', 1)
        ];

        // Ensure we capture user ID for login events
        if (isset($payload['uid'])) {
            $data['user_id'] = absint($payload['uid']);
        }

        $wpdb->insert($table_name, $data);
        
        // Prune old logs to keep the table size manageable
        $this->prune_logs();
    }

    /**
     * Deletes old log entries to prevent the database table from growing indefinitely.
     */
    private function prune_logs() {
        // Run this check randomly to avoid overhead on every request
        if (rand(1, 100) > 95) {
            return;
        }

        global $wpdb;
        $table_name = $wpdb->prefix . 'rsp_logs';
        
        // Get the total number of logs
        $total_logs = $wpdb->get_var("SELECT COUNT(id) FROM {$table_name}");
        $max_logs = apply_filters('rsp_max_log_entries', 2000);

        if ($total_logs > $max_logs) {
            // Find the ID of the Nth most recent log entry
            $prune_id = $wpdb->get_var(
                $wpdb->prepare(
                    "SELECT id FROM {$table_name} ORDER BY id DESC LIMIT 1 OFFSET %d",
                    $max_logs
                )
            );
            
            if ($prune_id) {
                // Delete all logs older than this ID
                $wpdb->query(
                    $wpdb->prepare(
                        "DELETE FROM {$table_name} WHERE id <= %d",
                        $prune_id
                    )
                );
            }
        }
    }
}