<?php
if (!defined('ABSPATH')) { exit; }
class RSP_Module_Activity_Log implements RSP_Module_Interface {
    public function init(){ add_action('init',[$this,'maybe_prune'],11); }
    public function maybe_prune(){
        if (rand(1,100) < 95) return;
        global $wpdb; $table=$wpdb->prefix.'rsp_logs';
        try{ $wpdb->query($wpdb->prepare("DELETE FROM $table WHERE id < (SELECT MIN(id) FROM (SELECT id FROM $table ORDER BY id DESC LIMIT %d) t)", 1000)); }catch(\Throwable $e){}
    }
}
