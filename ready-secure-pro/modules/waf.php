<?php
if (!defined('ABSPATH')) { exit; }
class RSP_Module_WAF implements RSP_Module_Interface {
    public function init(){
        add_action('init', [$this,'inspect'], 0);
    }
    private function rate_limit_key($ip){
        $win = max(10, (int) get_option('rsp_waf_window', 60));
        $bucket = floor(time() / $win);
        return 'rsp_waf_' . md5($ip.'|'.$bucket);
    }
    public function inspect(){
        if (!get_option('rsp_waf_enabled',1)) return;
        $ip = rsp_client_ip();
        // Simple patterns for SQLi/XSS/LFI
        $hay = strtolower($_SERVER['REQUEST_URI'] . ' ' . ( $_SERVER['QUERY_STRING'] ?? '' ) . ' ' . file_get_contents('php://input'));
        $patterns = [
            'union select','/**/union/**/select',' or 1=1','<script',' onerror=',' onload=','%3cscript','../','%2e%2e/','<?php','php://input','sleep(','benchmark('
        ];
        foreach ($patterns as $p){
            if (strpos($hay, $p) !== false){
                do_action('rsp_activity_log','waf_block',['ip'=>$ip,'pattern'=>$p]);
                status_header(403); exit;
            }
        }
        // Rate limit unauthenticated bursts to login & admin-ajax
        $uri = $_SERVER['REQUEST_URI'];
        if (!is_user_logged_in() && (strpos($uri,'/wp-login')!==false || strpos($uri,'admin-ajax.php')!==false)){
            $limit = max(30,(int)get_option('rsp_waf_rate_limit',120));
            $key = $this->rate_limit_key($ip);
            $count = (int) get_transient($key); $count++;
            set_transient($key, $count, max(10,(int)get_option('rsp_waf_window',60)));
            if ($count > $limit){
                do_action('rsp_activity_log','rate_limit',['ip'=>$ip,'count'=>$count]);
                status_header(429); exit;
            }
        }
    }
}
