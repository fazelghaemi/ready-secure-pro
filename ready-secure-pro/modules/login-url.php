<?php
if (!defined('ABSPATH')) { exit; }
class RSP_Module_Login_Url implements RSP_Module_Interface {
    private function slug(){ $s=trim((string)get_option('rsp_login_slug','manager')); return $s? ltrim($s,'/') : 'manager'; }
    private function login_url(){ return home_url('/'.$this->slug().'/'); }
    public function init(){
        add_filter('query_vars', function($vars){ $vars[]='rsp_custom_login'; return $vars; });
        add_action('init', function(){ add_rewrite_tag('%rsp_custom_login%','1'); add_rewrite_rule('^'.preg_quote($this->slug(),'/').'/?$','index.php?rsp_custom_login=1','top'); }, 9);
        add_action('template_redirect', [$this,'render_custom'], 0);
        add_action('init', [$this,'block_wp_login'], 1);
        add_filter('login_url', [$this,'filter_login_url'], 10, 3);
        add_filter('site_url',  [$this,'filter_site_url'], 10, 3);
        add_filter('network_site_url', [$this,'filter_site_url'], 10, 3);
    }
    public function render_custom(){
        $is_qv = (get_query_var('rsp_custom_login') === '1');
        $path = isset($_SERVER['REQUEST_URI'])? (string) parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH) : '';
        $want = '/'.$this->slug().'/';
        if (!$is_qv && !($path===$want || $path===rtrim($want,'/'))) return;
        if (!defined('DONOTCACHEPAGE')) define('DONOTCACHEPAGE', true);
        if (!headers_sent()) { nocache_headers(); header('X-RSP-Login: custom'); }
        global $pagenow; $pagenow='wp-login.php';
        $login_php = ABSPATH.'wp-login.php';
        if (file_exists($login_php)) { require $login_php; exit; }
        wp_die(__('فایل ورود وردپرس یافت نشد.','ready-secure-pro'));
    }
    public function block_wp_login(){
        $uri = isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '';
        $path = $uri ? parse_url($uri, PHP_URL_PATH) : '';
        if (!$path || stripos($path,'/wp-login.php')===false) return;
        $allowed = apply_filters('rsp_login_allowed_actions', ['logout','lostpassword','retrievepassword','resetpass','rp','postpass']);
        $action = isset($_REQUEST['action']) ? strtolower((string) $_REQUEST['action']) : '';
        if (!in_array($action, (array)$allowed, true)) { wp_safe_redirect($this->login_url(),302); exit; }
    }
    public function filter_login_url($url,$redirect,$force){ $u=$this->login_url(); $args=[]; if($redirect) $args['redirect_to']=$redirect; if($force) $args['reauth']='1'; return $args? add_query_arg($args,$u):$u; }
    public function filter_site_url($url,$path,$scheme){ if (is_string($url) && strpos($url,'wp-login.php')!==false) return $this->login_url(); return $url; }
}
