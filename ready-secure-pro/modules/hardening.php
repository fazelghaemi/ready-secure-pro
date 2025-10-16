<?php
if (!defined('ABSPATH')) { exit; }
class RSP_Module_Hardening implements RSP_Module_Interface {
    public function init(){
        if(!defined('DISALLOW_FILE_EDIT')) define('DISALLOW_FILE_EDIT', true);
        remove_action('wp_head','wp_generator'); add_filter('the_generator','__return_empty_string');
        add_action('template_redirect', [$this,'block_author_enum']);
        add_action('init', [$this,'deny_sensitive_files']);
    }
    public function block_author_enum(){
        if (is_admin()) return;
        if (isset($_REQUEST['author']) && is_numeric($_REQUEST['author'])) { status_header(403); exit; }
    }
    public function deny_sensitive_files(){
        $file = basename(parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH));
        $deny = ['readme.html','license.txt','wp-config.php'];
        if (in_array($file,$deny,true)) { status_header(403); exit; }
    }
}
