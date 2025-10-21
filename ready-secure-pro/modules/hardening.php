<?php
if (!defined('ABSPATH')) { exit; }
class RSP_Module_Hardening implements RSP_Module_Interface {
    public function init(){
        add_action('init', [$this,'block_author_enum'], 1);
        add_action('init', [$this,'block_sensitive_paths'], 2);
        add_action('send_headers', [$this,'headers'], 20);
        add_action('admin_init', [$this,'settings']);
        if (!defined('DISALLOW_FILE_EDIT')) define('DISALLOW_FILE_EDIT', true);
    }
    public function settings(){
        register_setting('rsp_settings','rsp_headers_hsts',['type'=>'boolean','default'=>1]);
        register_setting('rsp_settings','rsp_headers_referrer',['type'=>'string','default'=>'no-referrer']);
        add_settings_section('rsp_headers', __('هدرهای امنیتی HTTP','ready-secure-pro'), function(){ echo '<p>'.__('HSTS, Referrer-Policy و X-Frame-Options','ready-secure-pro').'</p>'; }, 'rsp_settings');
        add_settings_field('rsp_headers_hsts', __('HSTS فعال؟','ready-secure-pro'), function(){ echo '<input type="checkbox" name="rsp_headers_hsts" value="1" '.checked(get_option('rsp_headers_hsts',1),1,false).'>'; }, 'rsp_settings','rsp_headers');
        add_settings_field('rsp_headers_referrer', __('Referrer-Policy','ready-secure-pro'), function(){ echo '<input type="text" name="rsp_headers_referrer" value="'.esc_attr(get_option('rsp_headers_referrer','no-referrer')).'">'; }, 'rsp_settings','rsp_headers');
    }
    public function headers(){
        if (get_option('rsp_headers_hsts',1)) rsp_send_header_once('Strict-Transport-Security','max-age=31536000; includeSubDomains; preload');
        rsp_send_header_once('X-Frame-Options','SAMEORIGIN');
        rsp_send_header_once('Referrer-Policy', (string) get_option('rsp_headers_referrer','no-referrer'));
    }
    public function block_author_enum(){ if (is_admin()) return; if (isset($_GET['author'])){ status_header(404); exit; } }
    public function block_sensitive_paths(){
        $uri = isset($_SERVER['REQUEST_URI'])? $_SERVER['REQUEST_URI']: '';
        foreach (['/.env','/.git','/wp-config.php','/phpinfo.php','/vendor/','/backup.zip'] as $b){ if (stripos($uri,$b)!==false){ status_header(404); exit; } }
    }
}
class RSP_Module_Headers extends RSP_Module_Hardening {}
