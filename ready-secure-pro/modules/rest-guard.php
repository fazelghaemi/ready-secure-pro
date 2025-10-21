<?php
if (!defined('ABSPATH')) { exit; }
class RSP_Module_REST_Guard implements RSP_Module_Interface {
    public function init(){ add_action('rest_api_init',[$this,'guard'],9); add_action('admin_init',[$this,'settings']); }
    public function settings(){
        register_setting('rsp_settings','rsp_rest_mode',['type'=>'string','default'=>'restricted']);
        add_settings_section('rsp_rest', __('محافظت REST API','ready-secure-pro'), function(){ echo '<p>'.__('جلوگیری از enumerate کاربران و محدودسازی مهمان.','ready-secure-pro').'</p>'; }, 'rsp_settings_xmlrpc_rest');
        add_settings_field('rsp_rest_mode', __('حالت','ready-secure-pro'), function(){ $v=get_option('rsp_rest_mode','restricted'); echo '<select name="rsp_rest_mode"><option value="open"'.selected($v,'open',false).'>open</option><option value="restricted"'.selected($v,'restricted',false).'>restricted</option><option value="private"'.selected($v,'private',false).'>private</option></select>'; }, 'rsp_settings_xmlrpc_rest','rsp_rest');
    }
    public function guard(){
        $mode=get_option('rsp_rest_mode','restricted'); if($mode==='open') return;
        add_filter('rest_authentication_errors', function($result){ if(!empty($result)) return $result; if(is_user_logged_in()) return $result; if(get_option('rsp_rest_mode','restricted')==='private') return new WP_Error('forbidden',__('دسترسی REST فقط برای کاربران واردشده مجاز است.','ready-secure-pro'),['status'=>401]); return $result; }, 99);
        add_filter('rest_endpoints', function($endpoints){ if(is_user_logged_in()) return $endpoints; if(isset($endpoints['/wp/v2/users'])) unset($endpoints['/wp/v2/users']); if(isset($endpoints['/wp/v2/users/(?P<id>[\d]+)'])) unset($endpoints['/wp/v2/users/(?P<id>[\d]+)']); return $endpoints; }, 99);
    }
}
