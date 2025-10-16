<?php
if (!defined('ABSPATH')) { exit; }
class RSP_Module_Rest_Guard implements RSP_Module_Interface {
    public function init(){ add_filter('rest_authentication_errors', [$this,'guard']); }
    public function guard($result){
        if (!empty($result)) return $result;
        $route = isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '';
        if (strpos($route, '/wp-json/wp/v2/users') !== false && !is_user_logged_in())
            return new WP_Error('rest_forbidden', __('User listing is restricted.','ready-secure-pro'), ['status'=>401]);
        return $result;
    }
}
