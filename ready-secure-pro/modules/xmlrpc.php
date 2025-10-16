<?php
if (!defined('ABSPATH')) { exit; }
class RSP_Module_Xmlrpc implements RSP_Module_Interface {
    public function init(){ add_filter('xmlrpc_enabled','__return_false'); add_filter('wp_headers',[$this,'remove_x_pingback']); }
    public function remove_x_pingback($headers){ if(isset($headers['X-Pingback'])) unset($headers['X-Pingback']); return $headers; }
}
