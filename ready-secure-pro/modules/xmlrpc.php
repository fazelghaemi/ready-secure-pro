<?php
if (!defined('ABSPATH')) { exit; }
class RSP_Module_XMLRPC implements RSP_Module_Interface {
    public function init(){
        add_filter('xmlrpc_enabled','__return_false',99);
        add_filter('wp_headers', function($h){ if(isset($h['X-Pingback'])) unset($h['X-Pingback']); return $h; }, 11);
        add_filter('xmlrpc_methods', function($m){ unset($m['pingback.ping'],$m['pingback.extensions.getPingbacks']); return $m; }, 11);
    }
}
