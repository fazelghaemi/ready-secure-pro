<?php
if (!defined('ABSPATH')) { exit; }

class RSP_Module_Headers implements RSP_Module_Interface {
    public function init() { add_action('send_headers', [$this,'send']); }
    public function send() {
        if (is_admin()) { /* allow admin if conflicts */ }
        if (get_option('rsp_headers_hsts',1)) header('Strict-Transport-Security: max-age=31536000; includeSubDomains; preload');
        header('X-Content-Type-Options: nosniff');
        header('X-XSS-Protection: 0');
        header('Referrer-Policy: strict-origin-when-cross-origin');
        header('Permissions-Policy: camera=(), microphone=(), geolocation=()');
        header('Cross-Origin-Opener-Policy: same-origin');
        header('Cross-Origin-Embedder-Policy: require-corp');
        header('Cross-Origin-Resource-Policy: same-site');
        $mode = get_option('rsp_headers_mode','report-only');
        $csp  = trim((string) get_option('rsp_headers_csp',"default-src 'self'; img-src 'self' data:;"));
        if ($csp !== '') {
            if ($mode === 'enforce') header('Content-Security-Policy: '.$csp);
            else header('Content-Security-Policy-Report-Only: '.$csp);
        }
    }
}
