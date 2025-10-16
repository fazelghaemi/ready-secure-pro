<?php
    if (!defined('ABSPATH')) { exit; }

    /**
     * Ready Secure Pro — Helpers
     * - تشخیص IP کاربر پشت پروکسی/CDN به‌صورت ایمن (IPv4/IPv6)
     * - اکشن لاگ مرکزی: do_action('rsp_activity_log', $event, array $payload)
     * - اکسپورت/ایمپورت تنظیمات افزونه
     * - ابزارهای کوچک عمومی
     */

    /**
     * برخی نسخه‌های قدیمی PHP (قبل از 7.0) تابع intdiv ندارند؛
     * این تعریف کمکی باعث می‌شود افزونه روی آنها نیز اجرا شود.
     */
    if (!function_exists('intdiv')) {
        function intdiv($dividend, $divisor) {
            if ($divisor == 0) {
                trigger_error('Division by zero', E_USER_WARNING);
                return 0;
            }
            return ($dividend - ($dividend % $divisor)) / $divisor;
        }
    }

    /* ======================= IP Utilities ======================= */
    if (!function_exists('rsp_is_valid_ip')) {
        function rsp_is_valid_ip($ip){
            return (bool) filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_RES_RANGE);
        }
    }

    if (!function_exists('rsp_is_private_ip')) {
        function rsp_is_private_ip($ip){
            if (!filter_var($ip, FILTER_VALIDATE_IP)) return false;
            if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE) === false) return true;
            // IPv6: fc00::/7 (Unique local) + fe80::/10 (link-local)
            if (strpos($ip, ':') !== false) {
                $ipv6 = @inet_pton($ip); if ($ipv6 === false) return false;
                $fc00 = @inet_pton('fc00::'); $fe80 = @inet_pton('fe80::');
                if (strncmp($ipv6, $fc00, 1) === 0) return true;
                if (strncmp($ipv6, $fe80, 2) === 0) return true;
            }
            return false;
        }
    }

    if (!function_exists('rsp_ip_in_cidr')) {
        function rsp_ip_in_cidr($ip, $cidr){
            if (!is_string($ip) || !is_string($cidr) || $ip === '' || $cidr === '') return false;
            if (strpos($cidr, '/') === false) return strcasecmp($ip, $cidr) === 0;
            list($subnet, $mask) = explode('/', $cidr, 2);
            $mask = (int) $mask;
            $ip_bin  = @inet_pton($ip);
            $net_bin = @inet_pton($subnet);
            if ($ip_bin === false || $net_bin === false) return false;
            $len = strlen($ip_bin);
            $bytes = intdiv($mask, 8);
            $bits  = $mask % 8;
            if ($bytes > $len) $bytes = $len;
            if (strncmp($ip_bin, $net_bin, $bytes) !== 0) return false;
            if ($bits === 0) return true;
            $mask_byte = (0xFF00 >> $bits) & 0xFF;
            return ((ord($ip_bin[$bytes]) & $mask_byte) === (ord($net_bin[$bytes]) & $mask_byte));
        }
    }

    if (!function_exists('rsp_client_ip')) {
        /**
         * IP واقعی کاربر با درنظرگرفتن پروکسی‌های مورداعتماد.
         *
         * فیلترها:
         *  - rsp_trusted_proxies: (array) لیست IP/CIDR پروکسی‌های مورداعتماد (پیش‌فرض خالی)
         *  - rsp_client_ip_headers: (array) ترتیب هدرهایی که بررسی می‌شوند
         */
        function rsp_client_ip(){
            $remote = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '';
            $trusted = apply_filters('rsp_trusted_proxies', []);
            $is_trusted = false;
            foreach ((array)$trusted as $tp){
                if (rsp_ip_in_cidr($remote, $tp)) { $is_trusted = true; break; }
            }

            $order = apply_filters('rsp_client_ip_headers', [
                'HTTP_CF_CONNECTING_IP',
                'HTTP_X_FORWARDED_FOR',
                'HTTP_X_REAL_IP',
            ]);

            $candidates = [];
            foreach ($order as $key){
                if (!isset($_SERVER[$key])) continue;
                $val = trim((string) $_SERVER[$key]);
                if ($val === '') continue;
                if ($key === 'HTTP_X_FORWARDED_FOR'){
                    foreach (preg_split('/\s*,\s*/', $val) as $xip){ $candidates[] = $xip; }
                } else {
                    $candidates[] = $val;
                }
            }

            if (!$is_trusted || empty($candidates)){
                return $remote ?: '0.0.0.0';
            }

            foreach ($candidates as $ip){
                $ip = trim($ip);
                if (!rsp_is_valid_ip($ip)) continue;
                if (rsp_is_private_ip($ip)) continue;
                return $ip;
            }
            return $remote ?: '0.0.0.0';
        }
    }

    /* ======================= Activity Log ======================= */
    if (!function_exists('rsp_activity_log_write')) {
        function rsp_activity_log_write($event, $payload = []){
            try {
                $rows = get_option('rsp_activity_log', []);
                if (!is_array($rows)) $rows = [];
                $rows[] = [
                    'ts'   => current_time('timestamp', true),
                    'ip'   => function_exists('rsp_client_ip') ? rsp_client_ip() : (isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : ''),
                    'ua'   => isset($_SERVER['HTTP_USER_AGENT']) ? substr($_SERVER['HTTP_USER_AGENT'], 0, 190) : '',
                    'evt'  => (string) $event,
                    'data' => is_array($payload) ? $payload : (array) $payload,
                ];
                $max = 1000;
                $len = count($rows);
                if ($len > $max) $rows = array_slice($rows, $len - $max);
                update_option('rsp_activity_log', $rows, false);
            } catch (\Throwable $e) {
                // Fail silently
            }
        }
        add_action('rsp_activity_log', 'rsp_activity_log_write', 10, 2);
    }

    /* ======================= Options Export/Import ======================= */
    if (!function_exists('rsp_option_export')) {
        function rsp_option_export(){
            global $wpdb;
            $like = $wpdb->esc_like('rsp_') . '%';
            $rows = $wpdb->get_results($wpdb->prepare("SELECT option_name, option_value FROM {$wpdb->options} WHERE option_name LIKE %s", $like), ARRAY_A);
            $out = [];
            foreach ((array)$rows as $r){
                $name = $r['option_name'];
                if ($name === 'rsp_activity_log') continue;
                $val  = maybe_unserialize($r['option_value']);
                $out[$name] = $val;
            }
            return $out;
        }
    }

    if (!function_exists('rsp_option_import')) {
        function rsp_option_import(array $data){
            foreach ($data as $k=>$v){
                if (strpos($k, 'rsp_') !== 0) continue;
                update_option($k, $v, false);
            }
            return true;
        }
    }

    /* ======================= Misc Helpers ======================= */
    if (!function_exists('rsp_str_limit')) {
        function rsp_str_limit($s, $n = 190){
            $s = (string)$s;
            return mb_strlen($s, 'UTF-8') > $n ? (mb_substr($s, 0, $n, 'UTF-8').'…') : $s;
        }
    }

    if (!function_exists('rsp_bool')) {
        function rsp_bool($v){ return in_array($v, [1, '1', true, 'true', 'on', 'yes'], true); }
    }

    if (!function_exists('rsp_array_get')) {
        function rsp_array_get($arr, $key, $def=null){ return (is_array($arr) && array_key_exists($key,$arr)) ? $arr[$key] : $def; }
    }

    /* ======================= Security Headers Helpers (optional) ======================= */
    if (!function_exists('rsp_send_header_once')) {
        function rsp_send_header_once($name, $value){
            if (headers_sent()) return;
            foreach (headers_list() as $h){ if (stripos($h, $name.':') === 0) return; }
            header($name.': '.$value, true);
        }
    }
