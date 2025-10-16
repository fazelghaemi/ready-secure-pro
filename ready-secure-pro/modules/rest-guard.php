<?php
if (!defined('ABSPATH')) { exit; }

/**
 * ماژول: محافظت از REST API (wp-json) + محدودسازی نرخ + لیست سفید مسیرها/فضاها
 *
 * اهداف:
 *  - کنترل سطح دسترسی REST در سه حالت: open | restricted | private
 *    * open: رفتار پیش‌فرض وردپرس (فقط کاربران و اندپوینت‌های حساس بسته می‌شوند)
 *    * restricted (پیش‌فرض): خواندن عمومی GET برای اکثر اندپوینت‌ها، اما users و عملیات حساس فقط برای لاگین‌شده‌ها
 *    * private: کل REST برای مهمان‌ها بسته است مگر در لیست سفید
 *  - مسدودسازی enumerate کاربر: /wp/v2/users/* برای مهمان‌ها
 *  - Rate Limit برای همهٔ درخواست‌های REST بر اساس IP و پنجرهٔ زمانی
 *  - لیست سفید فضاهای نام (namespaces) و مسیرهای خاص (routes) از طریق آپشن/فیلتر
 *  - ثبت رویدادها در لاگ: rest_block, rest_rate_limit
 *
 * گزینه‌ها (Options):
 *  - rsp_rest_mode          (string)   open | restricted | private    — پیش‌فرض: restricted
 *  - rsp_rest_rate_limit    (int)      سقف درخواست در پنجره (پیش‌فرض 120)
 *  - rsp_rest_window        (int)      طول پنجره ثانیه (پیش‌فرض 60)
 *  - rsp_rest_allow_namespaces (string) لیست namespace مجاز (هر خط یک مورد)
 *  - rsp_rest_allow_routes     (string) لیست route مجاز کامل (هر خط یک مورد مانند /contact-form-7/v1/contact-forms/123/feedback)
 */
class RSP_Module_REST_Guard implements RSP_Module_Interface {

    public function init() {
        // حذف اندپوینت‌های users برای مهمان‌ها در لایه‌ی ثبت اندپوینت‌ها
        add_filter('rest_endpoints', [$this, 'strip_user_endpoints_for_guests'], 11);
        // گیت مرکزی + RateLimit قبل از اجرای کال‌بک‌ها
        add_filter('rest_pre_dispatch', [$this, 'gate_and_rate'], 10, 3);
        // اندپوینت تست سبک (اختیاری)
        add_action('rest_api_init', function(){
            register_rest_route('ready-secure-pro/v1', '/ping', [
                'methods'  => 'GET',
                'permission_callback' => '__return_true',
                'callback' => function(){ return new WP_REST_Response(['ok'=>true,'ts'=>time()], 200); }
            ]);
        });
    }

    /* ======================== Endpoint pruning ======================== */
    public function strip_user_endpoints_for_guests($endpoints){
        if (is_user_logged_in()) return $endpoints;
        // حذف /wp/v2/users و زیرمسیرهایش برای مهمان‌ها
        unset($endpoints['/wp/v2/users']);
        foreach (array_keys($endpoints) as $key){
            if (strpos($key, '/wp/v2/users/') === 0) unset($endpoints[$key]);
        }
        return $endpoints;
    }

    /* ======================== Gate + Rate ======================== */
    public function gate_and_rate($response, $server, $request){
        $route  = (string) $request->get_route();          // مانند: /wp/v2/posts
        $method = strtoupper((string) $request->get_method()); // GET/POST/...
        $ip     = function_exists('rsp_client_ip') ? rsp_client_ip() : (isset($_SERVER['REMOTE_ADDR'])? $_SERVER['REMOTE_ADDR'] : '');
        $ua     = isset($_SERVER['HTTP_USER_AGENT']) ? substr($_SERVER['HTTP_USER_AGENT'],0,190) : '';

        // 1) Rate limit برای همهٔ REST (به جز برخی مسیرهای مجاز)
        if ($this->is_rate_limited_target($route)){
            if ($this->rate_limit_exceeded($ip)){
                do_action('rsp_activity_log','rest_rate_limit',[ 'ip'=>$ip, 'route'=>$route, 'ua'=>$ua ]);
                return $this->rest_error(429, __('درخواست‌های بیش از حد به REST API. لطفاً بعداً تلاش کنید.', 'ready-secure-pro'));
            }
        }

        // 2) Gate بر اساس حالت انتخابی
        $mode = $this->mode();
        if ($mode === 'open'){
            // فقط users را برای مهمان‌ها ببند (در بالا هم حذف شده)
            if (!$this->allow_route_for_guest($route, $method)){
                if (!$this->is_allowed_by_whitelist($route)){
                    do_action('rsp_activity_log','rest_block',[ 'ip'=>$ip, 'route'=>$route, 'mode'=>$mode ]);
                    return $this->rest_error(401, __('دسترسی به این اندپوینت محدود شده است.', 'ready-secure-pro'));
                }
            }
            return $response;
        }

        if ($mode === 'restricted'){
            // خواندن GET عمومی برای بیشتر اندپوینت‌ها مجاز است، اما:
            // - users همیشه برای مهمان‌ها بسته است
            // - عملیات غیر GET برای مهمان‌ها مسدود می‌شود مگر در لیست سفید
            $is_guest = !is_user_logged_in();
            if ($is_guest){
                if ($this->is_users_route($route)){
                    do_action('rsp_activity_log','rest_block',[ 'ip'=>$ip, 'route'=>$route, 'mode'=>$mode ]);
                    return $this->rest_error(401, __('این اندپوینت فقط برای کاربران واردشده در دسترس است.', 'ready-secure-pro'));
                }
                if ($method !== 'GET' && !$this->is_allowed_by_whitelist($route)){
                    do_action('rsp_activity_log','rest_block',[ 'ip'=>$ip, 'route'=>$route, 'mode'=>$mode ]);
                    return $this->rest_error(401, __('ارسال داده به REST برای مهمان‌ها مجاز نیست.', 'ready-secure-pro'));
                }
            }
            return $response;
        }

        // private: همه چیز برای مهمان‌ها بسته مگر در لیست سفید
        if (!is_user_logged_in()){
            if (!$this->is_allowed_by_whitelist($route)){
                do_action('rsp_activity_log','rest_block',[ 'ip'=>$ip, 'route'=>$route, 'mode'=>$mode ]);
                return $this->rest_error(401, __('REST API فقط برای کاربران واردشده در دسترس است.', 'ready-secure-pro'));
            }
        }
        return $response;
    }

    /* ======================== Helpers ======================== */
    private function mode(){
        $m = strtolower((string) get_option('rsp_rest_mode','restricted'));
        return in_array($m, ['open','restricted','private'], true) ? $m : 'restricted';
    }

    private function is_users_route($route){
        return (strpos($route, '/wp/v2/users') === 0);
    }

    private function is_rate_limited_target($route){
        // همهٔ REST را ریت لیمیت کن، ولی امکان استثنا با فیلتر
        $except = apply_filters('rsp_rest_rl_exceptions', [
            '/ready-secure-pro/v1/ping',
        ]);
        foreach ((array)$except as $ex){ if (strpos($route, $ex) === 0) return false; }
        return true;
    }

    private function rate_limit_exceeded($ip){
        $limit = max(30, (int) get_option('rsp_rest_rate_limit', 120));
        $win   = max(10, (int) get_option('rsp_rest_window', 60));
        $bucket= (int) floor(time() / $win);
        $key   = 'rsp_rest_rl_' . md5($ip.'|'.$bucket);
        $count = (int) get_transient($key);
        $count++;
        set_transient($key, $count, $win);
        return ($count > $limit);
    }

    private function is_allowed_by_whitelist($route){
        // 1) مسیرهای صریح (route کامل)
        $raw_routes = (string) get_option('rsp_rest_allow_routes','');
        $routes = array_filter(array_map('trim', preg_split('/\r?\n/', $raw_routes)));
        $routes = apply_filters('rsp_rest_allow_routes', $routes);
        foreach ((array)$routes as $r){ if ($r !== '' && strpos($route, $r) === 0) return true; }

        // 2) فضاهای نام (namespaces)
        $raw_ns = (string) get_option('rsp_rest_allow_namespaces', "contact-form-7\nwoo\nwc\nwc-\");
        $namespaces = array_filter(array_map('trim', preg_split('/\r?\n/', $raw_ns)));
        $namespaces = apply_filters('rsp_rest_allow_namespaces', $namespaces);
        foreach ((array)$namespaces as $ns){
            if ($ns === '') continue;
            // route به شکل /namespace/… است
            if (strpos(ltrim($route,'/'), rtrim($ns,'/').'/') === 0) return true;
        }
        return false;
    }

    private function allow_route_for_guest($route, $method){
        // در حالت open، فقط users را ببند و بقیه بمانند
        if ($this->is_users_route($route)) return false;
        return true;
    }

    private function rest_error($status, $msg){
        return new WP_Error('rsp_rest_guard', (string)$msg, ['status'=>(int)$status]);
    }
}
