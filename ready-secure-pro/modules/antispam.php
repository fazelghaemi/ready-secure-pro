<?php
if (!defined('ABSPATH')) { exit; }

/**
 * ماژول: کاهش کامنت‌های اسپم
 * - Honeypot مخفی + زمان‌سنج (Min Submit Time)
 * - محدودسازی نرخ ارسال بر اساس IP/پنجره‌ی زمانی
 * - محدودیت تعداد لینک در محتوا
 * - واژگان/الگوهای سیاه برای محتوا/نام/ایمیل/URL
 * - لیست سفید دامنهٔ ایمیل (مثلاً دامنهٔ سازمان)
 * - قفل موقت IP پس از تخلفات مکرر
 * - ثبت رویداد: antispam_block, antispam_pass, antispam_lock
 *
 * گزینه‌ها (Options)
 *  - rsp_antispam_enable        (bool)  پیش‌فرض: 1
 *  - rsp_antispam_min_secs      (int)   کمینهٔ زمان بین لود فرم تا ارسال (پیش‌فرض 8)
 *  - rsp_antispam_rate_limit    (int)   حداکثر کامنت در پنجره (پیش‌فرض 5)
 *  - rsp_antispam_rate_window   (int)   طول پنجره بر حسب ثانیه (پیش‌فرض 60)
 *  - rsp_antispam_lock_minutes  (int)   قفل IP پس از عبور از نرخ/تخلفات (پیش‌فرض 30)
 *  - rsp_antispam_max_links     (int)   حداکثر لینک مجاز در یک کامنت (پیش‌فرض 2)
 *  - rsp_antispam_badwords      (string) هر خط یک عبارت/regex ساده (بدون اسلش)
 *  - rsp_antispam_allow_domains (string) لیست دامنه‌های ایمیل مجاز (هر خط یک دامنه)
 */
class RSP_Module_AntiSpam implements RSP_Module_Interface {

    const HP_NAME = 'rsp_hp_url';         // honeypot
    const TS_NAME = 'rsp_ts';             // timestamp
    const TK_NAME = 'rsp_tk';             // HMAC token

    public function init() {
        if (!get_option('rsp_antispam_enable', 1)) return;

        // درج فیلدهای مخفی در فرم کامنت
        add_action('comment_form_after_fields',       [$this, 'inject_fields']);
        add_action('comment_form_logged_in_after',    [$this, 'inject_fields']);
        add_action('wp_enqueue_scripts',              [$this, 'enqueue_css']);

        // اعتبارسنجی پیش از درج کامنت
        add_filter('preprocess_comment',              [$this, 'validate_comment'], 9);

        // ثبت موفقیت/شکست نهایی
        add_action('comment_post',                    [$this, 'on_comment_post'], 10, 3);
    }

    /* ================= UI ================= */
    public function enqueue_css(){
        // مخفی‌سازی honeypot به‌صورت ایمن (نه display:none صرف)
        $css = '.rsp-hp-field{position:absolute !important;left:-9999px !important;width:1px !important;height:1px !important;opacity:0 !important;pointer-events:none !important}';
        wp_register_style('rsp-antispam', false, [], RSP_VERSION);
        wp_enqueue_style('rsp-antispam');
        wp_add_inline_style('rsp-antispam', $css);
    }

    public function inject_fields(){
        $ts = time();
        $ip = $this->ip();
        $tk = $this->hmac($ts.'|'.$ip);
        echo '<p class="comment-form-url rsp-hp-field"><label for="'.esc_attr(self::HP_NAME).'">'.esc_html__('اگر انسان هستید این فیلد را خالی بگذارید','ready-secure-pro').'</label><input type="text" name="'.esc_attr(self::HP_NAME).'" id="'.esc_attr(self::HP_NAME).'" value="" autocomplete="off"></p>';
        echo '<input type="hidden" name="'.esc_attr(self::TS_NAME).'" value="'.esc_attr($ts).'">';
        echo '<input type="hidden" name="'.esc_attr(self::TK_NAME).'" value="'.esc_attr($tk).'">';
    }

    /* ================= Core ================= */
    public function validate_comment($data){
        // اگر کاربر مدیریت است، فقط چک‌های سبک را نگه داریم
        $is_admin = is_user_logged_in() && current_user_can('moderate_comments');

        $ip   = $this->ip();
        $fail = function($reason) use ($ip, $data){
            do_action('rsp_activity_log', 'antispam_block', [
                'ip' => $ip,
                'reason' => $reason,
                'author' => isset($data['comment_author']) ? sanitize_text_field($data['comment_author']) : '',
                'email'  => isset($data['comment_author_email']) ? sanitize_email($data['comment_author_email']) : '',
            ]);
            $this->bump_violation($ip);
            return new WP_Error('rsp_antispam', esc_html__('ارسال شما به‌عنوان اسپم شناسایی شد. لطفاً بعداً تلاش کنید.','ready-secure-pro'));
        };

        // 0) قفل IP
        if ($this->is_locked($ip)) {
            return $fail('locked');
        }

        // 1) Honeypot باید خالی باشد
        $hp = isset($_POST[self::HP_NAME]) ? trim((string) $_POST[self::HP_NAME]) : '';
        if ($hp !== '') return $fail('honeypot');

        // 2) زمان‌سنج: حداقل ثانیه از لود فرم تا ارسال
        $ts = isset($_POST[self::TS_NAME]) ? (int) $_POST[self::TS_NAME] : 0;
        $tk = isset($_POST[self::TK_NAME]) ? (string) $_POST[self::TK_NAME] : '';
        $min_secs = max(2, (int) get_option('rsp_antispam_min_secs', 8));
        $max_age  = 4 * HOUR_IN_SECONDS;
        if (!$this->verify_hmac($tk, $ts.'|'.$ip)) return $fail('bad_token');
        if (($ts <= 0) || (time() - $ts < $min_secs) || (time() - $ts > $max_age)) return $fail('timing');

        // 3) محدودیت لینک‌ها
        $max_links = max(0, (int) get_option('rsp_antispam_max_links', 2));
        $links = $this->count_links((string) $data['comment_content']);
        if ($max_links >= 0 && $links > $max_links && !$is_admin) return $fail('too_many_links:'.$links);

        // 4) واژگان/الگوهای سیاه
        $bad = $this->badwords();
        if (!empty($bad)){
            $hay = strtolower(
                (string)$data['comment_content'].'\n'.
                (string)$data['comment_author'].'\n'.
                (string)$data['comment_author_email'].'\n'.
                (string)$data['comment_author_url']
            );
            foreach ($bad as $pat){
                if ($pat === '') continue;
                // پترن ساده / رشته — اگر شامل کاراکترهای regex بود با preg تست می‌کنیم
                if ($this->looks_like_regex($pat)){
                    $re = '/'.str_replace('/', '\/', $pat).'/i';
                    if (@preg_match($re, $hay)) { if (@preg_match($re, $hay)) return $fail('badword_regex:'.$pat); }
                } else {
                    if (strpos($hay, strtolower($pat)) !== false) return $fail('badword:'.$pat);
                }
            }
        }

        // 5) دامنهٔ ایمیل در allowlist؟
        $email = isset($data['comment_author_email']) ? trim((string)$data['comment_author_email']) : '';
        if ($email !== '' && !$is_admin){
            $dom = strtolower(substr(strrchr($email, '@'), 1));
            if ($dom !== ''){
                $allow = $this->allow_domains();
                if (!empty($allow)){
                    // اگر allowlist تنظیم شده باشد، فقط همین دامنه‌ها اجازه می‌گیرند
                    $ok = false;
                    foreach ($allow as $d){ if ($d!=='' && $this->domain_match($dom, $d)) { $ok = true; break; } }
                    if (!$ok) return $fail('email_domain_not_allowed:'.$dom);
                }
            }
        }

        // 6) Rate limit
        if (!$is_admin){
            if ($this->rate_limit_exceeded($ip)){
                $this->lock($ip); // قفل کوتاه‌مدت
                return $fail('rate_limit');
            }
        }

        // عبور کرد
        do_action('rsp_activity_log', 'antispam_pass', [ 'ip'=>$ip ]);
        return $data;
    }

    public function on_comment_post($comment_ID, $comment_approved, $commentdata){
        // می‌توان اینجا رویدادهای اضافی ثبت کرد
    }

    /* ================= Helpers ================= */
    private function ip(){ return function_exists('rsp_client_ip') ? rsp_client_ip() : (isset($_SERVER['REMOTE_ADDR'])? $_SERVER['REMOTE_ADDR'] : ''); }

    private function key($prefix, $ip){ return $prefix . md5($ip); }

    private function is_locked($ip){ return (bool) get_transient($this->key('rsp_as_lock_', $ip)); }
    private function lock($ip){ $min = max(5, (int) get_option('rsp_antispam_lock_minutes', 30)); set_transient($this->key('rsp_as_lock_', $ip), 1, $min * MINUTE_IN_SECONDS); do_action('rsp_activity_log','antispam_lock',[ 'ip'=>$ip, 'minutes'=>$min ]); }

    private function rate_limit_exceeded($ip){
        $limit = max(1, (int) get_option('rsp_antispam_rate_limit', 5));
        $win   = max(10, (int) get_option('rsp_antispam_rate_window', 60));
        $bucket= (int) floor(time() / $win);
        $key   = $this->key('rsp_as_bkt_', $ip.'|'.$bucket);
        $n = (int) get_transient($key); $n++;
        set_transient($key, $n, $win);
        return ($n > $limit);
    }

    private function bump_violation($ip){
        // می‌توان تعداد تخلفات را برای اقدامات آینده شمرد
        $k = $this->key('rsp_as_vio_', $ip);
        $n = (int) get_transient($k); $n++;
        set_transient($k, $n, 6 * HOUR_IN_SECONDS);
        // اگر خیلی زیاد شد، قفل طولانی‌تر
        if ($n >= 5) $this->lock($ip);
    }

    private function count_links($text){
        $t = strtolower((string)$text);
        $n = 0;
        // http/https
        $n += preg_match_all('#https?://#i', $t, $m);
        // تگ‌های a
        $n += preg_match_all('#<a\s[^>]*href=#i', $t, $m2);
        return (int)$n;
    }

    private function badwords(){
        $raw = (string) get_option('rsp_antispam_badwords', "
viagra
casino
porn
sex\s?shop
loan\s?approved
http://bit\.ly
free\s?gift
cheap\s?price
خرید\s?فالوور
درآمد\s?دلاری
کسب\s?درآمد
شرط\s?بندی
سکس
ارز\s?دیجیتال\s?رایگان
        ");
        $arr = array_filter(array_map('trim', preg_split('/\r?\n/', $raw)));
        return $arr;
    }

    private function allow_domains(){
        $raw = (string) get_option('rsp_antispam_allow_domains', "");
        $arr = array_filter(array_map('trim', preg_split('/\r?\n/', $raw)));
        return $arr;
    }

    private function domain_match($dom, $rule){
        $dom = strtolower((string)$dom); $rule = strtolower((string)$rule);
        if ($dom === $rule) return true;
        // *.example.com
        if (substr($rule, 0, 2) === '*.' ){
            $base = substr($rule, 2);
            return (substr($dom, -strlen($base)) === $base);
        }
        return false;
    }

    private function hmac($str){ $key = wp_salt('auth'); return hash_hmac('sha256', (string)$str, (string)$key); }
    private function verify_hmac($tk, $str){ if (!$tk) return false; return hash_equals($this->hmac($str), (string)$tk); }

    private function looks_like_regex($s){ return (bool) preg_match('/[\\^$.|?*+()\[\]{}]/', (string)$s); }
}
