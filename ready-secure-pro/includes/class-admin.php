<?php
if (!defined('ABSPATH')) { exit; }

/**
 * Ready Secure Pro - Admin Area
 * v2.5.2
 * - [اصلاح] انتقال بارگذاری ترجمه‌ها به هوک init برای رفع Notice
 * - حذف ثبت تنظیمات ماژول‌های دیگر از این کلاس (رفع وابستگی)
 * - افزودن تب «راهنما» + دکمه‌های اعمال تنظیمات پیشنهادی (۳ پروفایل)
 * - هر تب/فرم گروه تنظیمات مستقل دارد؛ ذخیرهٔ یک فرم، بقیه را دست نمی‌زند
 * - پیام‌های settings_errors، Flush پیوندها (AJAX)، Export/Import تنظیمات
 * - حذف کامل بخش اسکنرها
 */
class RSP_Admin {

    public function init() {
        // [اصلاح] بارگذاری ترجمه‌ها به هوک init منتقل شد
        add_action('init', [$this, 'i18n']);
        // add_action('plugins_loaded', [$this, 'i18n']); // <-- حذف شد

        add_action('admin_menu',     [$this, 'menu']);
        add_action('admin_enqueue_scripts', [$this, 'assets']);

        // سکشن/فیلدهای همین کلاس (فقط برای اسلاگ ورود)
        add_action('admin_init', function () {
            // گروه تنظیمات مستقل برای اسلاگ ورود
            register_setting('rsp_settings_login', 'rsp_login_slug', [
                'type'              => 'string',
                'default'           => 'manager',
                'sanitize_callback' => 'sanitize_title',
            ]);

            add_settings_section(
                'rsp_login',
                __('آدرس ورود سفارشی', 'ready-secure-pro'),
                function () {
                    echo '<p>' . esc_html__('پس از تغییر اسلاگ، یک‌بار پیوندهای یکتا را ذخیره کنید یا از دکمه «بازسازی پیوندهای یکتا» استفاده کنید.', 'ready-secure-pro') . '</p>';
                },
                'rsp_settings_login' // نام گروه تنظیمات
            );

            add_settings_field(
                'rsp_login_slug',
                __('اسلاگ ورود', 'ready-secure-pro'),
                function () {
                    echo '<input type="text" name="rsp_login_slug" value="' . esc_attr(get_option('rsp_login_slug', 'manager')) . '" />';
                    echo '<p class="description">' . esc_html__('نمونه: manager', 'ready-secure-pro') . '</p>';
                },
                'rsp_settings_login', // نام گروه تنظیمات
                'rsp_login'          // نام سکشن
            );
        });

        // AJAX
        add_action('wp_ajax_rsp_export_settings', [$this, 'ajax_export_settings']);
        add_action('wp_ajax_rsp_import_settings', [$this, 'ajax_import_settings']);
        add_action('wp_ajax_rsp_get_logs',        [$this, 'ajax_get_logs']);
        add_action('wp_ajax_rsp_clear_logs',      [$this, 'ajax_clear_logs']);
        add_action('wp_ajax_rsp_flush_rewrites',  [$this, 'ajax_flush_rewrites']);
    }

    // این تابع اکنون فقط در هوک init اجرا می‌شود
    public function i18n() {
        load_plugin_textdomain('ready-secure-pro', false, dirname(plugin_basename(__FILE__), 2) . '/languages');
    }

    public function menu() {
        add_menu_page(
            __('Ready Secure Pro', 'ready-secure-pro'),
            __('Ready Secure', 'ready-secure-pro'),
            'manage_options',
            'ready-secure-pro',
            [$this, 'render'],
            'dashicons-shield',
            65
        );
    }

    public function assets($hook) {
        if ($hook !== 'toplevel_page_ready-secure-pro') return;
        wp_enqueue_style('rsp-admin', RSP_URL . 'assets/admin.css', [], RSP_VERSION);
        wp_enqueue_script('rsp-admin', RSP_URL . 'assets/admin.js', ['jquery'], RSP_VERSION, true);
        wp_localize_script('rsp-admin', 'RSP', [
            'ajax'  => admin_url('admin-ajax.php'),
            'nonce' => wp_create_nonce('rsp_nonce'),
        ]);
    }

    /** @deprecated */
    public function map_settings_to_groups() {
        // این تابع دیگر استفاده نمی‌شود.
    }

    public function render() {
        if (!current_user_can('manage_options')) return;

        settings_errors(); ?>

        <div class="rsp-wrap">
            <div class="rsp-header">
                <div class="rsp-brand">
                    <span class="rsp-logo">🛡️</span>
                    <h1>Ready Secure Pro</h1>
                    <span class="rsp-ver">v<?php echo esc_html(RSP_VERSION); ?></span>
                </div>
                <div class="rsp-actions">
                    <button class="rsp-btn" id="rsp-export"><?php _e('خروجی تنظیمات','ready-secure-pro'); ?></button>
                    <label class="rsp-btn"><?php _e('ورودی تنظیمات','ready-secure-pro'); ?><input type="file" id="rsp-import-file" accept="application/json" hidden></label>
                </div>
            </div>

            <div class="rsp-tabs">
                <button class="rsp-tab is-active" data-target="#tab-overview"><?php _e('نمای کلی','ready-secure-pro'); ?></button>
                <button class="rsp-tab" data-target="#tab-login"><?php _e('ورود و دسترسی','ready-secure-pro'); ?></button>
                <button class="rsp-tab" data-target="#tab-waf"><?php _e('فایروال / WAF','ready-secure-pro'); ?></button>
                <button class="rsp-tab" data-target="#tab-guard"><?php _e('گارد 404 / ضداسپم','ready-secure-pro'); ?></button>
                <button class="rsp-tab" data-target="#tab-logs"><?php _e('لاگ‌ها','ready-secure-pro'); ?></button>
                <button class="rsp-tab" data-target="#tab-help">❓ <?php _e('راهنما','ready-secure-pro'); ?></button>
            </div>

            <div class="rsp-panels">
                <div class="rsp-panel is-active" id="tab-overview">
                    <div class="rsp-card">
                        <h3><?php _e('وضعیت سریع','ready-secure-pro'); ?></h3>
                        <div class="rsp-status">
                            <div class="item"><span><?php _e('آدرس ورود:','ready-secure-pro'); ?></span><code><?php echo esc_html(home_url('/'.get_option('rsp_login_slug','manager').'/')); ?></code></div>
                            <div class="item"><span><?php _e('WAF فعال:','ready-secure-pro'); ?></span><strong><?php echo get_option('rsp_waf_enable',1)?__('بله','ready-secure-pro'):__('خیر','ready-secure-pro'); ?></strong></div>
                            <div class="item"><span><?php _e('گارد 404:','ready-secure-pro'); ?></span><strong><?php echo get_option('rsp_404_enable',1)?__('بله','ready-secure-pro'):__('خیر','ready-secure-pro'); ?></strong></div>
                            <div class="item"><span><?php _e('Brute Force:','ready-secure-pro'); ?></span><strong><?php echo get_option('rsp_bf_enable',1)?__('بله','ready-secure-pro'):__('خیر','ready-secure-pro'); ?></strong></div>
                            <div class="item"><span><?php _e('File Guard:','ready-secure-pro'); ?></span><strong><?php echo get_option('rsp_file_guard_enable',1)?__('بله','ready-secure-pro'):__('خیر','ready-secure-pro'); ?></strong></div>
                        </div>
                        <div style="margin-top:12px">
                            <button class="rsp-btn" id="rsp-flush-rewrites"><?php _e('بازسازی پیوندهای یکتا','ready-secure-pro'); ?></button>
                        </div>
                    </div>
                </div>

                <div class="rsp-panel" id="tab-login">
                    <form method="post" action="options.php" class="rsp-card">
                        <?php
                        settings_fields('rsp_settings_login');
                        do_settings_sections('rsp_settings_login');
                        submit_button(__('ذخیره تنظیمات ورود','ready-secure-pro'),'primary','submit',false,['class'=>'rsp-btn']); ?>
                    </form>

                    <form method="post" action="options.php" class="rsp-card">
                        <?php
                        settings_fields('rsp_settings_bf');
                        do_settings_sections('rsp_settings_bf');
                        submit_button(__('ذخیره تنظیمات Brute-Force','ready-secure-pro'),'primary','submit',false,['class'=>'rsp-btn']); ?>
                    </form>
                </div>

                <div class="rsp-panel" id="tab-waf">
                    <form method="post" action="options.php" class="rsp-card">
                        <?php
                        settings_fields('rsp_settings_waf');
                        do_settings_sections('rsp_settings_waf');
                        submit_button(__('ذخیره تنظیمات WAF','ready-secure-pro'),'primary','submit',false,['class'=>'rsp-btn']); ?>
                    </form>

                    <form method="post" action="options.php" class="rsp-card">
                        <?php
                        settings_fields('rsp_settings_xmlrpc_rest');
                        do_settings_sections('rsp_settings_xmlrpc_rest');
                        submit_button(__('ذخیره تنظیمات REST/XML-RPC','ready-secure-pro'),'primary','submit',false,['class'=>'rsp-btn']); ?>
                    </form>
                </div>

                <div class="rsp-panel" id="tab-guard">
                    <form method="post" action="options.php" class="rsp-card">
                        <?php
                        settings_fields('rsp_settings_404_antispam');
                        do_settings_sections('rsp_settings_404_antispam');
                        submit_button(__('ذخیره','ready-secure-pro'),'primary','submit',false,['class'=>'rsp-btn']); ?>
                    </form>
                </div>


                <div class="rsp-panel" id="tab-logs">
                    <div class="rsp-card">
                        <h3><?php _e('لاگ رویدادها','ready-secure-pro'); ?></h3>
                        <div class="rsp-actions" style="margin-bottom:10px">
                            <button class="rsp-btn success" id="rsp-refresh-logs"><?php _e('به‌روزرسانی','ready-secure-pro'); ?></button>
                            <button class="rsp-btn danger" id="rsp-clear-logs"><?php _e('حذف لاگ‌ها','ready-secure-pro'); ?></button>
                        </div>
                        <pre id="rsp-out-logs"></pre>
                    </div>
                </div>

                <div class="rsp-panel" id="tab-help">
                    <div class="rsp-card">
                        <h3>راهنمای سریع استفاده</h3>
                        <ol>
                            <li><strong>ورود و دسترسی:</strong> اسلاگ ورود را تنظیم کن (پیش‌فرض <code>manager</code>) و سپس «بازسازی پیوندهای یکتا» را بزن.</li>
                            <li><strong>فایروال (WAF):</strong> WAF را فعال کن؛ اگر پشت CDN هستی، IPهای مدیریتی یا عبارت‌های User-Agent معتبر را در Whitelist بنویس.</li>
                            <li><strong>گارد 404 / ضداسپم:</strong> آستانهٔ منطقی تعیین کن (مثلاً 12 خطا در 120 ثانیه، قفل 30 دقیقه) و ضداسپم دیدگاه را روشن بگذار.</li>
                            <li><strong>لاگ‌ها:</strong> رویدادهای امنیتی در این تب نمایش داده می‌شوند.</li>
                        </ol>
                        <div class="rsp-sep"></div>
                        <h3>تنظیمات پیشنهادی (پروفایل‌ها)</h3>
                        <p>با یک کلیک مقادیر پیشنهادی زیر اعمال می‌شوند. هر زمان بخواهی می‌توانی دستی تغییرشان بدهی.</p>
                        <div class="rsp-actions">
                            <button class="rsp-btn" data-rsp-apply="default">اعمال پروفایل: عمومی (پیشنهادی)</button>
                            <button class="rsp-btn" data-rsp-apply="cdn">اعمال پروفایل: فروشگاهی/پربازدید (CDN)</button>
                            <button class="rsp-btn" data-rsp-apply="strict">اعمال پروفایل: امنیت بالا</button>
                        </div>
                        <ul class="rsp-list" style="margin-top:10px">
                            <li>عمومی: WAF روشن، پنجره ۶۰ثانیه/حد ۶۰ درخواست، REST حالت <code>restricted</code>، 404 (۱۲/۱۲۰ثانیه/۳۰دقیقه)، ضداسپم (۸ثانیه/۲ لینک)، Brute Force (۵ تلاش/قفل ۱۵دقیقه).</li>
                            <li>فروشگاهی/CDN: WAF روشن با حد ۱۲۰، آستانهٔ 404=۲۰ و قفل ۱۵دقیقه، ضداسپم (۵ثانیه/۳ لینک).</li>
                            <li>امنیت بالا: WAF حد ۳۰، REST= <code>private</code>، 404 (۸/۹۰ثانیه/۶۰دقیقه)، Brute Force (۳ تلاش/۳۰ دقیقه).</li>
                        </ul>
                        <div class="rsp-sep"></div>
                        <h3>نکات سازگاری</h3>
                        <ul class="rsp-list">
                            <li>HSTS فقط روی HTTPS اعمال می‌شود.</li>
                            <li>اگر پشت CDN هستی، هدر <code>CF-Connecting-IP</code> فعال باشد تا شناسایی IP دقیق شود.</li>
                            <li>در صورت بروز خطای مثبت کاذب، مسیر/UA را در Whitelist بنویس یا حد WAF را کمی بالاتر ببر.</li>
                        </ul>
                    </div>

                    <script>
                    (function(){
                        function sendProfile(payload){
                            if(!window.RSP){ alert('Ajax not ready'); return; }
                            if(!confirm('آیا از اعمال تنظیمات پیشنهادی مطمئن هستید؟')) return;
                            fetch(RSP.ajax + '?action=rsp_import_settings&_ajax_nonce=' + encodeURIComponent(RSP.nonce), {
                                method: 'POST',
                                headers: {'Content-Type':'application/json'},
                                body: JSON.stringify(payload)
                            }).then(r=>r.json()).then(function(res){
                                if(res && res.success){
                                    alert('تنظیمات اعمال شد. صفحه رفرش می‌شود.');
                                    location.reload();
                                }else{
                                    alert('خطا در اعمال تنظیمات.');
                                }
                            }).catch(function(){ alert('خطای شبکه.'); });
                        }

                        var profiles = {
                            "default": {
                                "rsp_waf_enable":1, "rsp_waf_rate_window":60, "rsp_waf_rate_limit":60, "rsp_waf_whitelist":"",
                                "rsp_rest_mode":"restricted",
                                "rsp_404_enable":1, "rsp_404_threshold":12, "rsp_404_window":120, "rsp_404_lock_minutes":30,
                                "rsp_antispam_enable":1, "rsp_antispam_min_secs":8, "rsp_antispam_max_links":2,
                                "rsp_bf_enable":1, "rsp_bf_max":5, "rsp_bf_lock_min":15,
                                "rsp_file_guard_enable":1, "rsp_headers_hsts":1, "rsp_headers_referrer":"no-referrer"
                            },
                            "cdn": {
                                "rsp_waf_enable":1, "rsp_waf_rate_window":60, "rsp_waf_rate_limit":120, "rsp_waf_whitelist":"",
                                "rsp_rest_mode":"restricted",
                                "rsp_404_enable":1, "rsp_404_threshold":20, "rsp_404_window":120, "rsp_404_lock_minutes":15,
                                "rsp_antispam_enable":1, "rsp_antispam_min_secs":5, "rsp_antispam_max_links":3,
                                "rsp_bf_enable":1, "rsp_bf_max":5, "rsp_bf_lock_min":10,
                                "rsp_file_guard_enable":1, "rsp_headers_hsts":1, "rsp_headers_referrer":"strict-origin-when-cross-origin"
                            },
                            "strict": {
                                "rsp_waf_enable":1, "rsp_waf_rate_window":60, "rsp_waf_rate_limit":30, "rsp_waf_whitelist":"",
                                "rsp_rest_mode":"private",
                                "rsp_404_enable":1, "rsp_404_threshold":8, "rsp_404_window":90, "rsp_404_lock_minutes":60,
                                "rsp_antispam_enable":1, "rsp_antispam_min_secs":10, "rsp_antispam_max_links":1,
                                "rsp_bf_enable":1, "rsp_bf_max":3, "rsp_bf_lock_min":30,
                                "rsp_file_guard_enable":1, "rsp_headers_hsts":1, "rsp_headers_referrer":"no-referrer"
                            }
                        };

                        document.addEventListener('click', function(ev){
                            var el = ev.target.closest('[data-rsp-apply]');
                            if(!el) return;
                            var key = el.getAttribute('data-rsp-apply');
                            if(profiles[key]) sendProfile(profiles[key]);
                        });
                    })();
                    </script>
                </div>
            </div>
        </div>
        <?php
    }

    /** امنیت AJAX */
    private function check_ajax() {
        check_ajax_referer('rsp_nonce');
        if (!current_user_can('manage_options')) wp_send_json_error('forbidden', 403);
    }

    /* ===== AJAX ===== */

    public function ajax_export_settings() {
        $this->check_ajax();
        // اطمینان از وجود تابع قبل از فراخوانی
        if (!function_exists('rsp_option_export')) {
            require_once RSP_PATH . 'includes/helpers.php';
            if (!function_exists('rsp_option_export')) {
                 wp_send_json_error('helper_missing', 500);
                 return;
            }
        }
        wp_send_json_success(rsp_option_export());
    }

    public function ajax_import_settings() {
        $this->check_ajax();
        $raw = file_get_contents('php://input');
        $data = json_decode($raw, true);
        if (!$data) wp_send_json_error('bad_json',400);

        // Only accept whitelisted rsp_* keys
        $safe = [];
        foreach ((array)$data as $k=>$v) {
            if (is_string($k) && strpos($k,'rsp_')===0) $safe[$k]=$v;
        }

        // اطمینان از وجود تابع قبل از فراخوانی
        if (!function_exists('rsp_option_import')) {
             require_once RSP_PATH . 'includes/helpers.php';
        }

        if (function_exists('rsp_option_import')) {
            rsp_option_import($safe);
            wp_send_json_success(['ok'=>1]);
        } else {
            // Fallback
            foreach ($safe as $k=>$v) update_option($k,$v);
            wp_send_json_success(['ok'=>1,'fallback'=>1]);
        }
    }

    public function ajax_get_logs() {
        $this->check_ajax();
        global $wpdb;
        $t = $wpdb->prefix . 'rsp_logs';
        $rows = $wpdb->get_results("SELECT * FROM $t ORDER BY id DESC LIMIT 200", ARRAY_A);

        if (empty($rows) && $wpdb->last_error) {
             $rows = get_option('rsp_activity_log', []);
             if (!is_array($rows)) $rows = [];
             usort($rows, function($a, $b) {
                 $ts_a = isset($a['created_at']) ? strtotime($a['created_at']) : 0;
                 $ts_b = isset($b['created_at']) ? strtotime($b['created_at']) : 0;
                 return $ts_b <=> $ts_a;
             });
             $rows = array_slice($rows, 0, 200);
        } elseif (!$rows) {
            $rows = [];
        }

        wp_send_json_success($rows);
    }

    public function ajax_clear_logs() {
        $this->check_ajax();
        global $wpdb;
        $wpdb->query("TRUNCATE TABLE " . $wpdb->prefix . "rsp_logs");
        delete_option('rsp_activity_log');
        wp_send_json_success(['ok'=>1]);
    }

    public function ajax_flush_rewrites() {
        $this->check_ajax();
        flush_rewrite_rules(false);
        wp_send_json_success(['ok'=>1]);
    }
}