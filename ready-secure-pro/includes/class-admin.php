<?php
if (!defined('ABSPATH')) { exit; }

/**
 * کلاس پنل مدیریتی Ready Secure Pro
 * - تب‌بندی فارسی و برند Ready Studio
 * - دکمه‌ها با گوشهٔ 8px
 * - هندلرهای AJAX با بررسی nonce + capability
 */
class RSP_Admin {

    public function init() {
        add_action('admin_menu', [$this, 'menu']);
        add_action('admin_enqueue_scripts', [$this, 'assets']);
        add_action('admin_init', [$this, 'register_settings']);
        add_action('admin_head', [$this, 'inline_styles']);

        // پروفایل کاربر (2FA)
        add_action('show_user_profile', [$this, 'render_profile_2fa']);
        add_action('edit_user_profile', [$this, 'render_profile_2fa']);
        add_action('personal_options_update', [$this, 'save_profile_2fa']);
        add_action('edit_user_profile_update', [$this, 'save_profile_2fa']);

        // AJAX — همراه با nonce + capability
        add_action('wp_ajax_rsp_get_logs', [$this, 'ajax_get_logs']);
        add_action('wp_ajax_rsp_export_settings', [$this, 'ajax_export_settings']);
        add_action('wp_ajax_rsp_import_settings', [$this, 'ajax_import_settings']);
        add_action('wp_ajax_rsp_scan_fs', [$this, 'ajax_scan_fs']);
        add_action('wp_ajax_rsp_scan_integrity', [$this, 'ajax_scan_integrity']);
        add_action('wp_ajax_rsp_scan_malware', [$this, 'ajax_scan_malware']);
    }

    /** منو */
    public function menu() {
        add_menu_page(
            __('Ready Secure', 'ready-secure-pro'),
            __('Ready Secure', 'ready-secure-pro'),
            'manage_options',
            'ready-secure',
            [$this, 'render_page'],
            'dashicons-shield-alt',
            58
        );
    }

    /** استایل/اسکریپت ادمین */
    public function assets($hook) {
        if (strpos($hook, 'ready-secure') === false) return;
        wp_enqueue_style('rsp-admin', RSP_URL . 'assets/admin.css', [], RSP_VERSION);
        wp_enqueue_script('rsp-admin', RSP_URL . 'assets/admin.js', ['jquery'], RSP_VERSION, true);
        wp_localize_script('rsp-admin', 'RSP_DATA', [
            'ajax'  => admin_url('admin-ajax.php'),
            'nonce' => wp_create_nonce('rsp_nonce'),
        ]);
    }

    /** گرد کردن دکمه‌ها + بهینه‌سازی تایپوگرافی */
    public function inline_styles() {
        $screen = get_current_screen();
        if (!$screen || $screen->id !== 'toplevel_page_ready-secure') return;
        echo '<style>
            .rsp-wrap .button, .rsp-wrap .button-primary, .rsp-wrap .button-secondary { border-radius:8px !important; }
            .rsp-wrap input[type=text], .rsp-wrap input[type=number], .rsp-wrap textarea, .rsp-wrap select { border-radius:10px; }
        </style>';
    }

    /** ثبت تنظیمات */
    public function register_settings() {
        // گروه واحد برای سادگی
        $group = 'rsp_settings';

        // ورود و Brute-Force
        register_setting($group, 'rsp_login_slug', ['type'=>'string','sanitize_callback'=>'sanitize_title']);
        register_setting($group, 'rsp_bruteforce_max', ['type'=>'integer','default'=>5]);
        register_setting($group, 'rsp_bruteforce_lock_minutes', ['type'=>'integer','default'=>15]);
        register_setting($group, 'rsp_bruteforce_whitelist', ['type'=>'string','default'=>'']);
        register_setting($group, 'rsp_2fa_enforce_role', ['type'=>'string','default'=>'']);

        // هدرهای امنیتی
        register_setting($group, 'rsp_headers_hsts', ['type'=>'boolean','default'=>1]);
        register_setting($group, 'rsp_headers_mode', ['type'=>'string','default'=>'report-only']);
        register_setting($group, 'rsp_headers_csp',  ['type'=>'string','default'=>"default-src 'self'; img-src 'self' data:;"]);

        // WAF / Rate limit
        register_setting($group, 'rsp_waf_enabled',   ['type'=>'boolean','default'=>1]);
        register_setting($group, 'rsp_waf_rate_limit',['type'=>'integer','default'=>120]);
        register_setting($group, 'rsp_waf_window',    ['type'=>'integer','default'=>60]);

        // File Guard
        register_setting($group, 'rsp_file_guard_disable_php_uploads', ['type'=>'boolean','default'=>1]);
        register_setting($group, 'rsp_file_guard_auto_index', ['type'=>'boolean','default'=>1]);

        // Smart 404
        register_setting($group, 'rsp_404_enable',        ['type'=>'boolean','default'=>1]);
        register_setting($group, 'rsp_404_threshold',     ['type'=>'integer','default'=>20]);
        register_setting($group, 'rsp_404_window',        ['type'=>'integer','default'=>300]);
        register_setting($group, 'rsp_404_block_minutes', ['type'=>'integer','default'=>60]);

        // Anti-Spam
        register_setting($group, 'rsp_antispam_enable',     ['type'=>'boolean','default'=>1]);
        register_setting($group, 'rsp_antispam_min_seconds', ['type'=>'integer','default'=>5]);
        register_setting($group, 'rsp_antispam_honeypot',    ['type'=>'boolean','default'=>1]);

        // Content Protect
        register_setting($group, 'rsp_content_protect_enable', ['type'=>'boolean','default'=>1]);
    }

    /** پروفایل: فیلد 2FA */
    public function render_profile_2fa($user) { ?>
        <h2><?php _e('Ready Secure 2FA', 'ready-secure-pro'); ?></h2>
        <table class="form-table">
            <tr>
                <th><label for="rsp_totp_secret"><?php _e('TOTP Secret (Base32)', 'ready-secure-pro'); ?></label></th>
                <td>
                    <input type="text" name="rsp_totp_secret" id="rsp_totp_secret" value="<?php echo esc_attr(get_user_meta($user->ID,'rsp_totp_secret',true)); ?>" class="regular-text" />
                    <p class="description"><?php _e('اگر خالی باشد، 2FA برای این کاربر فعال نیست.', 'ready-secure-pro'); ?></p>
                    <p><a href="#" class="button" id="rsp-gen-secret"><?php _e('ساخت Secret', 'ready-secure-pro'); ?></a>
                    <input type="text" readonly id="rsp-otpauth" class="regular-text" placeholder="otpauth://..." /></p>
                    <script>
                        (function(){
                            function base32(len){const a='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';let s='';for(let i=0;i<len;i++)s+=a[Math.floor(Math.random()*a.length)];return s;}
                            document.getElementById('rsp-gen-secret').addEventListener('click', function(e){
                                e.preventDefault();
                                var sec = base32(32);
                                document.getElementById('rsp_totp_secret').value = sec;
                                var label = encodeURIComponent('<?php echo get_bloginfo('name'); ?>:<?php echo esc_js($user->user_login); ?>');
                                var uri = 'otpauth://totp/'+label+'?secret='+sec+'&issuer='+encodeURIComponent('<?php echo get_bloginfo('name'); ?>');
                                document.getElementById('rsp-otpauth').value = uri;
                            });
                        })();
                    </script>
                </td>
            </tr>
        </table>
    <?php }

    public function save_profile_2fa($user_id) {
        if (!current_user_can('edit_user', $user_id)) return;
        if (isset($_POST['rsp_totp_secret'])) {
            update_user_meta($user_id, 'rsp_totp_secret', sanitize_text_field($_POST['rsp_totp_secret']));
        }
    }

    /*** AJAX ***/
    private function check_ajax_security() {
        check_ajax_referer('rsp_nonce');
        if (!current_user_can('manage_options')) wp_send_json_error('forbidden', 403);
    }

    public function ajax_get_logs() {
        $this->check_ajax_security();
        $logs = get_option('rsp_activity_log', []);
        wp_send_json_success($logs);
    }

    public function ajax_export_settings() {
        $this->check_ajax_security();
        if (!function_exists('rsp_option_export')) wp_send_json_error('helper missing', 500);
        wp_send_json_success(rsp_option_export());
    }

    public function ajax_import_settings() {
        $this->check_ajax_security();
        $json = isset($_POST['payload']) ? wp_unslash($_POST['payload']) : '';
        $data = json_decode($json, true);
        if (!is_array($data)) wp_send_json_error('invalid json');
        foreach ($data as $k=>$v) {
            if (strpos($k,'rsp_') === 0) update_option($k, $v);
        }
        wp_send_json_success(true);
    }

    public function ajax_scan_fs() {
        $this->check_ajax_security();
        if (class_exists('RSP_Module_FS_Permissions')) {
            $m = new RSP_Module_FS_Permissions();
            if (method_exists($m, 'scan_report')) {
                $report = $m->scan_report();
                do_action('rsp_activity_log','fs_scan',[]);
                wp_send_json_success(['report'=>$report]);
            }
        }
        wp_send_json_error('module not found');
    }

    public function ajax_scan_integrity() {
        $this->check_ajax_security();
        if (class_exists('RSP_Module_Integrity')) {
            $m = new RSP_Module_Integrity();
            if (method_exists($m, 'scan_core')) {
                $res = $m->scan_core();
                wp_send_json_success($res);
            }
        }
        wp_send_json_error('module not found');
    }

    public function ajax_scan_malware() {
        $this->check_ajax_security();
        if (class_exists('RSP_Module_Malware')) {
            $m = new RSP_Module_Malware();
            if (method_exists($m, 'scan_quick')) {
                $res = $m->scan_quick();
                wp_send_json_success($res);
            }
        }
        wp_send_json_error('module not found');
    }

    /** رندر داشبورد تب‌بندی‌شده */
    public function render_page() { ?>
        <div class="rsp-wrap">
            <div class="rsp-topbar">
                <div class="rsp-brand">
                    <img class="rsp-logo-img" src="<?php echo esc_url( RSP_URL . 'assets/img/readystudio-logo.svg' ); ?>" alt="ReadyStudio" />
                    <span class="rsp-name">Ready Secure</span>
                    <span class="rsp-badge">Pro</span>
                </div>
                <div class="rsp-ver"><?php echo esc_html( sprintf(__('نسخه %s','ready-secure-pro'), RSP_VERSION) ); ?></div>
            </div>

            <div class="rsp-tabs">
                <button class="rsp-tab active" data-tab="overview"><?php _e('نمای کلی','ready-secure-pro'); ?></button>
                <button class="rsp-tab" data-tab="login"><?php _e('ورود و Brute‑Force','ready-secure-pro'); ?></button>
                <button class="rsp-tab" data-tab="headers"><?php _e('هدرها و هاردنینگ','ready-secure-pro'); ?></button>
                <button class="rsp-tab" data-tab="waf"><?php _e('فایروال و فایل‌ها','ready-secure-pro'); ?></button>
                <button class="rsp-tab" data-tab="smart404"><?php _e('مسدودسازی 404','ready-secure-pro'); ?></button>
                <button class="rsp-tab" data-tab="antispam"><?php _e('ضد اسپم دیدگاه','ready-secure-pro'); ?></button>
                <button class="rsp-tab" data-tab="scan"><?php _e('اسکن و سلامت','ready-secure-pro'); ?></button>
                <button class="rsp-tab" data-tab="logs"><?php _e('لاگ و ابزارها','ready-secure-pro'); ?></button>
            </div>

            <div class="rsp-panels">
                <!-- Overview -->
                <section class="rsp-panel show" id="tab-overview">
                    <div class="rsp-grid">
                        <div class="rsp-card stat">
                            <h3><?php _e('وضعیت امنیتی سایت','ready-secure-pro'); ?></h3>
                            <ul class="rsp-kv">
                                <li><b><?php _e('آدرس ورود','ready-secure-pro'); ?>:</b> /<?php echo esc_html(get_option('rsp_login_slug','manager')); ?>/</li>
                                <li><b>HSTS:</b> <?php echo get_option('rsp_headers_hsts',1)?'On':'Off'; ?></li>
                                <li><b>CSP:</b> <?php echo esc_html(get_option('rsp_headers_mode','report-only')); ?></li>
                                <li><b><?php _e('WAF','ready-secure-pro'); ?>:</b> <?php echo get_option('rsp_waf_enabled',1)?'Enabled':'Disabled'; ?></li>
                                <li><b><?php _e('مسدودسازی 404','ready-secure-pro'); ?>:</b> <?php echo get_option('rsp_404_enable',1)?'On':'Off'; ?></li>
                                <li><b><?php _e('آنتی‌اسپم دیدگاه','ready-secure-pro'); ?>:</b> <?php echo get_option('rsp_antispam_enable',1)?'On':'Off'; ?></li>
                            </ul>
                            <button type="button" class="button" id="rsp-run-integrity"><?php _e('اسکن هسته','ready-secure-pro'); ?></button>
                            <button type="button" class="button" id="rsp-run-malware"><?php _e('اسکن بدافزار سریع','ready-secure-pro'); ?></button>
                            <pre id="rsp-integrity-out" class="rsp-pre"></pre>
                            <pre id="rsp-malware-out" class="rsp-pre"></pre>
                        </div>
                        <div class="rsp-card">
                            <h3><?php _e('اجبار 2FA بر اساس نقش','ready-secure-pro'); ?></h3>
                            <form method="post" action="options.php">
                                <?php settings_fields('rsp_settings'); ?>
                                <label><?php _e('نقش هدف (مثال: administrator)','ready-secure-pro'); ?></label>
                                <input type="text" name="rsp_2fa_enforce_role" value="<?php echo esc_attr(get_option('rsp_2fa_enforce_role','')); ?>" />
                                <?php submit_button(__('ذخیره','ready-secure-pro')); ?>
                            </form>
                            <p class="rsp-note"><?php _e('TOTP Secret هر کاربر در پروفایل او تنظیم می‌شود.','ready-secure-pro'); ?></p>
                        </div>
                    </div>
                </section>

                <!-- Login & Brute-Force -->
                <section class="rsp-panel" id="tab-login">
                    <div class="rsp-grid">
                        <form method="post" action="options.php" class="rsp-card">
                            <h3><?php _e('آدرس ورود','ready-secure-pro'); ?></h3>
                            <?php settings_fields('rsp_settings'); ?>
                            <label><?php _e('Slug صفحه ورود','ready-secure-pro'); ?></label>
                            <input type="text" name="rsp_login_slug" value="<?php echo esc_attr(get_option('rsp_login_slug','manager')); ?>" />
                            <p class="rsp-note"><?php _e('پس از تغییر، به تنظیمات پیوند یکتا رفته و ذخیره کنید.','ready-secure-pro'); ?></p>
                            <?php submit_button(__('ذخیره','ready-secure-pro')); ?>
                        </form>

                        <form method="post" action="options.php" class="rsp-card">
                            <h3><?php _e('محافظت Brute‑Force','ready-secure-pro'); ?></h3>
                            <?php settings_fields('rsp_settings'); ?>
                            <label><?php _e('حداکثر تلاش ناموفق','ready-secure-pro'); ?></label>
                            <input type="number" name="rsp_bruteforce_max" value="<?php echo esc_attr(get_option('rsp_bruteforce_max',5)); ?>" />
                            <label><?php _e('مدت قفل (دقیقه)','ready-secure-pro'); ?></label>
                            <input type="number" name="rsp_bruteforce_lock_minutes" value="<?php echo esc_attr(get_option('rsp_bruteforce_lock_minutes',15)); ?>" />
                            <label><?php _e('IP لیست سفید (هر خط یک IP)','ready-secure-pro'); ?></label>
                            <textarea name="rsp_bruteforce_whitelist" rows="4" placeholder="127.0.0.1\n::1"><?php echo esc_textarea(get_option('rsp_bruteforce_whitelist','')); ?></textarea>
                            <?php submit_button(__('ذخیره','ready-secure-pro')); ?>
                        </form>
                    </div>
                </section>

                <!-- Headers & Hardening -->
                <section class="rsp-panel" id="tab-headers">
                    <form method="post" action="options.php" class="rsp-card">
                        <h3><?php _e('هدرهای امنیتی','ready-secure-pro'); ?></h3>
                        <?php settings_fields('rsp_settings'); ?>
                        <label><input type="checkbox" name="rsp_headers_hsts" value="1" <?php checked(get_option('rsp_headers_hsts',1),1); ?> /> <?php _e('فعال‌سازی HSTS','ready-secure-pro'); ?></label>
                        <label><?php _e('حالت CSP','ready-secure-pro'); ?></label>
                        <select name="rsp_headers_mode">
                            <option value="report-only" <?php selected(get_option('rsp_headers_mode','report-only'),'report-only'); ?>>Report-Only</option>
                            <option value="enforce" <?php selected(get_option('rsp_headers_mode','report-only'),'enforce'); ?>>Enforce</option>
                        </select>
                        <label><?php _e('قوانین CSP','ready-secure-pro'); ?></label>
                        <textarea name="rsp_headers_csp" rows="6"><?php echo esc_textarea(get_option('rsp_headers_csp', "default-src 'self'; img-src 'self' data:;")); ?></textarea>
                        <?php submit_button(__('ذخیره هدرها','ready-secure-pro')); ?>
                    </form>
                </section>

                <!-- WAF & File Guard -->
                <section class="rsp-panel" id="tab-waf">
                    <div class="rsp-grid">
                        <form method="post" action="options.php" class="rsp-card">
                            <h3><?php _e('فایروال (WAF) و محدودسازی نرخ','ready-secure-pro'); ?></h3>
                            <?php settings_fields('rsp_settings'); ?>
                            <label><input type="checkbox" name="rsp_waf_enabled" value="1" <?php checked(get_option('rsp_waf_enabled',1),1); ?> /> <?php _e('فعال‌سازی WAF','ready-secure-pro'); ?></label>
                            <label><?php _e('حداکثر درخواست در پنجره','ready-secure-pro'); ?></label>
                            <input type="number" name="rsp_waf_rate_limit" value="<?php echo esc_attr(get_option('rsp_waf_rate_limit',120)); ?>" />
                            <label><?php _e('طول پنجره (ثانیه)','ready-secure-pro'); ?></label>
                            <input type="number" name="rsp_waf_window" value="<?php echo esc_attr(get_option('rsp_waf_window',60)); ?>" />
                            <?php submit_button(__('ذخیره','ready-secure-pro')); ?>
                        </form>

                        <form method="post" action="options.php" class="rsp-card">
                            <h3><?php _e('حفاظت از فایل‌ها (uploads)','ready-secure-pro'); ?></h3>
                            <?php settings_fields('rsp_settings'); ?>
                            <label><input type="checkbox" name="rsp_file_guard_disable_php_uploads" value="1" <?php checked(get_option('rsp_file_guard_disable_php_uploads',1),1); ?> /> <?php _e('غیرفعال کردن اجرای PHP در uploads','ready-secure-pro'); ?></label>
                            <label><input type="checkbox" name="rsp_file_guard_auto_index" value="1" <?php checked(get_option('rsp_file_guard_auto_index',1),1); ?> /> <?php _e('ایجاد index.html در پوشه‌های حساس','ready-secure-pro'); ?></label>
                            <?php submit_button(__('ذخیره','ready-secure-pro')); ?>
                        </form>
                    </div>
                </section>

                <!-- Smart 404 -->
                <section class="rsp-panel" id="tab-smart404">
                    <form method="post" action="options.php" class="rsp-card">
                        <h3><?php _e('مسدودسازی هوشمند 404','ready-secure-pro'); ?></h3>
                        <?php settings_fields('rsp_settings'); ?>
                        <label><input type="checkbox" name="rsp_404_enable" value="1" <?php checked(get_option('rsp_404_enable',1),1); ?> /> <?php _e('فعال','ready-secure-pro'); ?></label>
                        <label><?php _e('حداکثر 404 در پنجره','ready-secure-pro'); ?></label>
                        <input type="number" name="rsp_404_threshold" value="<?php echo esc_attr(get_option('rsp_404_threshold',20)); ?>" />
                        <label><?php _e('طول پنجره (ثانیه)','ready-secure-pro'); ?></label>
                        <input type="number" name="rsp_404_window" value="<?php echo esc_attr(get_option('rsp_404_window',300)); ?>" />
                        <label><?php _e('مدت مسدودسازی (دقیقه)','ready-secure-pro'); ?></label>
                        <input type="number" name="rsp_404_block_minutes" value="<?php echo esc_attr(get_option('rsp_404_block_minutes',60)); ?>" />
                        <?php submit_button(__('ذخیره','ready-secure-pro')); ?>
                    </form>
                </section>

                <!-- Anti-Spam (دیدگاه) -->
                <section class="rsp-panel" id="tab-antispam">
                    <form method="post" action="options.php" class="rsp-card">
                        <h3><?php _e('کاهش اسپم دیدگاه‌ها','ready-secure-pro'); ?></h3>
                        <?php settings_fields('rsp_settings'); ?>
                        <label><input type="checkbox" name="rsp_antispam_enable" value="1" <?php checked(get_option('rsp_antispam_enable',1),1); ?> /> <?php _e('فعال','ready-secure-pro'); ?></label>
                        <label><?php _e('حداقل فاصله زمانی بین بارگذاری و ارسال (ثانیه)','ready-secure-pro'); ?></label>
                        <input type="number" name="rsp_antispam_min_seconds" value="<?php echo esc_attr(get_option('rsp_antispam_min_seconds',5)); ?>" />
                        <label><input type="checkbox" name="rsp_antispam_honeypot" value="1" <?php checked(get_option('rsp_antispam_honeypot',1),1); ?> /> <?php _e('فیلد هانی‌پات مخفی','ready-secure-pro'); ?></label>
                        <?php submit_button(__('ذخیره','ready-secure-pro')); ?>
                    </form>
                </section>

                <!-- Scan & Health -->
                <section class="rsp-panel" id="tab-scan">
                    <div class="rsp-grid">
                        <div class="rsp-card">
                            <h3><?php _e('اسکن سطح دسترسی فایل‌ها','ready-secure-pro'); ?></h3>
                            <p class="rsp-note"><?php _e('چک سریع wp-config.php، wp-content و uploads','ready-secure-pro'); ?></p>
                            <button type="button" class="button button-primary" id="rsp-scan-fs"><?php _e('اجرای اسکن','ready-secure-pro'); ?></button>
                            <pre id="rsp-scan-output" class="rsp-pre"></pre>
                        </div>
                        <div class="rsp-card">
                            <h3><?php _e('اسکن بدافزار','ready-secure-pro'); ?></h3>
                            <button type="button" class="button" id="rsp-scan-malware"><?php _e('اسکن سریع','ready-secure-pro'); ?></button>
                            <pre id="rsp-malware" class="rsp-pre"></pre>
                        </div>
                    </div>
                </section>

                <!-- Logs & Tools -->
                <section class="rsp-panel" id="tab-logs">
                    <div class="rsp-grid">
                        <div class="rsp-card">
                            <h3><?php _e('لاگ رویدادها','ready-secure-pro'); ?></h3>
                            <button type="button" class="button" id="rsp-export-log">Export JSON</button>
                            <pre id="rsp-log" class="rsp-pre"></pre>
                        </div>
                        <div class="rsp-card">
                            <h3><?php _e('Export / Import تنظیمات','ready-secure-pro'); ?></h3>
                            <button type="button" class="button" id="rsp-export-settings"><?php _e('Export Settings','ready-secure-pro'); ?></button>
                            <textarea id="rsp-settings-json" class="rsp-textarea" rows="8" placeholder="{ ... }"></textarea>
                            <button type="button" class="button button-primary" id="rsp-import-settings"><?php _e('Import Settings','ready-secure-pro'); ?></button>
                            <pre id="rsp-settings-hint" class="rsp-pre"></pre>
                        </div>
                    </div>
                </section>
            </div>
        </div>
    <?php }
}
