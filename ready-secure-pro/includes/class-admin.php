<?php
if (!defined('ABSPATH')) { exit; }

class RSP_Admin {
    public function init() {
        add_action('admin_menu', [$this, 'menu']);
        add_action('admin_enqueue_scripts', [$this, 'assets']);
        add_action('admin_init', [$this, 'register_settings']);
        add_action('wp_ajax_rsp_scan_fs', [$this, 'ajax_scan_fs']);
        add_action('wp_ajax_rsp_get_logs', [$this, 'ajax_get_logs']);
        add_action('wp_ajax_rsp_export_settings', [$this, 'ajax_export_settings']);
        add_action('wp_ajax_rsp_import_settings', [$this, 'ajax_import_settings']);
        add_action('wp_ajax_rsp_scan_integrity', [$this, 'ajax_scan_integrity']);
        // New AJAX action for Malware Scanner
        add_action('wp_ajax_rsp_run_malware_scan', [$this, 'ajax_run_malware_scan']);

        add_action('show_user_profile', [$this, 'render_profile_2fa']);
        add_action('edit_user_profile', [$this, 'render_profile_2fa']);
        add_action('personal_options_update', [$this, 'save_profile_2fa']);
        add_action('edit_user_profile_update', [$this, 'save_profile_2fa']);
    }

    public function menu() {
        add_menu_page(
            'Ready Secure', 'Ready Secure', 'manage_options', 'ready-secure', [$this, 'render_page'],
            'data:image/svg+xml;base64,' . base64_encode('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="#00b0a4"><path d="M12 2L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-3zm0 10.99h7c-.53 4.12-3.28 7.79-7 8.94V13H5V6.3l7-3.11v9.8z"/></svg>'),
            58
        );
    }

    public function assets($hook) {
        if (strpos($hook, 'ready-secure') === false) return;
        wp_enqueue_style('rsp-admin', RSP_URL . 'assets/admin.css', [], RSP_VERSION);
        wp_enqueue_script('rsp-admin', RSP_URL . 'assets/admin.js', ['jquery'], RSP_VERSION, true);
        wp_localize_script('rsp-admin', 'RSP_DATA', [
            'ajax_url' => admin_url('admin-ajax.php'),
            'nonce'    => wp_create_nonce('rsp_nonce'),
        ]);
    }

    public function register_settings() {
        $settings = [
            // Login & BruteForce
            'rsp_login_slug' => ['type' => 'string', 'sanitize_callback' => 'sanitize_title'],
            'rsp_bruteforce_max' => ['type' => 'integer', 'default' => 5],
            'rsp_bruteforce_lock_minutes' => ['type' => 'integer', 'default' => 15],
            'rsp_bruteforce_whitelist' => ['type' => 'string', 'default' => ''],
            'rsp_bruteforce_ip_blacklist' => ['type' => 'string', 'default' => ''], // New: IP Blacklist
            // reCAPTCHA v3 Settings
            'rsp_recaptcha_site_key' => ['type' => 'string', 'default' => ''],
            'rsp_recaptcha_secret_key' => ['type' => 'string', 'default' => ''],

            // Headers
            'rsp_headers_hsts' => ['type' => 'boolean', 'default' => 1],
            'rsp_headers_mode' => ['type' => 'string', 'default' => 'report-only'],
            'rsp_headers_csp' => ['type' => 'string', 'default' => "default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline';"],

            // WAF
            'rsp_waf_rate_limit' => ['type' => 'integer', 'default' => 120],
            'rsp_waf_window' => ['type' => 'integer', 'default' => 60],
            'rsp_waf_enabled' => ['type' => 'boolean', 'default' => 1],

            // 2FA
            'rsp_2fa_enforce_role' => ['type' => 'string', 'default' => ''],
        ];

        foreach ($settings as $name => $args) {
            register_setting('rsp_settings', $name, $args);
        }
    }

    public function render_profile_2fa($user) {
        // QR Code and Backup Codes logic added here
        $secret = get_user_meta($user->ID, 'rsp_totp_secret', true);
        $backup_codes_hashed = get_user_meta($user->ID, 'rsp_backup_codes', true);
        ?>
        <h2>Ready Secure: Two-Factor Authentication (2FA)</h2>
        <table class="form-table">
            <tr>
                <th><label for="rsp_totp_secret">TOTP Secret</label></th>
                <td>
                    <input type="text" name="rsp_totp_secret" id="rsp_totp_secret" value="<?php echo esc_attr($secret); ?>" class="regular-text" />
                    <button type="button" class="button" id="rsp-generate-secret">Generate Random Secret</button>
                    <p class="description">A Base32 encoded secret key. Leave empty to disable 2FA for this user.</p>

                    <?php if ($secret) :
                        $issuer = get_bloginfo('name');
                        $user_email = $user->user_email;
                        $qr_url = urlencode("otpauth://totp/{$issuer}:{$user_email}?secret={$secret}&issuer={$issuer}");
                    ?>
                        <div id="rsp-qr-code">
                            <p>Scan this QR code with your authenticator app (Google Authenticator, Authy, etc.):</p>
                            <img src="https://chart.googleapis.com/chart?chs=200x200&cht=qr&chl=<?php echo $qr_url; ?>" alt="QR Code">
                        </div>
                    <?php endif; ?>
                </td>
            </tr>
            <tr>
                <th>Backup Codes</th>
                <td>
                    <?php if (!empty($backup_codes_hashed) && is_array($backup_codes_hashed)): ?>
                        <p>2FA Backup codes are configured. Use them if you lose access to your authenticator app.</p>
                        <button type="submit" name="rsp_generate_backup_codes" class="button" value="1">Generate New Backup Codes</button>
                    <?php else: ?>
                        <p class="description">No backup codes generated. After setting a TOTP secret, save the page and then generate backup codes.</p>
                         <?php if ($secret): ?>
                             <button type="submit" name="rsp_generate_backup_codes" class="button" value="1">Generate Backup Codes</button>
                         <?php endif; ?>
                    <?php endif; ?>
                </td>
            </tr>
        </table>

        <script>
            // Simple secret generator
            document.getElementById('rsp-generate-secret')?.addEventListener('click', function(e){
                e.preventDefault();
                const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
                let secret = '';
                for (let i = 0; i < 16; i++) {
                    secret += alphabet.charAt(Math.floor(Math.random() * alphabet.length));
                }
                document.getElementById('rsp_totp_secret').value = secret;
            });
        </script>
    <?php }

    public function save_profile_2fa($user_id) {
        if (!current_user_can('edit_user', $user_id)) return;

        if (isset($_POST['rsp_totp_secret'])) {
            update_user_meta($user_id, 'rsp_totp_secret', sanitize_text_field($_POST['rsp_totp_secret']));
        }

        // Generate and save backup codes if requested
        if (isset($_POST['rsp_generate_backup_codes'])) {
            $codes = [];
            $hashed_codes = [];
            for ($i = 0; $i < 10; $i++) {
                $code = bin2hex(random_bytes(4)); // 8-character code
                $codes[] = $code;
                $hashed_codes[] = wp_hash_password($code);
            }
            update_user_meta($user_id, 'rsp_backup_codes', $hashed_codes);

            // Temporarily store plain codes to show to the user ONCE.
            update_user_meta($user_id, 'rsp_new_backup_codes_plain', $codes);
        }
    }

    // AJAX handlers... (scan_fs, get_logs, etc. remain similar but get_logs will change)
    public function ajax_get_logs() {
        check_ajax_referer('rsp_nonce');
        global $wpdb;
        $table_name = $wpdb->prefix . 'rsp_logs';
        $logs = $wpdb->get_results("SELECT * FROM {$table_name} ORDER BY id DESC LIMIT 100", ARRAY_A);
        wp_send_json_success($logs);
    }

    public function ajax_run_malware_scan() {
        check_ajax_referer('rsp_nonce');
        if (class_exists('RSP_Module_Malware_Scanner')) {
            $scanner = new RSP_Module_Malware_Scanner();
            $results = $scanner->scan();
            wp_send_json_success($results);
        }
        wp_send_json_error(['message' => 'Malware scanner module not found.']);
    }

    public function ajax_scan_fs() { check_ajax_referer('rsp_nonce'); if (class_exists('RSP_Module_FS_Permissions')) { $m = new RSP_Module_FS_Permissions(); wp_send_json_success(['report'=>$m->scan_report()]); } wp_send_json_error('module not found'); }
    public function ajax_export_settings() { check_ajax_referer('rsp_nonce'); wp_send_json_success(rsp_option_export()); }
    public function ajax_import_settings() { check_ajax_referer('rsp_nonce'); $json = isset($_POST['payload']) ? wp_unslash($_POST['payload']) : ''; $data = json_decode($json, true); if (!is_array($data)) wp_send_json_error('invalid json'); foreach ($data as $k=>$v) { if (strpos($k,'rsp_') === 0) update_option($k, $v); } wp_send_json_success(true); }
    public function ajax_scan_integrity() { check_ajax_referer('rsp_nonce'); if (class_exists('RSP_Module_Integrity')) { $m = new RSP_Module_Integrity(); wp_send_json_success($m->scan_core()); } wp_send_json_error('module not found'); }


    public function render_page() {
        if (isset($_GET['settings-updated'])) {
            // Add this to flush rewrite rules after saving login slug
            flush_rewrite_rules();
            ?>
            <div id="message" class="updated notice is-dismissible"><p>Settings saved. Rewrite rules have been flushed.</p></div>
            <?php
        }

        // Display newly generated backup codes if they exist
        $new_codes = get_user_meta(get_current_user_id(), 'rsp_new_backup_codes_plain', true);
        if (!empty($new_codes)) {
            echo '<div id="message" class="updated notice is-dismissible"><p><strong>Your new backup codes are:</strong><br><pre>' . implode("\n", $new_codes) . '</pre>Please save these in a safe place. You will not be able to see them again.</p></div>';
            delete_user_meta(get_current_user_id(), 'rsp_new_backup_codes_plain');
        }
    ?>
    <div class="rsp-wrap">
        <div class="rsp-sidebar">
            <div class="rsp-brand">
                <img class="rsp-logo-img" src="<?php echo esc_url(RSP_URL . 'assets/img/readystudio-logo.svg'); ?>" alt="ReadyStudio Logo" />
                <div class="rsp-brand-text">
                    <span class="rsp-name">Ready Secure</span>
                    <span class="rsp-ver">v<?php echo esc_html(RSP_VERSION); ?></span>
                </div>
            </div>
            <nav class="rsp-nav">
                <a class="rsp-nav-item active" href="#overview" data-tab="overview"><span class="dashicons dashicons-dashboard"></span> Overview</a>
                <a class="rsp-nav-item" href="#login-security" data-tab="login-security"><span class="dashicons dashicons-lock"></span> Login Security</a>
                <a class="rsp-nav-item" href="#firewall" data-tab="firewall"><span class="dashicons dashicons-shield"></span> Firewall</a>
                <a class="rsp-nav-item" href="#scanners" data-tab="scanners"><span class="dashicons dashicons-search"></span> Scanners</a>
                <a class="rsp-nav-item" href="#logs" data-tab="logs"><span class="dashicons dashicons-list-view"></span> Activity Logs</a>
                <a class="rsp-nav-item" href="#tools" data-tab="tools"><span class="dashicons dashicons-admin-tools"></span> Tools</a>
            </nav>
        </div>
        <main class="rsp-main">
            <form method="post" action="options.php">
                <?php settings_fields('rsp_settings'); ?>

                <section class="rsp-panel show" id="tab-overview">
                    <div class="rsp-panel-header"><h1>Overview</h1><p>A quick glance at your site's security status.</p></div>
                    </section>

                <section class="rsp-panel" id="tab-login-security">
                    <div class="rsp-panel-header"><h1>Login Security</h1><p>Protect your login form from unauthorized access.</p></div>
                    <div class="rsp-grid">
                        <div class="rsp-card">
                            <div class="rsp-card-header"><h3>Custom Login URL</h3></div>
                            <div class="rsp-card-content">
                                <div class="rsp-form-group">
                                    <label for="rsp_login_slug">Login Slug</label>
                                    <input type="text" id="rsp_login_slug" name="rsp_login_slug" value="<?php echo esc_attr(get_option('rsp_login_slug','manager')); ?>" />
                                    <p class="description">Change from /wp-admin/ to /your-slug/. Remember to save Permalinks after changing.</p>
                                </div>
                            </div>
                        </div>
                        <div class="rsp-card">
                            <div class="rsp-card-header"><h3>Brute-Force Protection</h3></div>
                            <div class="rsp-card-content">
                                <div class="rsp-form-group">
                                    <label for="rsp_bruteforce_max">Max Failed Attempts</label>
                                    <input type="number" id="rsp_bruteforce_max" name="rsp_bruteforce_max" value="<?php echo esc_attr(get_option('rsp_bruteforce_max',5)); ?>" />
                                </div>
                                <div class="rsp-form-group">
                                    <label for="rsp_bruteforce_lock_minutes">Lockout Duration (minutes)</label>
                                    <input type="number" id="rsp_bruteforce_lock_minutes" name="rsp_bruteforce_lock_minutes" value="<?php echo esc_attr(get_option('rsp_bruteforce_lock_minutes',15)); ?>" />
                                </div>
                            </div>
                        </div>
                        <div class="rsp-card">
                            <div class="rsp-card-header"><h3>Google reCAPTCHA v3</h3></div>
                            <div class="rsp-card-content">
                                <div class="rsp-form-group">
                                    <label for="rsp_recaptcha_site_key">Site Key</label>
                                    <input type="text" id="rsp_recaptcha_site_key" name="rsp_recaptcha_site_key" value="<?php echo esc_attr(get_option('rsp_recaptcha_site_key')); ?>" />
                                </div>
                                <div class="rsp-form-group">
                                    <label for="rsp_recaptcha_secret_key">Secret Key</label>
                                    <input type="password" id="rsp_recaptcha_secret_key" name="rsp_recaptcha_secret_key" value="<?php echo esc_attr(get_option('rsp_recaptcha_secret_key')); ?>" />
                                    <p class="description">Protects against bots without user friction.</p>
                                </div>
                            </div>
                        </div>
                    </div>
                </section>
                
                <section class="rsp-panel" id="tab-firewall">
                    <div class="rsp-panel-header"><h1>Firewall</h1><p>Configure WAF, Rate Limiting, and IP blocking rules.</p></div>
                     <div class="rsp-grid">
                         <div class="rsp-card">
                             <div class="rsp-card-header"><h3>WAF & Rate Limiting</h3></div>
                             <div class="rsp-card-content">
                                 <div class="rsp-form-group"><label><input type="checkbox" name="rsp_waf_enabled" value="1" <?php checked(get_option('rsp_waf_enabled', 1), 1); ?> /> Enable Basic WAF</label></div>
                                 <div class="rsp-form-group">
                                     <label for="rsp_waf_rate_limit">Rate Limit (requests)</label>
                                     <input type="number" id="rsp_waf_rate_limit" name="rsp_waf_rate_limit" value="<?php echo esc_attr(get_option('rsp_waf_rate_limit', 120)); ?>" />
                                 </div>
                                 <div class="rsp-form-group">
                                     <label for="rsp_waf_window">Rate Limit Window (seconds)</label>
                                     <input type="number" id="rsp_waf_window" name="rsp_waf_window" value="<?php echo esc_attr(get_option('rsp_waf_window', 60)); ?>" />
                                 </div>
                             </div>
                         </div>
                         <div class="rsp-card">
                            <div class="rsp-card-header"><h3>IP Access Lists</h3></div>
                             <div class="rsp-card-content">
                                 <div class="rsp-form-group">
                                     <label for="rsp_bruteforce_whitelist">IP Whitelist</label>
                                     <textarea id="rsp_bruteforce_whitelist" name="rsp_bruteforce_whitelist" rows="5"><?php echo esc_textarea(get_option('rsp_bruteforce_whitelist','')); ?></textarea>
                                     <p class="description">One IP per line. These IPs will bypass all blocking rules.</p>
                                 </div>
                                  <div class="rsp-form-group">
                                     <label for="rsp_bruteforce_ip_blacklist">IP Blacklist</label>
                                     <textarea id="rsp_bruteforce_ip_blacklist" name="rsp_bruteforce_ip_blacklist" rows="5"><?php echo esc_textarea(get_option('rsp_bruteforce_ip_blacklist','')); ?></textarea>
                                     <p class="description">One IP per line. These IPs will be blocked completely.</p>
                                 </div>
                             </div>
                         </div>
                     </div>
                </section>
                
                <section class="rsp-panel" id="tab-scanners">
                    <div class="rsp-panel-header"><h1>Scanners</h1><p>Check your site for file integrity issues and potential malware.</p></div>
                    <div class="rsp-grid">
                        <div class="rsp-card">
                            <div class="rsp-card-header"><h3>WordPress Core Integrity</h3></div>
                            <div class="rsp-card-content">
                                <p>Compares your core WordPress files against the official checksums to detect unauthorized changes.</p>
                                <button type="button" class="button button-primary" id="rsp-run-integrity">Scan Core Files</button>
                                <pre id="rsp-integrity-out" class="rsp-pre"></pre>
                            </div>
                        </div>
                        <div class="rsp-card">
                            <div class="rsp-card-header"><h3>File Permissions</h3></div>
                            <div class="rsp-card-content">
                                <p>Scans critical files and directories for recommended secure permissions.</p>
                                <button type="button" class="button button-primary" id="rsp-scan-fs">Scan Permissions</button>
                                <pre id="rsp-fs-out" class="rsp-pre"></pre>
                            </div>
                        </div>
                        <div class="rsp-card">
                            <div class="rsp-card-header"><h3>Malware Scanner (Basic)</h3></div>
                            <div class="rsp-card-content">
                                <p>Scans theme and plugin files for suspicious code patterns. This may take a while.</p>
                                <button type="button" class="button button-primary" id="rsp-run-malware-scan">Scan for Malware</button>
                                <pre id="rsp-malware-out" class="rsp-pre"></pre>
                            </div>
                        </div>
                    </div>
                </section>
                
                <section class="rsp-panel" id="tab-logs">
                    <div class="rsp-panel-header"><h1>Activity Logs</h1><p>Shows the latest security events recorded by the plugin.</p></div>
                     <div class="rsp-card">
                         <div class="rsp-card-header"><h3>Latest Events</h3></div>
                         <div class="rsp-card-content">
                            <button type="button" class="button" id="rsp-export-log">Export as JSON</button>
                            <pre id="rsp-log-out" class="rsp-pre">Loading logs...</pre>
                         </div>
                     </div>
                </section>
                
                 <section class="rsp-panel" id="tab-tools">
                    <div class="rsp-panel-header"><h1>Tools</h1><p>Utilities for managing plugin settings.</p></div>
                     <div class="rsp-card">
                         <div class="rsp-card-header"><h3>Import / Export</h3></div>
                         <div class="rsp-card-content">
                            <p>Save or load your plugin settings using JSON.</p>
                            <button type="button" class="button" id="rsp-export-settings">Export Settings</button>
                            <textarea id="rsp-settings-json" class="rsp-textarea" rows="8" placeholder="Paste your settings JSON here..."></textarea>
                            <button type="button" class="button button-primary" id="rsp-import-settings" style="margin-top: 10px;">Import Settings</button>
                            <pre id="rsp-settings-hint" class="rsp-pre"></pre>
                         </div>
                     </div>
                </section>

                <?php submit_button('Save All Settings'); ?>
            </form>
        </main>
    </div>
    <?php }
}