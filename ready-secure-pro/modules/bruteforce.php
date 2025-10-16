<?php
if (!defined('ABSPATH')) { exit; }

class RSP_Module_BruteForce implements RSP_Module_Interface {
    private $prefix = 'rsp_bf_';

    public function init() {
        add_filter('wp_authenticate_user', [$this, 'check_lock'], 99, 2);
        add_action('wp_login_failed', [$this, 'on_failed']);
        add_action('wp_login', [$this, 'on_success'], 10, 2);
        
        // Add reCAPTCHA script to login page
        $site_key = get_option('rsp_recaptcha_site_key');
        if ($site_key) {
            add_action('login_enqueue_scripts', [$this, 'enqueue_recaptcha']);
            add_action('login_form', [$this, 'recaptcha_field']);
        }
    }

    public function enqueue_recaptcha() {
        $site_key = get_option('rsp_recaptcha_site_key');
        wp_enqueue_script('rsp-recaptcha', "https://www.google.com/recaptcha/api.js?render={$site_key}", [], null, true);
        wp_add_inline_script('rsp-recaptcha', "grecaptcha.ready(function(){grecaptcha.execute('{$site_key}',{action:'login'}).then(function(token){document.getElementById('rsp_recaptcha_token').value=token;});});");
    }

    public function recaptcha_field() {
        echo '<input type="hidden" name="rsp_recaptcha_token" id="rsp_recaptcha_token" value="">';
    }

    private function is_ip_on_list($ip, $option_name) {
        $list = (string) get_option($option_name, '');
        if (empty($list)) return false;

        $ips = preg_split('/\r?\n/', $list, -1, PREG_SPLIT_NO_EMPTY);
        foreach ($ips as $line) {
            if (trim($line) === $ip) return true;
        }
        return false;
    }

    private function verify_recaptcha() {
        $site_key = get_option('rsp_recaptcha_site_key');
        $secret_key = get_option('rsp_recaptcha_secret_key');

        if (!$site_key || !$secret_key || !isset($_POST['rsp_recaptcha_token'])) {
            return true; // If not configured, bypass
        }
        
        $token = sanitize_text_field($_POST['rsp_recaptcha_token']);
        $response = wp_remote_post('https://www.google.com/recaptcha/api/siteverify', [
            'body' => [
                'secret'   => $secret_key,
                'response' => $token,
                'remoteip' => rsp_client_ip(),
            ],
        ]);
        
        if (is_wp_error($response)) {
            return true; // Fail open if Google is unreachable
        }

        $body = json_decode(wp_remote_retrieve_body($response), true);
        
        // Score is from 0.0 to 1.0. Lower is more likely a bot.
        // We consider anything below 0.5 as a failure.
        return ($body['success'] && isset($body['score']) && $body['score'] > 0.5);
    }

    public function check_lock($user, $pass) {
        $ip = rsp_client_ip();

        // 1. Check permanent blacklist
        if ($this->is_ip_on_list($ip, 'rsp_bruteforce_ip_blacklist')) {
            do_action('rsp_activity_log', 'blacklist_block', ['ip' => $ip]);
            return new WP_Error('rsp_blacklisted', __('Your IP address has been permanently blocked.', 'ready-secure-pro'));
        }
        
        // 2. Bypass for whitelist
        if ($this->is_ip_on_list($ip, 'rsp_bruteforce_whitelist')) {
            return $user;
        }

        // 3. Check temporary lock
        $transient_key = $this->prefix . md5($ip);
        $data = get_transient($transient_key);
        if (is_array($data) && !empty($data['locked'])) {
            return new WP_Error('rsp_locked', __('Too many failed login attempts. Please try again later.', 'ready-secure-pro'));
        }

        return $user;
    }

    public function on_failed($username) {
        $ip = rsp_client_ip();
        if ($this->is_ip_on_list($ip, 'rsp_bruteforce_whitelist')) return;

        // Verify reCAPTCHA. If it passes, don't count this as a failure.
        if ($this->verify_recaptcha()) {
            // reCAPTCHA passed, probably a human typo. Log it but don't increment counter.
            do_action('rsp_activity_log', 'login_failed_recaptcha_ok', ['ip' => $ip, 'username' => $username]);
            return;
        }
        
        // reCAPTCHA failed or wasn't present. This is a suspicious attempt.
        $max_attempts = max(1, (int) get_option('rsp_bruteforce_max', 5));
        $lock_minutes = max(1, (int) get_option('rsp_bruteforce_lock_minutes', 15));
        $transient_key = $this->prefix . md5($ip);
        
        $data = get_transient($transient_key);
        if (!is_array($data)) {
            $data = ['count' => 0, 'locked' => false];
        }
        
        $data['count']++;
        
        if ($data['count'] >= $max_attempts) {
            $data['locked'] = true;
            set_transient($transient_key, $data, $lock_minutes * MINUTE_IN_SECONDS);
            do_action('rsp_activity_log', 'lockout', ['ip' => $ip, 'username' => $username, 'minutes' => $lock_minutes]);
        } else {
            set_transient($transient_key, $data, 2 * HOUR_IN_SECONDS);
        }
        
        do_action('rsp_activity_log', 'login_failed', ['ip' => $ip, 'username' => $username, 'count' => $data['count']]);
    }

    public function on_success($user_login, $user) {
        delete_transient($this->prefix . md5(rsp_client_ip()));
        do_action('rsp_activity_log', 'login_success', ['ip' => rsp_client_ip(), 'username' => $user_login, 'uid' => $user->ID]);
    }
}