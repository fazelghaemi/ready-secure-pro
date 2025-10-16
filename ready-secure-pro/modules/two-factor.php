<?php
if (!defined('ABSPATH')) { exit; }

class RSP_Module_Two_Factor implements RSP_Module_Interface {
    public function init() {
        add_action('login_form', [$this, 'login_field']);
        add_filter('authenticate', [$this, 'verify'], 30, 3);
    }

    public function login_field() {
        echo '<p>
                <label for="rsp_2fa_code">Two-Factor Code</label>
                <input type="text" name="rsp_2fa_code" id="rsp_2fa_code" class="input" value="" size="20" autocomplete="one-time-code" placeholder="Or a backup code" />
              </p>';
    }

    private function base32_decode($b32) {
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $b32 = strtoupper(preg_replace('/[^A-Z2-7]/', '', $b32));
        $bits = '';
        foreach (str_split($b32) as $c) {
            $v = strpos($alphabet, $c);
            if ($v === false) continue;
            $bits .= str_pad(decbin($v), 5, '0', STR_PAD_LEFT);
        }
        $bytes = '';
        for ($i = 0; $i + 8 <= strlen($bits); $i += 8) {
            $bytes .= chr(bindec(substr($bits, $i, 8)));
        }
        return $bytes;
    }

    private function calculate_totp($secret, $timeSlice = null) {
        if ($timeSlice === null) {
            $timeSlice = floor(time() / 30);
        }
        $secretKey = $this->base32_decode($secret);
        $time = pack('N*', 0) . pack('N*', $timeSlice);
        $hm = hash_hmac('sha1', $time, $secretKey, true);
        $offset = ord(substr($hm, -1)) & 0x0F;
        $hashpart = substr($hm, $offset, 4);
        $value = unpack('N', $hashpart)[1] & 0x7FFFFFFF;
        $modulo = pow(10, 6);
        return str_pad($value % $modulo, 6, '0', STR_PAD_LEFT);
    }
    
    public function verify($user, $username, $password) {
        if (is_wp_error($user) || !$user instanceof WP_User) {
            return $user;
        }

        $role_to_enforce = get_option('rsp_2fa_enforce_role', '');
        $secret = get_user_meta($user->ID, 'rsp_totp_secret', true);

        // If 2FA is not enabled for this user, check if their role requires it.
        if (empty($secret)) {
            if ($role_to_enforce && in_array($role_to_enforce, (array) $user->roles, true)) {
                return new WP_Error('rsp_2fa_required', __('Error: Two-Factor Authentication is required for your user role. Please contact an administrator.', 'ready-secure-pro'));
            }
            return $user; // 2FA is not required for this user.
        }

        // 2FA is enabled; now verify the code.
        $code = isset($_POST['rsp_2fa_code']) ? trim(sanitize_text_field($_POST['rsp_2fa_code'])) : '';
        if (empty($code)) {
            return new WP_Error('rsp_2fa_invalid', __('Error: The Two-Factor code is empty.', 'ready-secure-pro'));
        }

        // --- Verification Logic ---
        $is_code_valid = false;

        // 1. Check against TOTP code (with time drift)
        $time_slice = floor(time() / 30);
        for ($i = -1; $i <= 1; $i++) {
            if ($this->calculate_totp($secret, $time_slice + $i) === $code) {
                $is_code_valid = true;
                break;
            }
        }
        
        // 2. If TOTP is not valid, check against backup codes
        if (!$is_code_valid) {
            $hashed_backup_codes = get_user_meta($user->ID, 'rsp_backup_codes', true);
            if (is_array($hashed_backup_codes)) {
                foreach ($hashed_backup_codes as $key => $hashed_code) {
                    if (wp_check_password($code, $hashed_code)) {
                        // Valid backup code found. Invalidate it for future use.
                        unset($hashed_backup_codes[$key]);
                        update_user_meta($user->ID, 'rsp_backup_codes', $hashed_backup_codes);
                        
                        do_action('rsp_activity_log', '2fa_backup_used', ['uid' => $user->ID, 'remaining' => count($hashed_backup_codes)]);
                        $is_code_valid = true;
                        break;
                    }
                }
            }
        }

        // 3. Final decision
        if ($is_code_valid) {
            do_action('rsp_activity_log', '2fa_success', ['uid' => $user->ID]);
            return $user;
        } else {
            return new WP_Error('rsp_2fa_invalid', __('Error: The Two-Factor code is incorrect.', 'ready-secure-pro'));
        }
    }
}