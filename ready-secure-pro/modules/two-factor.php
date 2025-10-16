<?php
if (!defined('ABSPATH')) { exit; }

/**
 * ماژول: احراز هویت دومرحله‌ای (TOTP) + کدهای پشتیبان
 * - افزودن فیلد «کد 2FA» به فرم ورود وردپرس (در مسیر سفارشی هم کار می‌کند)
 * - اعتبارسنجی TOTP Google Authenticator (window ±1)
 * - کدهای پشتیبان: تولید، ذخیرهٔ امن (هش)، مصرف یک‌بارمصرف
 * - اجبار 2FA برای نقش(های) مشخص (rsp_2fa_enforce_role)
 * - ثبت رویدادهای امنیتی در لاگ مرکزی
 *
 * وابستگی: کلاس‌ادمین قبلاً امکان ثبت Secret در پروفایل کاربر را فراهم می‌کند (meta: rsp_totp_secret)
 * این ماژول UI تولید/مدیریت «کدهای پشتیبان» را به پروفایل کاربر اضافه می‌کند.
 */
class RSP_Module_Two_Factor implements RSP_Module_Interface {

    const META_SECRET = 'rsp_totp_secret';
    const META_BACKUP = 'rsp_totp_backup_hashes'; // آرایه‌ای از هش‌ها

    public function init() {
        // فیلد ورود + اعتبارسنجی
        add_action('login_form',              [$this, 'render_login_field']);
        add_filter('authenticate',            [$this, 'enforce_twofactor'], 99, 3);

        // پروفایل کاربر: مدیریت کدهای پشتیبان
        add_action('show_user_profile',       [$this, 'render_profile_backup']);
        add_action('edit_user_profile',       [$this, 'render_profile_backup']);
        add_action('personal_options_update', [$this, 'save_profile_backup']);
        add_action('edit_user_profile_update',[$this, 'save_profile_backup']);
    }

    /* ==================== Login UI ==================== */
    public function render_login_field() {
        echo '<p><label for="rsp_2fa_code">' . esc_html__('کد تأیید ۲مرحله‌ای', 'ready-secure-pro') . '<br />'
            . '<input type="text" name="rsp_2fa_code" id="rsp_2fa_code" class="input" value="" size="20" autocomplete="one-time-code" /></label></p>';
    }

    /* ==================== Enforce + Verify ==================== */
    public function enforce_twofactor($user, $username, $password) {
        // اگر قبلاً خطاست، همان را برگردان
        if (is_wp_error($user)) return $user;
        if (!$user || !($user instanceof WP_User)) return $user;

        $uid = (int) $user->ID;
        $secret = trim((string) get_user_meta($uid, self::META_SECRET, true));

        // اگر اجبار نقش تنظیم شده بود و کاربر فاقد سکرت است
        if ($this->is_role_enforced($user) && $secret === '') {
            return new WP_Error('rsp_2fa_required', __('ورود فقط با فعال‌بودن 2FA مجاز است. لطفاً در پروفایل کاربری TOTP را فعال کنید.', 'ready-secure-pro'));
        }

        // اگر سکرت ندارد، نیازی به 2FA نیست
        if ($secret === '') return $user;

        // دریافت کد ارسالی
        $code = isset($_POST['rsp_2fa_code']) ? trim((string) $_POST['rsp_2fa_code']) : '';

        // اگر کد خالی است، خطا بده
        if ($code === '') {
            return new WP_Error('rsp_2fa_missing', __('کد 2FA لازم است.', 'ready-secure-pro'));
        }

        // اول: بررسی کد پشتیبان (10 عددی یا 8 عددی)
        if ($this->try_consume_backup_code($uid, $code)) {
            do_action('rsp_activity_log','2fa_backup_used',[ 'uid'=>$uid ]);
            return $user; // مجاز شد
        }

        // سپس: بررسی TOTP
        if (!$this->verify_totp($secret, $code)) {
            do_action('rsp_activity_log','2fa_failed',[ 'uid'=>$uid ]);
            return new WP_Error('rsp_2fa_invalid', __('کد 2FA نامعتبر است.', 'ready-secure-pro'));
        }

        // موفق
        do_action('rsp_activity_log','2fa_ok',[ 'uid'=>$uid ]);
        return $user;
    }

    private function is_role_enforced($user){
        $roles = trim((string) get_option('rsp_2fa_enforce_role',''));
        if ($roles === '') return false;
        $list = array_filter(array_map('trim', preg_split('/[,\|\s]+/', $roles)));
        if (empty($list)) return false;
        foreach ($user->roles as $r){ if (in_array($r, $list, true)) return true; }
        return false;
    }

    /* ==================== TOTP Core ==================== */
    // تولید کد TOTP بر اساس RFC 6238 (SHA1, 30s)
    private function totp_at($secret_base32, $timeSlice){
        $secret = $this->base32_decode($secret_base32);
        if ($secret === '') return '';
        $time = pack('N*', 0) . pack('N*', $timeSlice); // 64-bit big-endian
        $hash = hash_hmac('sha1', $time, $secret, true);
        $offset = ord(substr($hash, -1)) & 0x0F;
        $trunc = (ord($hash[$offset]) & 0x7F) << 24
               | (ord($hash[$offset+1]) & 0xFF) << 16
               | (ord($hash[$offset+2]) & 0xFF) << 8
               | (ord($hash[$offset+3]) & 0xFF);
        $code = $trunc % 1000000; // 6-digit
        return str_pad((string)$code, 6, '0', STR_PAD_LEFT);
    }

    private function verify_totp($secret_base32, $code){
        $code = preg_replace('/\s+/', '', (string)$code);
        if (!preg_match('/^\d{6}$/', $code)) return false;
        $t = (int) floor(time() / 30);
        // window ±1 برای تحمل اختلاف ساعت
        for ($i=-1; $i<=1; $i++){
            if (hash_equals($this->totp_at($secret_base32, $t+$i), $code)) return true;
        }
        return false;
    }

    private function base32_decode($b32){
        $b32 = strtoupper(preg_replace('/[^A-Z2-7]/i', '', (string)$b32));
        if ($b32 === '') return '';
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $buffer = 0; $bitsLeft = 0; $out = '';
        for ($i=0; $i<strlen($b32); $i++){
            $val = strpos($alphabet, $b32[$i]);
            if ($val === false) continue;
            $buffer = ($buffer << 5) | $val;
            $bitsLeft += 5;
            if ($bitsLeft >= 8){
                $bitsLeft -= 8;
                $out .= chr(($buffer >> $bitsLeft) & 0xFF);
            }
        }
        return $out;
    }

    /* ==================== Backup Codes ==================== */
    public function render_profile_backup($user){
        $uid = (int) $user->ID;
        $secret = trim((string) get_user_meta($uid, self::META_SECRET, true));
        echo '<h2>'.esc_html__('کدهای پشتیبان 2FA','ready-secure-pro').'</h2>';
        if ($secret === ''){
            echo '<p class="description">'.esc_html__('ابتدا 2FA را با ثبت Secret فعال کنید، سپس می‌توانید کدهای پشتیبان بسازید.','ready-secure-pro').'</p>';
            return;
        }
        $hashes = get_user_meta($uid, self::META_BACKUP, true);
        if (!is_array($hashes)) $hashes = [];
        $remaining = count($hashes);
        echo '<p class="description">'.sprintf(esc_html__('تعداد کدهای پشتیبان باقیمانده: %d','ready-secure-pro'), (int)$remaining).'</p>';
        echo '<p><button class="button" name="rsp_generate_backup" value="1">'.esc_html__('تولید ۱۰ کد پشتیبان جدید','ready-secure-pro').'</button> ';
        if ($remaining>0) echo '<button class="button" name="rsp_show_backup" value="1">'.esc_html__('نمایش کدهای موجود','ready-secure-pro').'</button>';
        echo '</p>';
        // نمایش کدها (فقط هش‌ها ذخیره‌اند؛ باید هنگام درخواست مجدد تولید شوند)
        if (isset($_REQUEST['rsp_show_backup']) && $remaining>0){
            echo '<div class="notice notice-info"><p>'.esc_html__('این کدها یک‌بارمصرف بوده و مانند گذرواژه محرمانه‌اند.','ready-secure-pro').'</p>';
            echo '<ul style="columns:2">';
            foreach ($hashes as $h){ echo '<li><code>••••••••</code></li>'; }
            echo '</ul></div>';
        }
    }

    public function save_profile_backup($uid){
        if (!current_user_can('edit_user', $uid)) return;
        if (isset($_POST['rsp_generate_backup'])){
            $codes  = $this->generate_backup_codes(10);
            $hashes = array_map([$this, 'hash_backup'], $codes);
            update_user_meta($uid, self::META_BACKUP, $hashes);
            // کدهای خام را یک‌بار به کاربر نشان دهیم (با admin_notices)
            add_action('admin_notices', function() use ($codes){
                echo '<div class="notice notice-success"><p>'.esc_html__('کدهای پشتیبان جدید — آنها را در جای امن نگه دارید:','ready-secure-pro').'</p><ul style="columns:2">';
                foreach ($codes as $c){ echo '<li><code>'.esc_html($c).'</code></li>'; }
                echo '</ul></div>';
            });
        }
    }

    private function generate_backup_codes($n=10){
        $out = [];
        for ($i=0;$i<$n;$i++){
            // الگو: 4 بلوک 2 رقمی → 8 رقم (خواناتر و کوتاه)
            $out[] = sprintf('%02d%02d%02d%02d', random_int(0,99), random_int(0,99), random_int(0,99), random_int(0,99));
        }
        return $out;
    }

    private function hash_backup($code){
        $sitekey = wp_salt('auth');
        return hash_hmac('sha256', (string)$code, (string)$sitekey);
    }

    private function try_consume_backup_code($uid, $code){
        $code = preg_replace('/\s+/', '', (string)$code);
        if ($code === '') return false;
        $hashes = get_user_meta($uid, self::META_BACKUP, true);
        if (!is_array($hashes) || empty($hashes)) return false;
        $hash = $this->hash_backup($code);
        $idx = array_search($hash, $hashes, true);
        if ($idx === false) return false;
        unset($hashes[$idx]);
        update_user_meta($uid, self::META_BACKUP, array_values($hashes));
        return true;
    }
}
