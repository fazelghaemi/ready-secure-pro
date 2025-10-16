<?php
if (!defined('ABSPATH')) { exit; }

/**
 * ماژول: حفاظت از فایل‌ها (File Guard)
 * - غیرفعال‌سازی اجرای اسکریپت در wp-content/uploads (و پوشه‌های فرعی)
 * - تولید .htaccess / web.config امن + index.html
 * - جلوگیری از آپلود پسوندهای خطرناک (php, phtml, phar, cgi, sh, htaccess, ini ...)
 * - اسکن روزانهٔ سریع برای یافتن فایل‌های اجرایی در uploads و ثبت لاگ
 *
 * گزینه‌ها:
 *  - rsp_file_guard_disable_php_uploads (bool)
 *  - rsp_file_guard_auto_index (bool)
 */
class RSP_Module_File_Guard implements RSP_Module_Interface {

    public function init() {
        add_action('init', [$this, 'bootstrap'], 5);
        add_filter('wp_handle_upload_prefilter', [$this, 'block_dangerous_uploads']);
        add_action('wp_handle_upload', [$this, 'ensure_after_upload']);
    }

    /**
     * آماده‌سازی و enforce قوانین در شروع درخواست
     */
    public function bootstrap() {
        if (!get_option('rsp_file_guard_disable_php_uploads', 1)) return;
        $up = wp_upload_dir();
        if (empty($up['basedir']) || !is_dir($up['basedir'])) return;

        $this->enforce_directory($up['basedir']);

        // اسکن سریع روزانه
        $tkey = 'rsp_file_guard_last_scan';
        if (false === get_transient($tkey)) {
            $found = $this->quick_scan($up['basedir']);
            if (!empty($found)) {
                do_action('rsp_activity_log', 'file_guard_scan', [
                    'found' => array_slice($found, 0, 50), // جلوگیری از تورم لاگ
                    'count' => count($found)
                ]);
            }
            set_transient($tkey, 1, DAY_IN_SECONDS);
        }
    }

    /**
     * پس از هر آپلود، اطمینان از وجود قوانین دایرکتوری
     */
    public function ensure_after_upload($upload) {
        if (!empty($upload['file'])) {
            $dir = dirname($upload['file']);
            $this->enforce_directory($dir);
        }
        return $upload;
    }

    /**
     * جلوگیری از آپلود پسوندهای خطرناک
     */
    public function block_dangerous_uploads($file) {
        $name = isset($file['name']) ? strtolower($file['name']) : '';
        $danger = [ 'php','phtml','pht','php3','php4','php5','php7','php8','phar','cgi','fcgi','pl','sh','bash','htaccess','user.ini','ini','conf','yaml','yml' ];
        $ext = strtolower(pathinfo($name, PATHINFO_EXTENSION));
        if (in_array($ext, $danger, true)) {
            $file['error'] = __('آپلود این نوع فایل به دلایل امنیتی ممنوع است.', 'ready-secure-pro');
        }
        // جلوگیری از فایل‌های با پسوند دوگانه مانند image.jpg.php
        if (preg_match('/\.(php|phtml|phar|cgi|pl|sh)(\.|$)/i', $name)) {
            $file['error'] = __('آپلود فایل با پسوند اجرایی مجاز نیست.', 'ready-secure-pro');
        }
        return $file;
    }

    /**
     * اِعمال قوانین در یک دایرکتوری: .htaccess / web.config / index.html
     */
    public function enforce_directory($dir) {
        if (!is_dir($dir) || !is_writable($dir)) return false;
        $ok = true;

        // 1) .htaccess برای Apache
        $ht = $dir . DIRECTORY_SEPARATOR . '.htaccess';
        $ht_body = $this->htaccess_body();
        $ok = $this->write_if_changed($ht, $ht_body) && $ok;

        // 2) web.config برای IIS
        $wc = $dir . DIRECTORY_SEPARATOR . 'web.config';
        $wc_body = $this->webconfig_body();
        $ok = $this->write_if_changed($wc, $wc_body) && $ok;

        // 3) index.html برای جلوگیری از Directory Listing
        if (get_option('rsp_file_guard_auto_index', 1)) {
            $ix = $dir . DIRECTORY_SEPARATOR . 'index.html';
            $ix_body = "<!doctype html><meta charset=\"utf-8\"><title>403</title>";
            if (!file_exists($ix)) @file_put_contents($ix, $ix_body);
        }

        // 4) برای پوشه‌های فرعی داخل uploads نیز index.html ایجاد کن (عمق کم برای کارایی)
        if (get_option('rsp_file_guard_auto_index', 1)) {
            $this->ensure_index_in_children($dir, 2);
        }

        return $ok;
    }

    /** محتوای .htaccess امن برای uploads */
    private function htaccess_body() {
        return trim(<<<HT
# Ready Secure Pro — File Guard
# جلوگیری از اجرای اسکریپت‌های PHP/CGI در این مسیر و زیرمسیرها
<IfModule mod_authz_core.c>
  <FilesMatch "\\\.(php|phtml|php3|php4|php5|php7|php8|phar|pl|cgi|fcgi|sh|bash)$">
    Require all denied
  </FilesMatch>
</IfModule>
<IfModule !mod_authz_core.c>
  <FilesMatch "\\\.(php|phtml|php3|php4|php5|php7|php8|phar|pl|cgi|fcgi|sh|bash)$">
    Order allow,deny
    Deny from all
  </FilesMatch>
</IfModule>
Options -ExecCGI
IndexIgnore *
HT);
    }

    /** محتوای web.config امن برای IIS */
    private function webconfig_body() {
        return trim(<<<XML
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>
    <security>
      <requestFiltering>
        <fileExtensions>
          <add fileExtension=".php" allowed="false" />
          <add fileExtension=".phtml" allowed="false" />
          <add fileExtension=".phar" allowed="false" />
          <add fileExtension=".cgi" allowed="false" />
          <add fileExtension=".pl" allowed="false" />
          <add fileExtension=".sh" allowed="false" />
        </fileExtensions>
      </requestFiltering>
    </security>
    <directoryBrowse enabled="false" />
  </system.webServer>
</configuration>
XML);
    }

    /** نوشتن فایل اگر محتوا تغییر کرده باشد */
    private function write_if_changed($path, $body) {
        $current = file_exists($path) ? @file_get_contents($path) : '';
        if ($current === $body) return true;
        $res = @file_put_contents($path, $body);
        if ($res === false) {
            do_action('rsp_activity_log', 'file_guard_write_fail', ['file' => $path]);
            return false;
        }
        do_action('rsp_activity_log', 'file_guard_written', ['file' => $path]);
        return true;
    }

    /** اسکن سریع برای پیدا کردن فایل‌های اجرایی مشکوک در uploads */
    private function quick_scan($base) {
        $found = [];
        $danger = '/\\\.(php|phtml|php3|php4|php5|php7|php8|phar|cgi|pl|sh|bash)$/i';
        $iter = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($base, FilesystemIterator::SKIP_DOTS),
            RecursiveIteratorIterator::SELF_FIRST
        );
        $c = 0;
        foreach ($iter as $file) {
            if ($file->isFile()) {
                $name = $file->getFilename();
                if (preg_match($danger, $name)) {
                    $found[] = (string)$file;
                    $c++;
                    if ($c > 5000) break; // محدودیت ایمنی
                }
            }
        }
        return $found;
    }

    /** ایجاد index.html در زیردایرکتوری‌ها تا عمق مشخص */
    private function ensure_index_in_children($dir, $depth = 1) {
        if ($depth < 0) return;
        $items = @scandir($dir);
        if (!is_array($items)) return;
        foreach ($items as $it) {
            if ($it === '.' || $it === '..') continue;
            $p = $dir . DIRECTORY_SEPARATOR . $it;
            if (is_dir($p)) {
                $ix = $p . DIRECTORY_SEPARATOR . 'index.html';
                if (!file_exists($ix)) @file_put_contents($ix, "<!doctype html><title>403</title>");
                $this->ensure_index_in_children($p, $depth - 1);
            }
        }
    }
}
