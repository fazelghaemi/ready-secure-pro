<?php
if (!defined('ABSPATH')) { exit; }

/**
 * File Guard: Deny PHP execution in uploads + quick scan + safer notices.
 * - Compatible with older PHP (no \Throwable).
 * - Uses transient for admin_notice on write failures.
 */
class RSP_Module_File_Guard implements RSP_Module_Interface {

    public function init() {
        if (!get_option('rsp_file_guard_enable', 1)) {
            return;
        }
        add_action('init', array($this, 'bootstrap'), 12);
        add_filter('wp_handle_upload_prefilter', array($this, 'prefilter'));
        add_action('admin_notices', array($this, 'maybe_notice'));
    }

    /** Get uploads base dir with fallback */
    private function uploads_dir() {
        $u = wp_upload_dir();
        return (is_array($u) && !empty($u['basedir'])) ? $u['basedir'] : (defined('WP_CONTENT_DIR') ? WP_CONTENT_DIR . '/uploads' : ABSPATH . 'wp-content/uploads');
    }

    /** Block risky file types on upload */
    public function prefilter($file) {
        $ext = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
        // Keep this tight; php-like extensions + obvious binaries/scripts
        $deny = array('php', 'php3', 'php4', 'php5', 'phtml', 'phar', 'cgi', 'pl', 'sh', 'exe', 'bat', 'cmd', 'js');
        if (in_array($ext, $deny, true)) {
            $file['error'] = __('پسوند فایل مجاز نیست.', 'ready-secure-pro');
        }
        return $file;
    }

    /** Show admin notice if we couldn't write rules to uploads dir */
    public function maybe_notice() {
        if (!current_user_can('manage_options')) {
            return;
        }
        if (get_transient('rsp_fg_write_error')) {
            delete_transient('rsp_fg_write_error');
            echo '<div class="notice notice-error"><p>' .
                 esc_html__('Ready Secure Pro: عدم توانایی نوشتن قوانین ایمنی در پوشه uploads. لطفاً دسترسی پوشه را بررسی کنید. اگر روی NGINX هستید، قوانین را دستی اعمال کنید.', 'ready-secure-pro') .
                 '</p></div>';
        }
    }

    /** Write file if content changed */
    private function write_if_changed($path, $content) {
        try {
            // Ensure directory exists
            $dir = dirname($path);
            if (!is_dir($dir)) {
                @wp_mkdir_p($dir);
            }
            $current = (file_exists($path) ? @file_get_contents($path) : false);
            if ($current !== false && md5($current) === md5($content)) {
                return true; // no change
            }
            // Attempt write
            $ok = @file_put_contents($path, $content);
            if ($ok === false) {
                set_transient('rsp_fg_write_error', 1, 2 * HOUR_IN_SECONDS);
                return false;
            }
            return true;
        } catch (Exception $e) {
            set_transient('rsp_fg_write_error', 1, 2 * HOUR_IN_SECONDS);
            return false;
        }
    }

    /** Daily quick scan: find PHP-like files in uploads */
    private function quick_scan($dir) {
        $found = array();
        try {
            $it = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS)
            );
            foreach ($it as $path => $info) {
                // Hard cap
                if (count($found) > 50) {
                    break;
                }
                if ($info->isFile()) {
                    $ext = strtolower(pathinfo($path, PATHINFO_EXTENSION));
                    if (in_array($ext, array('php', 'phtml', 'phar'), true)) {
                        $found[] = $path;
                    }
                }
            }
        } catch (Exception $e) {
            // ignore
        }
        if (!empty($found)) {
            do_action('rsp_activity_log', 'file_guard_scan', array('files' => $found));
        }
    }

    /** Main bootstrap: write denial rules for uploads */
    public function bootstrap() {
        $dir = $this->uploads_dir();

        // 1) Apache (.htaccess)
        $hta_body = <<<HTA
<FilesMatch "\\.(php|phtml|php5?|phar)$">
  Require all denied
</FilesMatch>
Options -Indexes
HTA;
        $this->write_if_changed($dir . '/.htaccess', $hta_body);

        // 2) IIS (web.config)
        // minimal & safe deny execution for PHP in uploads
        $webconfig_body = <<<XML
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>
    <handlers>
      <add name="Deny-PHP" path="*.php" verb="*" modules="IsapiModule" scriptProcessor="Denied" resourceType="Unspecified" requireAccess="None" />
      <add name="Deny-PHTML" path="*.phtml" verb="*" modules="IsapiModule" scriptProcessor="Denied" resourceType="Unspecified" requireAccess="None" />
      <add name="Deny-PHAR" path="*.phar" verb="*" modules="IsapiModule" scriptProcessor="Denied" resourceType="Unspecified" requireAccess="None" />
    </handlers>
    <directoryBrowse enabled="false" />
  </system.webServer>
</configuration>
XML;
        $this->write_if_changed($dir . '/web.config', $webconfig_body);

        // 3) index.html placeholder (hide listing on some stacks)
        $idx = $dir . '/index.html';
        if (!file_exists($idx)) {
            @file_put_contents($idx, '');
        }

        // 4) Daily quick scan
        $last = (int) get_transient('rsp_file_guard_last_scan');
        if (time() - $last > DAY_IN_SECONDS) {
            $this->quick_scan($dir);
            set_transient('rsp_file_guard_last_scan', time(), DAY_IN_SECONDS);
        }
    }
}
