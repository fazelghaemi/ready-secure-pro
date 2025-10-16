<?php
if (!defined('ABSPATH')) { exit; }

/**
 * ماژول: گزارش پرمیشن‌ها و مالکیت فایل‌ها (FS Permissions)
 * - اسکن سریع و ایمن فایل‌سیستم وردپرس برای تشخیص پرمیشن‌های خطرناک
 * - شناسایی: world-writable (others write), group-writable, باینری‌های executable غیرضروری، PHP داخل uploads،
 *   و ناسازگاری مالکیت با کاربر پردازش PHP
 * - گزارش خلاصه + فهرست موارد مهم (با سقف ایمنی برای جلوگیری از خروجی حجیم)
 * - اکشن AJAX: wp_ajax_rsp_scan_fs → خروجی JSON سازگار با پنل ادمین
 */
class RSP_Module_FS_Permissions implements RSP_Module_Interface {

    const LIMIT_NODES = 30000; // حداکثر فایل/دایرکتوری برای پیمایش
    const MAX_LIST    = 300;   // حداکثر آیتم در هر لیست خروجی

    public function init() {
        if (is_admin()) {
            add_action('wp_ajax_rsp_scan_fs', [$this, 'ajax_scan']);
        }
    }

    /**
     * هندلر AJAX: اسکن و بازگردانی JSON
     */
    public function ajax_scan() {
        // بررسی nonce (باید در کلاس ادمین با rsp_nonce مقداردهی شده باشد)
        if (function_exists('check_ajax_referer')) {
            check_ajax_referer('rsp_nonce');
        }
        $res = $this->scan();
        wp_send_json_success($res);
    }

    /**
     * اجرای اسکن فایل‌سیستم
     * @return array
     */
    public function scan() {
        $t0 = microtime(true);

        $is_windows = strtoupper(substr(PHP_OS, 0, 3)) === 'WIN' || (defined('PHP_OS_FAMILY') && PHP_OS_FAMILY === 'Windows');
        $php_uid = function_exists('getmyuid') ? @getmyuid() : null;
        $php_user = null;
        if (function_exists('posix_getpwuid') && is_int($php_uid)) {
            $pw = @posix_getpwuid($php_uid);
            if (is_array($pw) && isset($pw['name'])) $php_user = $pw['name'];
        }
        if (!$php_user) $php_user = is_int($php_uid) ? ('uid:'.$php_uid) : __('نامشخص','ready-secure-pro');

        $targets = $this->targets();

        $counts = [
            'files' => 0,
            'dirs'  => 0,
            'world_writable' => 0,
            'group_writable' => 0,
            'exec_files'     => 0,
            'owner_mismatch' => 0,
            'uploads_php'    => 0,
        ];

        $lists = [
            'world_writable' => [],
            'group_writable' => [],
            'exec_files'     => [],
            'owner_mismatch' => [],
            'uploads_php'    => [],
            'special'        => [], // مثل wp-config.php
        ];

        $node_limit = self::LIMIT_NODES;
        $visited = 0;

        $uploads_base = $this->uploads_basedir();

        foreach ($targets as $base) {
            if (!is_dir($base)) continue;

            $iter = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($base, FilesystemIterator::SKIP_DOTS),
                RecursiveIteratorIterator::SELF_FIRST
            );

            foreach ($iter as $file) {
                $path = (string)$file;
                $visited++;
                if ($visited > $node_limit) break 2;

                // رد کردن symlink برای پرهیز از حلقه‌ها
                if (is_link($path)) continue;

                $is_dir = $file->isDir();
                $is_file = !$is_dir && $file->isFile();
                if ($is_dir) $counts['dirs']++; else $counts['files']++;

                $perms = @fileperms($path);
                if ($perms === false) continue;
                $mode  = $perms & 0x1FF; // 0777
                $oct   = substr(sprintf('%o', $perms), -4);

                $owner = function_exists('fileowner') ? @fileowner($path) : null;
                $owner_name = null;
                if (function_exists('posix_getpwuid') && is_int($owner)) {
                    $pw = @posix_getpwuid($owner);
                    if (is_array($pw) && isset($pw['name'])) $owner_name = $pw['name'];
                }

                $row = [ 'path' => $this->rel($path), 'perm' => $oct, 'type' => ($is_dir?'dir':'file') ];
                if ($owner_name) $row['owner'] = $owner_name; elseif (is_int($owner)) $row['owner'] = 'uid:'.$owner;

                // world-writable
                if (($mode & 0x002) === 0x002) { // others write
                    $counts['world_writable']++;
                    if (count($lists['world_writable']) < self::MAX_LIST) $lists['world_writable'][] = $row;
                }
                // group-writable (مجاز در برخی استقرارها ولی بهتر است کم شود)
                if (($mode & 0x020) === 0x020) {
                    $counts['group_writable']++;
                    if (count($lists['group_writable']) < self::MAX_LIST) $lists['group_writable'][] = $row;
                }
                // executable files غیرضروری (به‌خصوص در wp-content)
                if ($is_file) {
                    $ext = strtolower(pathinfo($path, PATHINFO_EXTENSION));
                    $is_exec = ($mode & 0x111) !== 0; // هرکدام از بیت‌های اجرا
                    if ($is_exec && !in_array($ext, ['sh','cgi','pl','phar'], true)) {
                        $counts['exec_files']++;
                        if (count($lists['exec_files']) < self::MAX_LIST) $lists['exec_files'][] = $row;
                    }
                    // PHP داخل uploads
                    if ($uploads_base && strpos($path, $uploads_base) === 0 && in_array($ext, ['php','phtml','php5','php7','php8'], true)) {
                        $counts['uploads_php']++;
                        if (count($lists['uploads_php']) < self::MAX_LIST) $lists['uploads_php'][] = $row;
                    }
                }
                // مالکیت متفاوت با پردازش PHP (صرفاً هشدار)
                if (!$is_windows && is_int($php_uid) && is_int($owner) && $owner !== $php_uid) {
                    $counts['owner_mismatch']++;
                    if (count($lists['owner_mismatch']) < self::MAX_LIST) $lists['owner_mismatch'][] = $row;
                }
            }
        }

        // بررسی ویژه wp-config.php
        $cfg = ABSPATH . 'wp-config.php';
        if (is_file($cfg)) {
            $perms = @fileperms($cfg);
            if ($perms !== false) {
                $oct = substr(sprintf('%o', $perms), -4);
                $lists['special'][] = [ 'path' => $this->rel($cfg), 'perm' => $oct, 'type' => 'file' ];
            }
        }

        // زمان و گزارش متنی
        $elapsed = microtime(true) - $t0;
        $report_lines = [];
        $report_lines[] = sprintf(__('سیستم‌عامل: %s','ready-secure-pro'), $is_windows ? 'Windows' : 'Unix-like');
        $report_lines[] = sprintf(__('کاربر پردازش PHP: %s','ready-secure-pro'), esc_html($php_user));
        $report_lines[] = sprintf(__('مسیرهای بررسی‌شده: %d','ready-secure-pro'), count($targets));
        $report_lines[] = sprintf(__('فایل‌ها: %d / پوشه‌ها: %d','ready-secure-pro'), (int)$counts['files'], (int)$counts['dirs']);
        $report_lines[] = sprintf(__('مورد world-writable: %d','ready-secure-pro'), (int)$counts['world_writable']);
        $report_lines[] = sprintf(__('مورد group-writable: %d','ready-secure-pro'), (int)$counts['group_writable']);
        $report_lines[] = sprintf(__('فایل‌های executable مشکوک: %d','ready-secure-pro'), (int)$counts['exec_files']);
        $report_lines[] = sprintf(__('فایل PHP داخل uploads: %d','ready-secure-pro'), (int)$counts['uploads_php']);
        if (!$is_windows) $report_lines[] = sprintf(__('ناسازگاری مالکیت با کاربر PHP: %d','ready-secure-pro'), (int)$counts['owner_mismatch']);
        $report_lines[] = sprintf(__('زمان اجرا: %.2f ثانیه','ready-secure-pro'), (float)$elapsed);
        $report_lines[] = '---';
        $report_lines[] = __('پیشنهادهای ایمن:','ready-secure-pro');
        $report_lines[] = __('• فایل‌ها 0644 و دایرکتوری‌ها 0755 باشند (به‌جز نیازهای خاص).','ready-secure-pro');
        $report_lines[] = __('• از world-writable (…7, …6, …2) پرهیز کنید؛ در صورت نیاز به نوشتن، مالک/گروه درست را ست کنید.','ready-secure-pro');
        $report_lines[] = __('• در uploads هیچ فایل PHP نگه ندارید (ماژول File Guard همین را enforce می‌کند).','ready-secure-pro');
        $report_lines[] = __('• برای wp-config.php در صورت امکان 0600/0640 تنظیم کنید.','ready-secure-pro');

        // ثبت لاگ
        do_action('rsp_activity_log', 'fs_scan', [
            'files' => (int)$counts['files'],
            'dirs'  => (int)$counts['dirs'],
            'world_writable' => (int)$counts['world_writable'],
            'group_writable' => (int)$counts['group_writable'],
            'exec_files'     => (int)$counts['exec_files'],
            'uploads_php'    => (int)$counts['uploads_php'],
            'owner_mismatch' => (int)$counts['owner_mismatch'],
            'elapsed'        => (float)$elapsed,
        ]);

        return [
            'env' => [
                'os' => $is_windows ? 'Windows' : 'Unix-like',
                'php_user' => $php_user,
                'targets'  => array_map([$this,'rel'], $targets),
            ],
            'counts' => $counts,
            'lists'  => $lists,
            'report' => implode("\n", $report_lines),
            'elapsed'=> (float)$elapsed,
        ];
    }

    /** مسیرهای هدف برای اسکن */
    private function targets() {
        $targets = [ ABSPATH ];
        if (defined('WP_CONTENT_DIR')) $targets[] = WP_CONTENT_DIR;
        if (defined('WP_PLUGIN_DIR'))  $targets[] = WP_PLUGIN_DIR;
        if (function_exists('get_theme_root')) $targets[] = get_theme_root();
        $up = $this->uploads_basedir(); if ($up) $targets[] = $up;
        // حذف تکراری‌ها
        $targets = array_values(array_unique(array_filter($targets)));
        return $targets;
    }

    /** مسیر پایه آپلودها */
    private function uploads_basedir() {
        $up = @wp_upload_dir(null, false);
        if (is_array($up) && !empty($up['basedir'])) return $up['basedir'];
        return '';
    }

    /** مسیر نسبی برای گزارش خواناتر */
    private function rel($abs) {
        $abs = (string)$abs;
        $root = rtrim(ABSPATH, '/\\');
        if (strpos($abs, $root) === 0) return ltrim(substr($abs, strlen($root)), '/\\');
        return $abs;
    }
}
