<?php
if (!defined('ABSPATH')) { exit; }

/**
 * ماژول: اسکن سلامت هسته وردپرس (Core Integrity)
 * - استفاده از API رسمی WordPress: get_core_checksums(version, locale)
 * - مقایسهٔ md5 فایل‌های هسته با چکسام مرجع
 * - گزارش فایل‌های تغییر یافته، مفقود، و فایل‌های غیرمنتظره (مشکوک) در wp-admin/wp-includes/ریشه
 * - حالت‌های کار: checksums (آنلاین)، baseline (آفلاین با مبنا)، fallback (ساده)
 * - ثبت رویداد: integrity_scan
 */
class RSP_Module_Integrity implements RSP_Module_Interface {

    const OPT_BASELINE = 'rsp_core_hashes';
    const LIMIT_FILES  = 20000; // سقف ایمنی برای تعداد فایل اسکن‌شونده
    const MAX_REPORT   = 200;   // سقف لیست‌کردن فایل‌ها در خروجی

    public function init() {
        // این ماژول فراخوانی دستی از طریق AJAX دارد (scan_core)
    }

    /**
     * اجرای اسکن اصلی و بازگردانی گزارش مناسب برای AJAX
     * @return array
     */
    public function scan_core() {
        $t0 = microtime(true);

        // اطمینان از در دسترس بودن تابع
        if (!function_exists('get_core_checksums')) {
            require_once ABSPATH . 'wp-admin/includes/update.php';
        }

        $version = get_bloginfo('version');
        $locale  = determine_locale();
        $mode    = 'fallback';
        $manifest= [];

        // تلاش برای دریافت چکسام رسمی
        if (function_exists('get_core_checksums')) {
            $checksums = @get_core_checksums($version, $locale);
            if (!is_array($checksums)) {
                // برخی لوکال‌ها در wp.org چکسام ندارند—انگلیسی را امتحان کن
                $checksums = @get_core_checksums($version, 'en_US');
            }
            if (is_array($checksums)) {
                $manifest = $checksums;
                $mode = 'checksums';
                // ذخیرهٔ مبنا برای آفلاین‌های بعدی
                update_option(self::OPT_BASELINE, $manifest, false);
            }
        }

        // اگر آنلاین نشد و مبنا داریم، از baseline استفاده کن
        if ($mode !== 'checksums') {
            $baseline = get_option(self::OPT_BASELINE, []);
            if (is_array($baseline) && !empty($baseline)) {
                $manifest = $baseline;
                $mode = 'baseline';
            }
        }

        // مسیرهای هدف (فقط هسته)
        $targets = [ ABSPATH . 'wp-admin', ABSPATH . 'wp-includes', ABSPATH ];

        $modified = [];
        $missing  = [];
        $unexpected = [];
        $scanned  = 0;

        if (!empty($manifest)) {
            // --- حالت با مانیفست: فایل‌های مرجع را پیمایش کن ---
            foreach ($manifest as $rel => $hash) {
                // از wp-content صرف‌نظر کن
                if (strpos($rel, 'wp-content/') === 0) continue;
                $abs = ABSPATH . $rel;
                if (!file_exists($abs)) {
                    $missing[] = $rel;
                    continue;
                }
                // فقط فایل‌ها را چک کن
                if (!is_file($abs)) continue;
                $scanned++;
                if ($scanned > self::LIMIT_FILES) break;
                $md5 = @md5_file($abs);
                if (!$md5 || strtolower($md5) !== strtolower($hash)) {
                    $modified[] = $rel;
                }
            }

            // فایل‌های غیرمنتظره در مسیرهای هسته که در مانیفست نیستند
            $expected = array_fill_keys(array_keys($manifest), true);
            foreach ($targets as $base) {
                if (!is_dir($base)) continue;
                $it = new RecursiveIteratorIterator(
                    new RecursiveDirectoryIterator($base, FilesystemIterator::SKIP_DOTS),
                    RecursiveIteratorIterator::SELF_FIRST
                );
                foreach ($it as $file) {
                    if (!$file->isFile()) continue;
                    $path = (string) $file;
                    $rel  = ltrim(str_replace(ABSPATH, '', $path), '/\\');
                    if (strpos($rel, 'wp-content/') === 0) continue; // خارج از هسته
                    if (!isset($expected[$rel])) {
                        // فقط .php و فایل‌های اجرایی را مشکوک بدانیم
                        $ext = strtolower(pathinfo($rel, PATHINFO_EXTENSION));
                        if (in_array($ext, ['php','phtml','php5','php7','php8','phar','cgi','pl','sh'], true)) {
                            $unexpected[] = $rel;
                        }
                    }
                    $scanned++;
                    if ($scanned > self::LIMIT_FILES) break 2;
                }
            }
        } else {
            // --- حالت fallback: فقط شمارش و کشف فایل‌های اجرایی مشکوک ---
            foreach ($targets as $base) {
                if (!is_dir($base)) continue;
                $it = new RecursiveIteratorIterator(
                    new RecursiveDirectoryIterator($base, FilesystemIterator::SKIP_DOTS),
                    RecursiveIteratorIterator::SELF_FIRST
                );
                foreach ($it as $file) {
                    if (!$file->isFile()) continue;
                    $path = (string) $file;
                    $rel  = ltrim(str_replace(ABSPATH, '', $path), '/\\');
                    if (strpos($rel, 'wp-content/') === 0) continue;
                    $ext = strtolower(pathinfo($rel, PATHINFO_EXTENSION));
                    if (in_array($ext, ['php','phtml','php5','php7','php8','phar','cgi','pl','sh'], true)) {
                        $unexpected[] = $rel; // هر فایل اجرایی خارج از مانیفست (که نداریم) را پرچم بزن
                    }
                    $scanned++;
                    if ($scanned > self::LIMIT_FILES) break 2;
                }
            }
        }

        // خروجی خلاصه
        $elapsed = microtime(true) - $t0;
        $report  = [];
        $report[] = sprintf(__('نسخه وردپرس: %s','ready-secure-pro'), esc_html($version));
        $report[] = sprintf(__('حالت اسکن: %s','ready-secure-pro'), $mode);
        $report[] = sprintf(__('تعداد فایل‌های بررسی‌شده: %d','ready-secure-pro'), (int)$scanned);
        if (!empty($modified)) $report[] = sprintf(__('فایل‌های تغییر یافته: %d','ready-secure-pro'), count($modified));
        if (!empty($missing))  $report[] = sprintf(__('فایل‌های مفقود: %d','ready-secure-pro'), count($missing));
        if (!empty($unexpected))$report[] = sprintf(__('فایل‌های غیرمنتظره/مشکوک: %d','ready-secure-pro'), count($unexpected));
        $report[] = sprintf(__('زمان اجرا: %.2f ثانیه','ready-secure-pro'), (float)$elapsed);

        // محدودیت نمایش جزئیات برای جلوگیری از خروجی‌های خیلی بلند
        $detail = [];
        if (!empty($modified))  $detail['modified']  = array_slice($modified, 0, self::MAX_REPORT);
        if (!empty($missing))   $detail['missing']   = array_slice($missing, 0, self::MAX_REPORT);
        if (!empty($unexpected))$detail['unexpected']= array_slice($unexpected, 0, self::MAX_REPORT);

        // لاگ رویداد
        do_action('rsp_activity_log','integrity_scan', [
            'mode' => $mode,
            'wp'   => $version,
            'scanned' => (int)$scanned,
            'modified'=> count($modified),
            'missing' => count($missing),
            'unexpected' => count($unexpected),
            'elapsed' => (float)$elapsed,
        ]);

        return [
            'mode' => $mode,
            'version' => $version,
            'locale'  => $locale,
            'scanned' => (int)$scanned,
            'modified'=> $modified,
            'missing' => $missing,
            'unexpected' => $unexpected,
            'elapsed' => (float)$elapsed,
            'report' => implode("\n", $report),
            'detail' => $detail,
        ];
    }
}
