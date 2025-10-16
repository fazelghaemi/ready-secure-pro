<?php
if (!defined('ABSPATH')) { exit; }
class RSP_Module_Integrity implements RSP_Module_Interface {
    public function init(){ /* AJAX handled from admin */ }
    public function scan_core(){
        require_once ABSPATH . 'wp-admin/includes/update.php';
        $locale = get_locale();
        $ver = get_bloginfo('version');
        $checksums = wp_get_core_checksums($ver, $locale);
        if (!$checksums || !is_array($checksums)) $checksums = wp_get_core_checksums($ver, 'en_US');
        $report = [];
        if (!$checksums) return ['report'=>'نتوانستم چک‌سام هسته را دریافت کنم.'];
        foreach ($checksums as $file=>$hash){
            $path = ABSPATH.$file;
            if (!file_exists($path)){ $report[] = "گم شده: {$file}"; continue; }
            $md5 = md5_file($path);
            if ($md5 !== $hash){ $report[] = "ناهمخوان: {$file}"; }
        }
        if (empty($report)) $report[] = 'هسته وردپرس سالم است (چک‌سام‌ها هم‌خوان).';
        return ['report'=>implode("\n",$report)];
    }
}
