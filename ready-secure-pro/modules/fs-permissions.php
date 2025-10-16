<?php
if (!defined('ABSPATH')) { exit; }
class RSP_Module_FS_Permissions implements RSP_Module_Interface {
    public function init(){ /* ajax handled in admin class; this module provides scanner only */ }
    public function scan_report(){
        $items = [ ABSPATH.'wp-config.php', WP_CONTENT_DIR, WP_CONTENT_DIR.'/uploads' ];
        $out = [];
        foreach ($items as $p){ $out = array_merge($out, $this->check($p)); }
        return implode("\n", $out);
    }
    private function check($path, $file=0644, $dir=0755){
        $r = [];
        if (!file_exists($path)) { $r[] = "وجود ندارد: {$path}"; return $r; }
        if (is_dir($path)){
            $perm = fileperms($path) & 0777; $ok = ($perm==$dir);
            $r[] = sprintf("%s — dir perms: %o %s", $path, $perm, $ok?'OK':'⚠ ⇢ 0755');
            $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($path, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::SELF_FIRST);
            $c=0;
            foreach ($it as $i){
                $perm = fileperms($i) & 0777;
                if ($i->isDir()){ if($perm!=$dir) $r[] = sprintf("%s — dir %o (⇢ 0755)", $i, $perm); }
                else { if($perm!=$file) $r[] = sprintf("%s — file %o (⇢ 0644)", $i, $perm); }
                $c++; if($c>2000){ $r[]='... محدودیت نمایش 2000 آیتم'; break; }
            }
        } else {
            $perm = fileperms($path) & 0777; $ok = ($perm==$file);
            $r[] = sprintf("%s — file perms: %o %s", $path, $perm, $ok?'OK':'⚠ ⇢ 0644');
        }
        return $r;
    }
}
