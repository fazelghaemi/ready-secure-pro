<?php
if (!defined('ABSPATH')) { exit; }
class RSP_Module_Integrity implements RSP_Module_Interface {
    public function init(){ register_setting('rsp_settings','rsp_integrity_enable',['type'=>'boolean','default'=>1]); }
    public function scan(){
        global $wp_version; include_once ABSPATH.'wp-admin/includes/update.php'; $locale=get_locale();
        $checksums = get_core_checksums($wp_version, $locale);
        if (!$checksums) return ['ok'=>false,'error'=>'no_checksums'];
        $diff=[]; foreach($checksums as $file=>$hash){ $path=ABSPATH.$file; if(!file_exists($path)){ $diff[]=['file'=>$file,'status'=>'missing']; continue; } $md5=md5_file($path); if($md5!==$hash){ $diff[]=['file'=>$file,'status'=>'modified']; } }
        return ['ok'=>true,'modified'=>$diff];
    }
}
