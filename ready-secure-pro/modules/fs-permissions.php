<?php
if (!defined('ABSPATH')) { exit; }
class RSP_Module_FS_Permissions implements RSP_Module_Interface {
    public function init(){ add_action('admin_init',[$this,'settings']); }
    public function settings(){ add_settings_section('rsp_fs', __('بررسی سطح دسترسی فایل/پوشه','ready-secure-pro'), function(){ echo '<p>'.__('پیشنهاد: فایل‌ها 0644 و پوشه‌ها 0755','ready-secure-pro').'</p>'; }, 'rsp_settings'); }
    public function scan(){
        $root = ABSPATH; $max=5000; $bad=[];
        try{
            $it=new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::SELF_FIRST);
            foreach($it as $path=>$info){
                if($max--<=0) break;
                $perm = substr(sprintf('%o', $info->getPerms()), -4);
                if ($info->isDir()){
                    if (!in_array($perm, array('0755','0750','0705','0700'), true)) $bad[]=['path'=>$path,'perm'=>$perm,'type'=>'dir'];
                } else {
                    if (!in_array($perm, array('0644','0640','0604','0600'), true)) $bad[]=['path'=>$path,'perm'=>$perm,'type'=>'file'];
                }
            }
        }catch(\Throwable $e){}
        return ['bad'=>$bad,'checked'=>5000-$max];
    }
}
