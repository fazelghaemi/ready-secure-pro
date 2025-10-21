<?php
if (!defined('ABSPATH')) { exit; }
class RSP_Module_Smart_404 implements RSP_Module_Interface {
    private function ip(){ return function_exists('rsp_client_ip')? rsp_client_ip(): (isset($_SERVER['REMOTE_ADDR'])? $_SERVER['REMOTE_ADDR']: ''); }
    private function k($ip){ return 'rsp_404_'.md5($ip); }
    private function kl($ip){ return 'rsp_404_lock_'.md5($ip); }
    public function init(){ if(!get_option('rsp_404_enable',1)) return; add_action('template_redirect',[$this,'maybe'],0); add_action('admin_init',[$this,'settings']); }
    public function settings(){
        register_setting('rsp_settings','rsp_404_enable',['type'=>'boolean','default'=>1]);
        register_setting('rsp_settings','rsp_404_threshold',['type'=>'integer','default'=>12]);
        register_setting('rsp_settings','rsp_404_window',['type'=>'integer','default'=>120]);
        register_setting('rsp_settings','rsp_404_lock_minutes',['type'=>'integer','default'=>30]);
        add_settings_section('rsp_404',__('گارد 404 هوشمند','ready-secure-pro'),function(){ echo '<p>'.__('قفل IP پس از تکرار 404 مشکوک در پنجره زمانی.','ready-secure-pro').'</p>'; },'rsp_settings_404_antispam');
        add_settings_field('rsp_404_threshold',__('آستانه 404','ready-secure-pro'),function(){ echo '<input type="number" name="rsp_404_threshold" value="'.esc_attr(get_option('rsp_404_threshold',12)).'">'; },'rsp_settings_404_antispam','rsp_404');
        add_settings_field('rsp_404_window',__('پنجره (ثانیه)','ready-secure-pro'),function(){ echo '<input type="number" name="rsp_404_window" value="'.esc_attr(get_option('rsp_404_window',120)).'">'; },'rsp_settings_404_antispam','rsp_404');
        add_settings_field('rsp_404_lock_minutes',__('مدت قفل (دقیقه)','ready-secure-pro'),function(){ echo '<input type="number" name="rsp_404_lock_minutes" value="'.esc_attr(get_option('rsp_404_lock_minutes',30)).'">'; },'rsp_settings_404_antispam','rsp_404');
    }
    public function maybe(){
        $ip=$this->ip();
        if (get_transient($this->kl($ip))) { status_header(403); header('X-RSP-Block: 404'); exit; }
        if (!is_404()) return;
        $win=max(30,(int)get_option('rsp_404_window',120)); $th=max(5,(int)get_option('rsp_404_threshold',12));
        $bucket='b'.intdiv(time(),$win); $k=$this->k($ip.'|'.$bucket);
        $n=(int)get_transient($k); $n++; set_transient($k,$n,$win);
        if ($n>$th){ $min=max(5,(int)get_option('rsp_404_lock_minutes',30)); set_transient($this->kl($ip),1,$min*60); do_action('rsp_activity_log','404_lock',['ip'=>$ip,'minutes'=>$min]); status_header(403); exit; }
    }
}
