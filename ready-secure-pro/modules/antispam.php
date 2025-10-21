<?php
if (!defined('ABSPATH')) { exit; }
class RSP_Module_AntiSpam implements RSP_Module_Interface {
    const HP='rsp_hp_url'; const TS='rsp_ts';
    public function init(){
        if (!get_option('rsp_antispam_enable',1)) return;
        add_action('comment_form_after_fields',[$this,'inject']);
        add_action('comment_form_logged_in_after',[$this,'inject']);
        add_filter('preprocess_comment',[$this,'check'],9);
        add_action('admin_init',[$this,'settings']);
        add_action('wp_enqueue_scripts', function(){ wp_add_inline_style('wp-block-library','.rsp-hp{position:absolute;left:-9999px;opacity:0}'); });
    }
    public function settings(){
        register_setting('rsp_settings','rsp_antispam_enable',['type'=>'boolean','default'=>1]);
        register_setting('rsp_settings','rsp_antispam_min_secs',['type'=>'integer','default'=>8]);
        register_setting('rsp_settings','rsp_antispam_max_links',['type'=>'integer','default'=>2]);
        add_settings_section('rsp_as',__('کاهش اسپم دیدگاه','ready-secure-pro'),function(){ echo '<p>'.__('Honeypot + حداقل زمان + محدودیت لینک‌ها','ready-secure-pro').'</p>'; },'rsp_settings_404_antispam');
        add_settings_field('rsp_antispam_enable',__('فعال باشد؟','ready-secure-pro'),function(){ echo '<input type="checkbox" name="rsp_antispam_enable" value="1" '.checked(get_option('rsp_antispam_enable',1),1,false).'>'; },'rsp_settings_404_antispam','rsp_as');
        add_settings_field('rsp_antispam_min_secs',__('حداقل ثانیه پیش از ارسال','ready-secure-pro'),function(){ echo '<input type="number" name="rsp_antispam_min_secs" value="'.esc_attr(get_option('rsp_antispam_min_secs',8)).'">'; },'rsp_settings_404_antispam','rsp_as');
        add_settings_field('rsp_antispam_max_links',__('حداکثر لینک در کامنت','ready-secure-pro'),function(){ echo '<input type="number" name="rsp_antispam_max_links" value="'.esc_attr(get_option('rsp_antispam_max_links',2)).'">'; },'rsp_settings_404_antispam','rsp_as');
    }
    public function inject(){ $ts=time(); echo '<p class="rsp-hp"><label for="'.esc_attr(self::HP).'">'.esc_html__('اگر انسان هستید این فیلد را خالی بگذارید','ready-secure-pro').'</label><input type="text" name="'.esc_attr(self::HP).'" id="'.esc_attr(self::HP).'" value=""></p>'; echo '<input type="hidden" name="'.esc_attr(self::TS).'" value="'.esc_attr($ts).'">'; }
    public function check($data){
        if (is_user_logged_in() && current_user_can('moderate_comments')) return $data;
        $hp=isset($_POST[self::HP])? trim((string)$_POST[self::HP]):''; if($hp!=='') return new WP_Error('rsp_spam','اسپم شناسایی شد (honeypot).');
        $ts=isset($_POST[self::TS])? (int)$_POST[self::TS]:0; $min=max(2,(int)get_option('rsp_antispam_min_secs',8)); if($ts<=0 || (time()-$ts)<$min) return new WP_Error('rsp_spam','ارسال خیلی سریع بود.');
        $max_links=max(0,(int)get_option('rsp_antispam_max_links',2)); $t=strtolower((string)$data['comment_content']); $links=0; $links+=preg_match_all('#https?://#i',$t,$m); $links+=preg_match_all('#<a\s[^>]*href=#i',$t,$m2); if($links>$max_links) return new WP_Error('rsp_spam','لینک‌های زیاد در دیدگاه.');
        do_action('rsp_activity_log','antispam_pass',['ip'=> (function_exists('rsp_client_ip')? rsp_client_ip(): '') ]); return $data;
    }
}
