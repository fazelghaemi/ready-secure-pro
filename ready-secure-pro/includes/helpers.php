<?php
if (!defined('ABSPATH')) { exit; }

if (!function_exists('intdiv')) {
    function intdiv($dividend, $divisor) {
        if ($divisor == 0) { trigger_error('Division by zero', E_USER_WARNING); return 0; }
        return ($dividend - ($dividend % $divisor)) / $divisor;
    }
}

function rsp_ip_in_cidr($ip,$cidr){
    if (!is_string($ip) || !is_string($cidr) || $ip==='' || $cidr==='') return false;
    if (strpos($cidr,'/')===false) return strcasecmp($ip,$cidr)===0;
    list($subnet,$mask)=explode('/',$cidr,2); $mask=(int)$mask;
    $ipb=@inet_pton($ip); $net=@inet_pton($subnet);
    if ($ipb===false || $net===false) return false;
    $len=strlen($ipb); $bytes=intdiv($mask,8); $bits=$mask%8;
    if ($bytes>$len) $bytes=$len;
    if (strncmp($ipb,$net,$bytes)!==0) return false;
    if ($bits===0) return true;
    $mask_byte=(0xFF00 >> $bits) & 0xFF;
    return ((ord($ipb[$bytes]) & $mask_byte) === (ord($net[$bytes]) & $mask_byte));
}

function rsp_client_ip(){
    $remote = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '';
    $trusted = apply_filters('rsp_trusted_proxies', []); $is_trusted=false;
    foreach ((array)$trusted as $tp){ if (rsp_ip_in_cidr($remote,$tp)) { $is_trusted=true; break; } }
    $order = apply_filters('rsp_client_ip_headers', ['HTTP_CF_CONNECTING_IP','HTTP_X_FORWARDED_FOR','HTTP_X_REAL_IP']);
    $candidates=[];
    foreach ($order as $key){
        if (!isset($_SERVER[$key])) continue;
        $val=trim((string) $_SERVER[$key]); if($val==='') continue;
        if ($key==='HTTP_X_FORWARDED_FOR'){ foreach (preg_split('/\s*,\s*/',$val) as $xip){ $candidates[]=$xip; } }
        else{ $candidates[]=$val; }
    }
    if (!$is_trusted || empty($candidates)) return $remote ?: '0.0.0.0';
    foreach ($candidates as $ip){ if (filter_var($ip, FILTER_VALIDATE_IP)) return $ip; }
    return $remote ?: '0.0.0.0';
}

function rsp_activity_log_write($event,$payload=[]){
    global $wpdb;
    $data=[
        'event_type'=>substr((string)$event,0,100),
        'ip_address'=>substr(rsp_client_ip(),0,64),
        'user_id'=> is_user_logged_in()? get_current_user_id():0,
        'details'=> wp_json_encode($payload),
        'created_at'=> current_time('mysql'),
    ];
    try{
        $wpdb->insert($wpdb->prefix.'rsp_logs',$data,['%s','%s','%d','%s','%s']);
    }catch(\Throwable $e){
        try{
            $rows=get_option('rsp_activity_log',[]); if(!is_array($rows)) $rows=[];
            $rows[]=$data; if(count($rows)>1000) $rows=array_slice($rows,-1000);
            update_option('rsp_activity_log',$rows,false);
        }catch(\Throwable $e2){}
    }
}
add_action('rsp_activity_log','rsp_activity_log_write',10,2);

function rsp_bool($v){ return in_array($v,[1,'1',true,'true','on','yes'],true); }
function rsp_send_header_once($name,$value){
    if (headers_sent()) return;
    foreach (headers_list() as $h){ if (stripos($h,$name.':')===0) return; }
    header($name.': '.$value,true);
}

function rsp_option_export(){
    global $wpdb;
    $like=$wpdb->esc_like('rsp_').'%';
    $rows=$wpdb->get_results($wpdb->prepare("SELECT option_name, option_value FROM {$wpdb->options} WHERE option_name LIKE %s",$like), ARRAY_A);
    $out=[]; foreach($rows as $r){ $out[$r['option_name']]= maybe_unserialize($r['option_value']); }
    return $out;
}
function rsp_option_import($data){
    if (!is_array($data)) return false;
    foreach ($data as $k=>$v){ if (strpos($k,'rsp_')===0) update_option($k,$v,false); }
    return true;
}
