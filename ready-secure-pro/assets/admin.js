(function($){
  function activateTab(sel){
    $('.rsp-tab').removeClass('is-active'); $('.rsp-panel').removeClass('is-active');
    $('.rsp-tab[data-target="'+sel+'"]').addClass('is-active'); $(sel).addClass('is-active');
    localStorage.setItem('rsp_active_tab', sel);
  }
  $(document).on('click','.rsp-tab',function(){ activateTab($(this).data('target')); });
  $(function(){ activateTab(localStorage.getItem('rsp_active_tab') || '#tab-overview'); });

  // Export
  $('#rsp-export').on('click', function(){
    $.post(RSP.ajax, {action:'rsp_export_settings', _ajax_nonce:RSP.nonce}, function(res){
      if(!res.success) return alert('خطا'); const blob=new Blob([JSON.stringify(res.data,null,2)],{type:'application/json'});
      const a=document.createElement('a'); a.href=URL.createObjectURL(blob); a.download='ready-secure-settings.json'; a.click();
    });
  });
  // Import
  $('#rsp-import-file').on('change', function(e){
    const f=e.target.files[0]; if(!f) return;
    const r=new FileReader(); r.onload=function(){
      $.ajax({url:RSP.ajax+'?action=rsp_import_settings&_ajax_nonce='+RSP.nonce, method:'POST', data:r.result, contentType:'application/json'})
       .done(()=>alert('ok')).fail(()=>alert('خطا'));
    }; r.readAsText(f);
  });

  function runScan(btn, out, action){
    $(out).text('...'); $.post(RSP.ajax, {action:action, _ajax_nonce:RSP.nonce}, function(res){
      $(out).text(res.success? JSON.stringify(res.data,null,2) : 'خطا');
    });
  }
  $('#rsp-scan-integrity').on('click', function(e){ e.preventDefault(); runScan(this, '#rsp-out-integrity','rsp_scan_integrity'); });
  $('#rsp-scan-malware').on('click', function(e){ e.preventDefault(); runScan(this, '#rsp-out-malware','rsp_scan_malware'); });
  $('#rsp-scan-fs').on('click', function(e){ e.preventDefault(); runScan(this, '#rsp-out-fs','rsp_scan_fsperms'); });

  $('#rsp-refresh-logs').on('click', function(){ $('#rsp-out-logs').text('...'); $.post(RSP.ajax,{action:'rsp_get_logs',_ajax_nonce:RSP.nonce},function(res){ $('#rsp-out-logs').text(res.success? JSON.stringify(res.data,null,2):'خطا'); }); });
  $('#rsp-clear-logs').on('click', function(){ if(!confirm('حذف لاگ‌ها؟')) return; $.post(RSP.ajax,{action:'rsp_clear_logs',_ajax_nonce:RSP.nonce},function(){ alert('Done'); $('#rsp-out-logs').text('[]'); }); });
})(jQuery);
