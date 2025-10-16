/* Ready Secure Pro — Admin JS (Modern UX)
 * - تب‌ها با نگهداری وضعیت در localStorage + کلیدهای جهت‌دار
 * - Ripple افکت روی دکمه‌ها/تب‌ها (الهام از متریال)
 * - Toast/Modal سبک، و ابزارهای کمکی
 * - فراخوانی‌های AJAX برای اسکن‌ها و اکسپورت/ایمپورت و لاگ
 * - فیکس رنگ هدینگ‌ها روی تم سرمه‌ای
 */
(function(){
  'use strict';

  /* ===================== Utils ===================== */
  const $  = (s, r=document) => r.querySelector(s);
  const $$ = (s, r=document) => Array.from(r.querySelectorAll(s));
  const ls = window.localStorage;
  const ajaxURL = (window.RSP_DATA && RSP_DATA.ajax) || (window.ajaxurl || '');
  const nonce  = (window.RSP_DATA && RSP_DATA.nonce) || '';

  function on(type, selector, handler, root=document){
    root.addEventListener(type, e=>{
      const el = e.target.closest(selector); if(!el) return; handler(e, el);
    });
  }

  function qs(obj){
    return Object.entries(obj).map(([k,v])=> encodeURIComponent(k)+'='+encodeURIComponent(v)).join('&');
  }

  function post(action, data={}){
    if(!ajaxURL) return Promise.reject(new Error('ajax url missing'));
    const body = qs(Object.assign({action, _ajax_nonce: nonce}, data));
    return fetch(ajaxURL, {method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded; charset=UTF-8'}, body})
      .then(r=>r.json());
  }

  /* ===================== Toasts ===================== */
  function toast(msg, type='success', timeout=3800){
    let stack = $('.rsp-toast-stack');
    if(!stack){ stack = document.createElement('div'); stack.className='rsp-toast-stack'; document.body.appendChild(stack); }
    const el = document.createElement('div');
    el.className = 'rsp-toast';
    if(type==='warn') el.classList.add('warn');
    if(type==='danger' || type==='error') el.classList.add('danger');
    el.textContent = String(msg||'');
    stack.appendChild(el);
    setTimeout(()=>{ el.style.opacity='0'; el.style.transform='translateY(4px)'; setTimeout(()=> el.remove(), 200); }, timeout);
    return el;
  }

  /* ===================== Ripple (Material-like) ===================== */
  function injectRippleStyles(){
    if($('#rsp-ripple-style')) return;
    const st = document.createElement('style');
    st.id = 'rsp-ripple-style';
    st.textContent = `.rsp-ripple{position:relative;overflow:hidden}
      .rsp-ripple::after{content:"";position:absolute;inset:auto;pointer-events:none;border-radius:50%;transform:scale(0);opacity:.25;
        background:currentColor;animation:rsp-ripple .6s ease-out}
      @keyframes rsp-ripple{to{transform:scale(12);opacity:0}}`;
    document.head.appendChild(st);
  }
  function addRipple(el){ el.classList.add('rsp-ripple'); el.addEventListener('click', function(e){
      const r = el.getBoundingClientRect();
      const d = Math.max(r.width, r.height);
      const x = e.clientX - r.left - d/2; const y = e.clientY - r.top - d/2;
      const s = document.createElement('span');
      Object.assign(s.style,{position:'absolute',left:x+'px',top:y+'px',width:d+'px',height:d+'px'});
      s.className='rsp-ripple-effect';
      s.setAttribute('style', s.getAttribute('style'));
      el.appendChild(s);
      s.addEventListener('animationend', ()=> s.remove());
      s.style.animation='rsp-ripple .6s ease-out forwards';
    }); }

  /* ===================== Tabs ===================== */
  function activateTab(name){
    if(!name) return;
    $$('.rsp-tab').forEach(b=> b.classList.toggle('active', b.dataset.tab===name));
    $$('.rsp-panel').forEach(p=> p.classList.remove('show'));
    const panel = $('#tab-'+name);
    if(panel){ panel.classList.add('show'); ls.setItem('rsp_active_tab', name); }
  }

  function setupTabs(){
    injectRippleStyles();
    $$('.rsp-tab').forEach(b=> addRipple(b));

    on('click', '.rsp-tab', (e, el)=>{ e.preventDefault(); activateTab(el.dataset.tab); });

    // keyboard navigation (Left/Right/Home/End)
    on('keydown', '.rsp-tab', (e, el)=>{
      const tabs = $$('.rsp-tab');
      const i = tabs.indexOf(el);
      if(['ArrowRight','ArrowLeft','Home','End'].includes(e.key)) e.preventDefault();
      if(e.key==='ArrowRight'){ (tabs[i+1]||tabs[0]).focus(); (tabs[i+1]||tabs[0]).click(); }
      if(e.key==='ArrowLeft'){ (tabs[i-1]||tabs[tabs.length-1]).focus(); (tabs[i-1]||tabs[tabs.length-1]).click(); }
      if(e.key==='Home'){ tabs[0].focus(); tabs[0].click(); }
      if(e.key==='End'){ tabs[tabs.length-1].focus(); tabs[tabs.length-1].click(); }
    });

    const initial = ls.getItem('rsp_active_tab') || 'overview';
    if($('#tab-'+initial)) activateTab(initial); else activateTab('overview');
  }

  /* ===================== Actions / Buttons ===================== */
  function setLoading(btn, on){ if(!btn) return; btn.classList.toggle('loading', !!on); btn.disabled=!!on; }

  function setupActions(){
    // Integrity scan
    on('click', '#rsp-run-integrity', async (e, btn)=>{
      setLoading(btn, true);
      try{
        const res = await post('rsp_scan_integrity');
        const out = $('#rsp-integrity-out');
        out.textContent = (res && res.success) ? JSON.stringify(res.data, null, 2) : (res && res.data ? String(res.data) : 'خطا در اسکن');
        toast('اسکن هسته انجام شد');
      }catch(err){ toast('خطا در ارتباط با سرور', 'danger'); }
      setLoading(btn, false);
    });

    // Malware scan (quick)
    on('click', '#rsp-run-malware, #rsp-scan-malware', async (e, btn)=>{
      setLoading(btn, true);
      try{
        const res = await post('rsp_scan_malware');
        const out = $('#rsp-malware-out') || $('#rsp-malware');
        out.textContent = (res && res.success) ? (res.data.report || JSON.stringify(res.data, null, 2)) : 'اسکن انجام نشد';
        toast('اسکن بدافزار تکمیل شد');
      }catch(err){ toast('خطا در اسکن بدافزار', 'danger'); }
      setLoading(btn, false);
    });

    // FS permissions
    on('click', '#rsp-scan-fs', async (e, btn)=>{
      setLoading(btn, true);
      try{
        const res = await post('rsp_scan_fs');
        const out = $('#rsp-scan-output');
        out.textContent = (res && res.success) ? JSON.stringify(res.data.report || res.data, null, 2) : 'خطا در اسکن فایل‌ها';
        toast('اسکن فایل‌ها انجام شد');
      }catch(err){ toast('خطا در اسکن فایل‌ها', 'danger'); }
      setLoading(btn, false);
    });

    // Export Logs
    on('click', '#rsp-export-log', async (e, btn)=>{
      setLoading(btn, true);
      try{
        const res = await post('rsp_get_logs');
        const data = (res && res.success) ? res.data : [];
        const pre  = $('#rsp-log');
        pre.textContent = JSON.stringify(data, null, 2);
        // download
        const blob = new Blob([pre.textContent], {type:'application/json'});
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = 'ready-secure-logs.json'; a.click(); setTimeout(()=>URL.revokeObjectURL(a.href), 1000);
        toast('لاگ به JSON اکسپورت شد');
      }catch(err){ toast('خطا در دریافت لاگ', 'danger'); }
      setLoading(btn, false);
    });

    // Export Settings
    on('click', '#rsp-export-settings', async (e, btn)=>{
      setLoading(btn, true);
      try{
        const res = await post('rsp_export_settings');
        const data = (res && res.success) ? res.data : {};
        const ta = $('#rsp-settings-json');
        if(ta){ ta.value = JSON.stringify(data, null, 2); ta.focus(); ta.select(); document.execCommand('copy'); }
        toast('تنظیمات اکسپورت و کپی شد');
      }catch(err){ toast('خطا در اکسپورت تنظیمات', 'danger'); }
      setLoading(btn, false);
    });

    // Import Settings
    on('click', '#rsp-import-settings', async (e, btn)=>{
      const ta = $('#rsp-settings-json'); if(!ta) return;
      let payload = {};
      try{ payload = JSON.parse(ta.value || '{}'); }
      catch(err){ toast('JSON نامعتبر است', 'danger'); return; }
      setLoading(btn, true);
      try{
        const res = await post('rsp_import_settings', {payload: JSON.stringify(payload)});
        if(res && res.success){ toast('تنظیمات اعمال شد — صفحه را رفرش کنید'); }
        else { toast('اعمال تنظیمات ناموفق بود', 'danger'); }
      }catch(err){ toast('خطای شبکه هنگام ایمپورت', 'danger'); }
      setLoading(btn, false);
    });
  }

  /* ===================== Visual Fixes ===================== */
  function enforceHeadingColors(){
    // برخی پوسته‌های ادمین رنگ هدینگ را سیاه می‌کنند؛ ما آن را به رنگ متن تم تنظیم می‌کنیم
    const st = document.createElement('style');
    st.textContent = `.rsp-wrap h1,.rsp-wrap h2,.rsp-wrap h3,.rsp-wrap h4{color:var(--rsp-text)!important}`;
    document.head.appendChild(st);
  }

  /* ===================== Init ===================== */
  function boot(){
    enforceHeadingColors();
    setupTabs();
    setupActions();
    // Ripple برای همه دکمه‌ها داخل پنل
    injectRippleStyles();
    $$('.rsp-wrap .button, .rsp-wrap .button-primary, .rsp-wrap .button-secondary').forEach(addRipple);
  }

  if(document.readyState==='complete' || document.readyState==='interactive') setTimeout(boot,0);
  else document.addEventListener('DOMContentLoaded', boot);
})();
