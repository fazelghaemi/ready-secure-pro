<?php
if (!defined('ABSPATH')) { exit; }

/**
 * ماژول: حفاظت از محتوا (Front-End Content Protection)
 * - جلوگیری از راست‌کلیک، انتخاب متن، کپی/کات، درَگ روی تصاویر
 * - بلاک میان‌بُرهای رایج استخراج محتوا (Ctrl/Cmd+C, Ctrl/Cmd+X, Ctrl/Cmd+S, Ctrl/Cmd+U, Ctrl/Cmd+Shift+I, F12)
 * - تنها در فرانت فعال می‌شود و برای مدیران/نویسندگان (دارای edit_posts) قابل چشم‌پوشی است
 * - عناصر با کلاس `.rsp-allow-select` از ممنوعیت انتخاب مستثنی هستند
 *
 * Option: rsp_content_protect_enable (bool)
 */
class RSP_Module_Content_Protect implements RSP_Module_Interface {

    public function init() {
        // فقط در فرانت و وقتی فعال است
        if (is_admin()) return;
        if (!get_option('rsp_content_protect_enable', 1)) return;

        add_action('wp_enqueue_scripts', [$this, 'enqueue']);
        add_action('wp_head', [$this, 'inject_meta'], 1);
        add_filter('body_class', [$this, 'body_class']);
    }

    /** افزودن متا برای جلوگیری از ترجمه/کپی خودکار برخی مرورگرها */
    public function inject_meta() {
        if (!$this->should_apply()) return;
        echo "\n<meta http-equiv=\"imagetoolbar\" content=\"no\">\n"; // IE قدیمی
    }

    /** body class برای هدف گرفتن با CSS */
    public function body_class($classes) {
        if ($this->should_apply()) $classes[] = 'rsp-protect';
        return $classes;
    }

    /** آیا قوانین باید اعمال شوند؟ */
    private function should_apply() {
        if (!get_option('rsp_content_protect_enable', 1)) return false;
        // برای کاربرانی که توانایی ویرایش دارند، مزاحمت ایجاد نکن
        if (is_user_logged_in() && current_user_can('edit_posts')) return false;
        // فید/پرینت/پیش‌نمایش؟ — روی فید اعمال نکن
        if (is_feed()) return false;
        return true;
    }

    /** صف‌بندی CSS/JS محافظتی (Inline برای کاهش وابستگی) */
    public function enqueue() {
        if (!$this->should_apply()) return;

        // CSS: جلوگیری از انتخاب متن، درَگ تصویر، انتخابگر استثنا
        $css = trim('/* Ready Secure Pro — Content Protect */
            body.rsp-protect { -webkit-user-select:none; -moz-user-select:none; -ms-user-select:none; user-select:none; }
            body.rsp-protect img { -webkit-user-drag:none; -khtml-user-drag:none; -moz-user-select:none; -webkit-touch-callout:none; }
            body.rsp-protect .rsp-allow-select { -webkit-user-select:text; -moz-user-select:text; -ms-user-select:text; user-select:text; }
        ');
        wp_register_style('rsp-content-protect', false, [], RSP_VERSION);
        wp_enqueue_style('rsp-content-protect');
        wp_add_inline_style('rsp-content-protect', $css);

        // JS: بلاک رویدادها و میانبرها
        $js = "(function(){\n\n  function stop(e){ try{ e.preventDefault(); e.stopPropagation(); }catch(x){} return false; }\n  function isInputLike(el){ var t = (el && el.tagName) ? el.tagName.toLowerCase() : ''; return ['input','textarea'].indexOf(t)>-1 || el.isContentEditable; }\n\n  // راست‌کلیک و منو\n  document.addEventListener('contextmenu', function(e){ if(!isInputLike(e.target)){ stop(e); } }, {capture:true});\n\n  // انتخاب متن\n  document.addEventListener('selectstart', function(e){ if(!isInputLike(e.target)){ stop(e); } }, {capture:true});\n\n  // کپی/کات\n  ['copy','cut'].forEach(function(t){ document.addEventListener(t, function(e){ if(!isInputLike(e.target)){ stop(e); if(e.clipboardData){ e.clipboardData.setData('text/plain',''); } } }, {capture:true}); });\n\n  // درَگ روی تصاویر\n  document.addEventListener('dragstart', function(e){ var el=e.target; if(el && el.tagName && el.tagName.toLowerCase()==='img'){ stop(e); } }, {capture:true});\n\n  // میانبرهای رایج استخراج/دِو تولز\n  document.addEventListener('keydown', function(e){\n    var k=e.key||''; var c=e.ctrlKey||e.metaKey; var s=e.shiftKey;\n    // بلاک ذخیره/کپی/نمایش سورس/DevTools\n    if( (c && (k==='s' || k==='S' || k==='u' || k==='U' || k==='c' || k==='C' || k==='x' || k==='X')) || // Ctrl/Cmd + S/U/C/X\n        (c && s && (k==='I' || k==='i')) || // Ctrl/Cmd+Shift+I\n        (k==='F12') ){\n      if(!isInputLike(e.target)){ stop(e); }\n    }\n  }, {capture:true});\n\n})();";
        wp_register_script('rsp-content-protect', false, [], RSP_VERSION, true);
        wp_enqueue_script('rsp-content-protect');
        wp_add_inline_script('rsp-content-protect', $js);
    }
}
