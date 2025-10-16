<?php
if (!defined('ABSPATH')) { exit; }

class RSP_Module_Login_Url implements RSP_Module_Interface {
    public function init() {
        add_action('init', [$this, 'add_rewrite_rules']);
        add_filter('query_vars', [$this, 'add_query_vars']);
        add_action('template_redirect', [$this, 'intercept_login_page']);
        add_filter('login_url', [$this, 'filter_login_url'], 10, 3);
        add_filter('site_url', [$this, 'filter_site_url'], 10, 4);
        add_action('wp_loaded', [$this, 'block_direct_wp_login']);
    }

    public function add_rewrite_rules() {
        $slug = get_option('rsp_login_slug', 'manager');
        if ($slug) {
            add_rewrite_rule('^' . $slug . '/?$', 'index.php?rsp_login_page=1', 'top');
        }
    }

    public function add_query_vars($vars) {
        $vars[] = 'rsp_login_page';
        return $vars;
    }

    public function intercept_login_page() {
        if (get_query_var('rsp_login_page')) {
            global $pagenow;
            $pagenow = 'wp-login.php';
            require_once ABSPATH . 'wp-login.php';
            exit;
        }
    }

    public function filter_login_url($login_url, $redirect, $force_reauth) {
        $slug = get_option('rsp_login_slug', 'manager');
        $new_login_url = home_url('/' . $slug . '/');
        if ($redirect) {
            $new_login_url = add_query_arg('redirect_to', urlencode($redirect), $new_login_url);
        }
        return $new_login_url;
    }

    public function filter_site_url($url, $path, $scheme, $blog_id) {
        if ($path === 'wp-login.php' && $scheme !== 'admin') {
             $slug = get_option('rsp_login_slug', 'manager');
             return home_url('/' . $slug . '/');
        }
        return $url;
    }

    public function block_direct_wp_login() {
        global $pagenow;
        if ($pagenow === 'wp-login.php' && !get_query_var('rsp_login_page')) {
            $allowed_actions = ['logout', 'postpass', 'rp', 'resetpass', 'login'];
            $action = isset($_REQUEST['action']) ? $_REQUEST['action'] : 'login';

            if (!in_array($action, $allowed_actions, true)) {
                wp_safe_redirect(home_url('/'));
                exit;
            }
        }
    }
}