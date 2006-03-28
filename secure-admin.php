<?php
/*
Plugin Name: Secure Admin
Plugin URI: http://wordpress.org/#
Description: Access the admin backend over SSL.
Author: Ryan Boren
Version: 0.1
Author URI: http://boren.nu/
*/ 

// These functions are 2.1 and newer.  Add them for older releases.
if ( !function_exists('setup_userdata') ):
function setup_userdata($user_id = '') {
	global $user_login, $userdata, $user_level, $user_ID, $user_email, $user_url, $user_pass_md5, $user_identity;

	if ( '' == $user_id )
		$user = wp_get_current_user();
	else 
		$user = new WP_User($user_id);

	if ( 0 == $user->ID )
		return;

	$userdata = $user->data;
	$user_login	= $user->user_login;
	$user_level	= $user->user_level;
	$user_ID	= $user->ID;
	$user_email	= $user->user_email;
	$user_url	= $user->user_url;
	$user_pass_md5	= md5($user->user_pass);
	$user_identity	= $user->display_name;
}

function set_current_user($id, $name = '') {
	return wp_set_current_user($id, $name);
}

function wp_set_current_user($id, $name = '') {
	global $current_user;

	if ( isset($current_user) && ($id == $current_user->ID) )
		return $current_user;

	$current_user = new WP_User($id, $name);

	setup_userdata($current_user->ID);

	do_action('set_current_user');

	return $current_user;
}

function wp_get_current_user() {
	global $current_user;

	get_currentuserinfo();

	return $current_user;
}

endif;

if ( !function_exists('auth_redirect') ) :
function auth_redirect() {

	// Checks if a user is logged in, if not redirects them to the login page
	$login = '';
	if ( !empty($_COOKIE[USER_COOKIE]) && !empty($_COOKIE[PASS_COOKIE]) ) {
		if ( function_exists('wp_decrypt') )
			$id_bits = wp_decrypt($_COOKIE[USER_COOKIE]);
		else
			$id_bits = $_COOKIE[USER_COOKIE];

		$id_bits = explode('::', $id_bits);
		if ( is_array($id_bits) ) {
			$user_id = (int) $id_bits[0];
			$client_sig = $id_bits[1];
			if ( ($client_sig == sa_get_client_signature()) &&
				($user = get_userdata($user_id)) )
				$login = $user->user_login;
		}
	}
	
	if ( empty($login) || !wp_login($login, $_COOKIE[PASS_COOKIE], true) ) {
		nocache_headers();

		header('Location: ' . preg_replace('/^http/', 'https', get_settings('siteurl')) . '/wp-login.php?redirect_to=' . urlencode($_SERVER['REQUEST_URI']));
		//echo "Redirect to login";
		exit();
	} else if ( 'on' != $_SERVER['HTTPS'] ) {
		if ( false !== strpos($_SERVER['REQUEST_URI'], 'http') ) {
			header('Location: ' . preg_replace('/^http/', 'https', $_SERVER['REQUEST_URI']));
			exit();
		} else {
			header('Location: https://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI']);
			exit();			
		}
	}
}
endif;

if ( !function_exists('check_admin_referer') ) :
function check_admin_referer() {
	$adminurl = strtolower(get_settings('siteurl')).'/wp-admin';
	$adminurl = preg_replace('/^http/', 'https', $adminurl);
	$referer = strtolower($_SERVER['HTTP_REFERER']);
	if (!strstr($referer, $adminurl))
		die(__('Sorry, you need to <a href="http://codex.wordpress.org/Enable_Sending_Referrers">enable sending referrers</a> for this feature to work.'));
	do_action('check_admin_referer');
}
endif;

if ( !function_exists('get_currentuserinfo') ) :
function get_currentuserinfo() {
	global $current_user, $pagenow;

	if ( defined('XMLRPC_REQUEST') && XMLRPC_REQUEST )
		return false;

	if ( ! empty($current_user) )
		return;

	$cookie_bits = sa_get_cookie_path_hash();
	extract($cookie_bits);
	$cookiename = 'wordpressloggedin' . $cookiehash;

	if ( ! is_admin() && ('wp-comments-post.php' != $pagenow) ) {
		if ( ! empty($_COOKIE[$cookiename]) ) {
			if ( function_exists('wp_decrypt') )
				$id_bits = wp_decrypt($_COOKIE[$cookiename]);
			else
				$id_bits = $_COOKIE[$cookiename];
			$id_bits = explode('::', $id_bits);
			if ( is_array($id_bits) ) {
				$user_id = (int) $id_bits[0];
				$client_sig = $id_bits[1];
				if ( $client_sig == sa_get_client_signature() ) {
					wp_set_current_user($user_id);
					return;
				}
			}
		} 
		wp_set_current_user(0);
		return false;
	}

	if ( 'on' != $_SERVER['HTTPS'] )
		return;
					
	if ( empty($_COOKIE[USER_COOKIE]) || empty($_COOKIE[PASS_COOKIE]) ) {
		wp_set_current_user(0);
		return false;
	}

	if ( function_exists('wp_decrypt') )
		$id_bits = wp_decrypt($_COOKIE[USER_COOKIE]);
	else
		$id_bits = (int) $_COOKIE[USER_COOKIE];

	$user = '';
	$id_bits = explode('::', $id_bits);
	if ( is_array($id_bits) ) {
		$user_id = (int) $id_bits[0];
		$client_sig = $id_bits[1];
		if ( $client_sig == sa_get_client_signature() )
			$user = get_userdata($user_id);
	}

	if ( ! $user ) {
		wp_set_current_user(0);
		return false;		
	}
	
	if ( !wp_login($user->user_login, $_COOKIE[PASS_COOKIE], true) ) {
		wp_set_current_user(0);
		return false;
	}

	wp_set_current_user($user_id);
}
endif;

if ( !function_exists('wp_setcookie') ) :
function wp_setcookie($username, $password, $already_md5 = false, $home = '', $siteurl = '', $remember = false) {
	if ( !$already_md5 )
		$password = md5( md5($password) ); // Double hash the password in the cookie.

	$cookie_bits = sa_get_cookie_path_hash($home, $siteurl);
	extract($cookie_bits);

	if ( $remember )
		$expire = time() + 31536000;
	else
		$expire = 0;

	$user = new WP_User(0, $username);
	$user_id = $user->ID;
	$id_bits = $user_id . '::' . sa_get_client_signature();
	if ( function_exists('wp_encrypt') )
		$id_bits = wp_encrypt($id_bits);

	// Set insecure "logged in" cookies.
	setcookie('wordpressloggedin' . $cookiehash, $id_bits, $expire, $cookiepath, COOKIE_DOMAIN);

	if ( !empty($sitecookiepath) && ($cookiepath != $sitecookiepath) )
		setcookie('wordpressloggedin' . $cookiehash, $id_bits, $expire, $sitecookiepath, COOKIE_DOMAIN);

	// Set secure auth cookies.
	setcookie(USER_COOKIE, $id_bits, $expire, $cookiepath, COOKIE_DOMAIN, 1);
	setcookie(PASS_COOKIE, $password, $expire, $cookiepath, COOKIE_DOMAIN, 1);

	if ( !empty($sitecookiepath) && ($cookiepath != $sitecookiepath) ) {
		setcookie(USER_COOKIE, $id_bits, $expire, $sitecookiepath, COOKIE_DOMAIN, 1);
		setcookie(PASS_COOKIE, $password, $expire, $sitecookiepath, COOKIE_DOMAIN, 1);
	}
}
endif;

if ( !function_exists('wp_clearcookie') ) :
function wp_clearcookie() {
	$cookie_bits = sa_get_cookie_path_hash();
	extract($cookie_bits);
	
	setcookie(USER_COOKIE, ' ', time() - 31536000, COOKIEPATH, COOKIE_DOMAIN, 1);
	setcookie(PASS_COOKIE, ' ', time() - 31536000, COOKIEPATH, COOKIE_DOMAIN, 1);
	setcookie('wordpressloggedin' . $cookiehash, ' ', time() - 31536000, COOKIEPATH, COOKIE_DOMAIN);

	if ( !empty($sitecookiepath) && ($cookiepath != $sitecookiepath) ) {
		setcookie(USER_COOKIE, ' ', time() - 31536000, SITECOOKIEPATH, COOKIE_DOMAIN, 1);
		setcookie(PASS_COOKIE, ' ', time() - 31536000, SITECOOKIEPATH, COOKIE_DOMAIN, 1);
		setcookie('wordpressloggedin' . $cookiehash, ' ', time() - 31536000, SITECOOKIEPATH, COOKIE_DOMAIN);
	}
}
endif;

if ( !function_exists('wp_get_cookie_login') ):
function wp_get_cookie_login() {
	if ( empty($_COOKIE[USER_COOKIE]) || empty($_COOKIE[PASS_COOKIE]) )
		return false;

	$login = '';
	if ( function_exists('wp_decrypt') )
		$id_bits = wp_decrypt($_COOKIE[USER_COOKIE]);
	else
		$id_bits = (int) $_COOKIE[USER_COOKIE];

	$id_bits = explode('::', $id_bits);
	if ( ! is_array($id_bits) )
		return false;
	$user_id = (int) $id_bits[0];
	$client_sig = $id_bits[1];
	if ( $client_sig != sa_get_client_signature() )
		return false;
	if ( $user = get_userdata($user_id) )
		$login = $user->user_login;
			
	return array('login' => $login,	'password' => $_COOKIE[PASS_COOKIE]);
}
endif;

function sa_get_client_signature() {
	global $sa_client_sig;
	
	if ( isset($sa_client_sig) )
		return $sa_client_sig;

	$sa_client_sig = array();
	$sa_client_sig[] = $_SERVER['HTTP_USER_AGENT'];
	//$sa_client_sig[] = $_SERVER['HTTP_ACCEPT'];
	//$sa_client_sig[] = $_SERVER['HTTP_ACCEPT_CHARSET'];
	//$sa_client_sig[] = $_SERVER['HTTP_ACCEPT_ENCODING'];
	//$sa_client_sig[] = $_SERVER['HTTP_ACCEPT_LANGUAGE'];
	
	$sa_client_sig = md5(serialize($sa_client_sig));
	return $sa_client_sig;
}

function sa_get_cookie_path_hash($home = '', $siteurl = '') {
	if ( empty($home) )
		$cookiepath = COOKIEPATH;
	else
		$cookiepath = preg_replace('|https?://[^/]+|i', '', $home . '/' );

	if ( empty($siteurl) ) {
		if ( defined('SITECOOKIEPATH') )
			$sitecookiepath = SITECOOKIEPATH;
		else
			$sitecookiepath = '';
		if ( defined('COOKIEHASH') )
			$cookiehash = COOKIEHASH;
		else
			$cookiehash = '';
	} else {
		$sitecookiepath = preg_replace('|https?://[^/]+|i', '', $siteurl . '/' );
		$cookiehash = md5($siteurl);
	}

	if ( !empty($cookiehash) )
		$cookiehash = '_' . $cookiehash;
		
	return compact('cookiepath', 'sitecookiepath', 'cookiehash'); 
}

function sa_ob_handler($buffer) {
	$admin_url = get_settings('siteurl') . '/wp-admin';
	$login_url = get_settings('siteurl') . '/wp-login.php';
	$comment_url = get_settings('siteurl') . '/wp-comments-post.php';

	$secure_admin_url = preg_replace('/^https?/', 'https', $admin_url);
	$secure_login_url = preg_replace('/^https?/', 'https', $login_url);
	$secure_comment_url = preg_replace('/^https?/', 'https', $comment_url);

	$replace_this = array($admin_url, $login_url, $comment_url);
	$with_this = array($secure_admin_url, $secure_login_url, $secure_comment_url);
	if ( is_admin() ) {
		$includes_url = get_settings('siteurl') . '/wp-includes';
		$secure_includes_url = preg_replace('/^https?/', 'https', $includes_url);
		$replace_this[] = $includes_url;
		$with_this[] = $secure_includes_url;
	}

	if ( is_preview() && ( 'on' == $_SERVER['HTTPS'] ) ) {
		$site_url = get_settings('siteurl');
		$secure_site_url = preg_replace('/^https?/', 'https', $site_url);
		$replace_this[] = $site_url;
		$with_this[] = $secure_site_url;
	}
	return (str_replace($replace_this, $with_this, $buffer));
}

// Use secure post links when linking to posts from a secure page.
function sa_post_link($link) {
	global $pagenow;

	if ( ('on' == $_SERVER['HTTPS']) && ('wp-comments-post.php' != $pagenow) )
		$link = preg_replace('/^https?/', 'https', $link);
	return $link;
}

function sa_register_ob_handler() {
	ob_start('sa_ob_handler');	
}

function sa_shutdown() {
	ob_end_flush();	
}

add_action('init', 'sa_register_ob_handler');
add_action('shutdown', 'sa_shutdown');
add_filter('post_link', 'sa_post_link');
add_filter('page_link', 'sa_post_link');
?>
