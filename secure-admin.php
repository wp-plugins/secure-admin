<?php
/*
Plugin Name: Secure Admin
Plugin URI: http://wordpress.org/#
Description: Access the admin backend over SSL.
Author: Ryan Boren
Version: 0.1
Author URI: http://boren.nu/
*/ 

if ( !function_exists('auth_redirect') ) :
function auth_redirect() {
	
	// Checks if a user is logged in, if not redirects them to the login page
	if ( (!empty($_COOKIE[USER_COOKIE]) && 
				!wp_login($_COOKIE[USER_COOKIE], $_COOKIE[PASS_COOKIE], true)) ||
			 (empty($_COOKIE[USER_COOKIE])) ) {
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


if ( !function_exists('wp_setcookie') ) :
function wp_setcookie($username, $password, $already_md5 = false, $home = '', $siteurl = '', $remember = false) {
	if ( !$already_md5 )
		$password = md5( md5($password) ); // Double hash the password in the cookie.

	if ( empty($home) )
		$cookiepath = COOKIEPATH;
	else
		$cookiepath = preg_replace('|https?://[^/]+|i', '', $home . '/' );

	if ( empty($siteurl) ) {
		$sitecookiepath = SITECOOKIEPATH;
		$cookiehash = COOKIEHASH;
	} else {
		$sitecookiepath = preg_replace('|https?://[^/]+|i', '', $siteurl . '/' );
		$cookiehash = md5($siteurl);
	}

	if ( $remember )
		$expire = time() + 31536000;
	else
		$expire = 0;

	setcookie(USER_COOKIE, $username, $expire, $cookiepath, COOKIE_DOMAIN, 1);
	setcookie(PASS_COOKIE, $password, $expire, $cookiepath, COOKIE_DOMAIN, 1);

	if ( $cookiepath != $sitecookiepath ) {
		setcookie(USER_COOKIE, $username, $expire, $sitecookiepath, COOKIE_DOMAIN, 1);
		setcookie(PASS_COOKIE, $password, $expire, $sitecookiepath, COOKIE_DOMAIN, 1);
	}
}
endif;

if ( !function_exists('wp_clearcookie') ) :
function wp_clearcookie() {
	setcookie(USER_COOKIE, ' ', time() - 31536000, COOKIEPATH, COOKIE_DOMAIN, 1);
	setcookie(PASS_COOKIE, ' ', time() - 31536000, COOKIEPATH, COOKIE_DOMAIN, 1);
	setcookie(USER_COOKIE, ' ', time() - 31536000, SITECOOKIEPATH, COOKIE_DOMAIN, 1);
	setcookie(PASS_COOKIE, ' ', time() - 31536000, SITECOOKIEPATH, COOKIE_DOMAIN, 1);
}
endif;

function sa_ob_handler($buffer) {
	$admin_url = get_settings('siteurl') . '/wp-admin';
	$secure_admin_url = preg_replace('/^https?/', 'https', $admin_url);
	return (str_replace($admin_url, $secure_admin_url, $buffer));
}

function sa_register_ob_handler() {
	ob_start('sa_ob_handler');	
}

function sa_shutdown() {
	ob_end_flush();	
}
add_action('init', 'sa_register_ob_handler');
add_action('shutdown', 'sa_shutdown');
?>
