<?php
/*
Plugin Name: Secure Admin
Plugin URI: http://http://wordpress.org/extend/plugins/secure-admin/
Description: Secures Login and Admin pages using Private or Shared SSL
Author: Ryan Boren and Robert Accettura
Version: 0.3b1

*/

//
// What protocol
//
function http() {
	if ( 'on' == $_SERVER['HTTPS'] )
		return 'https';
	return 'http';
}

//
// Get the blog domain for both MU or Single installs
//
function sa_blog_domain(){
	global $current_blog;
	if(isset($current_blog)){
		return $current_blog->domain;
	}
	return str_replace('http://', '', get_option('siteurl'));
}

//
// If https is requested, present https links.
//
function sa_ob_handler($buffer) {
	$replace_this = $with_this = array();

	$siteurl = get_option('siteurl');
	$blogdomain = sa_blog_domain();

	$replace_this[] = $siteurl . '/wp-admin';
	$with_this[] = "https://{$blogdomain}/wp-admin";

	$replace_this[] =  $siteurl . '/wp-login.php';
	$with_this[] =  "https://{$blogdomain}/wp-login.php";

	if( function_exists('is_redirected_domain') && is_redirected_domain() == false ) {
		$replace_this[] = $siteurl . '/wp-comments-post.php';
		$with_this[] = "https://{$blogdomain}/wp-comments-post.php";
	}

	if ( is_admin() ) {
		$replace_this[] = $includes_url = $siteurl . '/wp-includes';
		$with_this[] = preg_replace('/^https?/', 'https', $includes_url);
	}

	if ( is_preview() && ( 'on' == $_SERVER['HTTPS'] ) ) {
		$replace_this[] = $siteurl;
		$with_this[] = preg_replace('/^https?/', 'https', $siteurl);
	}

	if ( defined('STATIC_HOST') ) {
		$replace_this[] = STATIC_HOST;
		$with_this[] = preg_replace('/^https?/', 'https', STATIC_HOST);
	}
	return (str_replace($replace_this, $with_this, $buffer));
}

//
// Use secure post links when linking to posts from a secure page.
//
function sa_post_link($link) {
	global $pagenow;

	if ( ('on' == $_SERVER['HTTPS']) && ('wp-comments-post.php' != $pagenow) )
		$link = preg_replace('/^https?/', 'https', $link);
	return $link;
}

//
// Use secure links when using edit links
//
function sa_edit_items_link($link) {
	if ( strpos($link, 'wp-admin') !== false )
		$link = str_replace('http://', 'https://', $link);
	return $link;
}


function sa_register_ob_handler() {
	if ('on' == $_SERVER['HTTPS'])
		ob_start('sa_ob_handler');
}

add_action('init', 'sa_register_ob_handler');
add_filter('preview_post_link', 'sa_post_link');
add_filter('preview_page_link', 'sa_post_link');
add_filter('edit_post_link', 'sa_edit_items_link');
add_filter('edit_comment_link', 'sa_edit_items_link');

?>
