<?php

declare(strict_types=1);

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

namespace Gecka\WP\Plugin\Antispam;

/**
 * Tells a submission of a form the plugin rendered from a call reaching the
 * same hook with no form behind it.
 *
 * The comment, login and registration hooks also fire for the REST API,
 * XML-RPC, WP-CLI, the cron and the importers. Those requests carry no
 * honeypot and no timestamp, and checking them would lock out the site rather
 * than the bots.
 *
 * @author Laurent Dinclaux - Gecka <laurent@gecka.nc>
 */
class Request
{
    /**
     * A request with no browser behind it.
     *
     * @return bool
     */
    public static function isNonInteractive(): bool
    {
        return (defined('REST_REQUEST') && REST_REQUEST)
            || (defined('XMLRPC_REQUEST') && XMLRPC_REQUEST)
            || (defined('WP_CLI') && WP_CLI)
            || wp_doing_cron();
    }

    /**
     * A browser submission of the form that posts every one of $fields: the
     * fields the handler of the form itself requires, so that a submission
     * the handler processes is never one this check skips.
     *
     * @param string|string[] $fields Field, or fields, only the form being checked posts.
     *
     * @return bool
     */
    public static function isFormPost(string|array $fields): bool
    {
        if (self::isNonInteractive()) {
            return false;
        }

        foreach ((array) $fields as $field) {
            // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Only tells which form is posting, the form checks its own nonce.
            if (! isset($_POST[$field])) {
                return false;
            }
        }

        return true;
    }

    /**
     * A POST to wp-login.php, the target of its login, registration and lost
     * password forms and of wp_login_form(). wp-login.php handles them on the
     * request method alone, whatever fields come with it.
     *
     * @return bool
     */
    public static function isLoginScreenPost(): bool
    {
        return ($GLOBALS['pagenow'] ?? '') === 'wp-login.php'
            && self::method() === 'POST';
    }

    /**
     * A POST to wp-signup.php, the registration of a network, its user step
     * or its site step
     *
     * @return bool
     */
    public static function isSignupPost(): bool
    {
        return ($GLOBALS['pagenow'] ?? '') === 'wp-signup.php'
            && self::method() === 'POST';
    }

    /**
     * A submission of the classic WooCommerce checkout: the AJAX request its
     * script sends, the same action posted to admin-ajax.php, where
     * WooCommerce registers it too, or the form posted with its button when
     * scripts are off. Payment buttons placing an order from another page
     * take other routes, and the Update totals button of the form without
     * scripts places none.
     *
     * @return bool
     */
    public static function isClassicCheckout(): bool
    {
        // phpcs:disable WordPress.Security.NonceVerification -- Only tells which route is placing the order, WooCommerce checks its nonce.
        $ajax = sanitize_key(self::query('wc-ajax'));
        $action = wp_doing_ajax() ? sanitize_key(self::requested('action')) : '';

        return ! self::isNonInteractive()
            && ($ajax === 'checkout' || $action === 'woocommerce_checkout' || isset($_POST['woocommerce_checkout_place_order']));
        // phpcs:enable
    }

    /**
     * The HTTP method of the request, in upper case
     *
     * @return string
     */
    public static function method(): string
    {
        if (! isset($_SERVER['REQUEST_METHOD']) || ! is_scalar($_SERVER['REQUEST_METHOD'])) {
            return '';
        }

        return strtoupper(sanitize_key(wp_unslash((string) $_SERVER['REQUEST_METHOD'])));
    }

    /**
     * A posted value, unslashed, as a string.
     *
     * @param string $name Field name.
     *
     * @return string
     */
    public static function post(string $name): string
    {
        // phpcs:disable WordPress.Security.NonceVerification.Missing -- Read for the spam checks, the form checks its own nonce.
        if (! isset($_POST[$name]) || ! is_scalar($_POST[$name])) {
            return '';
        }

        return sanitize_textarea_field(wp_unslash((string) $_POST[$name]));
        // phpcs:enable
    }

    /**
     * A value of the query string, unslashed, as a single line.
     *
     * @param string $name
     *
     * @return string
     */
    public static function query(string $name): string
    {
        // phpcs:disable WordPress.Security.NonceVerification.Recommended -- Picks a view, a notice or a period; an action checks its nonce itself.
        if (! isset($_GET[$name]) || ! is_scalar($_GET[$name])) {
            return '';
        }

        return sanitize_text_field(wp_unslash((string) $_GET[$name]));
        // phpcs:enable
    }

    /**
     * A value posted or in the query string, unslashed, as a single line.
     *
     * @param string $name
     *
     * @return string
     */
    public static function requested(string $name): string
    {
        // phpcs:disable WordPress.Security.NonceVerification -- Picks the action; the action checks its nonce itself.
        if (! isset($_REQUEST[$name]) || ! is_scalar($_REQUEST[$name])) {
            return '';
        }

        return sanitize_text_field(wp_unslash((string) $_REQUEST[$name]));
        // phpcs:enable
    }
}
