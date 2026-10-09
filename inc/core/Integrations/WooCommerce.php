<?php

declare(strict_types=1);

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

namespace Gecka\WP\Plugin\Antispam\Integrations;

use Gecka\WP\Plugin\Antispam\Request;

/**
 * The checkout and the My account forms of WooCommerce: login,
 * registration, lost password.
 *
 * The checkout block posts to the Store API, which runs none of the hooks of
 * the classic checkout: only the [woocommerce_checkout] shortcode is
 * protected, on the routes of its form. Payment buttons that place an order
 * from a product or cart page run the same checkout hook without the form,
 * and are left alone.
 *
 * The login form of the app authorization screen (/wc-auth/) has no hook
 * inside it: the fields go in through the output of the page, between the
 * header and the footer hooks of that screen. WooCommerce processes a login
 * form posted to any address, so no address is exempt from the check.
 *
 * @author Laurent Dinclaux - Gecka <laurent@gecka.nc>
 */
class WooCommerce extends Integration
{
    /**
     * Whether the app authorization screen is being held back.
     *
     * @var bool
     */
    private bool $holding = false;

    /**
     * @return bool
     */
    public function available(): bool
    {
        return class_exists('WooCommerce');
    }

    /**
     * @return void
     */
    public function setup(): void
    {
        add_action('woocommerce_after_checkout_billing_form', [$this, 'renderCheckout']);
        add_action('woocommerce_checkout_process', [$this, 'checkCheckout'], self::PRIORITY);

        add_action('woocommerce_login_form', [$this, 'renderLogin']);
        add_action('woocommerce_auth_page_header', [$this, 'startAuthPage']);
        add_action('woocommerce_auth_page_footer', [$this, 'endAuthPage']);
        add_filter('woocommerce_process_login_errors', [$this, 'checkLogin'], self::PRIORITY);

        add_action('woocommerce_register_form', [$this, 'renderRegistration']);
        add_filter('woocommerce_registration_errors', [$this, 'checkRegistration'], self::PRIORITY);

        add_action('woocommerce_lostpassword_form', [$this, 'renderLostPassword']);
        add_action('lostpassword_post', [$this, 'checkLostPassword'], self::PRIORITY);
    }

    /**
     * @return void
     */
    public function renderCheckout(): void
    {
        echo $this->fields('woocommerce_checkout'); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped by Guard::fields().
    }

    /**
     * @return void
     */
    public function renderLogin(): void
    {
        echo $this->fields('woocommerce_login'); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped by Guard::fields().
    }

    /**
     * Starts holding the app authorization screen back, so the fields can go
     * in its login form.
     *
     * @return void
     */
    public function startAuthPage(): void
    {
        $this->holding = $this->plugin->settings()->enabled('woocommerce_login') && ob_start();
    }

    /**
     * Prints the app authorization screen held back, the fields added at the
     * start of its login form.
     *
     * @return void
     */
    public function endAuthPage(): void
    {
        if (! $this->holding) {
            return;
        }

        $this->holding = false;
        $fields = $this->fields('woocommerce_login');
        $page = (string) ob_get_clean();

        // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Page printed by WooCommerce, fields escaped by Guard::fields().
        echo preg_replace_callback('/<form\b[^>]*\bwc-auth-login\b[^>]*>/', static fn(array $m): string => $m[0] . $fields, $page, 1) ?? $page;
    }

    /**
     * @return void
     */
    public function renderRegistration(): void
    {
        echo $this->fields('woocommerce_registration'); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped by Guard::fields().
    }

    /**
     * @return void
     */
    public function renderLostPassword(): void
    {
        echo $this->fields('woocommerce_lost_password'); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped by Guard::fields().
    }

    /**
     * Stops an order whose checkout form did not pass the checks.
     *
     * @return void
     */
    public function checkCheckout(): void
    {
        if (! Request::isClassicCheckout() || ! $this->plugin->settings()->enabled('woocommerce_checkout')) {
            return;
        }

        $names = [Request::post('billing_first_name'), Request::post('billing_last_name')];

        if ($this->verify('woocommerce_checkout', $names) && function_exists('wc_add_notice')) {
            wc_add_notice(esc_html($this->message()), 'error');
        }
    }

    /**
     * Checks the login forms of My account and of the app authorization
     * screen. WooCommerce processes a login on these three fields, whatever
     * nonce field carries the nonce.
     *
     * @param mixed $errors \WP_Error.
     *
     * @return mixed
     */
    public function checkLogin(mixed $errors): mixed
    {
        return $this->checkAccountForm('woocommerce_login', ['login', 'username', 'password'], $errors);
    }

    /**
     * Checks the registration of My account, which WooCommerce processes on
     * these two fields: the filter also runs for the accounts created at
     * checkout and by code, which post neither.
     *
     * @param mixed $errors \WP_Error.
     *
     * @return mixed
     */
    public function checkRegistration(mixed $errors): mixed
    {
        return $this->checkAccountForm('woocommerce_registration', ['register', 'email'], $errors, [Request::post('username')]);
    }

    /**
     * Checks the lost password form of My account, which WooCommerce
     * processes on these two fields; the one of wp-login.php runs the same
     * hook.
     *
     * @param mixed $errors \WP_Error, nothing when an older caller fires the hook bare.
     *
     * @return void
     */
    public function checkLostPassword(mixed $errors = null): void
    {
        $this->checkAccountForm('woocommerce_lost_password', ['wc_reset_password', 'user_login'], $errors);
    }

    /**
     * Adds an error when a My account form did not pass the checks. What
     * posts to wp-login.php belongs to the Login integration.
     *
     * @param string   $surface
     * @param string[] $fields  The fields WooCommerce requires to process the form.
     * @param mixed    $errors  \WP_Error.
     * @param string[] $names
     *
     * @return mixed
     */
    private function checkAccountForm(string $surface, array $fields, mixed $errors, array $names = []): mixed
    {
        if (! $errors instanceof \WP_Error
            || Request::isLoginScreenPost()
            || ! Request::isFormPost($fields)
            || ! $this->plugin->settings()->enabled($surface)
        ) {
            return $errors;
        }

        if ($this->verify($surface, array_filter($names))) {
            $errors->add('gecka_antispam', esc_html($this->message()));
        }

        return $errors;
    }
}
