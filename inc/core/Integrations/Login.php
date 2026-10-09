<?php

declare(strict_types=1);

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

namespace Gecka\WP\Plugin\Antispam\Integrations;

use Gecka\WP\Plugin\Antispam\Request;

/**
 * The login and lost password forms of wp-login.php, and the login form
 * wp_login_form() prints in a page, which posts to wp-login.php too.
 *
 * Every POST to wp-login.php is checked, whatever fields it carries: the
 * screen logs in and sends reset links on the request method alone. The
 * WooCommerce forms run the same hooks from the My account page, and are
 * left to the WooCommerce integration.
 *
 * @author Laurent Dinclaux - Gecka <laurent@gecka.nc>
 */
class Login extends Integration
{
    /**
     * Always: the login forms are those of WordPress
     *
     * @return bool
     */
    public function available(): bool
    {
        return true;
    }

    /**
     * Hooks the fields into the login and lost password forms, and the
     * checks ahead of the other plugins.
     *
     * @return void
     */
    public function setup(): void
    {
        add_action('login_form', [$this, 'renderLogin']);
        add_filter('login_form_middle', [$this, 'appendLogin']);
        add_filter('wp_authenticate_user', [$this, 'checkLogin'], self::PRIORITY);

        add_action('lostpassword_form', [$this, 'renderLostPassword']);
        add_action('lostpassword_post', [$this, 'checkLostPassword'], self::PRIORITY);
    }

    /**
     * Prints the fields in the login form of wp-login.php.
     *
     * @return void
     */
    public function renderLogin(): void
    {
        echo $this->fields('login'); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped by Guard::fields().
    }

    /**
     * Adds the fields to the form of wp_login_form().
     *
     * @param mixed $html
     *
     * @return mixed
     */
    public function appendLogin(mixed $html): mixed
    {
        return is_string($html) ? $html . $this->fields('login') : $html;
    }

    /**
     * Refuses a login whose form did not pass the checks, before the password
     * is even compared.
     *
     * @param mixed $user \WP_User, or \WP_Error from a check that ran before.
     *
     * @return mixed
     */
    public function checkLogin(mixed $user): mixed
    {
        if (! $user instanceof \WP_User
            || ! Request::isLoginScreenPost()
            || ! $this->plugin->settings()->enabled('login')
        ) {
            return $user;
        }

        return $this->verify('login') ? new \WP_Error('gecka_antispam', esc_html($this->message())) : $user;
    }

    /**
     * Prints the fields in the lost password form of wp-login.php.
     *
     * @return void
     */
    public function renderLostPassword(): void
    {
        echo $this->fields('lost_password'); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped by Guard::fields().
    }

    /**
     * Refuses to send a reset link when the form did not pass the checks.
     *
     * @param mixed $errors \WP_Error, nothing when an older caller fires the hook bare.
     *
     * @return void
     */
    public function checkLostPassword(mixed $errors = null): void
    {
        if (! $errors instanceof \WP_Error
            || ! Request::isLoginScreenPost()
            || ! $this->plugin->settings()->enabled('lost_password')
        ) {
            return;
        }

        if ($this->verify('lost_password')) {
            $errors->add('gecka_antispam', esc_html($this->message()));
        }
    }
}
