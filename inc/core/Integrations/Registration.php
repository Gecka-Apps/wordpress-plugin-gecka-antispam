<?php

declare(strict_types=1);

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

namespace Gecka\WP\Plugin\Antispam\Integrations;

use Gecka\WP\Plugin\Antispam\Request;

/**
 * The registration form of wp-login.php, and that of a network,
 * wp-signup.php: its user step, and its site step, which validates the user
 * again and carries the time the first step was shown at.
 *
 * @author Laurent Dinclaux - Gecka <laurent@gecka.nc>
 */
class Registration extends Integration
{
    /**
     * @return bool
     */
    public function available(): bool
    {
        return true;
    }

    /**
     * @return void
     */
    public function setup(): void
    {
        add_action('register_form', [$this, 'render']);
        add_filter('registration_errors', [$this, 'check'], self::PRIORITY, 2);

        add_action('signup_extra_fields', [$this, 'renderSignup']);
        add_action('signup_blogform', [$this, 'renderSignup']);
        add_filter('wpmu_validate_user_signup', [$this, 'checkSignup'], self::PRIORITY);
    }

    /**
     * Prints the fields in the registration form.
     *
     * @return void
     */
    public function render(): void
    {
        echo $this->fields('registration'); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped by Guard::fields().
    }

    /**
     * Prints the fields in a step of the registration of a network, to a
     * visitor not logged in.
     *
     * @return void
     */
    public function renderSignup(): void
    {
        if (! is_user_logged_in()) {
            echo $this->fields('registration', Request::isSignupPost()); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped by Guard::fields().
        }
    }

    /**
     * Refuses a step of the registration of a network posted by a visitor
     * whose form did not pass the checks, with an error wp-signup.php shows
     * above the extra fields. Other callers of wpmu_validate_user_signup(),
     * the network administration for one, are left alone.
     *
     * @param mixed $result user_name, user_email, errors.
     *
     * @return mixed
     */
    public function checkSignup(mixed $result): mixed
    {
        if (! is_array($result)
            || ! ($result['errors'] ?? null) instanceof \WP_Error
            || is_user_logged_in()
            || ! Request::isSignupPost()
            || ! $this->plugin->settings()->enabled('registration')
        ) {
            return $result;
        }

        if ($this->verify('registration', [(string) ($result['user_name'] ?? '')])) {
            $result['errors']->add('generic', esc_html($this->message()));
        }

        return $result;
    }

    /**
     * Refuses a registration posted to wp-login.php when its form did not
     * pass the checks. wp-login.php registers on the request method alone,
     * whatever fields come with it.
     *
     * @param mixed $errors \WP_Error.
     * @param mixed $login  User name chosen.
     *
     * @return mixed
     */
    public function check(mixed $errors, mixed $login = ''): mixed
    {
        if (! $errors instanceof \WP_Error
            || ! Request::isLoginScreenPost()
            || ! $this->plugin->settings()->enabled('registration')
        ) {
            return $errors;
        }

        if ($this->verify('registration', [is_string($login) ? $login : ''])) {
            $errors->add('gecka_antispam', esc_html($this->message()));
        }

        return $errors;
    }
}
