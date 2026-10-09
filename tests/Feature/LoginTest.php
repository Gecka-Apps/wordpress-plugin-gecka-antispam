<?php

declare(strict_types=1);

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

use Gecka\WP\Plugin\Antispam\Guard;

beforeEach(function () {
    $this->user = get_user_by('id', static::factory()->user->create());
    $GLOBALS['pagenow'] = 'wp-login.php';
    $_SERVER['REQUEST_METHOD'] = 'POST';
});

afterEach(function () {
    $_POST = [];
    $GLOBALS['pagenow'] = 'index.php';
    unset($_SERVER['REQUEST_METHOD']);
});

it('refuses a login posted to wp-login.php without the fields, even without the submit button', function () {
    $_POST = ['log' => $this->user->user_login, 'pwd' => 'guess'];

    $result = apply_filters('wp_authenticate_user', $this->user, 'guess');

    expect($result)->toBeInstanceOf(WP_Error::class)
        ->and($result->get_error_code())->toBe('gecka_antispam');
});

it('lets a login with the fields through', function () {
    post_form('login', age: 0, fields: ['log' => $this->user->user_login]);

    expect(apply_filters('wp_authenticate_user', $this->user, 'secret'))->toBe($this->user);
});

it('checks a login posted to wp-login.php even with a WooCommerce nonce', function () {
    $_POST = ['log' => $this->user->user_login, 'woocommerce-login-nonce' => 'forged'];

    expect(apply_filters('wp_authenticate_user', $this->user, 'guess'))->toBeInstanceOf(WP_Error::class);
});

it('leaves alone the logins that do not post to wp-login.php', function () {
    $GLOBALS['pagenow'] = 'index.php';

    expect(apply_filters('wp_authenticate_user', $this->user, 'guess'))->toBe($this->user);
});

it('never checks nor counts a login made through XML-RPC or the REST API', function () {
    gecka_antispam()->stats()->reset();
    $_POST = [];

    $GLOBALS['pagenow'] = 'xmlrpc.php';
    expect(apply_filters('wp_authenticate_user', $this->user, 'secret'))->toBe($this->user);

    $GLOBALS['pagenow'] = 'index.php';
    $errors = new WP_Error();
    do_action('lostpassword_post', $errors, $this->user);

    expect(apply_filters('wp_authenticate_user', $this->user, 'secret'))->toBe($this->user)
        ->and($errors->has_errors())->toBeFalse()
        ->and(gecka_antispam()->stats()->totals(1))->toBe([]);
});

it('refuses to send a reset link without the fields', function () {
    $errors = new WP_Error();

    do_action('lostpassword_post', $errors, $this->user);

    expect($errors->get_error_code())->toBe('gecka_antispam');
});

it('survives the lost password hook fired with no argument', function () {
    do_action('lostpassword_post');

    expect(true)->toBeTrue();
});

it('refuses a registration posted to wp-login.php without the fields', function () {
    $errors = apply_filters('registration_errors', new WP_Error(), 'marie', 'marie@example.org');

    expect($errors->get_error_code())->toBe('gecka_antispam');
});

it('checks both steps of the registration of a network, and leaves its other callers alone', function () {
    $signup = fn(): array => apply_filters('wpmu_validate_user_signup', ['user_name' => 'marie', 'user_email' => 'marie@example.org', 'errors' => new WP_Error()]);
    $GLOBALS['pagenow'] = 'wp-signup.php';

    expect($signup()['errors']->get_error_code())->toBe('generic');

    post_form('registration', fields: ['user_name' => 'marie', 'stage' => 'validate-blog-signup']);
    ob_start();
    do_action('signup_blogform', new WP_Error());
    $carried = (string) ob_get_clean();

    expect($signup()['errors']->has_errors())->toBeFalse()
        ->and($carried)->toContain('name="' . Guard::TOKEN_FIELD . '" value="' . strtok($_POST[Guard::TOKEN_FIELD], '.') . '.');

    $_POST = [];
    $GLOBALS['pagenow'] = 'network/user-new.php';

    expect($signup()['errors']->has_errors())->toBeFalse();
});

it('lets a registration with the fields through', function () {
    post_form('registration', fields: ['user_login' => 'marie']);

    $errors = apply_filters('registration_errors', new WP_Error(), 'marie', 'marie@example.org');

    expect($errors->has_errors())->toBeFalse();
});
