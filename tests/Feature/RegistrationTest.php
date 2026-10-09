<?php

declare(strict_types=1);

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

use Gecka\WP\Plugin\Antispam\Guard;
use Gecka\WP\Plugin\Antispam\Integrations\Registration;

beforeEach(function () {
    gecka_antispam()->stats()->reset();
    $this->registration = new Registration(gecka_antispam());
    $GLOBALS['pagenow'] = 'wp-login.php';
    $_SERVER['REQUEST_METHOD'] = 'POST';
});

afterEach(function () {
    $_POST = [];
    $GLOBALS['pagenow'] = 'index.php';
    unset($_SERVER['REQUEST_METHOD']);
    wp_set_current_user(0);
});

it('prints the fields in the registration form, and in the signup form of a network for visitors', function () {
    ob_start();
    $this->registration->render();
    $form = (string) ob_get_clean();

    ob_start();
    $this->registration->renderSignup();
    $signup = (string) ob_get_clean();

    wp_set_current_user(static::factory()->user->create());
    ob_start();
    $this->registration->renderSignup();
    $loggedIn = (string) ob_get_clean();

    expect($form)->toContain('name="' . Guard::TOKEN_FIELD . '"')
        ->and($signup)->toContain('name="' . Guard::TOKEN_FIELD . '"')
        ->and($loggedIn)->toBe('');
});

it('refuses a registration posted to wp-login.php without the fields, and counts it', function () {
    $_POST = ['user_login' => 'newcomer', 'user_email' => 'newcomer@example.test'];

    $errors = apply_filters('registration_errors', new WP_Error(), 'newcomer', 'newcomer@example.test');

    expect($errors->get_error_code())->toBe('gecka_antispam')
        ->and(gecka_antispam()->stats()->totals(1))->toBe(['registration' => [Guard::TOKEN => 1]]);
});

it('lets a registration with the fields through, and catches a random name', function () {
    post_form('registration', fields: ['user_login' => 'marie']);

    expect(apply_filters('registration_errors', new WP_Error(), 'marie', 'marie@example.test')->get_error_code())->toBe('');

    post_form('registration', fields: ['user_login' => 'qASQAhqkpFGqnKkRROl']);

    expect(apply_filters('registration_errors', new WP_Error(), 'qASQAhqkpFGqnKkRROl', 'x@example.test')->get_error_code())->toBe('gecka_antispam')
        ->and(gecka_antispam()->stats()->totals(1)['registration'])->toBe([Guard::PASSED => 1, Guard::RANDOM_NAME => 1]);
});

it('leaves alone a registration made by code, outside wp-login.php', function () {
    $GLOBALS['pagenow'] = 'index.php';

    expect(apply_filters('registration_errors', new WP_Error(), 'api', 'api@example.test')->get_error_code())->toBe('')
        ->and(gecka_antispam()->stats()->totals(1))->toBe([]);
});

it('checks the signup form of a network on its own route, and leaves it alone when switched off', function () {
    $GLOBALS['pagenow'] = 'wp-signup.php';
    $result = ['user_name' => 'newcomer', 'errors' => new WP_Error()];

    expect($this->registration->checkSignup($result)['errors']->get_error_code())->toBe('generic');

    antispam_settings(['surfaces' => ['registration' => false]]);

    expect($this->registration->checkSignup(['user_name' => 'newcomer', 'errors' => new WP_Error()])['errors']->get_error_code())->toBe('')
        ->and($this->registration->checkSignup('not an array'))->toBe('not an array');
});
