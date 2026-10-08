<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

use Gecka\WP\Plugin\Antispam\Integrations\Comments;
use Gecka\WP\Plugin\Antispam\Integrations\ContactForm7;
use Gecka\WP\Plugin\Antispam\Integrations\GravityForms;
use Gecka\WP\Plugin\Antispam\Integrations\Login;
use Gecka\WP\Plugin\Antispam\Integrations\Registration;
use Gecka\WP\Plugin\Antispam\Integrations\WooCommerce;

it('checks a form before the other plugins hooked at the default priority', function (string $class, array $hooks) {
    $integration = new $class(gecka_antispam());
    $integration->setup();

    foreach ($hooks as $hook => $method) {
        expect(has_filter($hook, [$integration, $method]))->toBeInt()->toBeLessThan(10);
    }
})->with([
    'comments' => [Comments::class, ['preprocess_comment' => 'check']],
    'login' => [Login::class, ['wp_authenticate_user' => 'checkLogin', 'lostpassword_post' => 'checkLostPassword']],
    'registration' => [Registration::class, ['registration_errors' => 'check']],
    'woocommerce' => [WooCommerce::class, [
        'woocommerce_checkout_process' => 'checkCheckout',
        'woocommerce_process_login_errors' => 'checkLogin',
        'woocommerce_registration_errors' => 'checkRegistration',
        'lostpassword_post' => 'checkLostPassword',
    ]],
    'contact form 7' => [ContactForm7::class, ['wpcf7_spam' => 'check']],
    'gravity forms' => [GravityForms::class, ['gform_validation' => 'validate', 'gform_entry_is_spam' => 'check']],
]);
