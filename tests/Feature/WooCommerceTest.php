<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

use Gecka\WP\Plugin\Antispam\Guard;
use Gecka\WP\Plugin\Antispam\Integrations\WooCommerce;
use Gecka\WP\Plugin\Antispam\Request;

beforeEach(function () {
    gecka_antispam()->stats()->reset();
    $this->woocommerce = new WooCommerce(gecka_antispam());
});

afterEach(function () {
    $_POST = [];
    $_GET = [];
    unset($_REQUEST['action']);
});

it('tells the routes of the classic checkout from the payment buttons', function () {
    expect(Request::isClassicCheckout())->toBeFalse();

    $_GET['wc-ajax'] = 'checkout';
    expect(Request::isClassicCheckout())->toBeTrue();

    $_GET = [];
    $_POST['woocommerce_checkout_place_order'] = 'Place order';
    expect(Request::isClassicCheckout())->toBeTrue();

    $_POST = ['woocommerce_checkout_update_totals' => 'Update totals'];
    expect(Request::isClassicCheckout())->toBeFalse();
});

it('checks an order posted to admin-ajax.php, where WooCommerce registers its checkout too', function () {
    add_filter('wp_doing_ajax', '__return_true');
    $_REQUEST['action'] = 'woocommerce_checkout';

    expect(Request::isClassicCheckout())->toBeTrue();

    $this->woocommerce->checkCheckout();

    expect(gecka_antispam()->stats()->totals(1)['woocommerce_checkout'])->toBe([Guard::TOKEN => 1]);

    $_REQUEST['action'] = 'woocommerce_update_order_review';
    expect(Request::isClassicCheckout())->toBeFalse();

    remove_filter('wp_doing_ajax', '__return_true');
    $_REQUEST['action'] = 'woocommerce_checkout';
    expect(Request::isClassicCheckout())->toBeFalse();
});

it('checks an order placed from the classic checkout', function () {
    $_GET['wc-ajax'] = 'checkout';

    $this->woocommerce->checkCheckout();

    expect(gecka_antispam()->stats()->totals(1)['woocommerce_checkout'])->toBe([Guard::TOKEN => 1]);
});

it('leaves alone an order placed by a payment button from another page', function () {
    $_POST = ['action' => 'ppcp_create_order', 'woocommerce-process-checkout-nonce' => 'abc', 'caller_page' => 'product'];

    $this->woocommerce->checkCheckout();

    expect(gecka_antispam()->stats()->totals(1))->toBe([]);
});

it('checks the login form posted from any address, the app authorization screen included', function (string $uri) {
    $previous = $_SERVER['REQUEST_URI'] ?? null;
    $_SERVER['REQUEST_URI'] = $uri;
    $_POST = ['login' => 'Log in', 'username' => 'editor', 'password' => 'secret', 'woocommerce-login-nonce' => 'abc'];

    expect($this->woocommerce->checkLogin(new WP_Error())->get_error_code())->toBe('gecka_antispam');

    $_SERVER['REQUEST_URI'] = $previous;
})->with(['/my-account/', '/my-account/?/wc-auth/', '/wc-auth/v1/login?app_name=Zapier']);

it('puts the fields in the login form of the app authorization screen', function () {
    ob_start();
    $this->woocommerce->startAuthPage();
    echo '<h1>Connect</h1><form method="post" class="wc-auth-login"><p>login</p></form>';
    $this->woocommerce->endAuthPage();
    $html = (string) ob_get_clean();

    expect($html)->toMatch('/<form method="post" class="wc-auth-login">(<style>[^<]*<\/style>)?<input type="hidden" name="' . Guard::TOKEN_FIELD . '"/s')
        ->and($html)->toStartWith('<h1>Connect</h1>')
        ->and($html)->toEndWith('<p>login</p></form>');
});

it('leaves the app authorization screen alone when the login form is switched off', function () {
    antispam_settings(['surfaces' => ['woocommerce_login' => false]]);

    ob_start();
    $this->woocommerce->startAuthPage();
    echo '<form method="post" class="wc-auth-login"></form>';
    $this->woocommerce->endAuthPage();

    expect((string) ob_get_clean())->toBe('<form method="post" class="wc-auth-login"></form>');
});

it('checks the account forms on the fields WooCommerce processes them on, whatever nonce field is posted', function () {
    $_POST = ['register' => 'Register', 'email' => 'bot@example.test', '_wpnonce' => 'abc'];

    expect($this->woocommerce->checkRegistration(new WP_Error())->get_error_code())->toBe('gecka_antispam');

    $_POST = ['wc_reset_password' => 'true', 'user_login' => 'editor', '_wpnonce' => 'abc'];
    $errors = new WP_Error();
    $this->woocommerce->checkLostPassword($errors);

    expect($errors->get_error_code())->toBe('gecka_antispam')
        ->and(gecka_antispam()->stats()->totals(1))->toEqualCanonicalizing(['woocommerce_registration' => [Guard::TOKEN => 1], 'woocommerce_lost_password' => [Guard::TOKEN => 1]]);
});

it('leaves alone a registration WooCommerce does not process: no register field, as at checkout', function () {
    $_POST = ['email' => 'buyer@example.test', 'woocommerce-register-nonce' => 'abc'];

    expect($this->woocommerce->checkRegistration(new WP_Error())->get_error_code())->toBe('')
        ->and(gecka_antispam()->stats()->totals(1))->toBe([]);
});
