<?php

declare(strict_types=1);

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

use Gecka\WP\Plugin\Antispam\Guard;

afterEach(function () {
    $_POST = [];
});

it('adds a signed timestamp and a hidden honeypot to a form', function () {
    $html = (new Guard(gecka_antispam()))->fields('comments');
    $name = gecka_antispam()->guard()->honeypotName();

    expect($html)->toMatch('/name="_gecka_antispam" value="\d+\.[0-9a-f]{24}"/')
        ->and($html)->toContain('name="' . $name . '"')
        ->and($html)->toContain('tabindex="-1"')
        ->and($html)->toContain('aria-hidden="true"')
        ->and($html)->toContain('display:none');
});

it('carries the style hiding the honeypot in every form printed without a head', function () {
    $guard = new Guard(gecka_antispam());

    expect($guard->fields('comments'))->toContain('<style>')
        ->and($guard->fields('login'))->toContain('<style>');
});

it('leaves the style hiding the honeypot to the head of the page', function () {
    $guard = new Guard(gecka_antispam());
    $guard->enqueueStyle();

    expect($guard->fields('comments'))->not->toContain('<style>')
        ->and(implode('', (array) wp_styles()->get_data('gecka-antispam', 'after')))->toContain('display:none!important');

    wp_dequeue_style('gecka-antispam');
    wp_deregister_style('gecka-antispam');
});

it('lets through a form filled in by a person', function () {
    post_form('comments');

    expect(gecka_antispam()->guard()->check('comments'))->toBeNull();
});

it('catches a filled honeypot', function () {
    post_form('comments', honeypot: 'https://spam.example');

    expect(gecka_antispam()->guard()->check('comments'))->toBe(Guard::HONEYPOT);
});

it('catches a missing or forged timestamp', function () {
    $_POST = [];
    expect(gecka_antispam()->guard()->check('comments'))->toBe(Guard::TOKEN);

    post_form('comments');
    $_POST[Guard::TOKEN_FIELD] = (time() - 30) . '.000000000000000000000000';
    expect(gecka_antispam()->guard()->check('comments'))->toBe(Guard::TOKEN);
});

it('refuses a timestamp issued for another form', function () {
    post_form('login');

    expect(gecka_antispam()->guard()->check('comments'))->toBe(Guard::TOKEN);
});

it('catches a form sent faster than the minimum delay', function () {
    antispam_settings(['min_delay' => 5, 'sign_in_min_delay' => 0]);

    post_form('comments', age: 2);
    expect(gecka_antispam()->guard()->check('comments'))->toBe(Guard::TOO_FAST);

    post_form('login', age: 0);
    expect(gecka_antispam()->guard()->check('login'))->toBeNull();
});

it('catches a timestamp older than 8 days by default, and none with no maximum age', function () {
    post_form('comments', age: 7 * DAY_IN_SECONDS);
    expect(gecka_antispam()->guard()->check('comments'))->toBeNull();

    post_form('comments', age: 9 * DAY_IN_SECONDS);
    expect(gecka_antispam()->guard()->check('comments'))->toBe(Guard::EXPIRED);

    antispam_settings(['max_age' => 0]);
    expect(gecka_antispam()->guard()->check('comments'))->toBeNull();

    antispam_settings(['max_age' => 24]);
    post_form('comments', age: 2 * DAY_IN_SECONDS);
    expect(gecka_antispam()->guard()->check('comments'))->toBe(Guard::EXPIRED);

    antispam_settings(['max_age' => 192]);
});

it('catches names made of random letters', function (string $name, bool $random) {
    expect(Guard::isRandomName($name))->toBe($random);
})->with([
    ['qASQAhqkpFGqnKkRROl', true],
    ['MarieClaireDeLaFontaine', false],
    ['Jean-Pierre Dupont', false],
    ['McDonald', false],
    ['ABCDEFGHIJKLMN', false],
]);

it('catches a random name only when the check is on', function () {
    post_form('comments');

    expect(gecka_antispam()->guard()->check('comments', ['qASQAhqkpFGqnKkRROl']))->toBe(Guard::RANDOM_NAME);

    antispam_settings(['random_names' => false]);
    expect(gecka_antispam()->guard()->check('comments', ['qASQAhqkpFGqnKkRROl']))->toBeNull();
    antispam_settings(['random_names' => true]);
});

it('catches a message of a single word of random letters', function () {
    post_form('comments');
    $guard = gecka_antispam()->guard();

    expect($guard->check('comments', [], 'fWxBIRsgipbaeRuKXpLXpU'))->toBe(Guard::RANDOM_TEXT)
        ->and($guard->check('comments', [], " fWxBIRsgipbaeRuKXpLXpU.\n"))->toBe(Guard::RANDOM_TEXT)
        ->and($guard->check('comments', [], 'fWxBIRsgipbaeRuKXpLXpU encore'))->toBeNull()
        ->and($guard->check('comments', [], 'Merci'))->toBeNull()
        ->and($guard->check('comments', [], ''))->toBeNull()
        ->and($guard->check('comments', []))->toBeNull();

    antispam_settings(['random_names' => false]);
    expect($guard->check('comments', [], 'fWxBIRsgipbaeRuKXpLXpU'))->toBeNull();
    antispam_settings(['random_names' => true]);
});

it('refuses a message shorter than the minimum of words, when one is set', function () {
    post_form('comments');
    $guard = gecka_antispam()->guard();

    antispam_settings(['min_words' => 3]);
    expect($guard->check('comments', [], 'Merci beaucoup'))->toBe(Guard::SHORT)
        ->and($guard->check('comments', [], ''))->toBe(Guard::SHORT)
        ->and($guard->check('comments', [], "Merci\nbeaucoup à vous"))->toBeNull()
        ->and($guard->check('comments', []))->toBeNull();
    antispam_settings(['min_words' => 0]);

    expect($guard->check('comments', [], ''))->toBeNull()
        ->and(Guard::words("  Un  deux\tтри\nquatre. "))->toBe(['Un', 'deux', 'три', 'quatre.']);
});
