<?php

declare(strict_types=1);

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

use Gecka\WP\Plugin\Antispam\Guard;
use Gecka\WP\Plugin\Antispam\Settings;

beforeEach(function () {
    gecka_antispam()->stats()->reset();
});

afterEach(function () {
    $_POST = [];
    remove_all_filters('gecka_antispam_protect');
});

it('prints the fields of a custom form, signed for its name', function () {
    $html = gecka_antispam_fields('Demande de devis');

    expect($html)->toContain('name="' . Guard::TOKEN_FIELD . '"')
        ->and($html)->toContain('name="' . gecka_antispam()->guard()->honeypotName() . '"')
        ->and(Settings::customSurface('Demande de devis'))->toBe('custom:demandededevis');
});

it('refuses a custom form posted without its fields, and counts it under its name', function () {
    $result = gecka_antispam_check('devis', 'Bonjour, je voudrais un devis.');

    expect($result['refused'])->toBeTrue()
        ->and($result['reason'])->toBe(Guard::TOKEN)
        ->and($result['message'])->not->toBe('')
        ->and(gecka_antispam()->stats()->totals(1))->toBe(['custom:devis' => [Guard::TOKEN => 1]])
        ->and(Settings::surfaceLabel('custom:devis'))->toBe('Custom form: devis');
});

it('lets a custom form with its fields through, and catches a random name', function () {
    post_form('custom:devis');

    expect(gecka_antispam_check('devis', 'Bonjour, je voudrais un devis.', ['Marie Dupont']))->toMatchArray(['refused' => false, 'spam' => false, 'reason' => null, 'message' => ''])
        ->and(gecka_antispam_check('devis', 'Bonjour', ['qASQAhqkpFGqnKkRROl'])['reason'])->toBe(Guard::RANDOM_NAME)
        ->and(gecka_antispam()->stats()->totals(1)['custom:devis'])->toBe([Guard::PASSED => 1, Guard::RANDOM_NAME => 1]);
});

it('refuses a token signed for another form', function () {
    post_form('custom:newsletter');

    expect(gecka_antispam_check('devis')['reason'])->toBe(Guard::TOKEN);
});

it('leaves a custom form alone when the protect filter turns it off', function () {
    add_filter('gecka_antispam_protect', fn(bool $enabled, string $surface) => $surface === 'custom:devis' ? false : $enabled, 10, 2);

    expect(gecka_antispam_fields('devis'))->toBe('')
        ->and(gecka_antispam_check('devis', 'Bonjour')['refused'])->toBeFalse()
        ->and(gecka_antispam()->stats()->totals(1))->toBe([]);
});
