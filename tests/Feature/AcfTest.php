<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

use Gecka\WP\Plugin\Antispam\Integrations\Acf;
use Gecka\WP\Plugin\Antispam\Settings;

beforeEach(function () {
    $this->acf = new Acf(gecka_antispam());
});

afterEach(function () {
    $_POST = [];
});

it('adds the fields after the fields of every form', function () {
    $args = $this->acf->render(['id' => 'acf-form', 'html_after_fields' => '<p>after</p>']);

    expect($args['html_after_fields'])->toStartWith('<p>after</p>')
        ->and($args['html_after_fields'])->toContain('name="_gecka_antispam"');
});

it('adds the fields to the marked forms only in the marked mode', function () {
    antispam_settings(['modes' => ['acf' => Settings::MODE_MARKED]]);

    expect($this->acf->render(['id' => 'acf-form'])['html_after_fields'] ?? '')->toBe('')
        ->and($this->acf->render(['id' => 'acf-form', Acf::ARGUMENT => true])['html_after_fields'])->toContain('name="_gecka_antispam"');
});

it('refuses a protected form submitted without the fields', function () {
    expect(fn() => $this->acf->check(['id' => 'acf-form']))->toThrow(Exception::class);
});

it('lets a protected form with the fields through', function () {
    post_form('acf');

    expect($this->acf->check(['id' => 'acf-form']))->toBe(['id' => 'acf-form']);
});

it('leaves alone the forms without the marker in the marked mode', function () {
    antispam_settings(['modes' => ['acf' => Settings::MODE_MARKED]]);

    expect($this->acf->check(['id' => 'acf-form']))->toBe(['id' => 'acf-form']);
});
