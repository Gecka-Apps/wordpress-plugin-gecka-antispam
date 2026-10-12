<?php

declare(strict_types=1);

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

use Gecka\WP\Plugin\Antispam\Plugin;
use Gecka\WP\Plugin\Antispam\Settings;
use Gecka\WP\Plugin\Antispam\Setup;

it('protects every form by default', function () {
    foreach (Settings::surfaces() as $surface) {
        expect(gecka_antispam()->settings()->enabled($surface))->toBeTrue();
    }
});

it('draws a honeypot name once per site', function () {
    $name = gecka_antispam()->settings()->get('honeypot_name');
    gecka_antispam()->settings()->flush();

    expect(Settings::isValidFieldName($name))->toBeTrue()
        ->and(gecka_antispam()->settings()->get('honeypot_name'))->toBe($name);
});

it('keeps the settings within bounds', function () {
    $settings = gecka_antispam()->settings()->sanitize(
        [
            'form' => 'general',
            'surfaces' => ['comments' => '1'],
            'min_delay' => 500,
            'min_words' => -3,
            'filter_threshold' => 10,
            'filter_review' => 80,
            'filter_reject' => 40,
        ],
    );

    expect($settings['surfaces']['comments'])->toBeTrue()
        ->and($settings['surfaces']['login'])->toBeFalse()
        ->and($settings['min_delay'])->toBe(60)
        ->and($settings['min_words'])->toBe(0)
        ->and($settings['filter_threshold'])->toBe(51)
        ->and($settings['filter_review'])->toBe(51)
        ->and($settings['filter_reject'])->toBe(51)
        ->and($settings)->not->toHaveKey('caught_comments');
});

it('refuses a honeypot name a form already uses', function (string $name, bool $valid) {
    expect(Settings::isValidFieldName($name))->toBe($valid);
})->with([
    ['homepage_x7k2', true],
    ['url', false],
    ['action', false],
    ['redirect_to', false],
    ['email', false],
    ['wp_secret', false],
    ['1abc', false],
    ['Has-Caps', false],
]);

it('lets a filter switch a form off', function () {
    add_filter('gecka_antispam_protect', fn($enabled, $surface) => $surface !== 'login', 10, 2);

    expect(gecka_antispam()->settings()->enabled('login'))->toBeFalse()
        ->and(gecka_antispam()->settings()->enabled('comments'))->toBeTrue();
});

it('draws the honeypot name once the settings page has registered its sanitizer', function () {
    (new \Gecka\WP\Plugin\Antispam\Admin\SettingsPage(gecka_antispam()))->registerSetting();
    update_option(Settings::OPTION, ['min_delay' => 8, 'surfaces' => ['login' => false]]);
    gecka_antispam()->settings()->flush();

    $name = gecka_antispam()->settings()->get('honeypot_name');
    $saved = get_option(Settings::OPTION);

    expect(Settings::isValidFieldName($name))->toBeTrue()
        ->and($saved['honeypot_name'])->toBe($name)
        ->and($saved['min_delay'])->toBe(8)
        ->and($saved['surfaces']['login'])->toBeFalse()
        ->and($saved['surfaces']['comments'])->toBeTrue();

    unregister_setting(\Gecka\WP\Plugin\Antispam\Admin\SettingsPage::PAGE, Settings::OPTION);
});

it('unticks the boxes the settings form leaves out, and only those', function () {
    $settings = gecka_antispam()->settings();

    expect($settings->sanitize(['form' => 'general', 'surfaces' => ['comments' => '1']])['surfaces']['login'])->toBeFalse()
        ->and($settings->sanitize(['random_names' => false])['surfaces']['login'])->toBeTrue()
        ->and($settings->sanitize(['random_names' => false])['learn_approved'])->toBeTrue();
});

it('leaves the boxes of the other tab alone', function () {
    $settings = gecka_antispam()->settings();

    $general = $settings->sanitize(['form' => 'general', 'surfaces' => ['comments' => '1']]);
    $filter = $settings->sanitize(['form' => 'filter', 'filter_reject' => 90]);

    expect($general['filter'])->toBeTrue()
        ->and($general['learn_approved'])->toBeTrue()
        ->and($general['random_names'])->toBeFalse()
        ->and($filter['filter'])->toBeFalse()
        ->and($filter['learn_approved'])->toBeFalse()
        ->and($filter['filter_reject'])->toBe(90)
        ->and($filter['surfaces']['login'])->toBeTrue()
        ->and($filter['random_names'])->toBeTrue();
});

it('protects every form of the plugins with a marker by default', function () {
    $settings = gecka_antispam()->settings();

    foreach (Settings::MARKED_SURFACES as $surface) {
        expect($settings->mode($surface))->toBe(Settings::MODE_ALL)
            ->and($settings->protects($surface, false))->toBeTrue();
    }
});

it('protects only the marked forms in the marked mode, and none once off', function () {
    antispam_settings(['modes' => ['contact_form_7' => Settings::MODE_MARKED]]);

    expect(gecka_antispam()->settings()->protects('contact_form_7', false))->toBeFalse()
        ->and(gecka_antispam()->settings()->protects('contact_form_7', true))->toBeTrue();

    antispam_settings(['surfaces' => ['contact_form_7' => false]]);

    expect(gecka_antispam()->settings()->protects('contact_form_7', true))->toBeFalse();
});

it('reads the off, every form and marked choices of the settings form', function () {
    $saved = gecka_antispam()->settings()->sanitize(
        [
            'form' => 'general',
            'modes' => ['contact_form_7' => 'off', 'gravity_forms' => Settings::MODE_MARKED, 'acf' => Settings::MODE_ALL],
        ],
    );

    expect($saved['surfaces']['contact_form_7'])->toBeFalse()
        ->and($saved['modes']['contact_form_7'])->toBe(Settings::MODE_ALL)
        ->and($saved['surfaces']['gravity_forms'])->toBeTrue()
        ->and($saved['modes']['gravity_forms'])->toBe(Settings::MODE_MARKED)
        ->and($saved['surfaces']['acf'])->toBeTrue()
        ->and($saved['modes']['acf'])->toBe(Settings::MODE_ALL);
});

it('puts every setting back to its default, but the name of the honeypot', function () {
    $settings = gecka_antispam()->settings();
    $name = $settings->get('honeypot_name');
    update_option(Settings::OPTION, array_merge((array) get_option(Settings::OPTION), ['min_delay' => 12, 'filter_reject' => 99]));
    $settings->flush();

    $settings->reset();

    expect($settings->get('min_delay'))->toBe($settings->defaults()['min_delay'])
        ->and($settings->get('filter_reject'))->toBe(95)
        ->and($settings->get('honeypot_name'))->toBe($name);
});

it('rotates the counters every six months by default, within one month and five years', function () {
    $settings = gecka_antispam()->settings();

    expect($settings->defaults()['filter_rotation'])->toBe(6)
        ->and($settings->sanitize(['form' => 'filter', 'filter_rotation' => 0])['filter_rotation'])->toBe(1)
        ->and($settings->sanitize(['form' => 'filter', 'filter_rotation' => 99])['filter_rotation'])->toBe(60)
        ->and(gecka_antispam()->rotationPeriod())->toBe(6 * MONTH_IN_SECONDS);
});

it('lists the forms once as identifiers and once with their labels, in the same order', function () {
    expect(Settings::surfaces())->toBe(array_merge(...array_values(array_map(static fn(array $group): array => array_keys($group['surfaces']), Settings::groups()))));
});

it('draws the honeypot name when the plugin is set up', function () {
    delete_option(Settings::OPTION);
    gecka_antispam()->settings()->flush();

    Setup::install(Plugin::VERSION);

    expect(get_option(Settings::OPTION)['honeypot_name'] ?? '')->toMatch('/^[a-z_]+_[a-z0-9]{4}$/');
});
