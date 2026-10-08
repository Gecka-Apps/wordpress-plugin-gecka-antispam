<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

use Gecka\SpamFilter\Model\Background;
use Gecka\WP\Plugin\Antispam\Admin\SiteHealth;
use Gecka\WP\Plugin\Antispam\Schema;
use Gecka\WP\Plugin\Antispam\Setup;

beforeEach(function () {
    gecka_antispam()->statisticalFilter()->reset();
    $this->health = new SiteHealth(gecka_antispam());
    $this->directory = get_temp_dir() . 'gecka-antispam-health-' . wp_generate_password(6, false);
    wp_mkdir_p($this->directory);
    add_filter('gecka_antispam_background_directory', fn() => $this->directory);
});

afterEach(function () {
    remove_all_filters('gecka_antispam_background_directory');
    array_map('unlink', glob($this->directory . '/*') ?: []);
    rmdir($this->directory);
    wp_clear_scheduled_hook(Setup::PURGE_EVENT);
});

it('tests the filter only while it is switched on, and the daily task always', function () {
    expect(array_keys($this->health->tests(['direct' => []])['direct']))->toBe(['gecka_antispam_schedule', 'gecka_antispam_filter', 'gecka_antispam_background', 'gecka_antispam_snapshot']);

    antispam_settings(['filter' => false]);

    expect(array_keys($this->health->tests(['direct' => []])['direct']))->toBe(['gecka_antispam_schedule']);
});

it('recommends background tables when there is none', function () {
    expect($this->health->testBackground()['status'])->toBe('recommended');
});

it('is content with a background table', function () {
    Background::write(french_table(), $this->directory . '/fr.bin');
    $result = $this->health->testBackground();

    expect($result['status'])->toBe('good')
        ->and($result['description'])->toContain('fr');
});

it('names the background tables left out', function () {
    Background::write(french_table(), $this->directory . '/fr.bin');
    file_put_contents($this->directory . '/xx.bin', (string) gzcompress(str_repeat('not a table ', 300)));
    $result = $this->health->testBackground();

    expect($result['status'])->toBe('recommended')
        ->and($result['description'])->toContain('xx.bin')
        ->and($result['actions'])->toContain('tab=filter');
});

it('says when the filter cannot work', function () {
    expect($this->health->testFilter()['status'])->toBe('good');

    global $wpdb;

    Schema::storage()->drop();
    $suppressed = $wpdb->suppress_errors();

    expect($this->health->testFilter()['status'])->toBe('critical');

    $wpdb->suppress_errors($suppressed);

    Schema::storage()->install(\Gecka\WP\Plugin\Antispam\StatisticalFilter::BITS);
});

it('tells whether the daily task is scheduled and runs', function () {
    wp_clear_scheduled_hook(Setup::PURGE_EVENT);
    expect($this->health->testSchedule()['status'])->toBe('recommended');

    wp_schedule_event(time() - 3 * DAY_IN_SECONDS, 'daily', Setup::PURGE_EVENT);
    expect($this->health->testSchedule()['status'])->toBe('recommended')
        ->and($this->health->testSchedule()['actions'])->toBe('');

    wp_clear_scheduled_hook(Setup::PURGE_EVENT);
    wp_schedule_event(time() + HOUR_IN_SECONDS, 'daily', Setup::PURGE_EVENT);
    expect($this->health->testSchedule()['status'])->toBe('good');
});

it('describes the plugin in the Info tab, without anything of the senders', function () {
    gecka_antispam()->journal()->record('comments', 'honeypot', 'Cheap pills online');
    $info = $this->health->information([])['gecka-antispam'];

    expect(array_keys($info['fields']))->toBe(['version', 'forms', 'filter', 'thresholds', 'minimums', 'learnt', 'rotation', 'background', 'left_out', 'snapshot', 'refused'])
        ->and($info['fields']['refused']['debug'])->toBe('pending 1, learnt 0')
        ->and(json_encode($info))->not->toContain('Cheap pills');

    gecka_antispam()->journal()->clear();
});
