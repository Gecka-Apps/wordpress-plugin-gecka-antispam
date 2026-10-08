<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

use Gecka\WP\Plugin\Antispam\Admin\FilterView;

beforeEach(function () {
    require_once ABSPATH . 'wp-admin/includes/template.php';
    require_once ABSPATH . 'wp-admin/includes/plugin.php';
});

/**
 * The block of the settings that serve the filter only, as the tab prints it.
 *
 * @return string
 */
function filter_settings_block(): string
{
    ob_start();
    (new FilterView(gecka_antispam()))->render();
    $html = (string) ob_get_clean();

    preg_match('/<tbody data-gecka-antispam-shown-by="gecka-antispam-filter"[^>]*>.*?<\/tbody>/s', $html, $block);

    return $block[0] ?? '';
}

it('shows the settings of the filter while it is switched on', function () {
    antispam_settings(['filter' => true]);

    $block = filter_settings_block();

    expect($block)->toStartWith('<tbody data-gecka-antispam-shown-by="gecka-antispam-filter">')
        ->and($block)->toContain('name="gecka_antispam_settings[filter_reject]"');
});

it('prints the settings of the filter hidden while it is switched off, still posted so they keep their values', function () {
    antispam_settings(['filter' => false, 'filter_reject' => 97]);

    $block = filter_settings_block();

    expect($block)->toStartWith('<tbody data-gecka-antispam-shown-by="gecka-antispam-filter" hidden>')
        ->and($block)->toContain('name="gecka_antispam_settings[filter_reject]" value="97"')
        ->and($block)->toContain('name="gecka_antispam_settings[learn_approved]"');
});

it('names the switch the block follows', function () {
    ob_start();
    (new FilterView(gecka_antispam()))->render();

    expect((string) ob_get_clean())->toContain('id="gecka-antispam-filter" name="gecka_antispam_settings[filter]"');
});
