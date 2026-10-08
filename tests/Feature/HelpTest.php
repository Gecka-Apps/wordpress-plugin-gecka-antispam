<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

use Gecka\WP\Plugin\Antispam\Admin\Help;

beforeEach(function () {
    require_once ABSPATH . 'wp-admin/includes/class-wp-screen.php';
    require_once ABSPATH . 'wp-admin/includes/screen.php';
});

/**
 * The Help tabs a tab of the settings page gets, by id.
 *
 * @param string $tab
 *
 * @return array<string, array<string, mixed>>
 */
function help_tabs(string $tab): array
{
    $screen = WP_Screen::get('settings_page_gecka-antispam-' . $tab);
    $screen->remove_help_tabs();
    Help::add(gecka_antispam(), $screen, $tab);

    return $screen->get_help_tabs();
}

it('explains what the filter reads on the settings and filter tabs, and the background tables on the filter tab only', function () {
    expect(array_keys(help_tabs('settings')))->toBe([Help::FIELDS, 'gecka-antispam-comments', 'gecka-antispam-other-forms'])
        ->and(array_keys(help_tabs('filter')))->toContain(Help::FIELDS, Help::BACKGROUNDS)
        ->and(help_tabs('stats'))->toBe([])
        ->and(help_tabs('refused'))->toBe([]);
});

it('opens a tab of the Help from a link', function () {
    expect(Help::link(Help::FIELDS))->toContain('data-help-tab="' . Help::FIELDS . '"')
        ->and(Help::link(Help::FIELDS))->toContain('href="#tab-panel-' . Help::FIELDS . '"');
});
