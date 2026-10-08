<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

use Gecka\WP\AdminMenu\Menus;
use Gecka\WP\AdminMenu\Tab;
use Gecka\WP\Plugin\Antispam\Admin\DashboardWidget;
use Gecka\WP\Plugin\Antispam\Admin\RefusedView;
use Gecka\WP\Plugin\Antispam\Admin\SettingsPage;
use Gecka\WP\Plugin\Antispam\Admin\StatsView;
use Gecka\WP\Plugin\Antispam\Backgrounds;
use Gecka\WP\Plugin\Antispam\Guard;
use Gecka\WP\Plugin\Antispam\Settings;
use Gecka\WP\Plugin\Antispam\StatisticalFilter;
use Mantle\Testing\Exceptions\WP_Die_Exception;

$actAs = static fn(string $role) => wp_set_current_user(wp_insert_user(['user_login' => $role . '-' . wp_generate_password(6, false), 'user_pass' => wp_generate_password(), 'role' => $role]));
$tabs = static fn(string $page): array => array_map(static fn(Tab $tab): string => $tab->slug(), $page === SettingsPage::PAGE ? Menus::options($page)->tabs() : Menus::menu(SettingsPage::MENU)->page($page)->tabs());

beforeEach(function () {
    // A check that let a request through would redirect, then exit and end the run.
    add_filter('wp_redirect', static function (string $location): never {
        throw new RuntimeException('Redirected to ' . $location);
    });
    add_filter('pre_http_request', static fn() => new WP_Error('gecka_antispam_offline', 'No request leaves these tests.'));
});

afterEach(function () {
    remove_all_filters('gecka_antispam_capability');
    gecka_antispam()->journal()->clear();
    gecka_antispam()->stats()->reset();
    gecka_antispam()->statisticalFilter()->reset();
    unset($_REQUEST['_wpnonce'], $_REQUEST['action'], $_GET['action'], $_GET['ids']);
    $GLOBALS['current_screen'] = null;
    wp_set_current_user(0);
});

it('leaves the statistics and the refused submissions to moderators, the filter and the settings to administrators', function () {
    expect(SettingsPage::capability('stats'))->toBe('moderate_comments')
        ->and(SettingsPage::capability('refused'))->toBe('moderate_comments')
        ->and(SettingsPage::capability('filter'))->toBe('manage_options')
        ->and(SettingsPage::capability('settings'))->toBe('manage_options')
        ->and(apply_filters('option_page_capability_' . SettingsPage::PAGE, 'manage_options'))->toBe('manage_options');
});

it('lets a filter change the capability of a screen, the filter tab going with the settings', function () {
    add_filter('gecka_antispam_capability', static fn(string $capability, string $screen) => match ($screen) {
        'refused' => 'manage_options',
        'settings' => 'edit_others_posts',
        default => '',
    }, 10, 2);

    expect(SettingsPage::capability('refused'))->toBe('manage_options')
        ->and(SettingsPage::capability('filter'))->toBe('edit_others_posts')
        ->and(apply_filters('option_page_capability_' . SettingsPage::PAGE, 'manage_options'))->toBe('edit_others_posts')
        ->and(SettingsPage::capability('stats'))->toBe('manage_options');
});

it('shows an editor the Antispam tabs of the Security pages, not Settings > Antispam', function () use ($actAs, $tabs) {
    $actAs('editor');

    expect($tabs(SettingsPage::PAGES['stats']))->toContain(SettingsPage::TAB)
        ->and($tabs(SettingsPage::PAGES['refused']))->toContain(SettingsPage::TAB)
        ->and($tabs(SettingsPage::PAGE))->toBe([]);
});

it('shows an author none of the screens', function () use ($actAs, $tabs) {
    $actAs('author');

    expect($tabs(SettingsPage::PAGES['stats']))->not->toContain(SettingsPage::TAB)
        ->and($tabs(SettingsPage::PAGES['refused']))->not->toContain(SettingsPage::TAB)
        ->and($tabs(SettingsPage::PAGE))->toBe([]);
});

it('refuses the routes of the statistical filter to an editor', function () use ($actAs) {
    $actAs('editor');

    foreach (['/learn-existing', '/backgrounds/check', '/backgrounds/next'] as $route) {
        $response = rest_do_request(new WP_REST_Request('POST', '/' . SettingsPage::REST_NAMESPACE . $route));

        expect($response->get_status())->toBe(403);
    }
});

it('hides the reset button of the statistics from an editor', function () use ($actAs) {
    $render = static function (): string {
        ob_start();
        (new StatsView(gecka_antispam()))->render();

        return (string) ob_get_clean();
    };

    $actAs('editor');
    expect($render())->not->toContain('gecka_antispam_reset_stats');

    $actAs('administrator');
    expect($render())->toContain('gecka_antispam_reset_stats');
});

it('links the dashboard widget to the refused submissions only for those who may see them', function () use ($actAs) {
    gecka_antispam()->journal()->record('comments', Guard::HONEYPOT, 'Cheap pills online');
    $render = static function (): string {
        ob_start();
        (new DashboardWidget(gecka_antispam()))->render();

        return (string) ob_get_clean();
    };

    $actAs('editor');
    expect($render())->toContain(SettingsPage::PAGES['refused']);

    add_filter('gecka_antispam_capability', static fn(string $capability, string $screen) => $screen === 'refused' ? 'manage_options' : $capability, 10, 2);
    expect($render())->not->toContain(SettingsPage::PAGES['refused'])
        ->and($render())->toContain(SettingsPage::PAGES['stats']);
});

it('refuses each button to whoever lacks the capability of its screen, and changes nothing', function (string $action, string $role) use ($actAs) {
    gecka_antispam()->stats()->record('comments', Guard::HONEYPOT);
    gecka_antispam()->statisticalFilter()->learn('casino bonus viagra pills cheap', StatisticalFilter::SPAM);
    gecka_antispam()->journal()->record('comments', Guard::HONEYPOT, 'Cheap pills online');
    update_option(Settings::OPTION, array_merge((array) get_option(Settings::OPTION), ['min_delay' => 12]));
    gecka_antispam()->settings()->flush();

    $state = static fn(): array => [
        gecka_antispam()->stats()->totals(1),
        gecka_antispam()->statisticalFilter()->counts(),
        gecka_antispam()->journal()->count(),
        gecka_antispam()->settings()->get('min_delay'),
        get_option(Backgrounds::OPTION),
    ];
    $before = $state();

    $actAs($role);
    $_REQUEST['_wpnonce'] = wp_create_nonce($action);

    expect(static fn() => do_action('admin_post_' . $action))->toThrow(WP_Die_Exception::class, 'Sorry, you are not allowed to do that.')
        ->and($state())->toBe($before);
})->with([
    'reset the statistics' => ['gecka_antispam_reset_stats', 'editor'],
    'reset the filter' => ['gecka_antispam_reset_filter', 'editor'],
    'reset the settings' => ['gecka_antispam_reset_settings', 'editor'],
    'learn from the existing' => ['gecka_antispam_learn_existing', 'editor'],
    'update the background tables' => ['gecka_antispam_update_backgrounds', 'editor'],
    'delete every refused submission' => ['gecka_antispam_clear_refused', 'author'],
]);

it('refuses a button posted without its nonce, administrators included', function () use ($actAs) {
    gecka_antispam()->stats()->record('comments', Guard::HONEYPOT);
    $before = gecka_antispam()->stats()->totals(1);

    $actAs('administrator');
    $_REQUEST['_wpnonce'] = wp_create_nonce('gecka_antispam_reset_settings');

    expect(static fn() => do_action('admin_post_gecka_antispam_reset_stats'))->toThrow(WP_Die_Exception::class, 'The link you followed has expired.')
        ->and(gecka_antispam()->stats()->totals(1))->toBe($before);
});

it('refuses the bulk actions of the Journal to an author, and to a request without its nonce', function (string $role, string $nonce) use ($actAs) {
    require_once ABSPATH . 'wp-admin/includes/class-wp-screen.php';
    require_once ABSPATH . 'wp-admin/includes/screen.php';

    gecka_antispam()->journal()->record('comments', Guard::HONEYPOT, 'Cheap pills online');
    $id = (int) gecka_antispam()->journal()->entries(1, 10)[0]->id;

    $actAs($role);
    set_current_screen('security_page_' . SettingsPage::PAGES['refused']);
    $_REQUEST['action'] = $_GET['action'] = 'delete';
    $_GET['ids'] = [(string) $id];
    $_REQUEST['_wpnonce'] = wp_create_nonce($nonce);

    expect(static fn() => (new RefusedView(gecka_antispam()))->load())->toThrow(WP_Die_Exception::class, $role === 'author' ? 'Sorry, you are not allowed to do that.' : 'The link you followed has expired.')
        ->and(gecka_antispam()->journal()->count())->toBe(1);
})->with([
    'author' => ['author', 'bulk-refused-entries'],
    'editor without the nonce' => ['editor', 'gecka_antispam_clear_refused'],
]);

it('refuses the settings form to an editor', function () use ($actAs) {
    $allowed = static fn(): bool => current_user_can(apply_filters('option_page_capability_' . SettingsPage::PAGE, 'manage_options'));

    $actAs('editor');
    expect($allowed())->toBeFalse();

    $actAs('administrator');
    expect($allowed())->toBeTrue();
});

it('adds the dashboard widget for an editor, not for an author', function () use ($actAs) {
    require_once ABSPATH . 'wp-admin/includes/dashboard.php';
    require_once ABSPATH . 'wp-admin/includes/template.php';
    require_once ABSPATH . 'wp-admin/includes/class-wp-screen.php';
    require_once ABSPATH . 'wp-admin/includes/screen.php';

    $added = static function (): bool {
        $GLOBALS['wp_meta_boxes'] = [];
        set_current_screen('dashboard');
        (new DashboardWidget(gecka_antispam()))->add();

        return isset($GLOBALS['wp_meta_boxes']['dashboard']['normal']['core']['gecka_antispam']);
    };

    $actAs('author');
    expect($added())->toBeFalse();

    $actAs('editor');
    expect($added())->toBeTrue();
});
