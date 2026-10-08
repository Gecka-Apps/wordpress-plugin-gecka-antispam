<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

use Gecka\WP\Plugin\Antispam\Admin\RefusedTable;
use Gecka\WP\Plugin\Antispam\Admin\RefusedView;
use Gecka\WP\Plugin\Antispam\Guard;
use Gecka\WP\Plugin\Antispam\StatisticalFilter;

beforeEach(function () {
    require_once ABSPATH . 'wp-admin/includes/class-wp-list-table.php';
    require_once ABSPATH . 'wp-admin/includes/class-wp-screen.php';
    require_once ABSPATH . 'wp-admin/includes/screen.php';

    gecka_antispam()->journal()->clear();
    wp_set_current_user(wp_insert_user(['user_login' => 'admin-' . wp_generate_password(6, false), 'user_pass' => wp_generate_password(), 'role' => 'administrator']));
    set_current_screen('settings_page_gecka-antispam');
    unset($_GET['view'], $_GET['paged'], $_REQUEST['paged']);
});

afterEach(function () {
    unset($_GET['view'], $_GET['paged'], $_REQUEST['paged'], $_GET['action'], $_REQUEST['action'], $_GET['ids'], $_REQUEST['_wpnonce']);
    $GLOBALS['current_screen'] = null;
    gecka_antispam()->statisticalFilter()->reset();
});

/**
 * The rows of the table, as the page prints them.
 *
 * @return string
 */
function refused_rows(): string
{
    $table = new RefusedTable(gecka_antispam());
    $table->prepare_items();
    ob_start();
    $table->display_rows();

    return (string) ob_get_clean();
}

/**
 * The operations the row actions of the printed rows link to.
 *
 * @param string $html
 *
 * @return string[]
 */
function row_operations(string $html): array
{
    preg_match_all('/[?&;]action=([a-z_]+)/', $html, $matches);

    return array_values(array_unique($matches[1]));
}

it('pages the refused submissions by the number the screen options hold', function () {
    $journal = gecka_antispam()->journal();

    foreach (range(1, 7) as $i) {
        $journal->record('comments', Guard::HONEYPOT, "Spam number $i");
    }

    update_user_meta(get_current_user_id(), RefusedView::PER_PAGE_OPTION, 3);
    $_GET['paged'] = $_REQUEST['paged'] = '3';

    $table = new RefusedTable(gecka_antispam());
    $table->prepare_items();

    expect($table->get_pagination_arg('total_pages'))->toBe(3)
        ->and($table->get_pagination_arg('total_items'))->toBe(7)
        ->and($table->items)->toHaveCount(1);
});

it('lists the entries learnt in their own view, with the column saying how', function () {
    $journal = gecka_antispam()->journal();
    $journal->record('comments', Guard::HONEYPOT, 'Cheap pills online');
    $journal->record('comments', Guard::TOO_FAST, 'Bonjour, une question sur vos horaires');
    $journal->learn([(int) $journal->entries(1, 10)[0]->id], StatisticalFilter::HAM);

    $_GET['view'] = 'learnt';
    $table = new RefusedTable(gecka_antispam());
    $table->prepare_items();

    expect($table->items)->toHaveCount(1)
        ->and(array_keys($table->get_columns()))->toContain('learnt');

    unset($_GET['view']);
    $pending = new RefusedTable(gecka_antispam());
    $pending->prepare_items();

    expect($pending->items)->toHaveCount(1)
        ->and(array_keys($pending->get_columns()))->not->toContain('learnt');
});

it('folds a long text in the compact view and shows it whole in the extended view', function () {
    $text = str_repeat('Lorem ipsum dolor sit amet. ', 20);
    gecka_antispam()->journal()->record('comments', Guard::HONEYPOT, $text);

    $render = function (): string {
        $table = new RefusedTable(gecka_antispam());
        $table->prepare_items();
        ob_start();
        $table->display_rows();

        return (string) ob_get_clean();
    };

    // set_user_setting() needs the headers unsent; the setting is stored as it would leave it.
    $mode = static function (string $mode): void {
        unset($GLOBALS['_updated_user_settings']);
        update_user_option(get_current_user_id(), 'user-settings', RefusedView::MODE_SETTING . '=' . $mode, false);
    };

    $mode('list');
    expect($render())->toContain('<details>');

    $mode('excerpt');
    expect($render())->not->toContain('<details>');
});

it('offers learning either way and deleting under the text of an entry to review', function () {
    antispam_settings(['filter' => true]);
    gecka_antispam()->journal()->record('comments', Guard::HONEYPOT, 'Cheap pills online');

    $html = refused_rows();

    expect(row_operations($html))->toBe(['learn_spam', 'learn_ham', 'delete'])
        ->and($html)->toContain('_wpnonce=' . wp_create_nonce('bulk-refused-entries'));
});

it('offers learning the other way, unlearning and deleting under an entry learnt', function (string $learnt, array $operations) {
    antispam_settings(['filter' => true]);
    $journal = gecka_antispam()->journal();
    $journal->record('comments', Guard::HONEYPOT, 'Cheap pills online');
    $journal->learn([(int) $journal->entries(1, 10)[0]->id], $learnt);

    $_GET['view'] = 'learnt';

    expect(row_operations(refused_rows()))->toBe($operations);
})->with([
    'as spam' => [StatisticalFilter::SPAM, ['learn_ham', 'unlearn', 'delete']],
    'as legitimate' => [StatisticalFilter::HAM, ['learn_spam', 'unlearn', 'delete']],
]);

it('offers deleting only, and no rating, while the statistical filter is off', function () {
    antispam_settings(['filter' => false]);
    gecka_antispam()->journal()->record('comments', Guard::HONEYPOT, 'Cheap pills online');

    expect(row_operations(refused_rows()))->toBe(['delete'])
        ->and(array_keys((new RefusedTable(gecka_antispam()))->get_columns()))->not->toContain('score');
});

it('rates each text once the statistical filter has learnt enough, and shows a dash before', function () {
    antispam_settings(['filter' => true, 'filter_min_spam' => 1, 'filter_min_ham' => 1]);
    gecka_antispam()->journal()->record('comments', Guard::HONEYPOT, 'Cheap pills online casino bonus');

    expect(refused_rows())->toContain("column-score' data-colname=\"Spam rating\">&mdash;</td>");

    gecka_antispam()->statisticalFilter()->learn('cheap pills online casino bonus viagra', StatisticalFilter::SPAM);
    gecka_antispam()->statisticalFilter()->learn('merci pour votre article sur la mairie', StatisticalFilter::HAM);

    expect(refused_rows())->toMatch("/column-score' data-colname=\"Spam rating\">\\d+(\\.\\d)? % spam<\\/td>/");
});

it('learns the entry a row action links to, as the bulk action does', function () {
    antispam_settings(['filter' => true]);
    $journal = gecka_antispam()->journal();
    $journal->record('comments', Guard::HONEYPOT, 'Cheap pills online');

    preg_match('/href="([^"]+action=learn_spam[^"]*)"/', refused_rows(), $link);
    parse_str((string) parse_url(html_entity_decode($link[1]), PHP_URL_QUERY), $query);
    $_GET = array_merge($_GET, $query);
    $_REQUEST = array_merge($_REQUEST, $query);

    add_filter('wp_redirect', static function (string $location): never {
        throw new RuntimeException($location);
    });

    expect(static fn() => (new RefusedView(gecka_antispam()))->load())->toThrow(RuntimeException::class, 'done=1&op=learn_spam')
        ->and($journal->count())->toBe(0)
        ->and($journal->count(true))->toBe(1)
        ->and(gecka_antispam()->statisticalFilter()->counts()['spam'])->toBe(1);
});
