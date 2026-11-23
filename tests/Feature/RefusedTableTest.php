<?php

declare(strict_types=1);

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
        $journal->record('comments', Guard::HONEYPOT, "Spam number $i sent by a bot");
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
    $journal->record('comments', Guard::HONEYPOT, 'Cheap pills online at the best price');
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
    gecka_antispam()->journal()->record('comments', Guard::HONEYPOT, 'Cheap pills online at the best price');

    $html = refused_rows();

    expect(row_operations($html))->toBe(['learn_spam', 'learn_ham', 'delete'])
        ->and($html)->toContain('_wpnonce=' . wp_create_nonce('bulk-refused-entries'));
});

it('offers learning the other way, unlearning and deleting under an entry learnt', function (string $learnt, array $operations) {
    antispam_settings(['filter' => true]);
    $journal = gecka_antispam()->journal();
    $journal->record('comments', Guard::HONEYPOT, 'Cheap pills online at the best price');
    $journal->learn([(int) $journal->entries(1, 10)[0]->id], $learnt);

    $_GET['view'] = 'learnt';

    expect(row_operations(refused_rows()))->toBe($operations);
})->with([
    'as spam' => [StatisticalFilter::SPAM, ['learn_ham', 'unlearn', 'delete']],
    'as legitimate' => [StatisticalFilter::HAM, ['learn_spam', 'unlearn', 'delete']],
]);

it('offers deleting only, and no rating, while the statistical filter is off', function () {
    antispam_settings(['filter' => false]);
    gecka_antispam()->journal()->record('comments', Guard::HONEYPOT, 'Cheap pills online at the best price');

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
    $journal->record('comments', Guard::HONEYPOT, 'Cheap pills online at the best price');

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

/**
 * A statistical filter that rates the texts, having learnt one spam and one
 * legitimate text, and the journal holding an entry of each kind: the spam
 * rated near 68 %, the legitimate text near 33 %, the spam threshold at 60 %.
 *
 * @return array{spam: int, ham: int} Ids of the entries.
 */
function rated_entries(): array
{
    antispam_settings(['filter' => true, 'filter_min_spam' => 1, 'filter_min_ham' => 1, 'filter_threshold' => 60]);
    $filter = gecka_antispam()->statisticalFilter();
    $filter->learn('cheap pills online casino bonus viagra', StatisticalFilter::SPAM);
    $filter->learn('merci pour votre article sur la mairie', StatisticalFilter::HAM);

    $journal = gecka_antispam()->journal();
    $journal->record('comments', Guard::HONEYPOT, 'Cheap pills online casino bonus viagra');
    $journal->record('comments', Guard::HONEYPOT, 'Merci pour votre article sur la mairie');

    $ids = [];

    foreach ($journal->entries(1, 10) as $entry) {
        $ids[str_starts_with($entry->text, 'Cheap') ? 'spam' : 'ham'] = (int) $entry->id;
    }

    return $ids;
}

/**
 * The links to the views of the table, as the page prints them.
 *
 * @return string
 */
function refused_views(): string
{
    $table = new RefusedTable(gecka_antispam());
    $table->prepare_items();
    ob_start();
    $table->views();

    return (string) ob_get_clean();
}

/**
 * The ids of the entries a view of the table lists.
 *
 * @param string|null $view The view argument of the address, none for the entries to review.
 *
 * @return int[]
 */
function listed_ids(?string $view = null): array
{
    if ($view === null) {
        unset($_GET['view']);
    } else {
        $_GET['view'] = $view;
    }

    $table = new RefusedTable(gecka_antispam());
    $table->prepare_items();

    return array_map(static fn(object $item): int => (int) $item->id, $table->items);
}

it('lists to review the entries rated below the spam threshold, and as spam those rated from it', function () {
    $ids = rated_entries();

    expect(listed_ids())->toBe([$ids['ham']])
        ->and(listed_ids('spam'))->toBe([$ids['spam']]);
});

it('sorts every entry by the threshold it is given, and by none without one', function () {
    $ids = rated_entries();
    $journal = gecka_antispam()->journal();

    expect(array_keys($journal->triage(101, 5)['review']))->toEqualCanonicalizing([$ids['spam'], $ids['ham']])
        ->and(array_keys($journal->triage(0, 5)['spam']))->toEqualCanonicalizing([$ids['spam'], $ids['ham']])
        ->and($journal->triage(null, 5)['review'])->toBe([$ids['ham'] => null, $ids['spam'] => null]);
});

it('lists as spam, whatever its rating, an entry the filter learns nothing from', function (string $outcome, string $text) {
    rated_entries();
    $journal = gecka_antispam()->journal();
    $journal->record('comments', $outcome, $text);
    $id = (int) $journal->entries(1, 1)[0]->id;

    expect(listed_ids('spam'))->toContain($id)
        ->and(listed_ids())->not->toContain($id)
        ->and($journal->triage(101, 5)['spam'])->toHaveKey($id);
})->with([
    'refused for too few words' => [Guard::SHORT, 'Merci pour votre article sur la mairie de la commune'],
    'refused for a random message' => [Guard::RANDOM_TEXT, 'qASQAhqkpFGqnKkRROl'],
    'shorter than the minimum' => [Guard::HONEYPOT, 'Merci pour tout'],
    'a single random word' => [Guard::HONEYPOT, 'qASQAhqkpFGqnKkRROl'],
]);

it('sorts by its text, as any other, an entry refused for the random name of its sender', function () {
    $ids = rated_entries();
    $journal = gecka_antispam()->journal();
    $journal->record('comments', Guard::RANDOM_NAME, 'Merci pour votre article sur la mairie de la ville');
    $id = (int) $journal->entries(1, 1)[0]->id;

    expect(listed_ids())->toEqualCanonicalizing([$id, $ids['ham']])
        ->and(listed_ids('spam'))->toBe([$ids['spam']]);
});

it('sorts the entries by their reason and their length alone while the filter rates nothing', function () {
    $ids = rated_entries();
    antispam_settings(['filter_min_spam' => 100]);
    gecka_antispam()->journal()->record('comments', Guard::SHORT, 'Merci pour votre article sur la mairie de la commune');

    expect(listed_ids())->toEqualCanonicalizing([$ids['spam'], $ids['ham']])
        ->and(listed_ids('spam'))->toHaveCount(1);
});

it('leaves the entries learnt out of both views of the entries to review', function () {
    $ids = rated_entries();
    gecka_antispam()->journal()->learn([$ids['ham'], $ids['spam']], StatisticalFilter::SPAM);

    expect(listed_ids())->toBe([])
        ->and(listed_ids('spam'))->toBe([])
        ->and(listed_ids('learnt'))->toEqualCanonicalizing([$ids['spam'], $ids['ham']]);
});

it('keeps the Spam view in the address of the row actions', function () {
    rated_entries();

    $_GET['view'] = 'spam';

    expect(refused_rows())->toContain('view=spam');
});

it('offers the Spam view even while the statistical filter is off', function () {
    antispam_settings(['filter' => false]);

    expect(refused_views())->toContain('view=spam')
        ->and(refused_views())->toContain('view=learnt');
});

it('shows under the date the country a text was last sent from', function () {
    $journal = gecka_antispam()->journal();
    $journal->record('comments', Guard::HONEYPOT, 'Cheap pills online at the best price', 'NC');
    $journal->record('comments', Guard::HONEYPOT, 'Bonjour, une question sur vos horaires');

    $table = new RefusedTable(gecka_antispam());
    $table->prepare_items();
    ob_start();
    $table->display_rows();
    $html = (string) ob_get_clean();

    expect(substr_count($html, 'class="gecka-antispam-country"'))->toBe(1)
        ->and($html)->toContain('data-country="NC"')
        ->and($table->showsCountries())->toBeTrue();
});
