<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

use Gecka\SpamFilter\Label;
use Gecka\SpamFilter\Model\Background;
use Gecka\SpamFilter\Model\CountTable;
use Gecka\SpamFilter\Testing\StorageContract;
use Gecka\WP\Plugin\Antispam\Plugin;
use Gecka\WP\Plugin\Antispam\Schema;
use Gecka\WP\Plugin\Antispam\StatisticalFilter;
use Gecka\WP\Plugin\Antispam\StatisticalFilter\WpdbStorage;

beforeEach(function () {
    gecka_antispam()->statisticalFilter()->reset();
});

afterEach(function () {
    remove_all_filters('gecka_antispam_background_directory');

    if (isset($this->background)) {
        array_map('unlink', glob($this->background . '/*') ?: []);
        rmdir($this->background);
    }
});

/**
 * A directory of background tables the filter reads, removed after the test.
 *
 * @param array<string, CountTable|string> $files File name => table, or raw bytes.
 *
 * @return string
 */
function background_directory(array $files): string
{
    $directory = get_temp_dir() . 'gecka-antispam-background-' . wp_generate_password(6, false);
    wp_mkdir_p($directory);
    test()->background = $directory;

    foreach ($files as $name => $content) {
        $content instanceof CountTable ? Background::write($content, "$directory/$name") : file_put_contents("$directory/$name", $content);
    }

    add_filter('gecka_antispam_background_directory', fn() => $directory);

    return $directory;
}

/**
 * Teaches the filter a few spams and a few legitimate messages.
 *
 * @return void
 */
function teach_filter(int $times = 5): void
{
    $statisticalFilter = gecka_antispam()->statisticalFilter();

    for ($i = 0; $i < $times; $i++) {
        $statisticalFilter->learn("Cheap viagra casino bonus, click https://pills.example/buy now $i", StatisticalFilter::SPAM);
        $statisticalFilter->learn("Bonjour, je souhaite un devis pour la refonte du site de notre association $i", StatisticalFilter::HAM);
    }
}

it('rates nothing before it learnt anything', function () {
    expect(gecka_antispam()->statisticalFilter()->classify('Bonjour, une question sur vos tarifs'))->toBe(0.5)
        ->and(gecka_antispam()->statisticalFilter()->ready(1, 1))->toBeFalse();
});

it('tells spam from ham once trained', function () {
    teach_filter();

    expect(gecka_antispam()->statisticalFilter()->classify('viagra casino bonus pills'))->toBeGreaterThan(0.6)
        ->and(gecka_antispam()->statisticalFilter()->classify('un devis pour le site de notre association'))->toBeLessThan(0.4)
        ->and(gecka_antispam()->statisticalFilter()->counts())->toMatchArray(['ham' => 5, 'spam' => 5])
        ->and(gecka_antispam()->statisticalFilter()->ready(5, 5))->toBeTrue()
        ->and(gecka_antispam()->statisticalFilter()->ready(6, 5))->toBeFalse()
        ->and(gecka_antispam()->statisticalFilter()->ready(5, 6))->toBeFalse();
});

it('starts rating after 20 spam texts and 10 legitimate ones by default', function () {
    teach_filter(10);

    expect(gecka_antispam()->filterReady())->toBeFalse();

    for ($i = 0; $i < 10; $i++) {
        gecka_antispam()->statisticalFilter()->learn("Bitcoin mining tools, free download https://btc.example/get $i", StatisticalFilter::SPAM);
    }

    expect(gecka_antispam()->statisticalFilter()->counts())->toMatchArray(['spam' => 20, 'ham' => 10])
        ->and(gecka_antispam()->filterReady())->toBeTrue();
});

it('counts the features of the texts learnt, not their words', function () {
    global $wpdb;

    gecka_antispam()->statisticalFilter()->learn('Viagra casino bonus', StatisticalFilter::SPAM);
    $storage = Schema::storage();

    expect(gecka_antispam()->statisticalFilter()->counts()['features'])->toBeGreaterThan(3)
        ->and($wpdb->get_col($wpdb->prepare('SELECT feature FROM %i', $storage->countsTable())))->each->toBeNumeric();
});

it('moves a text from one category to the other', function () {
    $statisticalFilter = gecka_antispam()->statisticalFilter();
    $statisticalFilter->learn('hello world message', StatisticalFilter::SPAM);

    $statisticalFilter->relearn('hello world message', StatisticalFilter::SPAM, 0, StatisticalFilter::HAM);

    expect($statisticalFilter->counts())->toMatchArray(['ham' => 1, 'spam' => 0]);
});

it('forgets nothing of a generation ahead of the storage, and learns the new category', function () {
    $statisticalFilter = gecka_antispam()->statisticalFilter();
    $statisticalFilter->learn('hello world message', StatisticalFilter::SPAM);

    expect($statisticalFilter->unlearn('hello world message', StatisticalFilter::SPAM, 2))->toBeFalse()
        ->and($statisticalFilter->relearn('hello world message', StatisticalFilter::SPAM, 2, StatisticalFilter::HAM))->toBe(0)
        ->and($statisticalFilter->counts())->toMatchArray(['ham' => 1, 'spam' => 1])
        ->and($statisticalFilter->error())->toBeNull();
});

it('reads the counters again when a text is learnt while they are read', function () {
    $statisticalFilter = gecka_antispam()->statisticalFilter();
    $statisticalFilter->learn('cheap pills online', StatisticalFilter::SPAM);
    $learnt = false;

    add_filter(
        'query',
        function (string $query) use (&$learnt, $statisticalFilter): string {
            if (! $learnt && str_contains($query, 'ORDER BY feature')) {
                $learnt = true;
                $statisticalFilter->learn('casino bonus free spins', StatisticalFilter::SPAM);
            }

            return $query;
        },
    );

    $counts = Schema::storage()->load();
    remove_all_filters('query');

    expect($learnt)->toBeTrue()
        ->and($counts->texts(Label::Spam))->toBe(2)
        ->and($counts->total(Label::Spam))->toBe(Schema::storage()->load()->total(Label::Spam));
});

it('learns nothing from an empty text', function () {
    expect(gecka_antispam()->statisticalFilter()->learn('   ', StatisticalFilter::SPAM))->toBeNull()
        ->and(gecka_antispam()->statisticalFilter()->counts()['spam'])->toBe(0);
});

it('forgets everything when reset', function () {
    teach_filter();

    gecka_antispam()->statisticalFilter()->reset();

    expect(gecka_antispam()->statisticalFilter()->counts())->toBe(['ham' => 0, 'spam' => 0, 'features' => 0])
        ->and(gecka_antispam()->statisticalFilter()->classify('viagra casino bonus pills'))->toBe(0.5);
});

it('rates with what another request learnt', function () {
    teach_filter();
    $before = gecka_antispam()->statisticalFilter()->classify('viagra casino bonus pills');

    // A new instance reads the snapshot written by the first one, then the
    // tables once a text learnt elsewhere moved their version.
    $other = new StatisticalFilter();
    $other->learn('viagra casino bonus pills', StatisticalFilter::SPAM);

    expect((new StatisticalFilter())->classify('viagra casino bonus pills'))->toBeGreaterThan($before);
});

it('reads the background tables of the directory', function () {
    background_directory(['fr.bin' => french_table()]);

    $statisticalFilter = new StatisticalFilter();
    teach_filter();

    expect($statisticalFilter->languages())->toBe(['fr'])
        ->and($statisticalFilter->backgroundProblems())->toBe([])
        ->and($statisticalFilter->classify('viagra casino bonus pills'))->toBeGreaterThan(0.5)
        ->and($statisticalFilter->error())->toBeNull();
});

it('leaves out the files that are not background tables, and reads on with the others', function () {
    background_directory(['fr.bin' => french_table(), 'xx.bin' => (string) gzcompress(str_repeat('not a table ', 300)), 'notes.bin' => french_table()]);

    $statisticalFilter = new StatisticalFilter();
    teach_filter();

    expect($statisticalFilter->languages())->toBe(['fr'])
        ->and($statisticalFilter->backgroundProblems())->toHaveCount(2)
        ->and($statisticalFilter->classify('viagra casino bonus pills'))->toBeGreaterThan(0.5)
        ->and($statisticalFilter->learn('viagra casino bonus pills', StatisticalFilter::SPAM))->toBe(0);

    unlink(test()->background . '/xx.bin');
    unlink(test()->background . '/notes.bin');

    expect((new StatisticalFilter())->backgroundProblems())->toBe([]);
});

it('refuses a background table holding more counters than a class of the site', function () {
    background_directory(['en.bin' => new CountTable(1 << (StatisticalFilter::BITS + 1))]);

    $statisticalFilter = new StatisticalFilter();

    expect($statisticalFilter->languages())->toBe([])
        ->and($statisticalFilter->backgroundProblems())->toHaveCount(1)
        ->and($statisticalFilter->backgroundProblems()[0])->toStartWith('en.bin: ');
});

it('reads five background tables at most, the language of the site first', function () {
    background_directory(array_fill_keys(['aa.bin', 'bb.bin', 'cc.bin', 'dd.bin', 'ee.bin', 'en.bin'], french_table()));

    $statisticalFilter = new StatisticalFilter();

    expect($statisticalFilter->languages())->toBe(['en', 'aa', 'bb', 'cc', 'dd'])
        ->and($statisticalFilter->backgroundProblems())->toHaveCount(1)
        ->and($statisticalFilter->backgroundProblems()[0])->toStartWith('ee.bin: ');
});

it('keeps its counters as the library expects', function () {
    global $wpdb;

    $made = [];

    try {
        StorageContract::verify(
            function (int $bits) use (&$made, $wpdb): WpdbStorage {
                $storage = new WpdbStorage($wpdb->prefix . 'gecka_antispam_contract' . count($made) . '_');
                $storage->drop();
                $storage->install($bits);

                return $made[] = $storage;
            },
        );
    } finally {
        array_map(static fn(WpdbStorage $storage) => $storage->drop(), $made);
    }

    expect($made)->not->toBeEmpty();
});

it('starts the clock on the first daily run, and rotates once the period is over', function () {
    teach_filter();
    $plugin = gecka_antispam();

    expect($plugin->rotateFilter())->toBeFalse()
        ->and(Plugin::rotated())->toBeGreaterThan(time() - 5);

    expect($plugin->rotateFilter())->toBeFalse()
        ->and($plugin->statisticalFilter()->tally()->generation)->toBe(0);

    update_option(Plugin::ROTATED_OPTION, time() - 7 * MONTH_IN_SECONDS, false);

    expect($plugin->rotateFilter())->toBeTrue()
        ->and($plugin->statisticalFilter()->tally()->generation)->toBe(1)
        ->and($plugin->statisticalFilter()->tally()->recent(Label::Spam))->toBe(0)
        ->and($plugin->statisticalFilter()->counts())->toMatchArray(['spam' => 5, 'ham' => 5])
        ->and(Plugin::rotated())->toBeGreaterThan(time() - 5);
});

it('keeps rating after rotations, the minimum counting every text learnt', function () {
    antispam_settings(['filter_min_spam' => 5, 'filter_min_ham' => 5]);
    teach_filter();

    gecka_antispam()->statisticalFilter()->rotate();
    gecka_antispam()->statisticalFilter()->rotate();
    gecka_antispam()->statisticalFilter()->rotate();

    expect(gecka_antispam()->filterReady())->toBeTrue()
        ->and(gecka_antispam()->statisticalFilter()->classify('viagra casino bonus pills'))->toBeGreaterThan(0.5);
});

it('moves a text to the other category exactly up to one rotation after it was learnt', function () {
    global $wpdb;

    $statisticalFilter = gecka_antispam()->statisticalFilter();
    $storage = Schema::storage();
    $generation = $statisticalFilter->learn('hello world message', StatisticalFilter::SPAM);

    $statisticalFilter->rotate();

    expect($statisticalFilter->relearn('hello world message', StatisticalFilter::SPAM, $generation, StatisticalFilter::HAM))->toBe(1)
        ->and($statisticalFilter->counts())->toMatchArray(['ham' => 1, 'spam' => 0])
        ->and((int) $wpdb->get_var($wpdb->prepare('SELECT SUM(count_spam + archive_spam) FROM %i', $storage->countsTable())))->toBe(0);
});

it('leaves a text learnt two rotations ago where it is, and learns the right category', function () {
    $statisticalFilter = gecka_antispam()->statisticalFilter();
    $generation = $statisticalFilter->learn('hello world message', StatisticalFilter::SPAM);

    $statisticalFilter->rotate();
    $statisticalFilter->rotate();

    expect($statisticalFilter->unlearn('hello world message', StatisticalFilter::SPAM, (int) $generation))->toBeFalse()
        ->and($statisticalFilter->relearn('hello world message', StatisticalFilter::SPAM, $generation, StatisticalFilter::HAM))->toBe(2)
        ->and($statisticalFilter->counts())->toMatchArray(['ham' => 1, 'spam' => 1]);
});

it('dates the archive by the last rotation once there was one, by the period before', function () {
    $plugin = gecka_antispam();
    $period = $plugin->rotationPeriod();
    update_option(Plugin::ROTATED_OPTION, time() - DAY_IN_SECONDS);

    expect($plugin->archives(time() - 2 * DAY_IN_SECONDS))->toBeFalse()
        ->and($plugin->archives(time() - $period - DAY_IN_SECONDS))->toBeTrue();

    $plugin->statisticalFilter()->rotate();
    update_option(Plugin::ROTATED_OPTION, time() - DAY_IN_SECONDS);

    expect($plugin->archives(time() - 2 * DAY_IN_SECONDS))->toBeTrue()
        ->and($plugin->archives(time() - HOUR_IN_SECONDS))->toBeFalse()
        ->and($plugin->archives(time() - 2 * $period))->toBeNull();

    delete_option(Plugin::ROTATED_OPTION);
});

it('learns an older text into the archive, one generation back', function () {
    $statisticalFilter = gecka_antispam()->statisticalFilter();

    expect($statisticalFilter->learn('hello world message', StatisticalFilter::SPAM, true))->toBe(-1)
        ->and($statisticalFilter->tally()->recent(Label::Spam))->toBe(0)
        ->and($statisticalFilter->unlearn('hello world message', StatisticalFilter::SPAM, -1))->toBeTrue()
        ->and($statisticalFilter->counts()['spam'])->toBe(0);
});
