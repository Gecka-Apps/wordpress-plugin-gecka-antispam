<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

use Gecka\WP\Plugin\Antispam\Guard;
use Gecka\WP\Plugin\Antispam\Journal;
use Gecka\WP\Plugin\Antispam\StatisticalFilter;

beforeEach(function () {
    gecka_antispam()->journal()->clear();
    gecka_antispam()->statisticalFilter()->reset();
});

it('keeps a refused submission once, counting the same text sent again', function () {
    $journal = gecka_antispam()->journal();

    $journal->record('contact_form_7', Guard::HONEYPOT, 'Cheap pills online');
    $journal->record('comments', Guard::TOO_FAST, 'Cheap pills online');
    $journal->record('comments', Guard::HONEYPOT, '   ');

    $entry = $journal->entries(1, 10)[0];

    expect($journal->count())->toBe(1)
        ->and((int) $entry->hits)->toBe(2)
        ->and($entry->surface)->toBe('comments')
        ->and($entry->outcome)->toBe(Guard::TOO_FAST);
});

it('learns entries as spam or as legitimate, and keeps them in the learnt view', function () {
    $journal = gecka_antispam()->journal();

    $journal->record('comments', Guard::HONEYPOT, 'Cheap pills online');
    $journal->record('comments', Guard::TOO_FAST, 'Bonjour, une question sur vos horaires');
    [$second, $first] = array_map(static fn($entry) => (int) $entry->id, $journal->entries(1, 10));

    expect($journal->learn([$first], StatisticalFilter::SPAM))->toBe(1)
        ->and($journal->learn([$second], StatisticalFilter::HAM))->toBe(1)
        ->and($journal->count())->toBe(0)
        ->and($journal->count(true))->toBe(2)
        ->and($journal->entries(1, 10, true)[1]->learnt)->toBe(StatisticalFilter::SPAM)
        ->and(gecka_antispam()->statisticalFilter()->counts())->toMatchArray(['spam' => 1, 'ham' => 1]);
});

it('moves an entry learnt the wrong way to the other category', function () {
    $journal = gecka_antispam()->journal();
    $journal->record('comments', Guard::HONEYPOT, 'Bonjour, une question sur vos horaires');
    $id = (int) $journal->entries(1, 10)[0]->id;

    $journal->learn([$id], StatisticalFilter::SPAM);

    expect($journal->learn([$id], StatisticalFilter::HAM))->toBe(1)
        ->and($journal->entries(1, 10, true)[0]->learnt)->toBe(StatisticalFilter::HAM)
        ->and(gecka_antispam()->statisticalFilter()->counts())->toMatchArray(['spam' => 0, 'ham' => 1]);
});

it('unlearns an entry back to review, unless the counters rotated twice since', function () {
    $journal = gecka_antispam()->journal();
    $journal->record('comments', Guard::HONEYPOT, 'Cheap pills online');
    $journal->record('comments', Guard::HONEYPOT, 'Casino bonus, free spins');
    [$recent, $old] = array_map(static fn($entry) => (int) $entry->id, $journal->entries(1, 10));

    $journal->learn([$old], StatisticalFilter::SPAM);
    gecka_antispam()->statisticalFilter()->rotate();
    gecka_antispam()->statisticalFilter()->rotate();
    $journal->learn([$recent], StatisticalFilter::SPAM);

    expect($journal->unlearn([$recent, $old]))->toBe([1, 1])
        ->and($journal->count())->toBe(1)
        ->and($journal->entries(1, 10)[0]->id)->toBe((string) $recent)
        ->and($journal->count(true))->toBe(1)
        ->and(gecka_antispam()->statisticalFilter()->counts()['spam'])->toBe(1);
});

it('deletes the entries older than the days kept, and the oldest past the most kept', function () {
    global $wpdb;

    $journal = gecka_antispam()->journal();
    $journal->record('comments', Guard::HONEYPOT, 'old');
    $journal->record('comments', Guard::HONEYPOT, 'recent');
    $wpdb->update(Journal::table(), ['updated' => gmdate('Y-m-d H:i:s', time() - (Journal::DAYS + 1) * DAY_IN_SECONDS)], ['text' => 'old']);

    $journal->purge();

    expect($journal->count())->toBe(1)
        ->and($journal->entries(1, 10)[0]->text)->toBe('recent');
});

it('deletes the entries chosen, or all of them', function () {
    $journal = gecka_antispam()->journal();
    $journal->record('comments', Guard::HONEYPOT, 'one');
    $journal->record('comments', Guard::HONEYPOT, 'two');

    $journal->delete([(int) $journal->entries(1, 10)[0]->id]);
    expect($journal->count())->toBe(1);

    $journal->clear();
    expect($journal->count())->toBe(0);
});

it('sends the entries learnt back to review when the filter forgets everything', function () {
    $journal = gecka_antispam()->journal();
    $journal->record('comments', Guard::HONEYPOT, 'Cheap pills online');
    $id = (int) $journal->entries(1, 10)[0]->id;

    gecka_antispam()->statisticalFilter()->rotate();
    gecka_antispam()->statisticalFilter()->rotate();
    $journal->learn([$id], StatisticalFilter::SPAM);
    gecka_antispam()->resetFilter();

    expect($journal->count())->toBe(1)
        ->and($journal->count(true))->toBe(0)
        ->and($journal->unlearn([$id]))->toBe([0, 0])
        ->and(gecka_antispam()->statisticalFilter()->counts()['spam'])->toBe(0);
});
