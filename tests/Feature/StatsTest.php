<?php

declare(strict_types=1);

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

use Gecka\WP\Plugin\Antispam\Admin\StatsView;
use Gecka\WP\Plugin\Antispam\Guard;
use Gecka\WP\Plugin\Antispam\Schema;

beforeEach(function () {
    gecka_antispam()->stats()->reset();
});

it('counts the submissions by form and outcome', function () {
    $stats = gecka_antispam()->stats();

    $stats->record('comments', Guard::PASSED);
    $stats->record('comments', Guard::HONEYPOT);
    $stats->record('comments', Guard::HONEYPOT);
    $stats->record('login', Guard::TOKEN);

    expect($stats->totals(7))->toBe(
        [
            'comments' => [Guard::HONEYPOT => 2, Guard::PASSED => 1],
            'login' => [Guard::TOKEN => 1],
        ],
    )->and(StatsView::summary($stats->totals(7)))->toMatchArray(['checked' => 4, 'passed' => 1, 'caught' => 3]);
});

it('counts the submissions held for review apart, and as gone through day by day', function () {
    $stats = gecka_antispam()->stats();

    $stats->record('contact_form_7', Guard::PASSED);
    $stats->record('contact_form_7', Guard::REVIEW);
    $stats->record('contact_form_7', Guard::FILTER_SPAM);

    $daily = $stats->daily(7);

    expect(StatsView::summary($stats->totals(7)))->toMatchArray(['checked' => 3, 'passed' => 1, 'review' => 1, 'caught' => 1, 'outcomes' => [Guard::FILTER_SPAM => 1]])
        ->and(end($daily))->toBe(['passed' => 2, 'caught' => 1]);
});

it('lists every day of the period, the days with no submission included', function () {
    gecka_antispam()->stats()->record('comments', Guard::PASSED);
    gecka_antispam()->stats()->record('comments', Guard::TOO_FAST);

    $daily = gecka_antispam()->stats()->daily(7);

    expect($daily)->toHaveCount(7)
        ->and(end($daily))->toBe(['passed' => 1, 'caught' => 1])
        ->and(reset($daily))->toBe(['passed' => 0, 'caught' => 0]);
});

it('drops the counters older than the days kept', function () {
    global $wpdb;

    $wpdb->insert(Schema::stats(), ['day' => '2001-01-01', 'surface' => 'comments', 'outcome' => Guard::PASSED, 'hits' => 3]);
    gecka_antispam()->stats()->record('comments', Guard::PASSED);

    gecka_antispam()->stats()->purge(30);

    expect((int) $wpdb->get_var('SELECT SUM(hits) FROM ' . Schema::stats()))->toBe(1);
});

it('shows the share of each check in what was caught, the largest first', function () {
    $stats = gecka_antispam()->stats();
    $stats->record('comments', Guard::HONEYPOT);
    $stats->record('comments', Guard::HONEYPOT);
    $stats->record('contact_form_7', Guard::TOO_FAST);
    $stats->record('comments', Guard::PASSED);

    ob_start();
    (new \Gecka\WP\Plugin\Antispam\Admin\StatsView(gecka_antispam()))->render();
    $html = (string) ob_get_clean();
    $start = (int) strpos($html, 'gecka-antispam-shares');
    $shares = substr($html, $start, (int) strpos($html, '</ul>', $start) - $start);

    expect($shares)->toContain('2 (66.7 %)')
        ->and($shares)->toContain('1 (33.3 %)')
        ->and(strpos($shares, Guard::outcomeLabel(Guard::HONEYPOT)))->toBeLessThan(strpos($shares, Guard::outcomeLabel(Guard::TOO_FAST)))
        ->and($shares)->not->toContain(Guard::outcomeLabel(Guard::PASSED));
});
