<?php

declare(strict_types=1);

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

use Gecka\WP\Plugin\Antispam\Admin\SettingsPage;
use Gecka\WP\Plugin\Antispam\Plugin;
use Gecka\WP\Plugin\Antispam\Schema;
use Gecka\WP\Plugin\Antispam\StatisticalFilter;

beforeEach(function () {
    gecka_antispam()->statisticalFilter()->reset();
    $post = static::factory()->post->create();

    foreach (['Cheap pills online, order now', 'Casino bonus, free spins'] as $content) {
        marked_spam(static::factory()->comment->create(['comment_post_ID' => $post, 'comment_approved' => 'spam', 'comment_content' => $content]));
    }

    static::factory()->comment->create(['comment_post_ID' => $post, 'comment_approved' => '1', 'comment_content' => 'Merci pour cet article très clair.']);
});

afterEach(function () {
    wp_set_current_user(0);
});

it('learns what the site holds through the REST route, and tells what is left', function () {
    wp_set_current_user(static::factory()->user->create(['role' => 'administrator']));

    $response = rest_do_request(new WP_REST_Request('POST', '/' . SettingsPage::REST_NAMESPACE . '/learn-existing'));

    expect($response->get_status())->toBe(200)
        ->and($response->get_data())->toBe(['learnt' => ['spam' => 2, 'ham' => 1], 'pending' => ['spam' => 0, 'ham' => 0], 'failed' => false])
        ->and(gecka_antispam()->statisticalFilter()->counts())->toMatchArray(['spam' => 2, 'ham' => 1]);
});

it('refuses the REST route to whoever cannot manage the options', function () {
    wp_set_current_user(static::factory()->user->create(['role' => 'editor']));

    $response = rest_do_request(new WP_REST_Request('POST', '/' . SettingsPage::REST_NAMESPACE . '/learn-existing'));

    expect($response->get_status())->toBe(403)
        ->and(gecka_antispam()->pendingTexts())->toBe([StatisticalFilter::SPAM => 2, StatisticalFilter::HAM => 1]);
});

it('stops when the filter fails, and leaves what it could not learn to the next time', function () {
    global $wpdb;

    $filter = gecka_antispam()->statisticalFilter();
    Schema::storage()->drop();

    // The queries on the dropped tables fail on purpose: their errors are not printed.
    $shown = $wpdb->suppress_errors();
    $learnt = gecka_antispam()->learnExisting(5);
    $wpdb->suppress_errors($shown);

    expect($learnt)->toBe([StatisticalFilter::SPAM => 0, StatisticalFilter::HAM => 0])
        ->and($filter->learningFailed())->toBeTrue()
        ->and(get_comments(['meta_key' => Plugin::META_TRAINED, 'status' => 'all', 'count' => true]))->toBe(0);

    $filter->reset();

    expect(gecka_antispam()->learnExisting(5))->toBe([StatisticalFilter::SPAM => 2, StatisticalFilter::HAM => 1])
        ->and($filter->learningFailed())->toBeFalse();
});
