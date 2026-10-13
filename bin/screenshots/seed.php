<?php

declare(strict_types=1);

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

/**
 * Fills a fresh site for the screenshots of the plugin, required by WP-CLI
 * (`wp eval 'require "...";'`): three months of counters and origins, a
 * month of refused submissions, a filter trained past its thresholds, a
 * few comments rated, the background tables downloaded.
 *
 * The figures are drawn from a fixed sequence, so that two runs give the
 * same screens. The counters are written straight into the tables: the
 * recorders of the plugin only stamp the current day.
 */

// phpcs:disable WordPress.DB -- Seed data written straight into the tables of the plugin.

use Gecka\WP\Plugin\Antispam\Guard;
use Gecka\WP\Plugin\Antispam\Journal;
use Gecka\WP\Plugin\Antispam\Origins;
use Gecka\WP\Plugin\Antispam\Plugin;
use Gecka\WP\Plugin\Antispam\Schema;
use Gecka\WP\Plugin\Antispam\StatisticalFilter;

(static function (): void {
    global $wpdb;

    $plugin = gecka_antispam();
    $state = 20261013;
    $draw = static function (int $min, int $max) use (&$state): int {
        $state = ($state * 1103515245 + 12345) % 2147483648;

        return $min + $state % ($max - $min + 1);
    };
    $today = new DateTimeImmutable('today', wp_timezone());
    $day = static fn(int $ago): string => $today->modify("-{$ago} days")->format('Y-m-d');
    $count = static function (string $table, array $row) use ($wpdb): void {
        $columns = implode(', ', array_keys($row));
        $values = implode(', ', array_fill(0, count($row), '%s'));
        $wpdb->query($wpdb->prepare("INSERT INTO {$table} ({$columns}) VALUES ({$values}) ON DUPLICATE KEY UPDATE hits = hits + VALUES(hits)", array_values($row))); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
    };

    // Counters: a quieter site on week-ends, a wave of bots in the third
    // week before today.
    $forms = [
        'comments' => [Guard::PASSED => [8, 30], Guard::REVIEW => [0, 3], Guard::HONEYPOT => [5, 40], Guard::RANDOM_TEXT => [2, 12], Guard::FILTER_REJECT => [3, 25], Guard::TOO_FAST => [1, 8], Guard::SHORT => [0, 4]],
        'contact_form_7' => [Guard::PASSED => [2, 9], Guard::HONEYPOT => [3, 20], Guard::FILTER_REJECT => [1, 10], Guard::EXPIRED => [0, 2], Guard::RANDOM_NAME => [0, 5]],
        'login' => [Guard::PASSED => [3, 12], Guard::BAD_BROWSER => [4, 30], Guard::TOKEN => [2, 15]],
        'registration' => [Guard::PASSED => [0, 2], Guard::RANDOM_NAME => [2, 14], Guard::HONEYPOT => [1, 9]],
        'lost_password' => [Guard::PASSED => [0, 2], Guard::TOKEN => [0, 6]],
    ];
    $countries = [['US', 30], ['CN', 22], ['RU', 18], ['VN', 9], ['IN', 8], ['BR', 7], ['DE', 6], ['NL', 6], ['FR', 5], ['UA', 4], ['SG', 4], ['ID', 3], ['GB', 3], ['NC', 2], ['AU', 2]];
    $networks = [['14061', 'DigitalOcean, LLC', 22], ['16509', 'Amazon.com, Inc.', 18], ['4134', 'Chinanet', 16], ['24940', 'Hetzner Online GmbH', 12], ['16276', 'OVH SAS', 10], ['12389', 'PJSC Rostelecom', 9], ['45102', 'Alibaba (US) Technology Co., Ltd.', 8], ['20473', 'The Constant Company, LLC', 7], ['9009', 'M247 Europe SRL', 6], ['7552', 'Viettel Group', 5], ['9498', 'Bharti Airtel Ltd.', 4], ['15169', 'Google LLC', 3], ['13335', 'Cloudflare, Inc.', 3], ['56089', 'OFFRATEL', 2], ['3215', 'Orange S.A.', 2]];
    $systems = [['windows', 34], ['linux', 28], ['other', 18], ['android', 9], ['macos', 7], ['ios', 3], ['', 1]];
    $spread = static function (array $pool, int $total, callable $write) use ($draw): void {
        $weights = array_sum(array_map(static fn(array $item): int => $item[count($item) - 1], $pool));

        foreach ($pool as $item) {
            $share = (int) round($total * $item[count($item) - 1] / $weights);
            $share = max(0, $share + $draw(-2, 2));

            if ($share > 0) {
                $write($item, $share);
            }
        }
    };

    for ($ago = 89; $ago >= 0; $ago--) {
        $weekend = in_array((int) $today->modify("-{$ago} days")->format('N'), [6, 7], true);
        $wave = $ago >= 14 && $ago <= 20 ? 3 : 1;
        $caught = 0;
        $accepted = 0;

        foreach ($forms as $surface => $outcomes) {
            foreach ($outcomes as $outcome => [$min, $max]) {
                $hits = $draw($min, $max);
                $hits = in_array($outcome, Guard::ACCEPTED, true) ? ($weekend ? intdiv($hits, 2) : $hits) : $hits * $wave;

                if ($hits === 0) {
                    continue;
                }

                $count(Schema::stats(), ['day' => $day($ago), 'surface' => $surface, 'outcome' => $outcome, 'hits' => $hits]);

                if (in_array($outcome, Guard::ACCEPTED, true)) {
                    $accepted += $hits;
                } else {
                    $caught += $hits;
                }
            }
        }

        foreach ([Guard::HONEYPOT => $caught, Guard::PASSED => $accepted] as $outcome => $total) {
            $spread($countries, $total, static fn(array $item, int $hits) => $count(Schema::origins(), ['day' => $day($ago), 'facet' => Origins::COUNTRY, 'value' => $item[0], 'outcome' => $outcome, 'name' => '', 'hits' => $hits]));
            $spread($networks, $total, static fn(array $item, int $hits) => $count(Schema::origins(), ['day' => $day($ago), 'facet' => Origins::NETWORK, 'value' => $item[0], 'outcome' => $outcome, 'name' => $item[1], 'hits' => $hits]));
            $spread($systems, $total, static fn(array $item, int $hits) => $count(Schema::origins(), ['day' => $day($ago), 'facet' => Origins::SYSTEM, 'value' => $item[0], 'outcome' => $outcome, 'name' => '', 'hits' => $hits]));
        }
    }

    // Refused submissions of the last month, the newest first on the
    // screen, a few of them sent several times.
    $products = ['replica watches', 'cheap SEO backlinks', 'crypto signals', 'weight loss pills', 'casino bonuses', 'followers', 'essay writing', 'VPN subscriptions', 'designer handbags', 'forex robots', 'solar panels', 'hair growth serum'];
    $spamTemplates = [
        'Get %1$s at 70%% off today only! Limited stock, click here >>> http://%2$s/deal',
        'Hello admin, I visited your website and I think you need %1$s. Contact me on WhatsApp +1 555 0%3$d',
        'Our team offers the best %1$s on the market. Guaranteed results or money back. Visit http://%2$s now!!!',
        'Earn $%3$d per day from home with %1$s, no experience needed. Register at http://%2$s/signup',
        'CONGRATULATIONS you have been selected to receive free %1$s. Claim your prize: http://%2$s/claim?id=%3$d',
        'Nice post. By the way, buy %1$s with 50%% discount and free worldwide shipping at http://%2$s',
    ];
    $hosts = ['bestdeals-now.example', 'promo-zone.example', 'quick-offers.example', 'super-sale.example', 'win-today.example', 'cheap-shop.example'];
    $spam = [];

    foreach ($products as $i => $product) {
        foreach ([0, 1, 2] as $j) {
            $template = $spamTemplates[($i + $j) % count($spamTemplates)];
            $spam[] = sprintf($template, $product, $hosts[($i * 3 + $j) % count($hosts)], 1000 + $i * 37 + $j * 11);
        }
    }

    $ham = [
        'Thanks for this article, it finally made the difference between the two approaches clear to me. I had been mixing them up for months.',
        'I tried the recipe last night with half the sugar and it still came out great. My kids asked for seconds, which never happens.',
        'Could you say a bit more about how this works on a multisite install? We run twelve sites on one network and I am not sure where the setting lives.',
        'Small correction: the release notes mention version 2.4, not 2.3. Otherwise a very helpful summary, thank you for putting it together.',
        'We have been using this method at the office since March and the support tickets about login problems dropped noticeably.',
        'Is there a way to export the data as CSV? I would like to compare the figures with the ones of our previous provider.',
        'Great walkthrough. One thing that caught me out was the file permissions on the uploads folder, maybe worth a note in the post.',
        'Bonjour, merci pour ce tutoriel très clair. Est-ce que la méthode fonctionne aussi avec la dernière version du thème ?',
        'I disagree with the conclusion but the data is well presented. The sample size seems small for the claims made in the last section.',
        'Just a heads up that the link to the documentation in the second paragraph returns a 404 now. The rest still works.',
        'Followed the steps on a fresh install and everything worked the first time. The screenshots helped a lot, thanks.',
        'How does this behave when the site is behind Cloudflare? We saw the visitor address replaced by the proxy one in another plugin.',
        'Lovely photos of the lagoon. Which lens did you use for the shot of the reef at the end of the post?',
        'We had the same issue after the update and clearing the object cache fixed it. Posting in case it helps someone else.',
    ];

    $surfaces = ['comments', 'comments', 'comments', 'contact_form_7', 'contact_form_7', 'woocommerce_reviews'];
    $reasons = [Guard::HONEYPOT, Guard::HONEYPOT, Guard::FILTER_REJECT, Guard::RANDOM_TEXT, Guard::TOO_FAST, Guard::SHORT, Guard::BAD_BROWSER];
    $journal = $plugin->journal();
    $ids = [];

    foreach (array_slice($spam, 0, 24) as $i => $text) {
        $journal->record($surfaces[$i % count($surfaces)], $reasons[$i % count($reasons)], $text);
        $when = gmdate('Y-m-d H:i:s', time() - $draw(1, 29) * DAY_IN_SECONDS - $draw(0, 86399));
        $wpdb->update(Journal::table(), ['created' => $when, 'updated' => $when, 'hits' => $i % 5 === 0 ? $draw(2, 9) : 1], ['hash' => md5($text)]);
        $ids[] = (int) $wpdb->get_var($wpdb->prepare('SELECT id FROM ' . Journal::table() . ' WHERE hash = %s', md5($text)));
    }

    // The filter: past its thresholds, with a rotation behind it, from the
    // journal for a part and from texts of its own for the rest.
    if (StatisticalFilter::supported()) {
        $filter = $plugin->statisticalFilter();

        foreach (array_slice($spam, 24) as $text) {
            $filter->learn($text, StatisticalFilter::SPAM);
        }

        foreach ($ham as $text) {
            $filter->learn($text, StatisticalFilter::HAM);
        }

        $journal->learn(array_slice($ids, 0, 8), StatisticalFilter::SPAM);
        update_option(Plugin::ROTATED_OPTION, time() - 47 * DAY_IN_SECONDS, false);
        WP_CLI::log(sprintf('filter: %d spam and %d legitimate texts learnt', $filter->counts()['spam'], $filter->counts()['ham']));
    }

    // Comments on the first post, rated as the integration would, in place
    // of the one WordPress installs with.
    $post = (int) $wpdb->get_var("SELECT ID FROM {$wpdb->posts} WHERE post_type = 'post' AND post_status = 'publish' ORDER BY ID ASC LIMIT 1");
    $dated = static fn(int $timestamp): array => ['comment_date' => get_date_from_gmt(gmdate('Y-m-d H:i:s', $timestamp)), 'comment_date_gmt' => gmdate('Y-m-d H:i:s', $timestamp)];

    if ($post > 0) {
        foreach ((array) get_comments(['post_id' => $post, 'fields' => 'ids']) as $id) {
            wp_delete_comment((int) $id, true);
        }

        $authors = [['Marie Lefort', 'marie@example.net'], ['Tom Kealy', 'tom.kealy@example.org'], ['Ana Souza', 'ana.souza@example.com'], ['Jean Waka', 'jean.waka@example.nc'], ['Priya Nair', 'priya@example.in']];

        foreach (array_slice($ham, 0, 5) as $i => $text) {
            $id = wp_insert_comment([
                'comment_post_ID' => $post,
                'comment_author' => $authors[$i][0],
                'comment_author_email' => $authors[$i][1],
                'comment_content' => $text,
                'comment_approved' => 1,
            ] + $dated(time() - ($i * 3 + 1) * DAY_IN_SECONDS - $draw(0, 40000)));

            if ($id) {
                update_comment_meta($id, Plugin::META_SCORE, $draw(1, 18) / 100);
                update_comment_meta($id, Plugin::META_REASON, Guard::PASSED);
            }
        }

        foreach (array_slice($spam, 30, 3) as $i => $text) {
            $id = wp_insert_comment([
                'comment_post_ID' => $post,
                'comment_author' => ['bestdeals', 'promo2026', 'WinnerX'][$i],
                'comment_author_email' => ['sales@bestdeals-now.example', 'promo@promo-zone.example', 'win@win-today.example'][$i],
                'comment_author_url' => 'http://' . $hosts[$i] . '/',
                'comment_content' => $text,
                'comment_approved' => 'spam',
            ] + $dated(time() - ($i * 2 + 1) * DAY_IN_SECONDS - $draw(0, 40000)));

            if ($id) {
                update_comment_meta($id, Plugin::META_SCORE, $draw(91, 99) / 100);
                update_comment_meta($id, Plugin::META_REASON, Guard::FILTER_SPAM);
            }
        }
    }

    // The background tables, and the logos of the networks counted when
    // Gecka Geolocation provides them.
    if ($plugin->backgrounds()->active()) {
        WP_CLI::log('background tables: downloading');
        $plugin->backgrounds()->update(180);
    }

    if (function_exists('gecka_geolocation_network_logo_url') && function_exists('gecka_geolocation_plugin')) {
        foreach ($networks as [$asn]) {
            gecka_geolocation_network_logo_url((int) $asn);
        }

        gecka_geolocation_plugin()->logos()->download();
    }

    WP_CLI::success('seeded');
})();
