<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

/*
 * WordPress installed once for the whole run, SQLite standing for MySQL, the
 * plugin loaded as a site loads it. The installation lands in .tests/ unless
 * WP_CORE_DIR names another directory.
 */

use Gecka\WP\Plugin\Antispam\Guard;
use Mantle\Testkit\TestCase;

if (! getenv('WP_CORE_DIR')) {
    putenv('WP_CORE_DIR=' . dirname(__DIR__) . '/.tests/wordpress');
}

/*
 * The statistical filter reads no background table unless a test hands it
 * some: tables left in the uploads of the test site, by a run that
 * downloaded real ones, would change every rating. Whatever a test writes in
 * this directory is removed after it.
 */
const NO_BACKGROUND = __DIR__ . '/../.tests/no-background';

uses(TestCase::class)
    ->beforeEach(function () {
        gecka_antispam()->settings()->flush();
        gecka_antispam()->statisticalFilter()->flushTally();
        add_filter('gecka_antispam_background_directory', static fn(): string => NO_BACKGROUND);
    })
    ->afterEach(fn() => remove_tree(NO_BACKGROUND))
    ->in(__DIR__);

\Mantle\Testing\manager()
    ->with_sqlite()
    ->loaded(static function (): void {
        require dirname(__DIR__) . '/bootstrap.php';
    })
    ->install();

/**
 * Posts the fields of a form as a browser would, the timestamp issued
 * $age seconds ago.
 *
 * @param string               $surface  The form.
 * @param int                  $age      Seconds since the form was displayed.
 * @param string               $honeypot Value of the honeypot field.
 * @param array<string, mixed> $fields   Other fields of the form.
 *
 * @return void
 */
function post_form(string $surface, int $age = 30, string $honeypot = '', array $fields = []): void
{
    $html = gecka_antispam()->guard()->fields($surface);

    preg_match('/name="' . Guard::TOKEN_FIELD . '" value="(\d+)\.([^"]+)"/', $html, $token);

    $time = (int) $token[1] - $age;
    $signature = substr(hash_hmac('sha256', $surface . '|' . get_current_blog_id() . '|' . $time, wp_salt('nonce')), 0, 24);

    $_POST = array_merge(
        $fields,
        [
            Guard::TOKEN_FIELD => $time . '.' . $signature,
            gecka_antispam()->guard()->honeypotName() => $honeypot,
        ],
    );
}

/**
 * Settings of the plugin, some of them changed.
 *
 * @param array<string, mixed> $settings
 *
 * @return void
 */
function antispam_settings(array $settings): void
{
    $saved = (array) get_option(\Gecka\WP\Plugin\Antispam\Settings::OPTION, []);

    update_option(\Gecka\WP\Plugin\Antispam\Settings::OPTION, array_merge($saved, $settings));
    gecka_antispam()->settings()->flush();
}

/**
 * Marks a comment as spam the way a moderator does, which WordPress records.
 *
 * @param int $comment
 *
 * @return int
 */
function marked_spam(int $comment): int
{
    add_comment_meta($comment, '_wp_trash_meta_status', '0');

    return $comment;
}

/**
 * A small background table of ordinary French.
 *
 * @return \Gecka\SpamFilter\Model\CountTable
 */
function french_table(): \Gecka\SpamFilter\Model\CountTable
{
    $table = new \Gecka\SpamFilter\Model\CountTable(1 << 12);

    foreach ((new \Gecka\SpamFilter\Tokenizer\FeatureHasher())->hashAll((new \Gecka\SpamFilter\Tokenizer\FeatureExtractor())->extract('Bonjour, je souhaite un devis pour notre association. Merci de votre réponse.')) as $hash => $count) {
        $table->add($hash, $count);
    }

    return $table;
}

/**
 * Removes a directory and everything in it, if it exists.
 *
 * @param string $directory
 *
 * @return void
 */
function remove_tree(string $directory): void
{
    if (! is_dir($directory)) {
        return;
    }

    $items = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($directory, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);

    foreach ($items as $item) {
        $item->isDir() ? rmdir($item->getPathname()) : unlink($item->getPathname());
    }

    rmdir($directory);
}
