<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

use Gecka\WP\Plugin\Antispam\Admin\RefusedView;
use Gecka\WP\Plugin\Antispam\Backgrounds;
use Gecka\WP\Plugin\Antispam\Journal;
use Gecka\WP\Plugin\Antispam\Plugin;
use Gecka\WP\Plugin\Antispam\Schema;
use Gecka\WP\Plugin\Antispam\Settings;
use Gecka\WP\Plugin\Antispam\Setup;

/**
 * Whether a table exists.
 *
 * @param string $table
 *
 * @return bool
 */
function table_exists(string $table): bool
{
    global $wpdb;

    return $wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s', $table)) === $table;
}

it('creates its tables and schedules the purge', function () {
    expect(table_exists(Schema::stats()))->toBeTrue()
        ->and(table_exists(Schema::storage()->countsTable()))->toBeTrue()
        ->and(table_exists(Schema::storage()->metaTable()))->toBeTrue()
        ->and(wp_next_scheduled(Setup::PURGE_EVENT))->not->toBeFalse()
        ->and(get_option(Setup::VERSION_OPTION))->toBe(Setup::installed(Plugin::VERSION));
});

it('schedules the daily task again when it went missing', function () {
    wp_clear_scheduled_hook(Setup::PURGE_EVENT);

    Setup::upgrade(Plugin::VERSION);

    expect(wp_next_scheduled(Setup::PURGE_EVENT))->not->toBeFalse();
});

it('runs the setup again when the version changes', function () {
    update_option(Setup::VERSION_OPTION, '0.0.1');

    Setup::upgrade(Plugin::VERSION);

    expect(get_option(Setup::VERSION_OPTION))->toBe(Setup::installed(Plugin::VERSION));
});

it('stops the purge when deactivated', function () {
    Setup::deactivate();

    expect(wp_next_scheduled(Setup::PURGE_EVENT))->toBeFalse()
        ->and(get_option(Setup::VERSION_OPTION))->toBeFalse();

    Setup::install(Plugin::VERSION);
});

it('leaves nothing behind when uninstalled', function () {
    $post = static::factory()->post->create();
    $comment = static::factory()->comment->create(['comment_post_ID' => $post]);
    update_comment_meta($comment, Plugin::META_TRAINED, 'spam');
    update_comment_meta($comment, Plugin::META_REASON, 'honeypot');
    update_post_meta($post, Plugin::META_TRAINED, 'ham');
    gecka_antispam()->settings()->get('honeypot_name');
    update_option(Plugin::ROTATED_OPTION, time());
    update_option(Backgrounds::OPTION, ['checked' => time()]);
    gecka_antispam()->backgrounds()->lock();
    $user = static::factory()->user->create(['role' => 'administrator']);
    set_transient(Backgrounds::QUEUED . $user, 1, HOUR_IN_SECONDS);
    update_user_meta($user, RefusedView::PER_PAGE_OPTION, 50);
    update_user_option($user, 'user-settings', 'editor=tinymce&' . RefusedView::MODE_SETTING . '=excerpt&libraryContent=browse');

    Setup::uninstall();

    expect(table_exists(Schema::stats()))->toBeFalse()
        ->and(table_exists(Schema::storage()->countsTable()))->toBeFalse()
        ->and(table_exists(Schema::storage()->metaTable()))->toBeFalse()
        ->and(get_option(Settings::OPTION))->toBeFalse()
        ->and(get_option(Setup::VERSION_OPTION))->toBeFalse()
        ->and(get_option(Plugin::ROTATED_OPTION))->toBeFalse()
        ->and(get_option(Backgrounds::OPTION))->toBeFalse()
        ->and(gecka_antispam()->backgrounds()->lock())->toBeTrue()
        ->and(get_transient(Backgrounds::QUEUED . $user))->toBeFalse()
        ->and(metadata_exists('user', $user, RefusedView::PER_PAGE_OPTION))->toBeFalse()
        ->and(get_user_option('user-settings', $user))->toBe('editor=tinymce&libraryContent=browse')
        ->and(wp_next_scheduled(Setup::PURGE_EVENT))->toBeFalse()
        ->and(metadata_exists('comment', $comment, Plugin::META_TRAINED))->toBeFalse()
        ->and(metadata_exists('comment', $comment, Plugin::META_REASON))->toBeFalse()
        ->and(metadata_exists('post', $post, Plugin::META_TRAINED))->toBeFalse();

    gecka_antispam()->backgrounds()->unlock();
    Setup::install(Plugin::VERSION);
});

it('keeps the reasons and the scores when the training is forgotten', function () {
    $post = static::factory()->post->create();
    $comment = static::factory()->comment->create(['comment_post_ID' => $post]);
    update_comment_meta($comment, Plugin::META_TRAINED, 'spam');
    update_comment_meta($comment, Plugin::META_REASON, 'honeypot');
    update_comment_meta($comment, Plugin::META_SCORE, 0.97);
    update_post_meta($post, Plugin::META_TRAINED, 'ham');

    Setup::forgetTraining();

    expect(metadata_exists('comment', $comment, Plugin::META_TRAINED))->toBeFalse()
        ->and(metadata_exists('post', $post, Plugin::META_TRAINED))->toBeFalse()
        ->and(get_comment_meta($comment, Plugin::META_REASON, true))->toBe('honeypot')
        ->and((float) get_comment_meta($comment, Plugin::META_SCORE, true))->toBe(0.97);
});

it('runs the setup again when only the tables changed', function () {
    global $wpdb;

    // phpcs:ignore WordPress.DB.DirectDatabaseQuery
    $wpdb->query($wpdb->prepare('DROP TABLE IF EXISTS %i', Journal::table()));
    update_option(Setup::VERSION_OPTION, Plugin::VERSION . '/' . (Schema::VERSION - 1));

    Setup::upgrade(Plugin::VERSION);

    expect(table_exists(Journal::table()))->toBeTrue();
});
