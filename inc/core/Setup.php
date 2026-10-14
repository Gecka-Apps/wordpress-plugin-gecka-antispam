<?php

declare(strict_types=1);

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

namespace Gecka\WP\Plugin\Antispam;

use Gecka\WP\Plugin\Antispam\Admin\RefusedView;
use Gecka\WP\Plugin\Antispam\Integrations\GravityForms;

/**
 * What the plugin leaves on a site: five tables, four options, a daily event,
 * a directory under uploads holding the background tables and the snapshot
 * of the filter, and meta on the comments, the Flamingo messages and the
 * Gravity Forms entries the statistical filter learnt from; for a while, the
 * lock of the downloads and a transient per administrator; and, on the
 * users, the screen options of the Refused list. Deleting the plugin
 * removes all of it.
 *
 * @author Laurent Dinclaux - Gecka <laurent@gecka.nc>
 */
class Setup
{
    /**
     * Option holding the versions of the plugin and of its tables whose
     * setup ran on a site, as 1.0.0/2.
     */
    public const VERSION_OPTION = 'gecka_antispam_version';

    /**
     * Daily event purging the old statistics and refused submissions,
     * rotating the counters of the filter and checking the background
     * tables.
     */
    public const PURGE_EVENT = 'gecka_antispam_purge';

    /**
     * Transient holding why the setup of the tables failed, for an hour:
     * while it is there the setup is not tried again, the administrators
     * see a notice and Site Health reports it.
     */
    public const FAILED_TRANSIENT = 'gecka_antispam_install_failed';

    /**
     * Hooks the state changes of the plugin up.
     *
     * @param string $file Main file of the plugin
     *
     * @return void
     */
    public static function hooks(string $file): void
    {
        register_activation_hook($file, [self::class, 'activate']);
        register_deactivation_hook($file, [self::class, 'deactivate']);
    }

    /**
     * Sets the plugin up on the site, or on every site when it is activated
     * for the network.
     *
     * @param bool $networkWide
     *
     * @return void
     */
    public static function activate(bool $networkWide = false): void
    {
        $install = static function (): void {
            self::tryInstall(Plugin::VERSION);
        };

        $networkWide ? self::onEachSite($install) : $install();
    }

    /**
     * Stops the events and has the setup run again on the next activation.
     *
     * @param bool $networkWide Whether the plugin is deactivated for the whole network.
     *
     * @return void
     */
    public static function deactivate(bool $networkWide = false): void
    {
        $stop = static function (): void {
            wp_clear_scheduled_hook(self::PURGE_EVENT);
            wp_clear_scheduled_hook(Backgrounds::EVENT);
            delete_option(self::VERSION_OPTION);
        };

        $networkWide ? self::onEachSite($stop) : $stop();
    }

    /**
     * Runs the setup on the current site when the version changed, which
     * covers a plugin updated by Composer and a site added to the network;
     * otherwise schedules the daily task again when it went missing.
     *
     * @param string $version Version of the plugin.
     *
     * @return void
     */
    public static function upgrade(string $version): void
    {
        if (get_option(self::VERSION_OPTION) !== self::installed($version)) {
            if (self::failure() === '') {
                self::tryInstall($version);
            }
        } elseif (! wp_next_scheduled(self::PURGE_EVENT)) {
            wp_schedule_event(time() + HOUR_IN_SECONDS, 'daily', self::PURGE_EVENT);
        }
    }

    /**
     * Why the last setup of the tables failed, while the failure is kept
     *
     * @return string Empty when the setup did not fail.
     */
    public static function failure(): string
    {
        $failure = get_transient(self::FAILED_TRANSIENT);

        return is_string($failure) ? $failure : '';
    }

    /**
     * Runs the setup, and keeps its failure instead of letting it end the
     * request: a database refusing the tables would otherwise end every
     * request of the site, the version staying unrecorded.
     *
     * @param string $version Version of the plugin.
     *
     * @return bool Whether the setup ran to its end.
     */
    private static function tryInstall(string $version): bool
    {
        try {
            self::install($version);
        } catch (\Throwable $e) {
            set_transient(self::FAILED_TRANSIENT, $e->getMessage() !== '' ? $e->getMessage() : get_class($e), HOUR_IN_SECONDS);

            return false;
        }

        delete_transient(self::FAILED_TRANSIENT);

        return true;
    }

    /**
     * What the option records once the setup ran: the versions of the plugin
     * and of its tables
     *
     * @param string $version Version of the plugin.
     *
     * @return string
     */
    public static function installed(string $version): string
    {
        return $version . '/' . Schema::VERSION;
    }

    /**
     * Creates the tables and schedules the purge on the current site, and
     * the download of the background tables when none was ever made.
     *
     * @param string $version Version of the plugin.
     *
     * @return void
     */
    public static function install(string $version): void
    {
        Schema::install();

        $settings = (array) get_option(Settings::OPTION, []);

        if (empty($settings['honeypot_name'])) {
            update_option(Settings::OPTION, array_merge($settings, ['honeypot_name' => Settings::randomFieldName()]));
        }

        if (! wp_next_scheduled(self::PURGE_EVENT)) {
            wp_schedule_event(time() + HOUR_IN_SECONDS, 'daily', self::PURGE_EVENT);
        }

        update_option(self::VERSION_OPTION, self::installed($version));
    }

    /**
     * Removes the tables, the options, the event, the directory and the meta,
     * on every site.
     *
     * @return void
     */
    public static function uninstall(): void
    {
        self::onEachSite(
            static function (): void {
                wp_clear_scheduled_hook(self::PURGE_EVENT);
                wp_clear_scheduled_hook(Backgrounds::EVENT);
                Schema::drop();
                self::deleteDirectory();

                delete_option(Settings::OPTION);
                delete_option(Plugin::ROTATED_OPTION);
                delete_option(Backgrounds::OPTION);
                delete_option(Backgrounds::LOCK);
                delete_option(self::VERSION_OPTION);
                delete_transient(self::FAILED_TRANSIENT);
                self::deleteTransients(Backgrounds::QUEUED);

                self::deleteMeta(
                    [Plugin::META_TRAINED, Plugin::META_GENERATION, Plugin::META_REASON, Plugin::META_SCORE],
                    [GravityForms::META_TRAINED, GravityForms::META_GENERATION, GravityForms::META_REASON],
                );
            },
        );

        self::deleteUserOptions();
    }

    /**
     * Drops the marks telling what the statistical filter learnt each comment,
     * message and entry as, on the current site, so they can all be learnt
     * again. Whether the plugins holding them are active or not.
     *
     * @return void
     */
    public static function forgetTraining(): void
    {
        self::deleteMeta([Plugin::META_TRAINED, Plugin::META_GENERATION], [GravityForms::META_TRAINED, GravityForms::META_GENERATION]);
    }

    /**
     * Deletes the directory of the plugin under uploads, on the current site,
     * when the file system can be written without credentials.
     *
     * @return void
     */
    private static function deleteDirectory(): void
    {
        global $wp_filesystem;

        $directory = StatisticalFilter::directory();

        if (! is_dir($directory)) {
            return;
        }

        require_once ABSPATH . 'wp-admin/includes/file.php';

        if (WP_Filesystem() && $wp_filesystem instanceof \WP_Filesystem_Base) {
            $wp_filesystem->delete($directory, true);
        }
    }

    /**
     * Drops meta of the plugin on the current site.
     *
     * @param string[] $keys      Comment and post meta.
     * @param string[] $entryKeys Gravity Forms entry meta.
     *
     * @return void
     */
    private static function deleteMeta(array $keys, array $entryKeys): void
    {
        global $wpdb;

        foreach ($keys as $key) {
            delete_metadata('comment', 0, $key, '', true);
            delete_metadata('post', 0, $key, '', true);
        }

        // Gravity Forms keeps the meta of its entries in a table of its own.
        $entryMeta = $wpdb->prefix . 'gf_entry_meta';

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Checked on demand.
        if ($wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s', $wpdb->esc_like($entryMeta))) !== $entryMeta) {
            return;
        }

        foreach ($entryKeys as $key) {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.SlowDBQuery.slow_db_query_meta_key -- Meta of the plugin, dropped on demand.
            $wpdb->delete($entryMeta, ['meta_key' => $key], ['%s']);
        }
    }

    /**
     * Drops the transients of the current site whose name starts with
     * $prefix. Kept in a persistent object cache, they are out of reach of
     * the query and expire by themselves.
     *
     * @param string $prefix
     *
     * @return void
     */
    private static function deleteTransients(string $prefix): void
    {
        global $wpdb;

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Transients of the plugin, named per user.
        foreach ((array) $wpdb->get_col($wpdb->prepare('SELECT option_name FROM %i WHERE option_name LIKE %s', $wpdb->options, $wpdb->esc_like('_transient_' . $prefix) . '%')) as $name) {
            delete_transient(substr((string) $name, strlen('_transient_')));
        }
    }

    /**
     * Drops the screen options of the Refused list kept on the users: the
     * entries per page, and the display mode inside the user settings
     * WordPress keeps as one string per site. The hidden columns stay: they
     * belong to the Journal screen, which other plugins share.
     *
     * @return void
     */
    private static function deleteUserOptions(): void
    {
        global $wpdb;

        delete_metadata('user', 0, RefusedView::PER_PAGE_OPTION, '', true);

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.SlowDBQuery.slow_db_query_meta_key -- Run once, when the plugin is deleted.
        $rows = (array) $wpdb->get_results($wpdb->prepare('SELECT user_id, meta_key, meta_value FROM %i WHERE meta_key LIKE %s AND meta_value LIKE %s', $wpdb->usermeta, '%' . $wpdb->esc_like('user-settings'), '%' . $wpdb->esc_like(RefusedView::MODE_SETTING) . '%'));

        foreach ($rows as $row) {
            $settings = trim((string) preg_replace('/(?:^|&)' . preg_quote(RefusedView::MODE_SETTING, '/') . '=[^&]*/', '', $row->meta_value), '&');
            update_user_meta((int) $row->user_id, $row->meta_key, $settings);
        }
    }

    /**
     * Runs a callback on every site of the network, or on the only site
     *
     * @param callable $callback
     *
     * @return void
     */
    private static function onEachSite(callable $callback): void
    {
        if (! is_multisite()) {
            $callback();

            return;
        }

        foreach (get_sites(
            [
                'fields' => 'ids',
                'number' => 0,
            ],
        ) as $blogId) {
            switch_to_blog((int) $blogId);
            $callback();
            restore_current_blog();
        }
    }
}
