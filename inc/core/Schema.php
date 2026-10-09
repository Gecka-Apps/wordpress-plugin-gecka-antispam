<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

namespace Gecka\WP\Plugin\Antispam;

use Gecka\WP\Plugin\Antispam\StatisticalFilter\WpdbStorage;

/**
 * The tables of the plugin, one set per site: the daily counters of the
 * statistics, the daily counters by origin, which hold the country, the
 * network and the system of the senders and never their address, the
 * journal of the submissions refused, and the two tables holding what the
 * spam filter learnt.
 *
 * @author Laurent Dinclaux - Gecka <laurent@gecka.nc>
 */
class Schema
{
    /**
     * Version of the tables. The setup runs again on a site whose recorded
     * version differs, whatever the version of the plugin.
     */
    public const VERSION = 2;

    /**
     * Table of the daily counters
     *
     * @return string
     */
    public static function stats(): string
    {
        global $wpdb;

        return $wpdb->prefix . 'gecka_antispam_stats';
    }

    /**
     * Table of the daily counters by origin: country, network, system
     *
     * @return string
     */
    public static function origins(): string
    {
        global $wpdb;

        return $wpdb->prefix . 'gecka_antispam_origins';
    }

    /**
     * Counters of the spam filter, on the current site
     *
     * @return WpdbStorage
     */
    public static function storage(): WpdbStorage
    {
        global $wpdb;

        return new WpdbStorage($wpdb->prefix . 'gecka_antispam_');
    }

    /**
     * Creates the tables, or brings them up to date, on the current site.
     *
     * @return void
     */
    public static function install(): void
    {
        global $wpdb;

        require_once ABSPATH . 'wp-admin/includes/upgrade.php';

        $collate = $wpdb->get_charset_collate();
        $stats = self::stats();

        dbDelta(
            "CREATE TABLE $stats (
            day date NOT NULL,
            surface varchar(40) NOT NULL,
            outcome varchar(20) NOT NULL,
            hits int(10) unsigned NOT NULL DEFAULT 0,
            PRIMARY KEY  (day,surface,outcome)
            ) $collate;",
        );

        $origins = self::origins();

        dbDelta(
            "CREATE TABLE $origins (
            day date NOT NULL,
            facet varchar(10) NOT NULL,
            value varchar(20) NOT NULL,
            outcome varchar(20) NOT NULL,
            name varchar(191) NOT NULL DEFAULT '',
            hits int(10) unsigned NOT NULL DEFAULT 0,
            PRIMARY KEY  (day,facet,value,outcome),
            KEY facet (facet,day)
            ) $collate;",
        );

        $journal = Journal::table();

        dbDelta(
            "CREATE TABLE $journal (
            id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
            hash char(32) NOT NULL,
            surface varchar(40) NOT NULL,
            outcome varchar(20) NOT NULL,
            text mediumtext NOT NULL,
            hits int(10) unsigned NOT NULL DEFAULT 1,
            created datetime NOT NULL,
            updated datetime NOT NULL,
            learnt varchar(8) DEFAULT NULL,
            generation int(11) DEFAULT NULL,
            PRIMARY KEY  (id),
            UNIQUE KEY hash (hash),
            KEY updated (updated),
            KEY learnt (learnt)
            ) $collate;",
        );

        self::storage()->install(StatisticalFilter::BITS);
    }

    /**
     * Drops the tables of the current site.
     *
     * @return void
     */
    public static function drop(): void
    {
        global $wpdb;

        foreach ([self::stats(), self::origins(), Journal::table()] as $table) {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Table of the plugin, dropped on uninstall.
            $wpdb->query($wpdb->prepare('DROP TABLE IF EXISTS %i', $table));
        }

        self::storage()->drop();
    }
}
