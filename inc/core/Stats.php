<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

namespace Gecka\WP\Plugin\Antispam;

/**
 * Daily counters of the submissions checked, by form and by outcome. Only
 * counts: no address, no content, nothing that tells who sent what.
 *
 * @author Laurent Dinclaux - Gecka <laurent@gecka.nc>
 */
class Stats
{
    /**
     * Counts a submission.
     *
     * @param string $surface The form it was sent from.
     * @param string $outcome What the checks made of it, one of the Guard constants.
     *
     * @return void
     */
    public function record(string $surface, string $outcome): void
    {
        global $wpdb;

        $table = Schema::stats();

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Table of the plugin; a counter is no cache candidate.
        $wpdb->query($wpdb->prepare('INSERT INTO %i (day, surface, outcome, hits) VALUES (%s, %s, %s, 1) ON DUPLICATE KEY UPDATE hits = hits + 1', $table, current_time('Y-m-d'), $surface, $outcome));
    }

    /**
     * Submissions of the last days, by form and outcome
     *
     * @param int $days
     *
     * @return array<string, array<string, int>> Hits by outcome, by form.
     */
    public function totals(int $days): array
    {
        global $wpdb;

        $table = Schema::stats();

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Table of the plugin, read on the statistics screen only.
        $rows = $wpdb->get_results($wpdb->prepare('SELECT surface, outcome, SUM(hits) AS hits FROM %i WHERE day >= %s GROUP BY surface, outcome', $table, self::since($days)));

        $totals = [];

        foreach ((array) $rows as $row) {
            $totals[$row->surface][$row->outcome] = (int) $row->hits;
        }

        return $totals;
    }

    /**
     * Submissions that went through, those held for review included, and
     * submissions caught, day by day, the days with none included
     *
     * @param int $days
     *
     * @return array<string, array{passed: int, caught: int}> Keyed by date, oldest first.
     */
    public function daily(int $days): array
    {
        global $wpdb;

        $table = Schema::stats();

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Table of the plugin, read on the statistics screen only.
        $rows = $wpdb->get_results($wpdb->prepare('SELECT day, outcome IN (%s, %s) AS passed, SUM(hits) AS hits FROM %i WHERE day >= %s GROUP BY day, outcome IN (%s, %s)', Guard::PASSED, Guard::REVIEW, $table, self::since($days), Guard::PASSED, Guard::REVIEW));

        $daily = [];
        $day = new \DateTimeImmutable(self::since($days), wp_timezone());

        for ($i = 0; $i < $days; $i++) {
            $daily[$day->modify("+$i days")->format('Y-m-d')] = ['passed' => 0, 'caught' => 0];
        }

        foreach ((array) $rows as $row) {
            if (isset($daily[$row->day])) {
                $daily[$row->day][$row->passed ? 'passed' : 'caught'] += (int) $row->hits;
            }
        }

        return $daily;
    }

    /**
     * Drops the counters older than the days kept.
     *
     * @param int $keep Days kept.
     *
     * @return void
     */
    public function purge(int $keep): void
    {
        global $wpdb;

        $table = Schema::stats();

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Table of the plugin.
        $wpdb->query($wpdb->prepare('DELETE FROM %i WHERE day < %s', $table, self::since($keep)));
    }

    /**
     * Drops every counter.
     *
     * @return void
     */
    public function reset(): void
    {
        global $wpdb;

        $table = Schema::stats();

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Table of the plugin.
        $wpdb->query($wpdb->prepare('DELETE FROM %i', $table));
    }

    /**
     * First day of a period ending today, in the time zone of the site
     *
     * @param int $days Length of the period, today included.
     *
     * @return string
     */
    public static function since(int $days): string
    {
        return (new \DateTimeImmutable('today', wp_timezone()))->modify('-' . max(0, $days - 1) . ' days')->format('Y-m-d');
    }
}
