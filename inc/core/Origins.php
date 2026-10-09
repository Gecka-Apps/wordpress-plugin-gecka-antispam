<?php

declare(strict_types=1);

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

namespace Gecka\WP\Plugin\Antispam;

/**
 * Daily counters of the submissions by where they came from: the country
 * and the network of the sender, as Gecka Geolocation tells them when it is
 * installed, and the operating system the user agent names. Only counts:
 * the plugin never reads the address itself, the geolocation locates the
 * visitor on its own.
 *
 * A network is kept under its autonomous system number, with the name of
 * its organisation as last seen. A sender the geolocation knows nothing of,
 * behind a private address for instance, counts under an empty value.
 *
 * @author Laurent Dinclaux - Gecka <laurent@gecka.nc>
 */
class Origins
{
    public const COUNTRY = 'country';

    public const NETWORK = 'network';

    public const SYSTEM = 'os';

    /**
     * The outcomes of a submission that went through.
     */
    public const ACCEPTED = [Guard::PASSED, Guard::REVIEW];

    /**
     * Characters of the name of a network kept.
     */
    private const NAME_LENGTH = 191;

    /**
     * The outcomes of a submission caught: every one but those that went
     * through
     *
     * @return string[]
     */
    public static function caught(): array
    {
        return array_values(array_diff(array_keys(Guard::outcomes()), self::ACCEPTED));
    }

    /**
     * Counts a submission under the country, the network and the system of
     * its sender.
     *
     * @param string $outcome What the statistics count it as, one of the Guard constants.
     *
     * @return void
     */
    public function count(string $outcome): void
    {
        // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Only matched against fixed patterns.
        $this->record(self::SYSTEM, self::system(wp_unslash((string) ($_SERVER['HTTP_USER_AGENT'] ?? ''))), $outcome);

        $record = function_exists('gecka_geolocation') ? gecka_geolocation() : null;

        if ($record === null) {
            return;
        }

        $asn = $record->asn();

        $this->record(self::COUNTRY, (string) $record->country(), $outcome);
        $this->record(self::NETWORK, $asn !== null ? (string) $asn : '', $outcome, (string) $record->asOrganization());
    }

    /**
     * Counts one hit.
     *
     * @param string $facet   One of the facet constants.
     * @param string $value
     * @param string $outcome
     * @param string $name    Name of the value, for a network.
     *
     * @return void
     */
    public function record(string $facet, string $value, string $outcome, string $name = ''): void
    {
        global $wpdb;

        $name = mb_substr($name, 0, self::NAME_LENGTH);

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Table of the plugin; a counter is no cache candidate.
        $wpdb->query($wpdb->prepare('INSERT INTO %i (day, facet, value, outcome, name, hits) VALUES (%s, %s, %s, %s, %s, 1) ON DUPLICATE KEY UPDATE hits = hits + 1, name = %s', Schema::origins(), current_time('Y-m-d'), $facet, $value, $outcome, $name, $name));
    }

    /**
     * The values of a facet seen most over the last days, for some outcomes
     *
     * @param string   $facet    One of the facet constants.
     * @param int      $days
     * @param string[] $outcomes
     * @param int      $limit
     *
     * @return array<int, array{value: string, name: string, hits: int}> The most seen first.
     */
    public function top(string $facet, int $days, array $outcomes, int $limit = 100): array
    {
        global $wpdb;

        if ($outcomes === []) {
            return [];
        }

        $in = implode(',', array_fill(0, count($outcomes), '%s'));

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber, PluginCheck.Security.DirectDB.UnescapedDBParameter -- Table of the plugin, read on the statistics screen only; $in is one placeholder per outcome.
        $rows = $wpdb->get_results($wpdb->prepare("SELECT value, MAX(name) AS name, SUM(hits) AS hits FROM %i WHERE facet = %s AND day >= %s AND outcome IN ($in) GROUP BY value ORDER BY hits DESC, value ASC LIMIT %d", Schema::origins(), $facet, Stats::since($days), ...[...$outcomes, $limit]));

        $top = [];

        foreach ((array) $rows as $row) {
            $top[] = ['value' => (string) $row->value, 'name' => (string) $row->name, 'hits' => (int) $row->hits];
        }

        return $top;
    }

    /**
     * Number of hits of a facet over the last days, for some outcomes
     *
     * @param string   $facet
     * @param int      $days
     * @param string[] $outcomes
     *
     * @return int
     */
    public function total(string $facet, int $days, array $outcomes): int
    {
        global $wpdb;

        if ($outcomes === []) {
            return 0;
        }

        $in = implode(',', array_fill(0, count($outcomes), '%s'));

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber, PluginCheck.Security.DirectDB.UnescapedDBParameter -- Table of the plugin, read on the statistics screen only; $in is one placeholder per outcome.
        return (int) $wpdb->get_var($wpdb->prepare("SELECT SUM(hits) FROM %i WHERE facet = %s AND day >= %s AND outcome IN ($in)", Schema::origins(), $facet, Stats::since($days), ...$outcomes));
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

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Table of the plugin.
        $wpdb->query($wpdb->prepare('DELETE FROM %i WHERE day < %s', Schema::origins(), Stats::since($keep)));
    }

    /**
     * Drops every counter.
     *
     * @return void
     */
    public function reset(): void
    {
        global $wpdb;

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Table of the plugin.
        $wpdb->query($wpdb->prepare('DELETE FROM %i', Schema::origins()));
    }

    /**
     * The operating systems told apart, with their labels
     *
     * @return array<string, string>
     */
    public static function systems(): array
    {
        return [
            'windows' => 'Windows',
            'macos' => 'macOS',
            'ios' => 'iOS',
            'ipados' => 'iPadOS',
            'android' => 'Android',
            'chromeos' => 'ChromeOS',
            'linux' => 'Linux',
            'other' => __('Other, or a script', 'gecka-antispam'),
            '' => __('No user agent', 'gecka-antispam'),
        ];
    }

    /**
     * The operating system a user agent names. The user agent is what the
     * client says of itself: a robot claims whatever it likes.
     *
     * @param string $agent
     *
     * @return string A key of systems().
     */
    public static function system(string $agent): string
    {
        $agent = trim($agent);

        return match (true) {
            $agent === '' => '',
            str_contains($agent, 'iPad') => 'ipados',
            (bool) preg_match('/iPhone|iPod/', $agent) => 'ios',
            str_contains($agent, 'Android') => 'android',
            str_contains($agent, 'CrOS') => 'chromeos',
            (bool) preg_match('/Macintosh|Mac OS X/', $agent) => 'macos',
            str_contains($agent, 'Windows') => 'windows',
            str_contains($agent, 'Linux') => 'linux',
            default => 'other',
        };
    }
}
