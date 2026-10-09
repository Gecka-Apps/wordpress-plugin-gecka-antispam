<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

namespace Gecka\WP\Plugin\Antispam;

/**
 * The submissions refused, kept for review: those a check of the form
 * caught, and those the statistical filter rated past the rejection
 * threshold.
 *
 * An entry holds what the statistical filter reads of the submission, the
 * subject and the message, with the form, the reason and the dates; nothing
 * of the sender. The same text sent again counts on the entry it already has.
 * A moderator learns an entry as spam or as legitimate, and the entry stays,
 * marked with what it was learnt as and the generation of the counters it
 * was learnt in: learnt the other way, it moves to the other category;
 * unlearnt, it goes back to review. Deleting an entry leaves what was learnt
 * of it.
 *
 * Entries are kept DAYS days at most, and MAX_ENTRIES at most whatever comes
 * in: past that number, each new entry pushes the oldest out, so a burst of
 * bots sending different texts holds the table at MAX_ENTRIES of MAX_LENGTH
 * characters.
 *
 * @author Laurent Dinclaux - Gecka <laurent@gecka.nc>
 */
class Journal
{
    /**
     * Days an entry is kept.
     */
    public const DAYS = 30;

    /**
     * Entries kept at most, the most recent ones.
     */
    public const MAX_ENTRIES = 5000;

    /**
     * Characters of a text kept, enough to review it.
     */
    private const MAX_LENGTH = 5000;

    /**
     * @var StatisticalFilter
     */
    private StatisticalFilter $statisticalFilter;

    /**
     * @param StatisticalFilter $statisticalFilter The filter the entries are learnt by.
     */
    public function __construct(StatisticalFilter $statisticalFilter)
    {
        $this->statisticalFilter = $statisticalFilter;
    }

    /**
     * Table of the journal
     *
     * @return string
     */
    public static function table(): string
    {
        global $wpdb;

        return $wpdb->prefix . 'gecka_antispam_journal';
    }

    /**
     * Records a submission refused, or counts it again when its text is
     * already there.
     *
     * @param string $surface The form it was sent from.
     * @param string $outcome What refused it.
     * @param string $text    What the filter reads of it.
     *
     * @return void
     */
    public function record(string $surface, string $outcome, string $text): void
    {
        global $wpdb;

        $text = trim(mb_substr($text, 0, self::MAX_LENGTH));

        if ($text === '') {
            return;
        }

        $now = current_time('mysql', true);

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Table of the plugin.
        $wpdb->query(
            $wpdb->prepare(
                'INSERT INTO %i (hash, surface, outcome, text, hits, created, updated) VALUES (%s, %s, %s, %s, 1, %s, %s) ON DUPLICATE KEY UPDATE hits = hits + 1, surface = VALUES(surface), outcome = VALUES(outcome), updated = VALUES(updated)',
                self::table(),
                md5($text),
                $surface,
                $outcome,
                $text,
                $now,
                $now,
            ),
        );

        if ($wpdb->insert_id && $this->total() > self::MAX_ENTRIES) {
            $this->trim();
        }
    }

    /**
     * Entries waiting for review, or those learnt, the most recent first
     *
     * @param int  $page    From 1.
     * @param int  $perPage
     * @param bool $learnt  The entries learnt instead of those waiting.
     *
     * @return array<int, object{id: string, surface: string, outcome: string, text: string, hits: string, created: string, updated: string, learnt: string|null, generation: string|null}>
     */
    public function entries(int $page, int $perPage, bool $learnt = false): array
    {
        global $wpdb;

        $where = self::learntCondition($learnt);

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Table of the plugin, read on the review screen; $where is one of two fixed conditions.
        $rows = $wpdb->get_results($wpdb->prepare("SELECT id, surface, outcome, text, hits, created, updated, learnt, generation FROM %i WHERE $where ORDER BY updated DESC, id DESC LIMIT %d OFFSET %d", self::table(), $perPage, max(0, $page - 1) * $perPage));

        return array_values((array) $rows);
    }

    /**
     * Entries waiting for review, or those learnt
     *
     * @param bool $learnt
     *
     * @return int
     */
    public function count(bool $learnt = false): int
    {
        global $wpdb;

        $where = self::learntCondition($learnt);

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Table of the plugin; $where is one of two fixed conditions.
        return (int) $wpdb->get_var($wpdb->prepare("SELECT COUNT(*) FROM %i WHERE $where", self::table()));
    }

    /**
     * The condition selecting the entries learnt, or those waiting, in a
     * form the index on the column serves
     *
     * @param bool $learnt
     *
     * @return string
     */
    private static function learntCondition(bool $learnt): string
    {
        return $learnt ? 'learnt IS NOT NULL' : 'learnt IS NULL';
    }

    /**
     * Has the filter learn entries as spam or as legitimate. An entry learnt
     * the other way before moves to the category; one already learnt as the
     * category stays as it is.
     *
     * @param int[]  $ids
     * @param string $category StatisticalFilter::SPAM or StatisticalFilter::HAM.
     *
     * @return int Entries now learnt as the category.
     */
    public function learn(array $ids, string $category): int
    {
        $learnt = 0;

        foreach ($this->rows($ids) as $id => $row) {
            $generation = $this->statisticalFilter->relearn($row['text'], $row['learnt'], $row['generation'], $category);

            if ($generation !== null) {
                $this->mark($id, $category, $generation);
                ++$learnt;
            }
        }

        return $learnt;
    }

    /**
     * Has the filter forget entries learnt, which go back to review. An
     * entry learnt before the previous rotation of the counters was halved
     * since and cannot be forgotten exactly: it stays learnt.
     *
     * @param int[] $ids
     *
     * @return array{0: int, 1: int} Entries forgotten, and entries too old to be.
     */
    public function unlearn(array $ids): array
    {
        $done = 0;
        $old = 0;

        foreach ($this->rows($ids) as $id => $row) {
            if ($row['learnt'] === null) {
                continue;
            }

            if ($this->statisticalFilter->unlearn($row['text'], $row['learnt'], (int) $row['generation'])) {
                $this->mark($id, null, null);
                ++$done;
            } else {
                ++$old;
            }
        }

        return [$done, $old];
    }

    /**
     * Sends every entry learnt back to review, for counters that start over
     * and hold none of them.
     *
     * @return void
     */
    public function forget(): void
    {
        global $wpdb;

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Table of the plugin.
        $wpdb->query($wpdb->prepare('UPDATE %i SET learnt = NULL, generation = NULL WHERE learnt IS NOT NULL', self::table()));
    }

    /**
     * Deletes entries, leaving what was learnt of them.
     *
     * @param int[] $ids
     *
     * @return void
     */
    public function delete(array $ids): void
    {
        global $wpdb;

        foreach (array_chunk(array_map('intval', $ids), 500) as $chunk) {
            $in = implode(',', array_fill(0, count($chunk), '%d'));

            // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber -- Table of the plugin; $in is one placeholder per id.
            $wpdb->query($wpdb->prepare("DELETE FROM %i WHERE id IN ($in)", self::table(), ...$chunk));
        }
    }

    /**
     * Deletes every entry.
     *
     * @return void
     */
    public function clear(): void
    {
        global $wpdb;

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Table of the plugin.
        $wpdb->query($wpdb->prepare('DELETE FROM %i', self::table()));
    }

    /**
     * Deletes the entries older than DAYS days, and the oldest past
     * MAX_ENTRIES.
     *
     * @return void
     */
    public function purge(): void
    {
        global $wpdb;

        $table = self::table();

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Table of the plugin, purged once a day.
        $wpdb->query($wpdb->prepare('DELETE FROM %i WHERE updated < %s', $table, gmdate('Y-m-d H:i:s', time() - self::DAYS * DAY_IN_SECONDS)));

        $this->trim();
    }

    /**
     * Every entry, waiting or learnt
     *
     * @return int
     */
    private function total(): int
    {
        global $wpdb;

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Table of the plugin.
        return (int) $wpdb->get_var($wpdb->prepare('SELECT COUNT(*) FROM %i', self::table()));
    }

    /**
     * Records what an entry was learnt as and in which generation, or that
     * it waits for review again.
     *
     * @param int         $id
     * @param string|null $learnt
     * @param int|null    $generation
     *
     * @return void
     */
    private function mark(int $id, ?string $learnt, ?int $generation): void
    {
        global $wpdb;

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Table of the plugin.
        $wpdb->update(self::table(), ['learnt' => $learnt, 'generation' => $generation], ['id' => $id]);
    }

    /**
     * Deletes the oldest entries past MAX_ENTRIES.
     *
     * @return void
     */
    private function trim(): void
    {
        global $wpdb;

        $table = self::table();

        // phpcs:disable WordPress.DB.DirectDatabaseQuery -- Table of the plugin.
        $last = $wpdb->get_row($wpdb->prepare('SELECT updated, id FROM %i ORDER BY updated DESC, id DESC LIMIT 1 OFFSET %d', $table, self::MAX_ENTRIES - 1));

        if ($last) {
            $wpdb->query($wpdb->prepare('DELETE FROM %i WHERE updated < %s OR (updated = %s AND id < %d)', $table, $last->updated, $last->updated, (int) $last->id));
        }
        // phpcs:enable
    }

    /**
     * Text of entries, what they were learnt as and in which generation, by id
     *
     * @param int[] $ids
     *
     * @return array<int, array{text: string, learnt: string|null, generation: int|null}>
     */
    private function rows(array $ids): array
    {
        global $wpdb;

        $rows = [];

        foreach (array_chunk(array_map('intval', $ids), 500) as $chunk) {
            $in = implode(',', array_fill(0, count($chunk), '%d'));

            // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber -- Table of the plugin; $in is one placeholder per id.
            foreach ((array) $wpdb->get_results($wpdb->prepare("SELECT id, text, learnt, generation FROM %i WHERE id IN ($in)", self::table(), ...$chunk)) as $row) {
                $rows[(int) $row->id] = [
                    'text' => (string) $row->text,
                    'learnt' => in_array($row->learnt, [StatisticalFilter::SPAM, StatisticalFilter::HAM], true) ? $row->learnt : null,
                    'generation' => $row->generation === null ? null : (int) $row->generation,
                ];
            }
        }

        return $rows;
    }
}
