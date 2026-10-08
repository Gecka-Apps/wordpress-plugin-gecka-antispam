<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

namespace Gecka\WP\Plugin\Antispam\StatisticalFilter;

use Gecka\SpamFilter\Generation;
use Gecka\SpamFilter\Label;
use Gecka\SpamFilter\Model\ClassCounts;
use Gecka\SpamFilter\Storage\Storage;
use Gecka\SpamFilter\Storage\Tally;
use Gecka\SpamFilter\Tokenizer\FeatureHasher;

/**
 * The counters of the spam filter in two tables of the site, through $wpdb.
 *
 * One row per feature slot holding the recent and the archived counter of
 * each class, and a key/value table for the feature space size, the text
 * counters of each generation, the texts learnt in all, the generation and
 * version numbers and a random installation id. The counters are signed,
 * MySQL refusing an unsigned column that a subtraction would take below
 * zero; GREATEST() keeps them at zero or above.
 *
 * A text is learnt inside a transaction of its own, opened with START
 * TRANSACTION: called while another transaction is open on the connection,
 * it commits that one first. Reading opens none.
 *
 * @author Laurent Dinclaux - Gecka <laurent@gecka.nc>
 */
class WpdbStorage implements Storage
{
    /**
     * Rows per query, read or written.
     */
    private const CHUNK = 500;

    /**
     * Reads of the counters at most while texts are being learnt.
     */
    private const LOAD_TRIES = 3;

    /**
     * Rows of the key/value table.
     */
    private const META = ['bits', 'hash', 'texts_ham', 'texts_spam', 'archive_texts_ham', 'archive_texts_spam', 'learned_ham', 'learned_spam', 'generation', 'version', 'install_id'];

    /**
     * @var string
     */
    private string $counts;

    /**
     * @var string
     */
    private string $meta;

    /**
     * @var array<string, int>|null
     */
    private ?array $values = null;

    /**
     * @param string $prefix Start of both table names, the site prefix included.
     */
    public function __construct(string $prefix)
    {
        $this->counts = $prefix . 'counts';
        $this->meta = $prefix . 'meta';
    }

    /**
     * Table of the counters
     *
     * @return string
     */
    public function countsTable(): string
    {
        return $this->counts;
    }

    /**
     * Table of the feature space size, the text counters and the version
     *
     * @return string
     */
    public function metaTable(): string
    {
        return $this->meta;
    }

    /**
     * Creates the tables, or brings them up to date, and writes the rows of
     * the key/value table that are missing. The feature space size is fixed
     * by the first install: tables installed with another size are refused.
     *
     * @param int $bits Log2 of the number of slots of each class.
     *
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function install(int $bits): void
    {
        global $wpdb;

        require_once ABSPATH . 'wp-admin/includes/upgrade.php';

        $collate = $wpdb->get_charset_collate();

        dbDelta(
            "CREATE TABLE {$this->counts} (
            feature int(10) unsigned NOT NULL,
            count_ham int(11) NOT NULL DEFAULT 0,
            count_spam int(11) NOT NULL DEFAULT 0,
            archive_ham int(11) NOT NULL DEFAULT 0,
            archive_spam int(11) NOT NULL DEFAULT 0,
            PRIMARY KEY  (feature)
            ) $collate;",
        );

        dbDelta(
            "CREATE TABLE {$this->meta} (
            name varchar(32) NOT NULL,
            value bigint(20) NOT NULL DEFAULT 0,
            PRIMARY KEY  (name)
            ) $collate;",
        );

        $rows = array_merge(
            array_fill_keys(self::META, 0),
            [
                'bits' => $bits,
                'hash' => FeatureHasher::VERSION,
                'install_id' => random_int(1, PHP_INT_MAX),
            ],
        );

        foreach ($rows as $name => $value) {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Table of the plugin.
            $wpdb->query($wpdb->prepare('INSERT IGNORE INTO %i (name, value) VALUES (%s, %d)', $this->meta, $name, $value));
        }

        $this->values = null;
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Table of the plugin.
        $installed = (int) $wpdb->get_var($wpdb->prepare('SELECT value FROM %i WHERE name = %s', $this->meta, 'bits'));

        if ($installed !== $bits) {
            /* translators: 1: feature space size of the tables, 2: size asked for */
            throw new \InvalidArgumentException(esc_html(sprintf(__('The spam filter tables were installed with %1$d bits, they cannot become %2$d: forget everything learnt and learn again.', 'gecka-antispam'), $installed, $bits)));
        }
    }

    /**
     * Drops both tables.
     *
     * @return void
     */
    public function drop(): void
    {
        global $wpdb;

        foreach ([$this->counts, $this->meta] as $table) {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.DirectDatabaseQuery.SchemaChange -- Table of the plugin.
            $wpdb->query($wpdb->prepare('DROP TABLE IF EXISTS %i', $table));
        }

        $this->values = null;
    }

    /**
     * Rebuilds the counters from the rows, read in chunks in the order of the
     * key, both generations added together. Each chunk is a query of its
     * own, outside any transaction: when the version moved while they were
     * read, a text was learnt in between and the counters are read again,
     * LOAD_TRIES times at most.
     *
     * @return ClassCounts
     */
    public function load(): ClassCounts
    {
        for ($try = 1; ; $try++) {
            $this->values = null;
            $meta = $this->read();
            $counts = ClassCounts::fromRows($meta['bits'], $this->rows(), $meta['texts_spam'] + $meta['archive_texts_spam'], $meta['texts_ham'] + $meta['archive_texts_ham']);
            $this->values = null;

            if ($try >= self::LOAD_TRIES || $this->read()['version'] === $meta['version']) {
                return $counts;
            }
        }
    }

    /**
     * Adds one text's deltas to a class in one generation inside a
     * transaction, visiting the slots in key order so that concurrent
     * transactions lock rows the same way.
     *
     * @param array<int, int> $hashed     Feature hash => count.
     * @param Label           $label
     * @param int             $sign       1 to learn, -1 to unlearn.
     * @param Generation      $generation
     *
     * @return int The generation number the text was written under.
     */
    public function apply(array $hashed, Label $label, int $sign, Generation $generation = Generation::Recent): int
    {
        $meta = $this->read();
        $mask = (1 << $meta['bits']) - 1;
        $slots = [];

        foreach ($hashed as $hash => $count) {
            $slot = $hash & $mask;
            $slots[$slot] = ($slots[$slot] ?? 0) + $count;
        }

        ksort($slots);

        $class = $label->isSpam() ? 'spam' : 'ham';
        $recent = $generation === Generation::Recent;
        $column = ($recent ? 'count_' : 'archive_') . $class;
        $texts = ($recent ? 'texts_' : 'archive_texts_') . $class;

        $current = $this->transaction(
            function () use ($slots, $column, $texts, $class, $sign): int {
                $current = $this->lockGeneration();

                $sign > 0 ? $this->add($slots, $column) : $this->subtract($slots, $column);
                $this->bump($texts, $sign);
                $this->bump('learned_' . $class, $sign);
                $this->bump('version', 1);

                return $current;
            },
        );

        $this->values = null;

        return $current;
    }

    /**
     * Halves every archived counter and text count, rounding down, adds the
     * recent ones to them, empties the recent generation, drops the rows
     * left empty and moves the generation and the version.
     *
     * The row of the generation is locked first, as apply() does, so both
     * take their locks in the same order; once it is held, no text can move
     * the counters nor the key/value table before the rotation commits. MySQL assigns from left to
     * right and SQLite from the values the row had, so either way the
     * archive takes the recent count before it is emptied.
     *
     * @return void
     */
    public function rotate(): void
    {
        $this->read();

        $this->transaction(
            function (): void {
                global $wpdb;

                $this->lockGeneration();

                // phpcs:disable WordPress.DB.DirectDatabaseQuery -- Table of the plugin.
                self::ensure($wpdb->query($wpdb->prepare('UPDATE %i SET archive_ham = (archive_ham >> 1) + count_ham, archive_spam = (archive_spam >> 1) + count_spam, count_ham = 0, count_spam = 0', $this->counts)));
                self::ensure($wpdb->query($wpdb->prepare('DELETE FROM %i WHERE count_ham = 0 AND count_spam = 0 AND archive_ham = 0 AND archive_spam = 0', $this->counts)));
                // phpcs:enable

                $this->values = null;
                $meta = $this->read();

                $this->set('archive_texts_ham', ($meta['archive_texts_ham'] >> 1) + $meta['texts_ham']);
                $this->set('archive_texts_spam', ($meta['archive_texts_spam'] >> 1) + $meta['texts_spam']);
                $this->set('texts_ham', 0);
                $this->set('texts_spam', 0);
                $this->bump('generation', 1);
                $this->bump('version', 1);
            },
        );

        $this->values = null;
    }

    /**
     * Generation number and text counts, read from the table every time.
     *
     * @return Tally
     */
    public function tally(): Tally
    {
        $this->values = null;
        $meta = $this->read();

        return new Tally($meta['generation'], $meta['texts_spam'], $meta['texts_ham'], $meta['learned_spam'], $meta['learned_ham']);
    }

    /**
     * Number of changes applied since the install, read from the table every time.
     *
     * @return int
     */
    public function version(): int
    {
        $this->values = null;

        return $this->read()['version'];
    }

    /**
     * The tables and the random id drawn at install.
     *
     * @return string
     */
    public function identity(): string
    {
        return 'wpdb:' . $this->counts . ':' . $this->read()['install_id'];
    }

    /**
     * Feature slots holding a count
     *
     * @return int
     */
    public function occupied(): int
    {
        global $wpdb;

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Table of the plugin.
        return (int) $wpdb->get_var($wpdb->prepare('SELECT COUNT(*) FROM %i', $this->counts));
    }

    /**
     * Adds positive deltas, several slots per query. VALUES() hands the
     * update the delta itself, never clamped since it is positive.
     *
     * @param array<int, int> $slots Slot => delta, in key order.
     * @param string          $column
     *
     * @return void
     */
    private function add(array $slots, string $column): void
    {
        global $wpdb;

        foreach (array_chunk($slots, self::CHUNK, true) as $chunk) {
            $values = implode(',', array_fill(0, count($chunk), '(%d, %d)'));
            $arguments = [];

            foreach ($chunk as $slot => $delta) {
                $arguments[] = $slot;
                $arguments[] = $delta;
            }

            // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber -- Table of the plugin; $values is one pair of placeholders per slot.
            self::ensure($wpdb->query($wpdb->prepare("INSERT INTO %i (feature, %i) VALUES $values ON DUPLICATE KEY UPDATE %i = %i + VALUES(%i)", $this->counts, $column, ...$arguments, ...array_fill(0, 3, $column))));
        }
    }

    /**
     * Subtracts deltas, one query per distinct delta and chunk of slots, then
     * drops the rows left empty. A slot without a row has nothing to lose.
     *
     * @param array<int, int> $slots Slot => delta, in key order.
     * @param string          $column
     *
     * @return void
     */
    private function subtract(array $slots, string $column): void
    {
        global $wpdb;

        $byDelta = [];

        foreach ($slots as $slot => $delta) {
            $byDelta[$delta][] = $slot;
        }

        foreach ($byDelta as $delta => $group) {
            foreach (array_chunk($group, self::CHUNK) as $chunk) {
                $in = implode(',', array_fill(0, count($chunk), '%d'));

                // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber -- Table of the plugin; $in is one placeholder per slot.
                self::ensure($wpdb->query($wpdb->prepare("UPDATE %i SET %i = GREATEST(0, %i - %d) WHERE feature IN ($in)", $this->counts, $column, $column, $delta, ...$chunk)));
            }
        }

        foreach (array_chunk(array_keys($slots), self::CHUNK) as $chunk) {
            $in = implode(',', array_fill(0, count($chunk), '%d'));

            // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber -- Table of the plugin; $in is one placeholder per slot.
            self::ensure($wpdb->query($wpdb->prepare("DELETE FROM %i WHERE feature IN ($in) AND count_ham = 0 AND count_spam = 0 AND archive_ham = 0 AND archive_spam = 0", $this->counts, ...$chunk)));
        }
    }

    /**
     * Adds to a row of the key/value table, keeping it at zero or above.
     *
     * @param string $name
     * @param int    $delta
     *
     * @return void
     */
    private function bump(string $name, int $delta): void
    {
        global $wpdb;

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Table of the plugin.
        self::ensure($wpdb->query($wpdb->prepare('UPDATE %i SET value = GREATEST(0, value + %d) WHERE name = %s', $this->meta, $delta, $name)));
    }

    /**
     * Sets a row of the key/value table.
     *
     * @param string $name
     * @param int    $value
     *
     * @return void
     */
    private function set(string $name, int $value): void
    {
        global $wpdb;

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Table of the plugin.
        self::ensure($wpdb->query($wpdb->prepare('UPDATE %i SET value = %d WHERE name = %s', $this->meta, $value, $name)));
    }

    /**
     * The counter rows, in key order, both generations added together
     *
     * @return \Generator<int, array{0: int, 1: int, 2: int}>
     */
    private function rows(): \Generator
    {
        global $wpdb;

        $after = -1;

        do {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Table of the plugin, read in chunks.
            $rows = (array) $wpdb->get_results($wpdb->prepare('SELECT feature, count_ham + archive_ham, count_spam + archive_spam FROM %i WHERE feature > %d ORDER BY feature LIMIT %d', $this->counts, $after, self::CHUNK * 10), ARRAY_N);

            foreach ($rows as $row) {
                $after = (int) $row[0];

                yield [$after, (int) $row[1], (int) $row[2]];
            }
        } while (count($rows) === self::CHUNK * 10);
    }

    /**
     * The generation number, its row locked until the end of the
     * transaction. apply() and rotate() both take this lock before touching
     * the counters, so a rotation never falls between the counters and the
     * text counts of one text, and apply() returns the generation it wrote
     * under. On SQLite, which has no row locks, the transaction holds the
     * whole database.
     *
     * @return int
     */
    private function lockGeneration(): int
    {
        global $wpdb;

        // phpcs:disable WordPress.DB.DirectDatabaseQuery -- Table of the plugin, locked for one write.
        $value = defined('DB_ENGINE') && DB_ENGINE === 'sqlite'
            ? $wpdb->get_var($wpdb->prepare('SELECT value FROM %i WHERE name = %s', $this->meta, 'generation'))
            : $wpdb->get_var($wpdb->prepare('SELECT value FROM %i WHERE name = %s FOR UPDATE', $this->meta, 'generation'));
        // phpcs:enable

        if ($value === null) {
            self::ensure(false);
        }

        return (int) $value;
    }

    /**
     * Runs $work inside a transaction, rolled back when a query fails.
     *
     * @template T
     *
     * @param callable(): T $work
     *
     * @return T
     */
    private function transaction(callable $work): mixed
    {
        global $wpdb;

        // phpcs:disable WordPress.DB.DirectDatabaseQuery -- One text learnt in one go.
        if ($wpdb->query('START TRANSACTION') === false) {
            self::ensure(false);
        }

        try {
            $result = $work();
            $wpdb->query('COMMIT');

            return $result;
        } catch (\Throwable $e) {
            $wpdb->query('ROLLBACK');

            throw $e;
        }
        // phpcs:enable
    }

    /**
     * Throws when a query failed.
     *
     * @param int|bool $result What $wpdb->query() returned.
     *
     * @return void
     */
    private static function ensure(int|bool $result): void
    {
        global $wpdb;

        if ($result === false) {
            throw new \RuntimeException(esc_html__('A query on the spam filter tables failed:', 'gecka-antispam') . ' ' . esc_html($wpdb->last_error));
        }
    }

    /**
     * The key/value table, read once until something changes it
     *
     * @return array<string, int>
     */
    private function read(): array
    {
        global $wpdb;

        if ($this->values !== null) {
            return $this->values;
        }

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Table of the plugin; the version moves with every text learnt.
        $rows = $wpdb->get_results($wpdb->prepare('SELECT name, value FROM %i', $this->meta), ARRAY_N);
        $values = array_fill_keys(self::META, 0);

        foreach ((array) $rows as $row) {
            if (array_key_exists($row[0], $values)) {
                $values[$row[0]] = (int) $row[1];
            }
        }

        if ($values['bits'] === 0) {
            throw new \RuntimeException(esc_html__('The spam filter tables are not installed.', 'gecka-antispam'));
        }

        if ($values['hash'] !== FeatureHasher::VERSION) {
            throw new \RuntimeException(esc_html__('The spam filter tables hold counts of another version of the filter: forget everything learnt and learn again.', 'gecka-antispam'));
        }

        return $this->values = $values;
    }
}
