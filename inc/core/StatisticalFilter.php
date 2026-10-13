<?php

declare(strict_types=1);

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

namespace Gecka\WP\Plugin\Antispam;

use Gecka\SpamFilter\Generation;
use Gecka\SpamFilter\Label;
use Gecka\SpamFilter\Model\Background;
use Gecka\SpamFilter\Model\ClassCounts;
use Gecka\SpamFilter\Model\CountTable;
use Gecka\SpamFilter\Model\LanguageBackground;
use Gecka\SpamFilter\SpamFilter;
use Gecka\SpamFilter\Storage\FileSnapshotCache;
use Gecka\SpamFilter\Storage\Tally;
use Gecka\WP\Plugin\Antispam\StatisticalFilter\WpdbStorage;

/**
 * The statistical filter: gecka/spamfilter, its counters kept in two tables
 * of the site, compared with the background tables of the languages the
 * site receives.
 *
 * It learns from what people mark as spam or as not spam, and rates a text
 * between 0 (ham) and 1 (spam), 0.5 meaning it knows nothing of the text.
 * The counters are counts on hashes: no word of a text is stored. They come
 * in two generations: what was learnt since the last rotation counts in
 * full, older counts halve at each rotation. Each text learnt is learnt in
 * a numbered generation, which is what unlearning it takes.
 *
 * Rating a text reads the counters into memory, 4 MB per class, from a
 * snapshot file rewritten whenever something was learnt since, and the
 * background tables, 4 MB per language, from the directory of the plugin
 * under uploads. A background table is read only when its file is named
 * after a language code and holds no more counters than a class: up to
 * MAX_LANGUAGES of them, the language of the site first. The others are left
 * out and reported, the filter reading on with the tables that remain.
 *
 * @author Laurent Dinclaux - Gecka <laurent@gecka.nc>
 */
class StatisticalFilter
{
    /**
     * A text marked as spam.
     */
    public const SPAM = 'spam';

    /**
     * A text marked as legitimate.
     */
    public const HAM = 'ham';

    /**
     * Log2 of the number of counters of each class.
     */
    public const BITS = 20;

    /**
     * Characters of a text the filter reads, the rest is left out.
     */
    private const MAX_LENGTH = 20000;

    /**
     * Background tables read at most.
     */
    public const MAX_LANGUAGES = 5;

    /**
     * Bytes of a background table inflated at most: as many counters as a
     * class of the site, and its header.
     */
    private const TABLE_BYTES = (1 << self::BITS) * 4 + 64;

    /**
     * Bytes of a background table file at most, as compressed.
     */
    public const FILE_BYTES = self::TABLE_BYTES + 65536;

    /**
     * Name of a background table, without .bin: a language code.
     */
    public const LANGUAGE_CODE = '/^[a-z]{2,3}(?:[-_][a-z0-9]{2,8})?\z/';

    /**
     * @var SpamFilter|null
     */
    private ?SpamFilter $filter = null;

    /**
     * Table prefix the filter was set up on.
     *
     * @var string
     */
    private string $prefix = '';

    /**
     * The tally read in this request, kept until the counters change: the
     * readiness, the generation and the counts are asked several times per
     * request, for one answer.
     *
     * @var Tally|null
     */
    private ?Tally $tally = null;

    /**
     * Whether $tally was read, and on which table prefix.
     *
     * @var string|null
     */
    private ?string $tallyPrefix = null;

    /**
     * Why the filter could not be set up, the last time it was tried.
     *
     * @var string|null
     */
    private ?string $error = null;

    /**
     * Whether the last text given to learn() could not be learnt for want of
     * a working filter or storage, rather than for being empty.
     *
     * @var bool
     */
    private bool $learningFailed = false;

    /**
     * Whether the last text given to unlearn() could not be forgotten for
     * want of a working filter or storage, rather than for being too old.
     *
     * @var bool
     */
    private bool $unlearningFailed = false;

    /**
     * Background tables read in this request.
     *
     * @var array{directory: string, background: LanguageBackground|null, languages: string[], problems: string[]}|null
     */
    private ?array $backgrounds = null;

    /**
     * Rating of a text, null when there is nothing to rate
     *
     * @param string $text
     *
     * @return float|null Between 0 (ham) and 1 (spam).
     */
    public function classify(string $text): ?float
    {
        $text = $this->prepare($text);
        $filter = $text === '' ? null : $this->filter();

        return $filter ? $filter->classify($text)->probability() : null;
    }

    /**
     * Learns a text as spam or as ham, in the recent generation, or in the
     * archive for a text dated before the last rotation.
     *
     * @param string $text
     * @param string $category self::SPAM or self::HAM.
     * @param bool   $archive
     *
     * @return int|null The generation the text was learnt in, null when it was not.
     */
    public function learn(string $text, string $category, bool $archive = false): ?int
    {
        $text = $this->prepare($text);
        $label = Label::tryFrom($category);
        $this->learningFailed = false;

        if ($text === '' || ! $label) {
            return null;
        }

        $filter = $this->filter();

        try {
            if (! $filter) {
                throw new \RuntimeException($this->error() ?? '');
            }

            $generation = $filter->learn($text, $label, $archive ? Generation::Archive : Generation::Recent);
            $this->flushTally();

            return $generation;
        } catch (\RuntimeException $e) {
            $this->failed($e);
            $this->learningFailed = true;

            return null;
        }
    }

    /**
     * Whether the last text given to learn() was not learnt because the
     * filter or its storage failed; it can be learnt later
     *
     * @return bool
     */
    public function learningFailed(): bool
    {
        return $this->learningFailed;
    }

    /**
     * Forgets a text learnt as spam or as ham. A text learnt before the
     * previous rotation was halved since and cannot be forgotten exactly:
     * nothing changes. Nor does a generation ahead of the storage, whose
     * tables were made again after the text was learnt.
     *
     * @param string $text
     * @param string $category   self::SPAM or self::HAM.
     * @param int    $generation The generation it was learnt in.
     *
     * @return bool Whether the text was forgotten.
     */
    public function unlearn(string $text, string $category, int $generation): bool
    {
        $text = $this->prepare($text);
        $label = Label::tryFrom($category);
        $this->unlearningFailed = false;

        if ($text === '' || ! $label) {
            return false;
        }

        $filter = $this->filter();

        if (! $filter) {
            $this->unlearningFailed = true;

            return false;
        }

        try {
            $forgotten = $filter->unlearn($text, $label, $generation);
            $this->flushTally();

            return $forgotten;
        } catch (\InvalidArgumentException) {
            return false;
        } catch (\RuntimeException $e) {
            $this->failed($e);
            $this->unlearningFailed = true;

            return false;
        }
    }

    /**
     * Learns a text as one category, forgetting it first as the category it
     * was learnt as before when that can still be done exactly.
     *
     * @param string      $text
     * @param string|null $previous   What the text was learnt as, null when it never was.
     * @param int|null    $generation The generation it was learnt in; 0 when none is recorded with it.
     * @param string      $category   What it is to be learnt as.
     *
     * @return int|null The generation the text is now learnt in as $category, null when it is not.
     */
    public function relearn(string $text, ?string $previous, ?int $generation, string $category): ?int
    {
        if ($previous === $category) {
            return $generation ?? 0;
        }

        $forgotten = false;

        if ($previous) {
            $forgotten = $this->unlearn($text, $previous, $generation ?? 0);

            if ($this->unlearningFailed) {
                $this->learningFailed = true;

                return null;
            }
        }

        $learnt = $this->learn($text, $category);

        // Forgotten and not learnt: the text is in no class, put it back in
        // the one the caller still records it in.
        if ($learnt === null && $this->learningFailed && $forgotten) {
            $this->learn($text, (string) $previous);
            $this->learningFailed = true;
        }

        return $learnt;
    }

    /**
     * Ages the counters: the archive halves and the recent counters join it.
     *
     * @return bool Whether the rotation was done.
     */
    public function rotate(): bool
    {
        $filter = $this->filter();

        if (! $filter) {
            return false;
        }

        try {
            $filter->rotate();
        } catch (\RuntimeException $e) {
            $this->failed($e);

            return false;
        }

        $this->flushTally();

        return true;
    }

    /**
     * Generation number, texts of the recent generation and texts learnt in
     * all; null when the tables cannot be read
     *
     * @return Tally|null
     */
    public function tally(): ?Tally
    {
        global $wpdb;

        if (! self::supported()) {
            return null;
        }

        if ($this->tallyPrefix === $wpdb->prefix) {
            return $this->tally;
        }

        try {
            $this->tally = Schema::storage()->tally();
        } catch (\RuntimeException $e) {
            $this->tally = null;
        }

        $this->tallyPrefix = $wpdb->prefix;

        return $this->tally;
    }

    /**
     * Has the next tally() read the counters again: after they changed by
     * another way than this instance, or in a test, between two requests
     * of one process.
     *
     * @return void
     */
    public function flushTally(): void
    {
        $this->tally = null;
        $this->tallyPrefix = null;
    }

    /**
     * Texts learnt as ham and as spam in all, rotations left aside, and
     * counters in use
     *
     * @return array{ham: int, spam: int, features: int}
     */
    public function counts(): array
    {
        $tally = $this->tally();

        try {
            $features = $tally ? Schema::storage()->occupied() : 0;
        } catch (\RuntimeException $e) {
            $features = 0;
        }

        return [
            'ham' => $tally ? $tally->learned(Label::Ham) : 0,
            'spam' => $tally ? $tally->learned(Label::Spam) : 0,
            'features' => $features,
        ];
    }

    /**
     * Whether the filter learnt enough texts of both kinds to rate one, in
     * all: a rotation never brings it back under the minimum
     *
     * @param int $spam Spam texts needed.
     * @param int $ham  Legitimate texts needed.
     *
     * @return bool
     */
    public function ready(int $spam, int $ham): bool
    {
        $tally = $this->tally();

        return $tally && $tally->learned(Label::Spam) >= $spam && $tally->learned(Label::Ham) >= $ham;
    }

    /**
     * Forgets everything learnt: the tables start over with a new identity,
     * and the snapshot of the old ones goes.
     *
     * @return void
     */
    public function reset(): void
    {
        $storage = Schema::storage();
        $storage->drop();
        $storage->install(self::BITS);

        if (is_file($this->snapshot())) {
            wp_delete_file($this->snapshot());
        }

        $this->filter = null;
        $this->error = null;
        $this->flushTally();
    }

    /**
     * Why the filter cannot rate nor learn, null when it can
     *
     * @return string|null
     */
    public function error(): ?string
    {
        if (! self::supported()) {
            return __('The intl and mbstring extensions of PHP are needed.', 'gecka-antispam');
        }

        try {
            Schema::storage()->tally();
        } catch (\RuntimeException $e) {
            return $e->getMessage();
        }

        return $this->error;
    }

    /**
     * Whether PHP has what the library needs
     *
     * @return bool
     */
    public static function supported(): bool
    {
        return extension_loaded('intl') && extension_loaded('mbstring');
    }

    /**
     * Whether the snapshot of the counters can be written; when it cannot,
     * each rating reads them from the tables, which takes longer
     *
     * @return bool
     */
    public static function snapshotWritable(): bool
    {
        $cache = self::directory() . '/cache';

        return is_dir($cache) ? wp_is_writable($cache) : wp_is_writable(self::directory()) || wp_is_writable(dirname(self::directory()));
    }

    /**
     * Languages of the background tables the filter reads
     *
     * @return string[]
     */
    public function languages(): array
    {
        return $this->backgrounds()['languages'];
    }

    /**
     * Background tables left out, each with the reason
     *
     * @return string[]
     */
    public function backgroundProblems(): array
    {
        return $this->backgrounds()['problems'];
    }

    /**
     * The background tables read, by language code
     *
     * @return array<string, CountTable>
     */
    public function backgroundTables(): array
    {
        return $this->backgrounds()['background']?->tables() ?? [];
    }

    /**
     * Directory the background tables are read from, one file per language
     * named after its code (fr.bin, en.bin).
     *
     * @return string
     */
    public function backgroundDirectory(): string
    {
        /**
         * Filters the directory the background tables are read from.
         *
         * @param string $directory
         */
        return (string) apply_filters('gecka_antispam_background_directory', self::directory() . '/background');
    }

    /**
     * Directory of the plugin under uploads, refused to web requests where
     * the server reads .htaccess files.
     *
     * @return string
     */
    public static function directory(): string
    {
        return wp_upload_dir(null, false)['basedir'] . '/gecka-antispam';
    }

    /**
     * Keeps why the filter failed and drops it, so the next call sets it up
     * again.
     *
     * @param \RuntimeException $e
     *
     * @return void
     */
    private function failed(\RuntimeException $e): void
    {
        $this->error = $e->getMessage();
        $this->filter = null;
    }

    /**
     * The text as the filter reads it
     *
     * @param string $text
     *
     * @return string
     */
    private function prepare(string $text): string
    {
        return trim(mb_substr($text, 0, self::MAX_LENGTH));
    }

    /**
     * The filter, set up on the tables of the current site; null when it
     * cannot be
     *
     * @return SpamFilter|null
     */
    private function filter(): ?SpamFilter
    {
        global $wpdb;

        if (! self::supported()) {
            return null;
        }

        // The tables change with the site of a network.
        if (! $this->filter || $this->prefix !== $wpdb->prefix) {
            $this->prefix = $wpdb->prefix;
            $this->filter = null;
            $this->error = null;

            wp_raise_memory_limit('gecka_antispam');

            try {
                $storage = Schema::storage();
                $this->filter = new SpamFilter(site: $this->site($storage), background: $this->background(), storage: $storage);
            } catch (\RuntimeException|\InvalidArgumentException $e) {
                $this->error = $e->getMessage();
            }
        }

        return $this->filter;
    }

    /**
     * The counters, from the snapshot file when it is current, from the
     * tables otherwise, and from the tables alone when the snapshot cannot
     * be written
     *
     * @param WpdbStorage $storage
     *
     * @return ClassCounts
     */
    private function site(WpdbStorage $storage): ClassCounts
    {
        self::protect();

        if (! self::snapshotWritable()) {
            return $storage->load();
        }

        try {
            return (new FileSnapshotCache($storage, $this->snapshot()))->load();
        } catch (\RuntimeException $e) {
            return $storage->load();
        }
    }

    /**
     * The background tables read, null when there is none
     *
     * @return LanguageBackground|null
     */
    private function background(): ?LanguageBackground
    {
        return $this->backgrounds()['background'];
    }

    /**
     * The background tables of the directory, read once per request, and
     * those left out with the reason, recorded for the administration
     *
     * @return array{directory: string, background: LanguageBackground|null, languages: string[], problems: string[]}
     */
    private function backgrounds(): array
    {
        $directory = $this->backgroundDirectory();

        if ($this->backgrounds !== null && $this->backgrounds['directory'] === $directory) {
            return $this->backgrounds;
        }

        $tables = [];
        $problems = [];

        foreach ($this->backgroundFiles($directory) as $file) {
            $name = basename($file);
            $code = strtolower(basename($file, '.bin'));

            if (! preg_match(self::LANGUAGE_CODE, $code)) {
                /* translators: %s: file name */
                $problems[] = sprintf(__('%s: the name is not a language code.', 'gecka-antispam'), $name);
            } elseif (count($tables) >= self::MAX_LANGUAGES) {
                /* translators: 1: file name, 2: number of tables */
                $problems[] = sprintf(__('%1$s: the filter reads %2$d tables at most.', 'gecka-antispam'), $name, self::MAX_LANGUAGES);
            } else {
                try {
                    $tables[$code] = self::table($file);
                } catch (\RuntimeException|\InvalidArgumentException $e) {
                    /* translators: 1: file name, 2: what is wrong with it */
                    $problems[] = sprintf(_x('%1$s: %2$s.', 'file and its problem', 'gecka-antispam'), $name, rtrim($e->getMessage(), '.'));
                }
            }
        }

        return $this->backgrounds = [
            'directory' => $directory,
            'background' => $tables ? new LanguageBackground($tables) : null,
            'languages' => array_keys($tables),
            'problems' => $problems,
        ];
    }

    /**
     * The .bin files of the directory, the one of the language of the site
     * first
     *
     * @param string $directory
     *
     * @return string[]
     */
    private function backgroundFiles(string $directory): array
    {
        $files = glob($directory . '/*.bin') ?: [];
        $site = strtolower(strtok(get_locale(), '_') ?: '');

        usort($files, static fn(string $a, string $b): int => [strtolower(basename($a, '.bin')) !== $site, $a] <=> [strtolower(basename($b, '.bin')) !== $site, $b]);

        return $files;
    }

    /**
     * One background table, refused when the file is not one or holds more
     * counters than a class of the site. The size is checked on the
     * compressed file, then on the inflated stream, before the table is
     * decoded.
     *
     * @param string $file
     *
     * @return CountTable
     */
    private static function table(string $file): CountTable
    {
        $size = is_readable($file) ? filesize($file) : false;
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- A local file of the plugin directory under uploads.
        $binary = $size !== false && $size <= self::FILE_BYTES ? file_get_contents($file) : false;

        return self::decode($binary === false ? '' : $binary);
    }

    /**
     * A background table from its bytes, refused when they are not one or
     * hold more counters than a class of the site; the inflated stream is
     * measured before the table is decoded.
     *
     * @param string $binary
     *
     * @return CountTable
     *
     * @throws Failure When the binary is no table, or too large a one.
     * @throws \RuntimeException When the library cannot read it.
     */
    public static function decode(string $binary): CountTable
    {
        if ($binary === '' || strlen($binary) > self::FILE_BYTES || ! self::inflatesWithin($binary, self::TABLE_BYTES)) {
            throw Failure::because(__('not a background table, or one larger than the filter accepts.', 'gecka-antispam')); // phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- Plain text by design, escaped where shown.
        }

        return Background::fromBinary($binary);
    }

    /**
     * Drops the background tables read in this request, and the filter
     * built on them, for tables just written.
     *
     * @return void
     */
    public function flushBackgrounds(): void
    {
        $this->backgrounds = null;
        $this->filter = null;
    }

    /**
     * Whether a zlib stream inflates to $limit bytes at most. The stream is
     * fed 1 KB at a time, so a slice never inflates past about 1 MB whatever
     * its ratio, and the bytes inflated are counted, not kept.
     *
     * @param string $binary
     * @param int    $limit
     *
     * @return bool
     */
    private static function inflatesWithin(string $binary, int $limit): bool
    {
        $context = inflate_init(ZLIB_ENCODING_DEFLATE);
        $size = 0;

        if ($context === false) {
            return false;
        }

        for ($offset = 0, $length = strlen($binary); $offset <= $length; $offset += 1024) {
            $last = $offset + 1024 > $length;
            // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- A file that is not zlib makes inflate_add() warn; it is refused all the same.
            $piece = @inflate_add($context, substr($binary, $offset, 1024), $last ? ZLIB_FINISH : ZLIB_NO_FLUSH);

            if ($piece === false) {
                return false;
            }

            $size += strlen($piece);

            if ($size > $limit) {
                return false;
            }

            if ($last) {
                break;
            }
        }

        return true;
    }

    /**
     * Snapshot file of the counters of the current site, under a name drawn
     * from the salts of the site
     *
     * @return string
     */
    private function snapshot(): string
    {
        return self::directory() . '/cache/site-' . substr(wp_hash('gecka-antispam-snapshot'), 0, 16) . '.bin';
    }

    /**
     * Creates the directory of the plugin under uploads with what keeps
     * web requests out of it: a .htaccess, for the servers that read it, and
     * an index.php in it and in each of its directories against listings.
     * Under nginx, the server configuration has to refuse the directory.
     *
     * @return void
     */
    public static function protect(): void
    {
        $directory = self::directory();

        if (! wp_mkdir_p($directory)) {
            return;
        }

        // phpcs:disable WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- Small files written once.
        if (! is_file($directory . '/.htaccess')) {
            file_put_contents($directory . '/.htaccess', "Require all denied\n");
        }

        foreach (['', '/background', '/cache'] as $sub) {
            if (is_dir($directory . $sub) && ! is_file($directory . $sub . '/index.php')) {
                file_put_contents($directory . $sub . '/index.php', "<?php\n// Silence is golden.\n");
            }
        }
        // phpcs:enable
    }
}
