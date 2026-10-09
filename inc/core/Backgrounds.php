<?php

declare(strict_types=1);

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

namespace Gecka\WP\Plugin\Antispam;

use Gecka\SpamFilter\Model\BackgroundDownloader;
use Gecka\SpamFilter\Tokenizer\FeatureHasher;

/**
 * The background tables of the statistical filter, downloaded from the
 * releases of spamfilter-backgrounds and kept up to date.
 *
 * The tables wanted are those of the languages the settings name or, when
 * they name none, those of the site (its locale, the languages of WPML or
 * Polylang) and English, which most sites receive: MAX_LANGUAGES at most,
 * the language of the site first.
 *
 * Updating goes in steps, so that no request carries more than one
 * download: check() reads the manifest of the release and queues the tables
 * wanted whose file is missing or differs from the release, then next()
 * downloads the first table of the queue, checks it against the size, the
 * SHA-256 and the feature hash version the manifest announces, decodes it
 * and moves it in place of its file. The statistical filter tab runs the
 * steps through the REST API, showing the progress; the scheduled event
 * runs them within a time budget and schedules itself again while tables
 * remain. The manifest is read again every INTERVAL, or the next day while
 * a table wanted is missing or the last check failed. A request holds a lock
 * while it changes the state or writes a table. A table the plugin installed goes once its
 * language is no longer wanted; a table copied by hand, or one the release
 * stopped publishing, stays.
 *
 * The requests are plain downloads from GitHub, under a user agent naming
 * the plugin only: nothing of the site goes out.
 *
 * @author Laurent Dinclaux - Gecka <laurent@gecka.nc>
 */
class Backgrounds
{
    /**
     * Option holding the state of the tables: those installed with their
     * checksum, the release and the languages it offers, the tables queued,
     * the last check and the errors.
     */
    public const OPTION = 'gecka_antispam_backgrounds';

    /**
     * Event updating the tables outside a visit.
     */
    public const EVENT = 'gecka_antispam_backgrounds';

    /**
     * Seconds between two readings of the manifest.
     */
    public const INTERVAL = 7 * 86400;

    /**
     * Sentences from which a table counts as solid, average or weak; below
     * the last, it is poor.
     */
    public const SOLID = 100000;

    public const AVERAGE = 10000;

    public const WEAK = 1000;

    /**
     * Seconds a download waits for its table at most, under the time limit
     * of a request.
     */
    public const TIMEOUT = 25;

    /**
     * Bytes of the manifest read at most.
     */
    private const MANIFEST_BYTES = 4 * 1024 * 1024;

    /**
     * Transient telling the statistical filter tab of a user to start the
     * downloads the settings saved just queued.
     */
    public const QUEUED = 'gecka_antispam_backgrounds_queued_';

    /**
     * Option holding, while a request checks or downloads, the time it took
     * the lock.
     */
    public const LOCK = 'gecka_antispam_backgrounds_lock';

    /**
     * Languages a release may offer at most, and characters of a name or a
     * source kept: what the plugin stores and the tab shows of a release
     * stays bounded whatever the release says.
     */
    private const MAX_LANGUAGES = 200;

    private const MAX_TEXT = 100;

    /**
     * Value of the lock while this request holds it.
     *
     * @var string|null
     */
    private ?string $lockToken = null;

    /**
     * Redirections followed at most to download a file: GitHub serves a
     * release file through two.
     */
    private const REDIRECTS = 5;

    /**
     * The state read from the option, until the option changes.
     *
     * @var array{tables: array<string, string>, release: string, languages: array<string, array{name: string, sentences: int, words: int, sources: string[], sha256: string, url: string, bytes: int}>, pending: string[], checked: int, error: string, errors: array<string, string>}|null
     */
    private ?array $state = null;

    /**
     * @var StatisticalFilter
     */
    private StatisticalFilter $statisticalFilter;

    /**
     * @var Settings
     */
    private Settings $settings;

    /**
     * @param StatisticalFilter $statisticalFilter The filter reading the tables.
     * @param Settings          $settings
     */
    public function __construct(StatisticalFilter $statisticalFilter, Settings $settings)
    {
        $this->statisticalFilter = $statisticalFilter;
        $this->settings = $settings;
    }

    /**
     * Hooks the updates up: the scheduled event, and the settings of the
     * filter saved.
     *
     * @return void
     */
    public function setup(): void
    {
        add_action(self::EVENT, [$this, 'refresh']);

        foreach (['add_option_', 'update_option_', 'delete_option_'] as $hook) {
            add_action(
                $hook . self::OPTION,
                function (): void {
                    $this->state = null;
                },
            );
        }

        // After Settings::flush(), so that the new settings are read.
        add_action('update_option_' . Settings::OPTION, [$this, 'settingsSaved'], 20, 2);
    }

    /**
     * Whether the plugin downloads the tables and keeps them up to date
     *
     * @return bool
     */
    public static function enabled(): bool
    {
        /**
         * Filters whether Gecka Antispam downloads the background tables and
         * keeps them up to date. False leaves the directory to whoever fills
         * it.
         *
         * @param bool $enabled
         */
        return (bool) apply_filters('gecka_antispam_background_updates', true);
    }

    /**
     * Whether the tables are to be downloaded now: the filter is on and can
     * read them, and the plugin keeps the tables
     *
     * @return bool
     */
    public function active(): bool
    {
        return (bool) $this->settings->get('filter') && StatisticalFilter::supported() && self::enabled();
    }

    /**
     * Takes the lock of the downloads, so that two requests never change
     * the state nor write a table at once. A lock older than twice TIMEOUT
     * belongs to a request that died, and is taken over.
     *
     * @return bool Whether the lock was taken; false while another request holds it.
     */
    public function lock(): bool
    {
        global $wpdb;

        $token = time() . ':' . wp_generate_password(12, false);

        // phpcs:disable WordPress.DB.DirectDatabaseQuery -- An atomic insert, as WP_Upgrader::create_lock() does; the option cache never holds it.
        if ($wpdb->query($wpdb->prepare('INSERT IGNORE INTO %i (option_name, option_value, autoload) VALUES (%s, %s, %s)', $wpdb->options, self::LOCK, $token, 'off'))) {
            $this->lockToken = $token;

            return true;
        }

        $since = $wpdb->get_var($wpdb->prepare('SELECT option_value FROM %i WHERE option_name = %s', $wpdb->options, self::LOCK));

        if ($since === null || (int) $since > time() - 2 * self::TIMEOUT) {
            return false;
        }

        if ($wpdb->query($wpdb->prepare('UPDATE %i SET option_value = %s WHERE option_name = %s AND option_value = %s', $wpdb->options, $token, self::LOCK, $since))) {
            $this->lockToken = $token;

            return true;
        }

        return false;
        // phpcs:enable
    }

    /**
     * Releases the lock of the downloads, when this request holds it: a
     * request outliving the takeover delay must not release the lock of the
     * request that took it over.
     *
     * @return void
     */
    public function unlock(): void
    {
        global $wpdb;

        if ($this->lockToken === null) {
            return;
        }

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- See lock().
        $wpdb->delete($wpdb->options, ['option_name' => self::LOCK, 'option_value' => $this->lockToken]);
        $this->lockToken = null;
    }

    /**
     * Quality of a table by the sentences it was built from: solid, average,
     * weak or poor
     *
     * @param int $sentences
     *
     * @return string
     */
    public static function quality(int $sentences): string
    {
        return match (true) {
            $sentences >= self::SOLID => 'solid',
            $sentences >= self::AVERAGE => 'average',
            $sentences >= self::WEAK => 'weak',
            default => 'poor',
        };
    }

    /**
     * Updates the tables when the filter is on and a check is due.
     *
     * @return void
     */
    public function refresh(): void
    {
        if ($this->due()) {
            $this->update();
        }
    }

    /**
     * When the settings saved change the languages wanted, or switch the
     * filter on: deletes the tables no longer wanted, and queues the
     * download of the others for the scheduled event and for the statistical
     * filter tab, which starts it when it opens. Nothing is downloaded while
     * the settings are saved.
     *
     * @param mixed $old
     * @param mixed $new
     *
     * @return void
     */
    public function settingsSaved(mixed $old, mixed $new): void
    {
        $old = is_array($old) ? $old : [];
        $new = is_array($new) ? $new : [];

        if (empty($new['filter']) || ! self::enabled() || (($old['background_languages'] ?? []) === ($new['background_languages'] ?? []) && ! empty($old['filter']))) {
            return;
        }

        $this->prune();
        $this->schedule();

        if (get_current_user_id()) {
            set_transient(self::QUEUED . get_current_user_id(), 1, HOUR_IN_SECONDS);
        }
    }

    /**
     * Whether the statistical filter tab of the current user is to start the
     * downloads the settings saved queued; asking clears it
     *
     * @return bool
     */
    public function takeQueued(): bool
    {
        $key = self::QUEUED . get_current_user_id();
        $queued = (bool) get_transient($key);

        delete_transient($key);

        return $queued;
    }

    /**
     * Whether the tables are to be checked: the filter is on, and the
     * interval is over, a table wanted is missing, tables wait in the queue
     * or a table installed has no entry of the release, as after a change of
     * the state the plugin keeps
     *
     * @return bool
     */
    public function due(): bool
    {
        if (! $this->active()) {
            return false;
        }

        $state = $this->state();

        return time() - $state['checked'] >= self::INTERVAL
            || $state['pending']
            || array_diff($this->wanted(), array_keys($state['tables'])) !== []
            || array_diff(array_keys($state['tables']), array_keys($state['languages'])) !== [];
    }

    /**
     * Checks the release and downloads the tables it queues, a table being
     * started while the time budget lasts; what remains goes to the
     * scheduled event again. A download lasts TIMEOUT at most, so the whole
     * takes $seconds and two TIMEOUT at worst: the check, then the last table.
     *
     * @param float $seconds Time budget.
     *
     * @return bool|null Whether everything went through, null when another request is updating.
     */
    public function update(float $seconds = 20): ?bool
    {
        if (! $this->lock()) {
            $this->schedule();

            return null;
        }

        try {
            $deadline = microtime(true) + $seconds;
            $checked = $this->check() !== null;

            while ($checked && microtime(true) < $deadline) {
                if ($this->next() === null) {
                    break;
                }
            }
        } finally {
            $this->unlock();
        }

        if ($this->state()['pending']) {
            $this->schedule();
        }

        return $checked && $this->errors() === '';
    }

    /**
     * Reads the manifest of the release, deletes the tables no longer wanted
     * and queues those wanted whose file is missing or differs from the
     * release. A check that fails keeps the time of the last one that went
     * through, so the daily event tries again. The caller holds the lock.
     *
     * @return array<int, array{code: string, name: string}>|null The tables queued, null when the release could not be read.
     */
    public function check(): ?array
    {
        $state = $this->state();
        $state['error'] = '';
        $state['errors'] = [];
        $state['pending'] = [];

        try {
            $directory = $this->directory();
            $manifest = $this->manifest();
            $state['release'] = is_string($manifest['version'] ?? null) ? $manifest['version'] : '';
            $state['languages'] = [];

            foreach ($manifest['languages'] as $code => $entry) {
                if (count($state['languages']) >= self::MAX_LANGUAGES) {
                    break;
                }

                if (is_string($code) && preg_match(StatisticalFilter::LANGUAGE_CODE, $code) && is_array($entry)) {
                    $state['languages'][$code] = self::entry($code, $entry);
                }
            }

            foreach (self::pick($this->requested(), $state['languages']) as $code) {
                $path = "$directory/$code.bin";

                if (isset($state['languages'][$code]) && (! is_file($path) || hash_file('sha256', $path) !== $state['languages'][$code]['sha256'])) {
                    $state['pending'][] = $code;
                }
            }

            $state['checked'] = time();
        } catch (\RuntimeException $e) {
            $state['error'] = $e->getMessage();
            $this->save($state);

            return null;
        }

        $this->save($state);
        $this->prune();

        return array_map(fn(string $code): array => ['code' => $code, 'name' => $this->name($code)], $state['pending']);
    }

    /**
     * Downloads the first table of the queue and takes it off, whether it
     * went through or not. The caller holds the lock.
     *
     * @return array{code: string, name: string, error: string|null, left: int}|null Null when the queue is empty.
     */
    public function next(): ?array
    {
        $state = $this->state();
        $code = array_shift($state['pending']);

        if ($code === null) {
            return null;
        }

        $error = null;

        try {
            $entry = $state['languages'][$code] ?? null;

            if ($entry === null || ! preg_match(StatisticalFilter::LANGUAGE_CODE, (string) $code)) {
                throw Failure::because(__('the release does not offer it.', 'gecka-antispam')); // phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- Plain text by design, escaped where shown.
            }

            $this->download($entry, $this->directory() . "/$code.bin");
            $state['tables'][$code] = $entry['sha256'];
            unset($state['errors'][$code]);
        } catch (\RuntimeException|\InvalidArgumentException $e) {
            $error = rtrim($e->getMessage(), '.') . '.';
            $state['errors'][$code] = $error;
        }

        $this->save($state);
        $this->statisticalFilter->flushBackgrounds();

        return ['code' => $code, 'name' => $this->name($code), 'error' => $error, 'left' => count($state['pending'])];
    }

    /**
     * Deletes the tables the plugin installed for a language no longer
     * wanted, and takes them off the queue. A table copied by hand stays.
     *
     * @return void
     */
    public function prune(): void
    {
        $state = $this->state();
        $requested = $this->requested();
        $directory = $this->statisticalFilter->backgroundDirectory();

        foreach ($state['tables'] as $code => $checksum) {
            $code = (string) $code;

            if (in_array($code, $requested, true)) {
                continue;
            }

            $path = "$directory/$code.bin";

            if (preg_match(StatisticalFilter::LANGUAGE_CODE, $code) && is_file($path) && hash_file('sha256', $path) === $checksum) {
                wp_delete_file($path);
            }

            unset($state['tables'][$code], $state['errors'][$code]);
        }

        $state['pending'] = array_values(array_intersect($state['pending'], $requested));
        $this->save($state);
        $this->statisticalFilter->flushBackgrounds();
    }

    /**
     * Languages of the tables wanted, as the settings name them or as the
     * site has them, before the release says which it offers
     *
     * @return string[]
     */
    public function requested(): array
    {
        $chosen = array_values(array_filter((array) $this->settings->get('background_languages'), 'is_string'));

        return $chosen ?: self::siteLanguages();
    }

    /**
     * Languages of the tables wanted that the release offers, MAX_LANGUAGES
     * at most; all of those requested while the release is unknown
     *
     * @return string[]
     */
    public function wanted(): array
    {
        return self::pick($this->requested(), $this->state()['languages']);
    }

    /**
     * The languages of the site, its own first, then English
     *
     * @return string[]
     */
    public static function siteLanguages(): array
    {
        $locales = [get_locale()];

        // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- The public API of WPML.
        foreach ((array) apply_filters('wpml_active_languages', null, 'skip_missing=0') as $language) {
            $locales[] = is_array($language) ? (string) ($language['default_locale'] ?? '') : '';
        }

        if (function_exists('pll_languages_list')) {
            $locales = array_merge($locales, array_map('strval', (array) pll_languages_list(['fields' => 'locale'])));
        }

        $locales[] = 'en';
        $codes = array_map(static fn(string $locale): string => strtolower(explode('_', $locale)[0]), $locales);

        return array_values(array_unique(array_filter($codes, static fn(string $code): bool => (bool) preg_match(StatisticalFilter::LANGUAGE_CODE, $code))));
    }

    /**
     * Name of a language in the language of the current user, the name the
     * release gives when intl has none
     *
     * @param string $code
     *
     * @return string
     */
    public function name(string $code): string
    {
        $name = class_exists('Locale') ? (string) \Locale::getDisplayLanguage($code, get_user_locale()) : '';

        if ($name === '' || strtolower($name) === $code) {
            $name = $this->state()['languages'][$code]['name'] ?? $code;
        }

        // WordPress fills in for mb_substr without the extension, not for
        // mb_strtoupper.
        return function_exists('mb_strtoupper') ? mb_strtoupper(mb_substr($name, 0, 1)) . mb_substr($name, 1) : ucfirst($name);
    }

    /**
     * The errors of the last check and of the downloads since, one line
     *
     * @return string
     */
    public function errors(): string
    {
        $state = $this->state();
        $lines = $state['error'] !== '' ? [$state['error']] : [];

        foreach ($state['errors'] as $code => $error) {
            /* translators: 1: language code, 2: what went wrong */
            $lines[] = sprintf(_x('%1$s: %2$s', 'language and its error', 'gecka-antispam'), $code, $error);
        }

        return implode(' ', $lines);
    }

    /**
     * What the plugin knows of the tables
     *
     * @return array{tables: array<string, string>, release: string, languages: array<string, array{name: string, sentences: int, words: int, sources: string[], sha256: string, url: string, bytes: int}>, pending: string[], checked: int, error: string, errors: array<string, string>}
     */
    public function state(): array
    {
        if ($this->state !== null) {
            return $this->state;
        }

        $saved = (array) get_option(self::OPTION, []);
        $languages = [];

        foreach ((array) ($saved['languages'] ?? []) as $code => $entry) {
            if (is_array($entry) && count($languages) < self::MAX_LANGUAGES) {
                $languages[(string) $code] = self::entry((string) $code, $entry);
            }
        }

        return $this->state = [
            'tables' => array_filter(array_map('strval', (array) ($saved['tables'] ?? []))),
            'release' => (string) ($saved['release'] ?? ''),
            'languages' => $languages,
            'pending' => array_values(array_map('strval', (array) ($saved['pending'] ?? []))),
            'checked' => (int) ($saved['checked'] ?? 0),
            'error' => (string) ($saved['error'] ?? ''),
            'errors' => array_map('strval', (array) ($saved['errors'] ?? [])),
        ];
    }

    /**
     * What is kept of a language a release offers, the texts cut to
     * MAX_TEXT characters
     *
     * @param string               $code
     * @param array<string, mixed> $entry As the release or the saved state gives it.
     *
     * @return array{name: string, sentences: int, words: int, sources: string[], sha256: string, url: string, bytes: int}
     */
    private static function entry(string $code, array $entry): array
    {
        $text = static fn(mixed $value): string => mb_substr(trim((string) (is_scalar($value) ? $value : '')), 0, self::MAX_TEXT);

        return [
            'name' => $text($entry['name'] ?? $code) ?: $code,
            'sentences' => (int) ($entry['sentences'] ?? 0),
            'words' => (int) ($entry['words'] ?? 0),
            'sources' => array_values(array_filter(array_map($text, array_slice((array) ($entry['sources'] ?? []), 0, 10)))),
            'sha256' => (string) ($entry['sha256'] ?? ''),
            'url' => (string) ($entry['url'] ?? ''),
            'bytes' => (int) ($entry['bytes'] ?? 0),
        ];
    }

    /**
     * Saves the state.
     *
     * @param array<string, mixed> $state
     *
     * @return void
     */
    private function save(array $state): void
    {
        update_option(self::OPTION, $state, false);
        $this->state = null;
    }

    /**
     * Schedules the update outside a visit, unless it already is.
     *
     * @return void
     */
    private function schedule(): void
    {
        if (! wp_next_scheduled(self::EVENT)) {
            wp_schedule_single_event(time() + MINUTE_IN_SECONDS, self::EVENT);
        }
    }

    /**
     * The codes requested that the release offers, MAX_LANGUAGES at most;
     * all of them while the release is unknown
     *
     * @param string[]             $requested
     * @param array<string, mixed> $offered   Entries by code, empty when unknown.
     *
     * @return string[]
     */
    private static function pick(array $requested, array $offered): array
    {
        if ($offered) {
            $requested = array_filter($requested, static fn(string $code): bool => isset($offered[$code]));
        }

        return array_slice(array_values(array_unique($requested)), 0, StatisticalFilter::MAX_LANGUAGES);
    }

    /**
     * URL of the manifest of the release
     *
     * @return string
     */
    private static function manifestUrl(): string
    {
        /**
         * Filters the URL of the manifest of the background tables, for a
         * mirror. The tables are downloaded from the same directory only.
         *
         * @param string $url
         */
        return (string) apply_filters('gecka_antispam_background_manifest', BackgroundDownloader::DEFAULT_MANIFEST);
    }

    /**
     * The manifest of the release, refused when it is malformed or built
     * for another feature hash version than the filter's
     *
     * @return array{languages: array<mixed>, version?: mixed}
     */
    private function manifest(): array
    {
        $manifest = json_decode($this->fetch(self::manifestUrl(), self::MANIFEST_BYTES), true);

        if (! is_array($manifest) || ! is_int($manifest['hash_version'] ?? null) || ! is_array($manifest['languages'] ?? null)) {
            throw Failure::because(__('The manifest of the background tables is malformed.', 'gecka-antispam')); // phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- Plain text by design, escaped where shown.
        }

        if ($manifest['hash_version'] !== FeatureHasher::VERSION) {
            // phpcs:disable WordPress.Security.EscapeOutput.ExceptionNotEscaped -- Plain text by design, escaped where shown.
            throw Failure::because(
                sprintf(
                    /* translators: 1: version of the published tables, 2: version of the filter */
                    __('The published background tables are built for feature hash version %1$d, the filter of this version of the plugin reads version %2$d. The tables in place are kept.', 'gecka-antispam'),
                    $manifest['hash_version'],
                    FeatureHasher::VERSION,
                ),
            );
            // phpcs:enable
        }

        /** @var array{languages: array<mixed>, version?: mixed} $manifest */
        return $manifest;
    }

    /**
     * Directory of the tables, created when missing
     *
     * @return string
     */
    private function directory(): string
    {
        $directory = $this->statisticalFilter->backgroundDirectory();

        if (! wp_mkdir_p($directory) || ! wp_is_writable($directory)) {
            /* translators: %s: directory on the server */
            throw Failure::because(sprintf(__('Cannot write in %s.', 'gecka-antispam'), $directory)); // phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- Plain text by design, escaped where shown.
        }

        if (str_starts_with($directory, StatisticalFilter::directory() . '/')) {
            StatisticalFilter::protect();
        }

        return $directory;
    }

    /**
     * Downloads one table, checks it and moves it in place of its file. It
     * is written next to its final name first, under a name of its own, so
     * that a request reading the directory never sees half a table and two
     * downloads of the same table never mix.
     *
     * @param array{url: string, bytes: int, sha256: string} $entry
     * @param string                                         $path
     *
     * @return void
     */
    private function download(array $entry, string $path): void
    {
        if (! self::besideManifest($entry['url']) || $entry['bytes'] <= 0 || $entry['bytes'] > StatisticalFilter::FILE_BYTES || ! preg_match('/^[0-9a-f]{64}$/', $entry['sha256'])) {
            throw Failure::because(__('its entry in the manifest is malformed.', 'gecka-antispam')); // phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- Plain text by design, escaped where shown.
        }

        $binary = $this->fetch($entry['url'], $entry['bytes']);

        if (strlen($binary) !== $entry['bytes'] || ! hash_equals($entry['sha256'], hash('sha256', $binary))) {
            throw Failure::because(__('the download does not match its checksum.', 'gecka-antispam')); // phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- Plain text by design, escaped where shown.
        }

        StatisticalFilter::decode($binary);

        $part = $path . '.' . wp_generate_password(8, false) . '.part';

        // phpcs:disable WordPress.WP.AlternativeFunctions -- A file of the plugin directory under uploads, moved in place in one step.
        if (file_put_contents($part, $binary) === false || ! rename($part, $path)) {
            wp_delete_file($part);

            /* translators: %s: file on the server */
            throw Failure::because(sprintf(__('cannot write %s.', 'gecka-antispam'), $path)); // phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- Plain text by design, escaped where shown.
        }
        // phpcs:enable
    }

    /**
     * Whether a URL lies in the directory of the manifest, or below it:
     * same scheme and host, a path without dot segments, no query
     *
     * @param string $url
     *
     * @return bool
     */
    private static function besideManifest(string $url): bool
    {
        $manifest = wp_parse_url(self::manifestUrl());
        $parts = wp_parse_url($url);

        if (! is_array($manifest) || ! is_array($parts) || isset($parts['query']) || isset($parts['fragment']) || isset($parts['user'])) {
            return false;
        }

        $path = $parts['path'] ?? '';
        $base = substr($manifest['path'] ?? '', 0, (int) strrpos($manifest['path'] ?? '', '/') + 1);

        return strtolower((string) ($parts['scheme'] ?? '')) === strtolower((string) ($manifest['scheme'] ?? ''))
            && strtolower((string) ($parts['host'] ?? '')) === strtolower((string) ($manifest['host'] ?? ''))
            && ($parts['port'] ?? null) === ($manifest['port'] ?? null)
            && $base !== ''
            && str_starts_with($path, $base)
            && ! preg_match('#(?:^|/)\.\.?(?:/|$)|%2e|%2f|\\\\#i', $path);
    }

    /**
     * The body of a URL, $maxBytes at most, within TIMEOUT for the request
     * and the redirections it goes through, each one checked by
     * wp_safe_remote_get() as the first
     *
     * @param string $url
     * @param int    $maxBytes
     *
     * @return string
     */
    private function fetch(string $url, int $maxBytes): string
    {
        $deadline = microtime(true) + self::TIMEOUT;
        $redirects = 0;

        for (;;) {
            $left = $deadline - microtime(true);
            $response = $left > 0 ? wp_safe_remote_get(
                $url,
                [
                    'timeout' => $left,
                    'redirection' => 0,
                    'limit_response_size' => $maxBytes + 1,
                    'user-agent' => 'Gecka-Antispam/' . Plugin::VERSION,
                ],
            ) : new \WP_Error('http_request_failed', __('Operation timed out.', 'gecka-antispam'));

            if (is_wp_error($response)) {
                /* translators: 1: URL, 2: error */
                throw Failure::because(sprintf(__('Cannot download %1$s: %2$s', 'gecka-antispam'), $url, $response->get_error_message())); // phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- Plain text by design, escaped where shown.
            }

            $status = (int) wp_remote_retrieve_response_code($response);
            $location = wp_remote_retrieve_header($response, 'location');

            if ($status < 300 || $status >= 400 || ! is_string($location) || $location === '' || $redirects++ >= self::REDIRECTS) {
                break;
            }

            $url = \WP_Http::make_absolute_url($location, $url);

            if (strtolower((string) wp_parse_url($url, PHP_URL_SCHEME)) !== 'https') {
                /* translators: %s: URL */
                throw Failure::because(sprintf(__('Cannot download %s: redirected off HTTPS.', 'gecka-antispam'), $url)); // phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- Plain text by design, escaped where shown.
            }
        }

        if ($status !== 200) {
            /* translators: 1: URL, 2: HTTP status code */
            throw Failure::because(sprintf(__('Cannot download %1$s: HTTP %2$d.', 'gecka-antispam'), $url, $status)); // phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- Plain text by design, escaped where shown.
        }

        $body = wp_remote_retrieve_body($response);

        if (strlen($body) > $maxBytes) {
            /* translators: %s: URL */
            throw Failure::because(sprintf(__('%s is larger than announced.', 'gecka-antispam'), $url)); // phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- Plain text by design, escaped where shown.
        }

        return $body;
    }
}
