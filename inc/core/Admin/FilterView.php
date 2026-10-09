<?php

declare(strict_types=1);

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

namespace Gecka\WP\Plugin\Antispam\Admin;

use Gecka\WP\Plugin\Antispam\Backgrounds;
use Gecka\WP\Plugin\Antispam\Plugin;
use Gecka\WP\Plugin\Antispam\Settings;
use Gecka\WP\Plugin\Antispam\StatisticalFilter;

/**
 * The statistical filter tab: what the filter learnt and whether it rates,
 * the background tables it reads with their languages, the buttons learning
 * what the site holds and forgetting everything, and the settings of the
 * filter. What the background tables are goes to a tab of the Help.
 *
 * @author Laurent Dinclaux - Gecka <laurent@gecka.nc>
 */
class FilterView
{
    use Controls;

    /**
     * @var Plugin
     */
    private Plugin $plugin;

    /**
     * @param Plugin $plugin
     */
    public function __construct(Plugin $plugin)
    {
        $this->plugin = $plugin;
    }

    /**
     * Prints the tab.
     *
     * @return void
     */
    public function render(): void
    {
        $this->notices();

        printf('<p>%s %s</p>', esc_html__('The statistical filter rates each message from 0 to 100 % spam, comparing it with what it learnt: the spam and the legitimate messages you mark in the comments, Flamingo, Gravity Forms and the Antispam tab of Security > Journal.', 'gecka-antispam'), Help::link(Help::FIELDS)); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped by Help::link().

        $this->state();
        $this->form();
    }

    /**
     * Prints the notices of a reset or a learning done.
     *
     * @return void
     */
    private function notices(): void
    {
        // phpcs:disable WordPress.Security.NonceVerification.Recommended -- Only picks a notice.
        if (sanitize_key($_GET['reset'] ?? '') === 'filter') {
            wp_admin_notice(__('The statistical filter forgot everything it learnt. The comments and messages already marked can be learnt again with the button below.', 'gecka-antispam'), ['type' => 'success', 'dismissible' => true]);
        }

        $backgrounds = sanitize_key($_GET['backgrounds'] ?? '');

        if ($backgrounds === 'updated') {
            $languages = $this->plugin->backgrounds()->state()['tables'];
            /* translators: %s: language codes */
            wp_admin_notice(esc_html($languages ? sprintf(__('Background tables up to date: %s.', 'gecka-antispam'), implode(', ', array_keys($languages))) : __('No background table to download.', 'gecka-antispam')), ['type' => 'success', 'dismissible' => true]);
        } elseif ($backgrounds === 'failed') {
            /* translators: %s: error */
            wp_admin_notice(esc_html(sprintf(__('The background tables could not all be downloaded: %s', 'gecka-antispam'), $this->plugin->backgrounds()->errors())), ['type' => 'error', 'dismissible' => true]);
        } elseif ($backgrounds === 'busy') {
            wp_admin_notice(esc_html__('Another request is updating the background tables. Try again in a minute.', 'gecka-antispam'), ['type' => 'warning', 'dismissible' => true]);
        }

        if (isset($_GET['learnt_spam'], $_GET['learnt_ham'])) {
            wp_admin_notice(
                sprintf(
                    /* translators: 1: spam texts learnt, 2: legitimate texts learnt */
                    __('Learnt: spam texts %1$s, legitimate texts %2$s.', 'gecka-antispam'),
                    number_format_i18n(absint($_GET['learnt_spam'])),
                    number_format_i18n(absint($_GET['learnt_ham'])),
                ),
                ['type' => 'success', 'dismissible' => true],
            );
        }

        if (isset($_GET['learn_failed'])) {
            wp_admin_notice(esc_html__('Learning stopped: the statistical filter could not learn a text. What is left was not marked and will be learnt next time.', 'gecka-antispam'), ['type' => 'error', 'dismissible' => true]);
        }
        // phpcs:enable
    }

    /**
     * Prints whether the filter rates, what it learnt, what the site holds
     * that it has not learnt yet and the buttons, then the background tables.
     *
     * @return void
     */
    private function state(): void
    {
        $settings = $this->plugin->settings();
        $statisticalFilter = $this->plugin->statisticalFilter();
        $on = (bool) $settings->get('filter');
        $counts = $statisticalFilter->counts();
        $error = $statisticalFilter->error();

        printf('<h2>%s</h2>', esc_html__('State', 'gecka-antispam'));

        if (! $on) {
            $state = __('Switched off.', 'gecka-antispam');
        } elseif ($error) {
            /* translators: %s: why the filter cannot work */
            $state = sprintf(__('Not working: %s', 'gecka-antispam'), $error);
        } elseif ($this->plugin->filterReady()) {
            $state = sprintf(
                /* translators: 1: rejection threshold, 2: spam threshold, 3: acceptance threshold, in percent */
                __('Active. Refused from %1$d %% spam, marked as spam from %2$d %%, flagged for review from %3$d %%, accepted below.', 'gecka-antispam'),
                (int) $settings->get('filter_reject'),
                (int) $settings->get('filter_threshold'),
                (int) $settings->get('filter_review'),
            );
        } else {
            $state = sprintf(
                /* translators: 1: spam texts still to learn, 2: legitimate texts still to learn */
                __('Learning: it rates nothing yet. Still to learn: spam texts %1$s, legitimate texts %2$s.', 'gecka-antispam'),
                number_format_i18n(max(0, (int) $settings->get('filter_min_spam') - $counts['spam'])),
                number_format_i18n(max(0, (int) $settings->get('filter_min_ham') - $counts['ham'])),
            );
        }

        printf('<p><strong>%s</strong></p>', esc_html($state));

        if ($on && ! StatisticalFilter::snapshotWritable()) {
            printf(
                '<p>%s</p>',
                esc_html(
                    sprintf(
                        /* translators: %s: directory on the server */
                        __('The counters cannot be kept in %s: each rating reads them from the database, which takes longer. Let PHP write in that directory.', 'gecka-antispam'),
                        StatisticalFilter::directory() . '/cache',
                    ),
                ),
            );
        }

        echo '<table class="widefat striped gecka-antispam-table gecka-antispam-filter"><tbody>';
        printf('<tr><th scope="row">%s</th><td class="num">%s</td></tr>', esc_html__('Spam texts learnt', 'gecka-antispam'), esc_html(number_format_i18n($counts['spam'])));
        printf('<tr><th scope="row">%s</th><td class="num">%s</td></tr>', esc_html__('Legitimate texts learnt', 'gecka-antispam'), esc_html(number_format_i18n($counts['ham'])));
        printf('<tr><th scope="row">%s</th><td class="num">%s</td></tr>', esc_html__('Counters in use', 'gecka-antispam'), esc_html(number_format_i18n($counts['features'])));

        $format = (string) get_option('date_format');

        $rotated = Plugin::rotated();
        $tally = $this->plugin->statisticalFilter()->tally();

        printf(
            '<tr><th scope="row">%s</th><td class="num">%s</td></tr>',
            esc_html__('Last rotation', 'gecka-antispam'),
            esc_html($tally && $tally->generation > 0 && $rotated ? (string) wp_date($format, $rotated) : __('none yet', 'gecka-antispam')),
        );

        if ($on && $rotated) {
            printf(
                '<tr><th scope="row">%s</th><td class="num">%s</td></tr>',
                esc_html__('Next rotation', 'gecka-antispam'),
                esc_html((string) wp_date($format, $rotated + $this->plugin->rotationPeriod())),
            );
        }

        echo '</tbody></table>';

        $months = (int) $settings->get('filter_rotation');

        printf(
            '<p>%s</p>',
            esc_html(
                sprintf(
                    /* translators: 1: rotation period in months, 2: twice that, 3: number of texts */
                    __('A text learnt counts in full for %1$d to %2$d months, then its weight halves every %1$d months, so that the spam of today outweighs the campaigns of past years. The counters rotate every %1$d months, or sooner once %3$s texts of one kind were learnt since the last rotation.', 'gecka-antispam'),
                    $months,
                    2 * $months,
                    number_format_i18n(Plugin::ROTATE_TEXTS),
                ),
            ),
        );

        $pending = $on ? $this->plugin->pendingTexts() : [StatisticalFilter::SPAM => 0, StatisticalFilter::HAM => 0];

        if ($on && array_sum($pending)) {
            printf(
                '<p>%s %s %s</p>',
                esc_html(
                    sprintf(
                        /* translators: 1: spam texts not learnt yet, 2: legitimate texts not learnt yet */
                        __('Already on the site and not learnt yet: spam texts %1$s, legitimate texts %2$s. They come from the spam queue and the approved comments, the spam and the inbox of Flamingo, and the Gravity Forms entries.', 'gecka-antispam'),
                        number_format_i18n($pending[StatisticalFilter::SPAM]),
                        number_format_i18n($pending[StatisticalFilter::HAM]),
                    ),
                ),
                esc_html(
                    sprintf(
                        /* translators: %d: months */
                        __('Those older than %d months are left out: they would have halved since. The most recent are learnt first.', 'gecka-antispam'),
                        2 * (int) $settings->get('filter_rotation'),
                    ),
                ),
                esc_html__('A spam is learnt only when a person or Akismet marked it: one this filter or a check for bots caught is left out, as it would only teach the filter what it already believes.', 'gecka-antispam'),
            );
        } elseif ($on) {
            printf(
                '<p>%s</p>',
                esc_html(
                    sprintf(
                        /* translators: %d: months */
                        __('Every comment and message of the last %d months already marked as spam or as legitimate has been read, and learnt unless left out.', 'gecka-antispam'),
                        2 * (int) $settings->get('filter_rotation'),
                    ),
                ),
            );
        }

        echo '<div class="gecka-admin-buttons">';

        // The learning button carries its progress below it, in a column
        // of its own next to the other button.
        if ($on && array_sum($pending)) {
            printf(
                '<div class="gecka-antispam-learn" data-url="%s" data-nonce="%s" data-total="%d" data-done="%s" data-progress="%s" data-error="%s">',
                esc_url(rest_url(SettingsPage::REST_NAMESPACE . '/learn-existing')),
                esc_attr(wp_create_nonce('wp_rest')),
                (int) array_sum($pending),
                esc_url(SettingsPage::url('filter')),
                /* translators: 1: spam texts learnt, 2: legitimate texts learnt, 3: texts left */
                esc_attr__('Learnt: spam texts %1$s, legitimate texts %2$s. Left: %3$s.', 'gecka-antispam'),
                esc_attr__('The learning stopped on an error. What was learnt is kept: click again to go on.', 'gecka-antispam'),
            );
            $this->actionButton('gecka_antispam_learn_existing', __('Learn from the existing comments and messages', 'gecka-antispam'), null, true);
            printf('<progress max="1" value="0" hidden aria-label="%s"></progress>', esc_attr__('Learning', 'gecka-antispam'));
            echo "<p class=\"gecka-antispam-learn-status\" role=\"status\" aria-live=\"polite\"></p></div>\n";
        }

        $this->actionButton('gecka_antispam_reset_filter', __('Forget everything learnt', 'gecka-antispam'), __('Forget every spam and legitimate text the filter learnt?', 'gecka-antispam'));
        echo '</div>';

        $this->backgroundTables($on);
    }

    /**
     * Prints the settings of the filter.
     *
     * @return void
     */
    private function form(): void
    {
        $settings = $this->plugin->settings()->all();

        printf('<h2>%s</h2>', esc_html__('Settings', 'gecka-antispam'));
        echo '<form action="options.php" method="post">';
        settings_fields(SettingsPage::PAGE);
        printf('<input type="hidden" name="%s[form]" value="filter">', esc_attr(Settings::OPTION));
        echo '<table class="form-table" role="presentation"><tbody>';

        $this->checkboxRow('filter', __('Filter', 'gecka-antispam'), (bool) $settings['filter'], __('Rate the texts, and learn from what is marked as spam or not spam.', 'gecka-antispam'));

        // The rest serves the filter only: hidden while it is switched off.
        printf('</tbody><tbody data-gecka-antispam-shown-by="gecka-antispam-filter"%s>', $settings['filter'] ? '' : ' hidden');
        $this->numberRow('filter_reject', __('Rejection threshold', 'gecka-antispam'), (int) $settings['filter_reject'], '%', __('From this rating, a text is refused with an error, as by the checks of the forms, and kept in the Antispam tab of Security > Journal. 100 refuses none.', 'gecka-antispam'));
        $this->numberRow('filter_threshold', __('Spam threshold', 'gecka-antispam'), (int) $settings['filter_threshold'], '%', __('From this rating, a text is marked as spam: a comment goes to the spam queue, a Contact Form 7 message to the spam of Flamingo, a Gravity Forms entry to its spam, where it can be marked as not spam.', 'gecka-antispam'));
        $this->numberRow('filter_review', __('Acceptance threshold', 'gecka-antispam'), (int) $settings['filter_review'], '%', __('Below this rating, a text goes through. From it up to the spam threshold, it goes through but is flagged for review: a comment waits for moderation, a Gravity Forms entry gets a note, Flamingo shows it in its Antispam column. The same value as the spam threshold flags none.', 'gecka-antispam'));
        $this->numberRow('filter_min_spam', __('Spam texts to learn first', 'gecka-antispam'), (int) $settings['filter_min_spam'], __('texts', 'gecka-antispam'), __('The filter rates nothing until it has learnt this many spam texts, and the legitimate texts below.', 'gecka-antispam'));
        $this->numberRow('filter_min_ham', __('Legitimate texts to learn first', 'gecka-antispam'), (int) $settings['filter_min_ham'], __('texts', 'gecka-antispam'), __('The filter rates nothing until it has learnt this many legitimate texts, and the spam texts above.', 'gecka-antispam'));
        $this->numberRow('filter_rotation', __('Rotation period', 'gecka-antispam'), (int) $settings['filter_rotation'], __('months', 'gecka-antispam'), __('At each rotation, the archived counters halve and the counters learnt since the previous rotation join them. Shorter, the filter follows new spam sooner and forgets sooner; a site receiving few legitimate messages is better off with a longer period.', 'gecka-antispam'));

        $this->checkboxRow('learn_approved', __('Learn from approved comments', 'gecka-antispam'), (bool) $settings['learn_approved'], __('Learn as legitimate a comment approved from the moderation queue.', 'gecka-antispam'));

        echo '</tbody></table>';
        submit_button();
        echo '</form>';
    }

    /**
     * Prints the background tables the filter reads or the settings want:
     * language and sources, sentences and quality, dictionary words, counters
     * in use and state; then the release and when it was checked.
     *
     * @param bool $on Whether the filter is on.
     *
     * @return void
     */
    private function backgroundTables(bool $on): void
    {
        $statisticalFilter = $this->plugin->statisticalFilter();
        $downloads = $this->plugin->backgrounds();
        $state = $downloads->state();
        $managed = Backgrounds::enabled();
        $read = $statisticalFilter->backgroundTables();
        $problems = $statisticalFilter->backgroundProblems();
        $codes = array_values(array_unique([...array_keys($read), ...($managed && $on ? $downloads->wanted() : [])]));

        printf('<h3>%s %s</h3>', esc_html__('Background tables', 'gecka-antispam'), Help::link(Help::BACKGROUNDS)); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped by Help::link().

        if ($problems) {
            printf('<p>%s</p><ul class="ul-disc">', esc_html__('Background tables left out:', 'gecka-antispam'));

            foreach ($problems as $problem) {
                printf('<li>%s</li>', esc_html($problem));
            }

            echo '</ul>';
        }

        if (! $read) {
            printf(
                '<p>%s</p>',
                esc_html(
                    $managed
                        ? __('No background table yet. Without one, the filter tells common words from rare ones by what it learnt alone, and takes a text in a language it learnt as spam only for spam. The tables of the languages chosen below are downloaded in the background; the button below downloads them now.', 'gecka-antispam')
                        : sprintf(
                            /* translators: %s: directory on the server */
                            __('No background table found in %s. Without one, the filter tells common words from rare ones by what it learnt alone, and takes a text in a language it learnt as spam only for spam. Copy there the tables of the languages the site receives, fr.bin, en.bin.', 'gecka-antispam'),
                            $statisticalFilter->backgroundDirectory(),
                        ),
                ),
            );
        }

        if ($codes) {
            echo '<div class="gecka-antispam-scroll"><table class="widefat striped gecka-antispam-table gecka-antispam-backgrounds"><thead><tr>';

            printf(
                '<th scope="col">%s</th><th scope="col" class="num">%s</th><th scope="col" class="num">%s</th><th scope="col" class="num">%s</th><th scope="col">%s</th>',
                esc_html__('Language', 'gecka-antispam'),
                esc_html__('Sentences', 'gecka-antispam'),
                esc_html__('Dictionary words', 'gecka-antispam'),
                esc_html__('Counters', 'gecka-antispam'),
                esc_html__('State', 'gecka-antispam'),
            );

            echo '</tr></thead><tbody>';

            foreach ($codes as $code) {
                $entry = $state['languages'][$code] ?? null;
                $table = $read[$code] ?? null;

                printf(
                    '<tr><th scope="row">%s <code>%s</code>%s</th><td class="num">%s</td><td class="num">%s</td><td class="num">%s</td><td>%s</td></tr>',
                    esc_html($downloads->name($code)),
                    esc_html($code),
                    $entry ? '<span class="gecka-antispam-sources">' . esc_html(implode(' ; ', $entry['sources'])) . '</span>' : '',
                    $entry ? esc_html(number_format_i18n($entry['sentences'])) . ' ' . wp_kses_post(self::quality($entry['sentences'])) : '—',
                    $entry && $entry['words'] ? esc_html(number_format_i18n($entry['words'])) : '—',
                    $table ? esc_html(number_format_i18n($table->occupied())) : '—',
                    esc_html(self::tableState($code, $table !== null, $state)),
                );
            }

            echo '</tbody></table></div>';
        }

        if ($managed && $state['checked']) {
            printf(
                '<p class="description">%s</p>',
                esc_html(
                    sprintf(
                        /* translators: 1: release, 2: date */
                        __('Release %1$s of the tables, checked on %2$s. The tables chosen are checked again every week.', 'gecka-antispam'),
                        $state['release'] ?: __('unknown', 'gecka-antispam'),
                        (string) wp_date((string) get_option('date_format'), $state['checked']),
                    ),
                ),
            );
        }

        if ($managed && $state['error'] !== '') {
            /* translators: %s: error */
            printf('<p>%s</p>', esc_html(sprintf(__('The last check of the background tables failed: %s', 'gecka-antispam'), $state['error'])));
        }

        if (! $on || ! $managed) {
            return;
        }

        // The save button sits in the row of the update button, outside its
        // form, which it names.
        echo '<form action="options.php" method="post" id="gecka-antispam-languages-form">';
        settings_fields(SettingsPage::PAGE);
        printf('<input type="hidden" name="%s[form]" value="backgrounds">', esc_attr(Settings::OPTION));
        $this->languagesField($downloads->requested());
        echo '</form>';

        echo '<div class="gecka-admin-buttons">';
        printf('<button type="submit" form="gecka-antispam-languages-form" class="button">%s</button> ', esc_html__('Save the languages', 'gecka-antispam'));

        // The update runs through the REST API, a table per request; it
        // starts by itself when the languages saved queued downloads.
        printf(
            '<div class="gecka-antispam-learn gecka-antispam-backgrounds-update" data-check="%s" data-next="%s" data-nonce="%s" data-done="%s" data-autostart="%s" data-checking="%s" data-progress="%s" data-busy="%s" data-error="%s">',
            esc_url(rest_url(SettingsPage::REST_NAMESPACE . '/backgrounds/check')),
            esc_url(rest_url(SettingsPage::REST_NAMESPACE . '/backgrounds/next')),
            esc_attr(wp_create_nonce('wp_rest')),
            esc_url(SettingsPage::url('filter')),
            $downloads->takeQueued() || $downloads->state()['pending'] ? '1' : '',
            esc_attr__('Reading the release of the tables…', 'gecka-antispam'),
            /* translators: 1: language, 2: number of the table, 3: tables to download */
            esc_attr__('Downloading %1$s (%2$s of %3$s)…', 'gecka-antispam'),
            esc_attr__('Another request is updating the tables, waiting for it…', 'gecka-antispam'),
            esc_attr__('The update stopped on an error. The tables downloaded are kept: click again to go on.', 'gecka-antispam'),
        );
        $this->actionButton('gecka_antispam_update_backgrounds', __('Update the background tables', 'gecka-antispam'));
        printf('<progress max="1" value="0" hidden aria-label="%s"></progress>', esc_attr__('Downloading', 'gecka-antispam'));
        echo "<p class=\"gecka-antispam-learn-status\" role=\"status\" aria-live=\"polite\"></p></div>\n";
        echo '</div>';
    }

    /**
     * State of a table: its error, to download, copied by hand, update
     * available, or up to date
     *
     * @param string               $code
     * @param bool                 $read  Whether the filter reads it.
     * @param array<string, mixed> $state What the plugin knows of the tables.
     *
     * @return string
     */
    private static function tableState(string $code, bool $read, array $state): string
    {
        $installed = $state['tables'][$code] ?? null;
        $offered = $state['languages'][$code]['sha256'] ?? null;

        return match (true) {
            /* translators: %s: error */
            isset($state['errors'][$code]) => sprintf(__('Error: %s', 'gecka-antispam'), $state['errors'][$code]),
            ! $read => __('To download', 'gecka-antispam'),
            $installed === null => __('Copied by hand', 'gecka-antispam'),
            $offered !== null && $offered !== $installed => __('Update available', 'gecka-antispam'),
            default => __('Up to date', 'gecka-antispam'),
        };
    }

    /**
     * Badge of the quality of a table by its sentences
     *
     * @param int $sentences
     *
     * @return string HTML.
     */
    private static function quality(int $sentences): string
    {
        $quality = Backgrounds::quality($sentences);
        $labels = [
            'solid' => __('solid', 'gecka-antispam'),
            'average' => __('average', 'gecka-antispam'),
            'weak' => __('weak', 'gecka-antispam'),
            'poor' => __('poor', 'gecka-antispam'),
        ];

        return sprintf('<span class="gecka-antispam-quality is-%s">%s</span>', esc_attr($quality), esc_html($labels[$quality]));
    }

    /**
     * Content of the Help tab of the background tables: what they are, why
     * the filter needs them, and which languages to choose.
     *
     * @return string HTML.
     */
    public static function backgroundsHelp(): string
    {
        $html = sprintf('<p>%s</p>', esc_html__('A background table holds how often words, pairs of words, links and the like come up in ordinary text of a language, drawn from up to 300,000 sentences of news, encyclopaedia and everyday corpora. The filter compares what it learnt with it, to tell a word common in the language from one that marks spam. Without it, a legitimate message in a language the filter saw in spam only is taken for spam.', 'gecka-antispam'));

        return $html . sprintf(
            '<p>%s</p>',
            esc_html(
                sprintf(
                    /* translators: 1: maximum number of languages, 2: sentences of a solid table, 3: of an average one, 4: of a weak one */
                    __('Choose the languages of the messages the site receives, not only the language of its pages: English nearly always, in which much of the spam is written. %1$d at most, each table taking 4 MB of memory when a text is rated. A table drawn from few sentences knows little of its language: it is solid from %2$s sentences, average from %3$s, weak from %4$s and poor below.', 'gecka-antispam'),
                    StatisticalFilter::MAX_LANGUAGES,
                    number_format_i18n(Backgrounds::SOLID),
                    number_format_i18n(Backgrounds::AVERAGE),
                    number_format_i18n(Backgrounds::WEAK),
                ),
            ),
        );
    }

    /**
     * Prints the field of the languages: a text field of codes, which
     * languages.js turns into a field of tags suggesting the languages of
     * the release.
     *
     * @param string[] $chosen The languages in use, chosen or of the site, so that a language added joins them.
     *
     * @return void
     */
    private function languagesField(array $chosen): void
    {
        $downloads = $this->plugin->backgrounds();
        $offered = $downloads->state()['languages'];
        $languages = [];
        $qualities = [
            'solid' => __('solid', 'gecka-antispam'),
            'average' => __('average', 'gecka-antispam'),
            'weak' => __('weak', 'gecka-antispam'),
            'poor' => __('poor', 'gecka-antispam'),
        ];

        foreach ($offered as $code => $entry) {
            $languages[$code] = [
                /* translators: 1: name of the language, 2: its code */
                'label' => sprintf(_x('%1$s (%2$s)', 'language and its code', 'gecka-antispam'), $downloads->name($code), $code),
                'detail' => sprintf(
                    /* translators: 1: number of sentences, 2: quality of the table */
                    _n('%1$s sentence, %2$s', '%1$s sentences, %2$s', $entry['sentences'], 'gecka-antispam'),
                    number_format_i18n($entry['sentences']),
                    $qualities[Backgrounds::quality($entry['sentences'])],
                ),
            ];
        }

        $collator = class_exists('Collator') ? new \Collator(get_user_locale()) : null;

        uasort($languages, static fn(array $a, array $b): int => $collator ? (int) $collator->compare($a['label'], $b['label']) : strcasecmp($a['label'], $b['label']));

        printf(
            '<p><label for="gecka-antispam-background_languages"><strong>%1$s</strong></label></p><div class="gecka-antispam-languages-field" data-languages="%2$s" data-max="%3$d" data-label="%4$s"><input type="text" class="regular-text code" id="gecka-antispam-background_languages" name="%5$s[background_languages]" value="%6$s" placeholder="%7$s" aria-describedby="gecka-antispam-background_languages-description"></div><p class="description" id="gecka-antispam-background_languages-description">%8$s</p>',
            esc_html__('Language background tables', 'gecka-antispam'),
            esc_attr((string) wp_json_encode($languages)),
            (int) StatisticalFilter::MAX_LANGUAGES,
            esc_attr__('Add a language', 'gecka-antispam'),
            esc_attr(Settings::OPTION),
            esc_attr(implode(', ', $chosen)),
            esc_attr(implode(', ', Backgrounds::siteLanguages())),
            esc_html(
                sprintf(
                    /* translators: 1: maximum number of languages, 2: language codes */
                    __('The languages of the messages the site receives, %1$d at most. Empty, those of the site and English: %2$s.', 'gecka-antispam'),
                    StatisticalFilter::MAX_LANGUAGES,
                    implode(', ', Backgrounds::siteLanguages()),
                ),
            ),
        );
    }
}
