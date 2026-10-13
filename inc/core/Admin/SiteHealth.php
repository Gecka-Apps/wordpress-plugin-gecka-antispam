<?php

declare(strict_types=1);

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

namespace Gecka\WP\Plugin\Antispam\Admin;

use Gecka\SpamFilter\Label;
use Gecka\WP\Plugin\Antispam\Backgrounds;
use Gecka\WP\Plugin\Antispam\Base;
use Gecka\WP\Plugin\Antispam\Plugin;
use Gecka\WP\Plugin\Antispam\Schema;
use Gecka\WP\Plugin\Antispam\Settings;
use Gecka\WP\Plugin\Antispam\Setup;
use Gecka\WP\Plugin\Antispam\StatisticalFilter;
use Gecka\WP\Plugin\Antispam\Value;

/**
 * Tools > Site Health: tests telling what keeps the plugin from working as
 * it should, each with a link to fix it, and a section of the Info tab
 * describing its state, ready to be copied for support.
 *
 * The tests of the statistical filter run only while it is switched on;
 * learning, before it rates anything, is a state, not a problem, and only
 * shows in the Info tab.
 *
 * @author Laurent Dinclaux - Gecka <laurent@gecka.nc>
 */
class SiteHealth extends Base
{
    /**
     * Seconds the daily task may be late before it counts as not running.
     */
    private const LATE = DAY_IN_SECONDS;

    /**
     * Hooks the tests and the Info section up. The tests run on the Site
     * Health screen, and from the cron for the weekly check of WordPress,
     * which keeps their counts only: the addresses their actions carry are
     * built without the menu there, and thrown away.
     *
     * @return void
     */
    public function setup(): void
    {
        add_filter('site_status_tests', [$this, 'tests']);
        add_filter('debug_information', [$this, 'information']);
    }

    /**
     * Adds the tests of the plugin.
     *
     * @param mixed $tests
     *
     * @return mixed
     */
    public function tests(mixed $tests): mixed
    {
        if (! is_array($tests)) {
            return $tests;
        }

        $direct = Value::list($tests['direct'] ?? null);
        $direct['gecka_antispam_tables'] = ['label' => __('The tables of Gecka Antispam', 'gecka-antispam'), 'test' => [$this, 'testTables']];
        $direct['gecka_antispam_schedule'] = ['label' => __('The daily task of Gecka Antispam', 'gecka-antispam'), 'test' => [$this, 'testSchedule']];

        if ($this->plugin->settings()->bool('filter')) {
            $direct['gecka_antispam_filter'] = ['label' => __('The statistical filter of Gecka Antispam', 'gecka-antispam'), 'test' => [$this, 'testFilter']];
            $direct['gecka_antispam_background'] = ['label' => __('The background tables of Gecka Antispam', 'gecka-antispam'), 'test' => [$this, 'testBackground']];
            $direct['gecka_antispam_snapshot'] = ['label' => __('The snapshot of the counters of Gecka Antispam', 'gecka-antispam'), 'test' => [$this, 'testSnapshot']];
        }

        $tests['direct'] = $direct;

        return $tests;
    }

    /**
     * Whether the tables of the plugin were set up for the version running.
     *
     * @return array<string, mixed>
     */
    public function testTables(): array
    {
        $failure = Setup::failure();

        if ($failure !== '') {
            return $this->result(
                'gecka_antispam_tables',
                'critical',
                __('The tables of Gecka Antispam could not be set up', 'gecka-antispam'),
                __('The plugin protects nothing until they are. The setup is tried again every hour; if this persists, the database user of the site cannot create or alter tables. The database said:', 'gecka-antispam'),
                [$failure],
            );
        }

        if (get_option(Setup::VERSION_OPTION) !== Setup::installed(Plugin::VERSION)) {
            return $this->result(
                'gecka_antispam_tables',
                'recommended',
                __('The tables of Gecka Antispam are not set up yet', 'gecka-antispam'),
                __('The setup runs on the next page load.', 'gecka-antispam'),
            );
        }

        return $this->result(
            'gecka_antispam_tables',
            'good',
            __('The tables of Gecka Antispam are set up', 'gecka-antispam'),
            __('They match the version of the plugin running.', 'gecka-antispam'),
        );
    }

    /**
     * Whether the statistical filter can rate and learn.
     *
     * @return array<string, mixed>
     */
    public function testFilter(): array
    {
        $error = $this->plugin->statisticalFilter()->error();

        if ($error) {
            return $this->result(
                'gecka_antispam_filter',
                'critical',
                __('The statistical filter of Gecka Antispam does not work', 'gecka-antispam'),
                sprintf(
                    /* translators: %s: why the filter cannot work */
                    __('It is switched on but cannot rate nor learn: %s The checks of the forms, the honeypot first, keep protecting the site.', 'gecka-antispam'),
                    $error,
                ),
            );
        }

        return $this->result(
            'gecka_antispam_filter',
            'good',
            __('The statistical filter of Gecka Antispam works', 'gecka-antispam'),
            __('Its tables can be read and written.', 'gecka-antispam'),
        );
    }

    /**
     * Whether background tables are read, and none was left out.
     *
     * @return array<string, mixed>
     */
    public function testBackground(): array
    {
        $statisticalFilter = $this->plugin->statisticalFilter();
        $problems = $statisticalFilter->backgroundProblems();
        $languages = $statisticalFilter->languages();
        $error = Backgrounds::enabled() ? $this->plugin->backgrounds()->errors() : '';

        if ($error !== '') {
            return $this->result(
                'gecka_antispam_background',
                'recommended',
                __('Gecka Antispam could not download its background tables', 'gecka-antispam'),
                __('The statistical filter reads on with the tables in place, if any. The download is tried again every day, and from the button of the statistical filter tab:', 'gecka-antispam'),
                [$error],
            );
        }

        if ($problems) {
            return $this->result(
                'gecka_antispam_background',
                'recommended',
                __('Gecka Antispam left background tables out', 'gecka-antispam'),
                __('The statistical filter reads on without them:', 'gecka-antispam'),
                $problems,
            );
        }

        if (! $languages) {
            return $this->result(
                'gecka_antispam_background',
                'recommended',
                __('Gecka Antispam has no background table', 'gecka-antispam'),
                Backgrounds::enabled()
                    ? __('Without one, the statistical filter tells common words from rare ones by what it learnt alone: until it has learnt many legitimate messages, a text in a language it saw in spam only is taken for spam. The tables of the languages of the site are downloaded in the background, or now from the button of the statistical filter tab.', 'gecka-antispam')
                    : sprintf(
                        /* translators: %s: directory on the server */
                        __('Without one, the statistical filter tells common words from rare ones by what it learnt alone: until it has learnt many legitimate messages, a text in a language it saw in spam only is taken for spam. Copy to %s the tables of the languages the site receives, fr.bin, en.bin.', 'gecka-antispam'),
                        $statisticalFilter->backgroundDirectory(),
                    ),
            );
        }

        $weak = [];
        $offered = $this->plugin->backgrounds()->state()['languages'];

        foreach ($languages as $code) {
            $sentences = $offered[$code]['sentences'] ?? null;

            if ($sentences !== null && $sentences < Backgrounds::AVERAGE) {
                /* translators: 1: language code, 2: number of sentences */
                $weak[] = sprintf(_n('%1$s: %2$s sentence', '%1$s: %2$s sentences', $sentences, 'gecka-antispam'), $code, number_format_i18n($sentences));
            }
        }

        if ($weak) {
            return $this->result(
                'gecka_antispam_background',
                'recommended',
                __('Gecka Antispam reads weak background tables', 'gecka-antispam'),
                sprintf(
                    /* translators: %s: number of sentences */
                    __('A table drawn from fewer than %s sentences knows little of its language, and helps the statistical filter little. Check that the site receives these languages, or learn more legitimate messages in them:', 'gecka-antispam'),
                    number_format_i18n(Backgrounds::AVERAGE),
                ),
                $weak,
            );
        }

        return $this->result(
            'gecka_antispam_background',
            'good',
            __('Gecka Antispam reads its background tables', 'gecka-antispam'),
            /* translators: %s: language codes */
            sprintf(__('Languages: %s.', 'gecka-antispam'), implode(', ', $languages)),
        );
    }

    /**
     * Whether the counters can be kept in a snapshot file.
     *
     * @return array<string, mixed>
     */
    public function testSnapshot(): array
    {
        if (! StatisticalFilter::snapshotWritable()) {
            return $this->result(
                'gecka_antispam_snapshot',
                'recommended',
                __('Gecka Antispam cannot keep a snapshot of its counters', 'gecka-antispam'),
                sprintf(
                    /* translators: %s: directory on the server */
                    __('Each rating reads the counters from the database, which takes longer. Let PHP write in %s.', 'gecka-antispam'),
                    StatisticalFilter::directory() . '/cache',
                ),
            );
        }

        return $this->result(
            'gecka_antispam_snapshot',
            'good',
            __('Gecka Antispam keeps a snapshot of its counters', 'gecka-antispam'),
            __('A rating reads the counters from a file, not from the database.', 'gecka-antispam'),
        );
    }

    /**
     * Whether the daily task is scheduled and runs.
     *
     * @return array<string, mixed>
     */
    public function testSchedule(): array
    {
        $next = wp_next_scheduled(Setup::PURGE_EVENT);

        if (! $next) {
            return $this->result(
                'gecka_antispam_schedule',
                'recommended',
                __('The daily task of Gecka Antispam is not scheduled', 'gecka-antispam'),
                __('Without it, the statistics and the refused submissions are never purged, and the counters of the statistical filter never rotate. The plugin schedules it again on the next page load; if this persists, WordPress cannot save its scheduled tasks.', 'gecka-antispam'),
            );
        }

        if ($next < time() - self::LATE) {
            return $this->result(
                'gecka_antispam_schedule',
                'recommended',
                __('The daily task of Gecka Antispam does not run', 'gecka-antispam'),
                sprintf(
                    /* translators: %s: date */
                    __('It was due on %s. The scheduled tasks of WordPress do not run on this site: without them, the statistics and the refused submissions are never purged, and the counters of the statistical filter never rotate.', 'gecka-antispam'),
                    (string) wp_date(Value::string(get_option('date_format')) . ' ' . Value::string(get_option('time_format')), $next),
                ),
            );
        }

        return $this->result(
            'gecka_antispam_schedule',
            'good',
            __('The daily task of Gecka Antispam runs', 'gecka-antispam'),
            __('It purges the statistics and the refused submissions, and rotates the counters of the statistical filter when due.', 'gecka-antispam'),
        );
    }

    /**
     * Adds the section of the plugin to the Info tab.
     *
     * @param mixed $info
     *
     * @return mixed
     */
    public function information(mixed $info): mixed
    {
        if (! is_array($info)) {
            return $info;
        }

        $settings = $this->plugin->settings();
        $statisticalFilter = $this->plugin->statisticalFilter();
        $on = $settings->bool('filter');
        $tally = $on ? $statisticalFilter->tally() : null;
        $rotated = Plugin::rotated();
        $format = Value::string(get_option('date_format'));
        $fields = [
            'version' => ['label' => __('Version', 'gecka-antispam'), 'value' => Plugin::VERSION . ' / ' . Schema::VERSION],
            'forms' => ['label' => __('Protected forms', 'gecka-antispam'), 'value' => $this->forms()],
            'filter' => ['label' => __('Statistical filter', 'gecka-antispam'), 'value' => $this->filterState(), 'debug' => $on ? ($statisticalFilter->error() ?? ($this->plugin->filterReady() ? 'active' : 'learning')) : 'off'],
        ];

        if ($on) {
            $fields += [
                'thresholds' => [
                    'label' => __('Thresholds', 'gecka-antispam'),
                    /* translators: 1: rejection, 2: spam, 3: acceptance threshold, in percent */
                    'value' => sprintf(__('rejection %1$d %%, spam %2$d %%, acceptance %3$d %%', 'gecka-antispam'), $settings->int('filter_reject'), $settings->int('filter_threshold'), $settings->int('filter_review')),
                    'debug' => sprintf('%d/%d/%d', $settings->int('filter_reject'), $settings->int('filter_threshold'), $settings->int('filter_review')),
                ],
                'minimums' => [
                    'label' => __('Texts to learn first', 'gecka-antispam'),
                    /* translators: 1: spam texts, 2: legitimate texts */
                    'value' => sprintf(__('spam %1$d, legitimate %2$d', 'gecka-antispam'), $settings->int('filter_min_spam'), $settings->int('filter_min_ham')),
                ],
                'learnt' => [
                    'label' => __('Texts learnt', 'gecka-antispam'),
                    /* translators: 1: spam texts, 2: legitimate texts */
                    'value' => $tally ? sprintf(__('spam %1$s, legitimate %2$s', 'gecka-antispam'), number_format_i18n($tally->learned(Label::Spam)), number_format_i18n($tally->learned(Label::Ham))) : '',
                    'debug' => $tally ? sprintf('spam %d, ham %d', $tally->learned(Label::Spam), $tally->learned(Label::Ham)) : '',
                ],
                'rotation' => [
                    'label' => __('Rotation of the counters', 'gecka-antispam'),
                    'value' => sprintf(
                        /* translators: 1: period in months, 2: generation number, 3: date of the last rotation */
                        __('every %1$d months; generation %2$d; last rotation: %3$s', 'gecka-antispam'),
                        $settings->int('filter_rotation'),
                        $tally ? $tally->generation : 0,
                        $tally && $tally->generation > 0 && $rotated ? (string) wp_date($format, $rotated) : __('none yet', 'gecka-antispam'),
                    ),
                ],
                'background' => [
                    'label' => __('Background tables', 'gecka-antispam'),
                    'value' => implode(', ', $statisticalFilter->languages()) ?: __('none', 'gecka-antispam'),
                ],
                'left_out' => [
                    'label' => __('Background tables left out', 'gecka-antispam'),
                    'value' => implode(' ', $statisticalFilter->backgroundProblems()) ?: __('none', 'gecka-antispam'),
                ],
                'snapshot' => [
                    'label' => __('Snapshot of the counters', 'gecka-antispam'),
                    'value' => StatisticalFilter::snapshotWritable() ? __('written', 'gecka-antispam') : __('cannot be written', 'gecka-antispam'),
                    'debug' => StatisticalFilter::snapshotWritable() ? 'writable' : 'not writable',
                ],
            ];
        }

        $journal = $this->plugin->journal();
        $fields['refused'] = [
            'label' => __('Refused submissions', 'gecka-antispam'),
            /* translators: 1: entries to review, 2: entries learnt */
            'value' => sprintf(__('to review %1$s, learnt %2$s', 'gecka-antispam'), number_format_i18n($journal->count()), number_format_i18n($journal->count(true))),
            'debug' => sprintf('pending %d, learnt %d', $journal->count(), $journal->count(true)),
        ];

        $info['gecka-antispam'] = [
            'label' => __('Gecka Antispam', 'gecka-antispam'),
            'fields' => $fields,
        ];

        return $info;
    }

    /**
     * The forms protected, those of the plugins active only, with the mode of
     * the plugins letting forms carry a marker
     *
     * @return string
     */
    private function forms(): string
    {
        $settings = $this->plugin->settings();
        $forms = [];

        foreach (Settings::groups() as $id => $group) {
            if (! $this->plugin->provides($id)) {
                continue;
            }

            foreach (array_keys($group['surfaces']) as $surface) {
                if (! $settings->enabled($surface)) {
                    continue;
                }

                $label = Settings::surfaceLabel($surface);

                if (in_array($surface, Settings::MARKED_SURFACES, true) && $settings->mode($surface) === Settings::MODE_MARKED) {
                    /* translators: %s: form */
                    $label = sprintf(__('%s (marked forms only)', 'gecka-antispam'), $label);
                }

                $forms[] = $label;
            }
        }

        return implode(', ', $forms) ?: __('none', 'gecka-antispam');
    }

    /**
     * What the statistical filter is doing
     *
     * @return string
     */
    private function filterState(): string
    {
        if (! $this->plugin->settings()->get('filter')) {
            return __('Switched off.', 'gecka-antispam');
        }

        $error = $this->plugin->statisticalFilter()->error();

        if ($error) {
            /* translators: %s: why the filter cannot work */
            return sprintf(__('Not working: %s', 'gecka-antispam'), $error);
        }

        return $this->plugin->filterReady() ? __('Active', 'gecka-antispam') : __('Learning: it rates nothing yet.', 'gecka-antispam');
    }

    /**
     * A result of a test, as Site Health expects it, with a link to the
     * statistical filter tab when there is something to fix there
     *
     * @param string   $test
     * @param string   $status      good, recommended or critical.
     * @param string   $label
     * @param string   $description
     * @param string[] $items       Lines listed below the description.
     *
     * @return array<string, mixed>
     */
    private function result(string $test, string $status, string $label, string $description, array $items = []): array
    {
        $list = $items ? '<ul class="ul-disc">' . implode('', array_map(static fn(string $item): string => '<li>' . esc_html($item) . '</li>', $items)) . '</ul>' : '';

        return [
            'label' => $label,
            'status' => $status,
            'badge' => ['label' => __('Antispam', 'gecka-antispam'), 'color' => 'blue'],
            'description' => '<p>' . esc_html($description) . '</p>' . $list,
            'actions' => $status === 'good' || in_array($test, ['gecka_antispam_schedule', 'gecka_antispam_tables'], true) ? '' : sprintf('<p><a href="%s">%s</a></p>', esc_url(SettingsPage::url('filter')), esc_html__('Statistical filter of Gecka Antispam', 'gecka-antispam')),
            'test' => $test,
        ];
    }
}
