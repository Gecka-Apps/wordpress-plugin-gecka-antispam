<?php

declare(strict_types=1);

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

namespace Gecka\WP\Plugin\Antispam;

use Gecka\SpamFilter\Label;
use Gecka\WP\Plugin\Antispam\Admin\DashboardWidget;
use Gecka\WP\Plugin\Antispam\Admin\SettingsPage;
use Gecka\WP\Plugin\Antispam\Admin\SiteHealth;
use Gecka\WP\Plugin\Antispam\Integrations\Acf;
use Gecka\WP\Plugin\Antispam\Integrations\Comments;
use Gecka\WP\Plugin\Antispam\Integrations\ContactForm7;
use Gecka\WP\Plugin\Antispam\Integrations\Custom;
use Gecka\WP\Plugin\Antispam\Integrations\Flamingo;
use Gecka\WP\Plugin\Antispam\Integrations\GravityForms;
use Gecka\WP\Plugin\Antispam\Integrations\Integration;
use Gecka\WP\Plugin\Antispam\Integrations\Learner;
use Gecka\WP\Plugin\Antispam\Integrations\Login;
use Gecka\WP\Plugin\Antispam\Integrations\Registration;
use Gecka\WP\Plugin\Antispam\Integrations\WooCommerce;

/**
 * Plugin instance: the pieces it hooks up, and what they all need to know.
 *
 * @author Laurent Dinclaux - Gecka <laurent@gecka.nc>
 */
class Plugin
{
    /**
     * Version of the plugin.
     */
    public const VERSION = '1.0.0';

    /**
     * Meta holding what the statistical filter learnt a comment or a message as.
     */
    public const META_TRAINED = '_gecka_antispam_trained';

    /**
     * Value of META_TRAINED for an item the filter read in one go and left
     * out, so it is not read again.
     */
    public const TRAINED_SKIPPED = 'skipped';

    /**
     * Meta holding the generation of the statistical filter a comment or a
     * message was learnt in.
     */
    public const META_GENERATION = '_gecka_antispam_generation';

    /**
     * Option holding when the counters of the statistical filter last
     * rotated, or when the plugin started counting the time to the first
     * rotation.
     */
    public const ROTATED_OPTION = 'gecka_antispam_rotated';

    /**
     * Texts of a class the recent generation holds at most: past that, the
     * counters rotate before the period is over.
     */
    public const ROTATE_TEXTS = 5000;

    /**
     * Items of each kind a source reads in one go when learning what it holds.
     */
    public const LEARN_BATCH = 50;

    /**
     * Meta holding why a comment was caught.
     */
    public const META_REASON = '_gecka_antispam_reason';

    /**
     * Meta holding the score the statistical filter gave a comment.
     */
    public const META_SCORE = '_gecka_antispam_score';

    /**
     * Main file of the plugin.
     *
     * @var string
     */
    private string $file;

    /**
     * @var Settings
     */
    private Settings $settings;

    /**
     * @var Guard
     */
    private Guard $guard;

    /**
     * @var Custom
     */
    private Custom $custom;

    /**
     * @var Stats
     */
    private Stats $stats;

    /**
     * @var Origins
     */
    private Origins $origins;

    /**
     * @var StatisticalFilter
     */
    private StatisticalFilter $statisticalFilter;

    /**
     * @var Journal
     */
    private Journal $journal;

    /**
     * @var Backgrounds
     */
    private Backgrounds $backgrounds;

    /**
     * The integrations whose plugin is active.
     *
     * @var Integration[]
     */
    private array $active = [];

    /**
     * @param string $file Main file of the plugin
     */
    public function __construct(string $file)
    {
        $this->file = $file;

        $this->settings = new Settings();
        add_action('add_option_' . Settings::OPTION, [$this->settings, 'flush']);
        add_action('update_option_' . Settings::OPTION, [$this->settings, 'flush']);
        $this->stats = new Stats();
        $this->origins = new Origins();
        $this->statisticalFilter = new StatisticalFilter();
        $this->journal = new Journal($this->statisticalFilter);
        $this->backgrounds = new Backgrounds($this->statisticalFilter, $this->settings);
        $this->backgrounds->setup();
        $this->guard = new Guard($this);
        $this->custom = new Custom($this);
        // template_redirect runs before a block theme renders its template,
        // which comes before wp_head.
        add_action('template_redirect', [$this->guard, 'enqueueStyle']);
        add_action('login_enqueue_scripts', [$this->guard, 'enqueueStyle']);

        foreach ($this->integrations() as $integration) {
            if ($integration->available()) {
                $integration->setup();
                $this->active[] = $integration;
            }
        }

        (new SettingsPage($this))->setup();
        (new DashboardWidget($this))->setup();
        (new SiteHealth($this))->setup();

        add_action('init', static function (): void {
            Setup::upgrade(self::VERSION);
        });
        add_action(
            Setup::PURGE_EVENT,
            function (): void {
                $this->stats->purge((int) $this->settings->get('stats_days'));
                $this->origins->purge((int) $this->settings->get('stats_days'));
                $this->journal->purge();
                $this->rotateFilter();
                $this->backgrounds->refresh();
            },
        );
    }

    /**
     * The forms the plugin knows how to protect, and the inbox it learns from
     *
     * @return Integration[]
     */
    private function integrations(): array
    {
        return [
            new Comments($this),
            new Login($this),
            new Registration($this),
            new WooCommerce($this),
            new ContactForm7($this),
            new Flamingo($this),
            new GravityForms($this),
            new Acf($this),
        ];
    }

    /**
     * Whether the plugin behind a group of forms is active: woocommerce,
     * contact_form_7, gravity_forms or acf
     *
     * @param string $group
     *
     * @return bool
     */
    public function provides(string $group): bool
    {
        $class = [
            'woocommerce' => WooCommerce::class,
            'contact_form_7' => ContactForm7::class,
            'gravity_forms' => GravityForms::class,
            'acf' => Acf::class,
        ][$group] ?? null;

        if ($class === null) {
            return true;
        }

        foreach ($this->active as $integration) {
            if ($integration instanceof $class) {
                return true;
            }
        }

        return false;
    }

    /**
     * The active sources the statistical filter can learn from in one go
     *
     * @return Learner[]
     */
    public function learners(): array
    {
        return array_values(array_filter($this->active, static fn(Integration $integration): bool => $integration instanceof Learner));
    }

    /**
     * Texts the sources hold, marked and not learnt yet, by category
     *
     * @return array<string, int> StatisticalFilter::SPAM and StatisticalFilter::HAM => count.
     */
    public function pendingTexts(): array
    {
        $pending = [StatisticalFilter::SPAM => 0, StatisticalFilter::HAM => 0];

        foreach ($this->learners() as $learner) {
            foreach (array_keys($pending) as $category) {
                $pending[$category] += $learner->pending($category);
            }
        }

        return $pending;
    }

    /**
     * Learns what the sources hold, the most recent first, batch after batch
     * until nothing is left, the time is up, a round of batches leaves as
     * much to learn as before it, or the filter fails to learn a text, which
     * StatisticalFilter::learningFailed() then tells.
     *
     * @param float $seconds Time to spend at most; a batch started goes to its end.
     *
     * @return array<string, int> StatisticalFilter::SPAM and StatisticalFilter::HAM => texts learnt.
     */
    public function learnExisting(float $seconds): array
    {
        $learnt = [StatisticalFilter::SPAM => 0, StatisticalFilter::HAM => 0];
        $deadline = microtime(true) + $seconds;

        while ($this->settings->get('filter') && microtime(true) < $deadline) {
            $progress = false;

            foreach ($this->learners() as $learner) {
                foreach (array_keys($learnt) as $category) {
                    $before = $learner->pending($category);

                    if ($before > 0 && microtime(true) < $deadline) {
                        $learnt[$category] += $learner->learnExisting($category, self::LEARN_BATCH);

                        if ($this->statisticalFilter()->learningFailed()) {
                            return $learnt;
                        }

                        $progress = $progress || $learner->pending($category) < $before;
                    }
                }
            }

            if (! $progress) {
                break;
            }
        }

        return $learnt;
    }

    /**
     * @return Settings
     */
    public function settings(): Settings
    {
        return $this->settings;
    }

    /**
     * @return Guard
     */
    public function guard(): Guard
    {
        return $this->guard;
    }

    /**
     * The forms developers protect themselves
     *
     * @return Custom
     */
    public function custom(): Custom
    {
        return $this->custom;
    }

    /**
     * @return Stats
     */
    public function stats(): Stats
    {
        return $this->stats;
    }

    /**
     * @return Origins
     */
    public function origins(): Origins
    {
        return $this->origins;
    }

    /**
     * @return StatisticalFilter
     */
    public function statisticalFilter(): StatisticalFilter
    {
        return $this->statisticalFilter;
    }

    /**
     * @return Journal
     */
    public function journal(): Journal
    {
        return $this->journal;
    }

    /**
     * @return Backgrounds
     */
    public function backgrounds(): Backgrounds
    {
        return $this->backgrounds;
    }

    /**
     * Forgets everything the statistical filter learnt, and the marks telling
     * what each comment, message, entry and refused submission was learnt as.
     *
     * @return void
     */
    public function resetFilter(): void
    {
        $this->statisticalFilter->reset();
        Setup::forgetTraining();
        $this->journal->forget();
        update_option(self::ROTATED_OPTION, time(), false);
    }

    /**
     * Seconds between two rotations of the counters
     *
     * @return int
     */
    public function rotationPeriod(): int
    {
        return (int) $this->settings->get('filter_rotation') * MONTH_IN_SECONDS;
    }

    /**
     * When the counters last rotated, or when the time to the first rotation
     * started; 0 before that
     *
     * @return int
     */
    public static function rotated(): int
    {
        return (int) get_option(self::ROTATED_OPTION, 0);
    }

    /**
     * Rotates the counters of the statistical filter once the period is
     * over, or once the recent generation holds ROTATE_TEXTS texts of a
     * class, whichever comes first. The first call only starts the clock.
     *
     * @return bool Whether the counters rotated.
     */
    public function rotateFilter(): bool
    {
        if (! $this->settings->get('filter')) {
            return false;
        }

        $tally = $this->statisticalFilter->tally();
        $since = self::rotated();

        if (! $tally) {
            return false;
        }

        if (! $since) {
            update_option(self::ROTATED_OPTION, time(), false);

            return false;
        }

        $due = time() - $since >= $this->rotationPeriod()
            || max($tally->recent(Label::Spam), $tally->recent(Label::Ham)) >= self::ROTATE_TEXTS;

        if (! $due || ! $this->statisticalFilter->rotate()) {
            return false;
        }

        update_option(self::ROTATED_OPTION, time(), false);

        return true;
    }

    /**
     * Whether an item dated $time belongs to the archive of the statistical
     * filter, to the recent generation, or is too old to be learnt: older
     * than two periods, it would have halved since. An item sent after the
     * last rotation goes to the recent generation, where a text learnt when
     * it came in still is; one sent before, to the archive. Before the first
     * rotation, the period alone decides.
     *
     * @param int $time Unix time.
     *
     * @return bool|null True for the archive, false for the recent generation, null when too old.
     */
    public function archives(int $time): ?bool
    {
        $age = time() - $time;
        $period = $this->rotationPeriod();

        if ($age >= 2 * $period) {
            return null;
        }

        $rotated = ($this->statisticalFilter->tally()->generation ?? 0) > 0 ? self::rotated() : 0;

        return $rotated > 0 ? $time < $rotated : $age >= $period;
    }

    /**
     * Whether the statistical filter is switched on and learnt enough to judge
     *
     * @return bool
     */
    public function filterReady(): bool
    {
        return $this->settings->get('filter') && $this->statisticalFilter->ready((int) $this->settings->get('filter_min_spam'), (int) $this->settings->get('filter_min_ham'));
    }

    /**
     * What a rating of the statistical filter makes of a text: refused,
     * marked as spam, held for review, or accepted
     *
     * @param float|null $score Between 0 and 1, null when there was nothing to rate.
     *
     * @return string|null Guard::FILTER_REJECT, Guard::FILTER_SPAM, Guard::REVIEW, or null when it goes through.
     */
    public function verdict(?float $score): ?string
    {
        $rating = $score === null ? 0 : $score * 100;
        $thresholds = [
            Guard::FILTER_REJECT => 'filter_reject',
            Guard::FILTER_SPAM => 'filter_threshold',
            Guard::REVIEW => 'filter_review',
        ];

        foreach ($thresholds as $outcome => $setting) {
            if ($rating >= (int) $this->settings->get($setting)) {
                return $outcome;
            }
        }

        return null;
    }

    /**
     * Url of a file of the plugin
     *
     * @param string $relative
     *
     * @return string
     */
    public function url(string $relative = ''): string
    {
        return plugins_url($relative, $this->file);
    }

    /**
     * Main file of the plugin
     *
     * @return string
     */
    public function file(): string
    {
        return $this->file;
    }
}
