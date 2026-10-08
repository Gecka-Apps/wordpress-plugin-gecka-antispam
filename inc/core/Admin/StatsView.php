<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

namespace Gecka\WP\Plugin\Antispam\Admin;

use Gecka\WP\Plugin\Antispam\Guard;
use Gecka\WP\Plugin\Antispam\Plugin;
use Gecka\WP\Plugin\Antispam\Settings;

/**
 * The statistics tab: totals of the period, submissions accepted and caught
 * over time, the share of each check in what was caught, and the counts by
 * form and outcome.
 *
 * @author Laurent Dinclaux - Gecka <laurent@gecka.nc>
 */
class StatsView
{
    use Controls;

    /**
     * Size of the chart, in the units of its view box.
     */
    private const WIDTH = 1040;

    private const HEIGHT = 240;

    /**
     * Room left of the plot for the axis labels, below for the dates, and
     * above for the top label.
     */
    private const GUTTER_LEFT = 40;

    private const GUTTER_BOTTOM = 24;

    private const GUTTER_TOP = 12;

    /**
     * Widest a bar gets, when the period has few of them.
     */
    private const MAX_BAR = 40;

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
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Only picks the period.
        $days = absint($_GET['days'] ?? 30);
        $days = in_array($days, SettingsPage::PERIODS, true) ? $days : 30;

        $this->notices();

        echo '<div class="gecka-antispam-periods">';

        foreach (SettingsPage::PERIODS as $period) {
            printf(
                '<a href="%s" class="button%s"%s>%s</a> ',
                esc_url(SettingsPage::url('stats', ['days' => $period])),
                $period === $days ? ' button-primary' : '',
                $period === $days ? ' aria-current="true"' : '',
                /* translators: %d: number of days */
                esc_html(sprintf(_n('%d day', '%d days', $period, 'gecka-antispam'), $period)),
            );
        }

        echo '</div>';

        $totals = $this->plugin->stats()->totals($days);
        $summary = self::summary($totals);

        $this->tiles($summary);
        $this->chart($this->plugin->stats()->daily($days));
        $this->shares($summary);
        $this->table($totals);

        if (current_user_can(SettingsPage::capability('settings'))) {
            echo '<div class="gecka-admin-buttons">';
            $this->actionButton('gecka_antispam_reset_stats', __('Reset the statistics', 'gecka-antispam'), __('Drop every counter?', 'gecka-antispam'));
            echo '</div>';
        }
    }

    /**
     * Submissions checked, accepted, held for review and caught, out of the
     * totals by form.
     *
     * @param array<string, array<string, int>> $totals
     *
     * @return array{checked: int, passed: int, review: int, caught: int, outcomes: array<string, int>}
     */
    public static function summary(array $totals): array
    {
        $outcomes = [];

        foreach ($totals as $byOutcome) {
            foreach ($byOutcome as $outcome => $hits) {
                $outcomes[$outcome] = ($outcomes[$outcome] ?? 0) + $hits;
            }
        }

        $review = $outcomes[Guard::REVIEW] ?? 0;
        $passed = $outcomes[Guard::PASSED] ?? 0;
        unset($outcomes[Guard::PASSED], $outcomes[Guard::REVIEW]);
        arsort($outcomes);

        return [
            'checked' => $passed + $review + array_sum($outcomes),
            'passed' => $passed,
            'review' => $review,
            'caught' => array_sum($outcomes),
            'outcomes' => $outcomes,
        ];
    }

    /**
     * Prints the notice of a reset done.
     *
     * @return void
     */
    private function notices(): void
    {
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Only picks a notice.
        if (sanitize_key($_GET['reset'] ?? '') === 'stats') {
            wp_admin_notice(__('The statistics were reset.', 'gecka-antispam'), ['type' => 'success', 'dismissible' => true]);
        }
    }

    /**
     * Prints the totals of the period.
     *
     * @param array{checked: int, passed: int, review: int, caught: int, outcomes: array<string, int>} $summary
     *
     * @return void
     */
    private function tiles(array $summary): void
    {
        $rate = $summary['checked'] ? $summary['caught'] / $summary['checked'] * 100 : 0;
        /* translators: %s: share of the submissions caught, in percent */
        $share = sprintf(__('%s %%', 'gecka-antispam'), number_format_i18n($rate, 1));
        $tiles = [
            __('Submissions checked', 'gecka-antispam') => number_format_i18n($summary['checked']),
            __('Accepted', 'gecka-antispam') => number_format_i18n($summary['passed']),
            __('To review', 'gecka-antispam') => number_format_i18n($summary['review']),
            __('Caught', 'gecka-antispam') => number_format_i18n($summary['caught']),
            __('Catch rate', 'gecka-antispam') => $share,
        ];

        echo '<div class="gecka-antispam-tiles">';

        foreach ($tiles as $label => $value) {
            printf('<div class="gecka-antispam-tile card"><span class="gecka-antispam-tile-value">%s</span><span class="gecka-antispam-tile-label">%s</span></div>', esc_html($value), esc_html($label));
        }

        echo '</div>';
    }

    /**
     * Prints the submissions accepted and caught over the period, as stacked
     * bars: one per day, one per week past 90 days. The same figures follow
     * in a table, folded.
     *
     * @param array<string, array{passed: int, caught: int}> $daily
     *
     * @return void
     */
    private function chart(array $daily): void
    {
        $buckets = [];
        $size = count($daily) > 90 ? 7 : 1;

        foreach (array_chunk($daily, $size, true) as $chunk) {
            $day = (string) array_key_first($chunk);
            $time = (new \DateTimeImmutable($day . ' 12:00', wp_timezone()))->getTimestamp();
            $period = (string) wp_date((string) get_option('date_format'), $time);

            $buckets[$day] = [
                'passed' => array_sum(array_column($chunk, 'passed')),
                'caught' => array_sum(array_column($chunk, 'caught')),
                /* translators: %s: first day of the week */
                'period' => $size > 1 ? sprintf(__('Week of %s', 'gecka-antispam'), $period) : $period,
                /* translators: short date on the axis of the chart, see https://www.php.net/manual/datetime.format.php */
                'date' => (string) wp_date(_x('j M', 'chart axis', 'gecka-antispam'), $time),
            ];
        }

        $max = max(1, ...array_map(static fn($bucket) => $bucket['passed'] + $bucket['caught'], array_values($buckets)));
        $max = self::niceCeiling($max);

        $plotWidth = self::WIDTH - self::GUTTER_LEFT;
        $baseline = self::HEIGHT - self::GUTTER_BOTTOM;
        $plotHeight = $baseline - self::GUTTER_TOP;
        $step = $plotWidth / count($buckets);
        $barWidth = max(1.0, min(self::MAX_BAR, $step - 2));

        printf('<h2>%s</h2>', esc_html__('Accepted and caught', 'gecka-antispam'));

        echo '<div class="gecka-antispam-legend">';
        printf('<span><i class="gecka-antispam-swatch is-passed"></i>%s</span>', esc_html__('Accepted', 'gecka-antispam'));
        printf('<span><i class="gecka-antispam-swatch is-caught"></i>%s</span>', esc_html__('Caught', 'gecka-antispam'));
        echo '</div>';

        echo '<div class="gecka-antispam-chart-frame card">';
        printf(
            '<svg class="gecka-antispam-chart" viewBox="0 0 %d %d" role="img" aria-label="%s">',
            (int) self::WIDTH,
            (int) self::HEIGHT,
            esc_attr__('Submissions accepted and caught over the period. The same figures follow in a table.', 'gecka-antispam'),
        );

        foreach ([0, 0.5, 1] as $fraction) {
            $y = $baseline - $fraction * $plotHeight;

            printf('<line class="grid" x1="%d" x2="%d" y1="%.1f" y2="%.1f"/>', (int) self::GUTTER_LEFT, (int) self::WIDTH, (float) $y, (float) $y);
            printf('<text class="axis" x="%d" y="%.1f" text-anchor="end" dominant-baseline="middle">%s</text>', (int) self::GUTTER_LEFT - 6, (float) $y, esc_html(number_format_i18n($max * $fraction)));
        }

        $index = 0;
        $labelEvery = max(1, (int) ceil(count($buckets) / 8));

        foreach ($buckets as $bucket) {
            $slot = self::GUTTER_LEFT + $index * $step;
            $x = $slot + ($step - $barWidth) / 2;
            $passedHeight = $bucket['passed'] / $max * $plotHeight;
            $caughtHeight = $bucket['caught'] / $max * $plotHeight;
            echo '<g class="bar">';
            printf(
                '<title>%s</title>',
                /* translators: 1: day or week, 2: submissions accepted, 3: submissions caught */
                esc_html(sprintf(__('%1$s. Accepted: %2$s, caught: %3$s', 'gecka-antispam'), $bucket['period'], number_format_i18n($bucket['passed']), number_format_i18n($bucket['caught']))),
            );
            printf('<rect class="hit" x="%.1f" y="0" width="%.1f" height="%d"/>', (float) $slot, (float) $step, (int) $baseline);

            if ($passedHeight > 0) {
                self::bar($x, $baseline - $passedHeight, $barWidth, $passedHeight, 'passed', $caughtHeight <= 0);
            }

            if ($caughtHeight > 0) {
                // 2 units of the surface between the two segments.
                self::bar($x, $baseline - $passedHeight - $caughtHeight, $barWidth, max(0.5, $caughtHeight - ($passedHeight > 0 ? 2 : 0)), 'caught', true);
            }

            echo '</g>';

            if ($index % $labelEvery === 0) {
                $labelX = $x + $barWidth / 2;

                printf('<text class="axis" x="%.1f" y="%d" text-anchor="middle">%s</text>', (float) $labelX, (int) self::HEIGHT - 6, esc_html($bucket['date']));
            }

            $index++;
        }

        echo '</svg></div>';

        printf('<details class="gecka-antispam-figures"><summary>%s</summary>', esc_html($size > 1 ? __('Figures week by week', 'gecka-antispam') : __('Figures day by day', 'gecka-antispam')));
        echo '<div class="gecka-antispam-scroll"><table class="widefat striped gecka-antispam-table"><thead><tr>';
        printf('<th scope="col">%s</th>', esc_html($size > 1 ? __('Week', 'gecka-antispam') : __('Day', 'gecka-antispam')));
        printf('<th scope="col" class="num">%s</th><th scope="col" class="num">%s</th>', esc_html__('Accepted', 'gecka-antispam'), esc_html__('Caught', 'gecka-antispam'));
        echo '</tr></thead><tbody>';

        foreach (array_reverse($buckets) as $bucket) {
            printf(
                '<tr><th scope="row">%s</th><td class="num">%s</td><td class="num">%s</td></tr>',
                esc_html($bucket['period']),
                esc_html(number_format_i18n($bucket['passed'])),
                esc_html(number_format_i18n($bucket['caught'])),
            );
        }

        echo '</tbody></table></div></details>';
    }

    /**
     * Prints a segment of a bar, its top rounded when it ends the bar.
     *
     * @param float  $x
     * @param float  $y
     * @param float  $width
     * @param float  $height
     * @param string $series
     * @param bool   $top    Whether the segment ends the bar.
     *
     * @return void
     */
    private static function bar(float $x, float $y, float $width, float $height, string $series, bool $top): void
    {
        $radius = $top ? min(4, $width / 2, $height) : 0;

        $path = sprintf(
            'M%.1f %.1f V%.1f Q%.1f %.1f %.1f %.1f H%.1f Q%.1f %.1f %.1f %.1f V%.1f Z',
            $x,
            $y + $height,
            $y + $radius,
            $x,
            $y,
            $x + $radius,
            $y,
            $x + $width - $radius,
            $x + $width,
            $y,
            $x + $width,
            $y + $radius,
            $y + $height,
        );

        printf('<path class="%s" d="%s"/>', esc_attr($series), esc_attr($path));
    }

    /**
     * A round number above the highest value of the chart, even so the
     * middle line of the grid falls on a whole number
     *
     * @param int $value
     *
     * @return int
     */
    private static function niceCeiling(int $value): int
    {
        $magnitude = 10 ** (int) floor(log10($value));

        // Below 10, 1 and 5 would put the middle line on a half.
        foreach ($magnitude > 1 ? [1, 2, 5, 10] : [2, 4, 6, 8, 10] as $factor) {
            if ($value <= $factor * $magnitude) {
                return (int) ($factor * $magnitude);
            }
        }

        return $value;
    }

    /**
     * Prints, for each check, how many submissions it caught over the period
     * and its share of all those caught, the largest first, as bars.
     *
     * @param array{checked: int, passed: int, review: int, caught: int, outcomes: array<string, int>} $summary
     *
     * @return void
     */
    private function shares(array $summary): void
    {
        printf('<h2>%s</h2>', esc_html__('Caught by check', 'gecka-antispam'));

        if (! $summary['caught']) {
            printf('<p>%s</p>', esc_html__('Nothing caught over this period.', 'gecka-antispam'));

            return;
        }

        echo '<ul class="gecka-antispam-shares">';

        foreach ($summary['outcomes'] as $outcome => $hits) {
            $share = $hits / $summary['caught'] * 100;

            printf(
                '<li><span class="gecka-antispam-share-label">%s</span><span class="gecka-antispam-share-bar" aria-hidden="true"><span style="width: %s%%"></span></span><span class="gecka-antispam-share-value">%s</span></li>',
                esc_html(Guard::outcomeLabel((string) $outcome)),
                esc_attr(number_format(max($share, 0.5), 2, '.', '')),
                esc_html(
                    sprintf(
                        /* translators: 1: submissions caught, 2: share in percent */
                        __('%1$s (%2$s %%)', 'gecka-antispam'),
                        number_format_i18n($hits),
                        number_format_i18n($share, 1),
                    ),
                ),
            );
        }

        echo '</ul>';
    }

    /**
     * Prints the submissions by form and outcome.
     *
     * @param array<string, array<string, int>> $totals
     *
     * @return void
     */
    private function table(array $totals): void
    {
        printf('<h2>%s</h2>', esc_html__('By form', 'gecka-antispam'));

        if (! $totals) {
            printf('<p>%s</p>', esc_html__('No submission checked over this period.', 'gecka-antispam'));

            return;
        }

        $outcomes = Guard::outcomes();

        echo '<div class="gecka-antispam-scroll"><table class="widefat striped gecka-antispam-table"><thead><tr>';
        printf('<th scope="col">%s</th>', esc_html__('Form', 'gecka-antispam'));

        foreach ($outcomes as $label) {
            printf('<th scope="col" class="num">%s</th>', esc_html($label));
        }

        echo '</tr></thead><tbody>';

        $custom = array_filter(array_map('strval', array_keys($totals)), static fn(string $surface): bool => str_starts_with($surface, Settings::CUSTOM_PREFIX));
        sort($custom);

        foreach ([...Settings::surfaces(), ...$custom] as $surface) {
            if (empty($totals[$surface])) {
                continue;
            }

            printf('<tr><th scope="row">%s</th>', esc_html(Settings::surfaceLabel($surface)));

            foreach (array_keys($outcomes) as $outcome) {
                printf('<td class="num">%s</td>', esc_html(number_format_i18n($totals[$surface][$outcome] ?? 0)));
            }

            echo '</tr>';
        }

        echo '</tbody></table></div>';
    }
}
