<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

namespace Gecka\WP\Plugin\Antispam\Admin;

use Gecka\WP\Plugin\Antispam\Base;
use Gecka\WP\Plugin\Antispam\Guard;

/**
 * Dashboard widget, for those who may see the statistics: the submissions
 * of the last seven days, what caught them, and a link to the statistics.
 *
 * @author Laurent Dinclaux - Gecka <laurent@gecka.nc>
 */
class DashboardWidget extends Base
{
    /**
     * Days the widget covers.
     */
    private const DAYS = 7;

    /**
     * @return void
     */
    public function setup(): void
    {
        add_action('wp_dashboard_setup', [$this, 'add']);
    }

    /**
     * @return void
     */
    public function add(): void
    {
        if (! current_user_can(SettingsPage::capability('stats'))) {
            return;
        }

        wp_add_dashboard_widget('gecka_antispam', __('Antispam', 'gecka-antispam'), [$this, 'render']);
        add_action('admin_print_styles-index.php', [Styles::class, 'enqueue']);
    }

    /**
     * @return void
     */
    public function render(): void
    {
        $summary = StatsView::summary($this->plugin->stats()->totals(self::DAYS));

        $counts = $this->plugin->statisticalFilter()->counts();
        $rows = [
            __('Submissions checked', 'gecka-antispam') => $summary['checked'],
            __('To review', 'gecka-antispam') => $summary['review'],
            __('Caught', 'gecka-antispam') => $summary['caught'],
        ];
        $refused = $this->plugin->journal()->count();

        foreach ($summary['outcomes'] as $outcome => $hits) {
            $rows['&nbsp;&nbsp;' . Guard::outcomeLabel($outcome)] = $hits;
        }

        $rows[__('Spam texts learnt', 'gecka-antispam')] = $counts['spam'];
        $rows[__('Legitimate texts learnt', 'gecka-antispam')] = $counts['ham'];

        /* translators: %d: number of days */
        printf('<p class="gecka-antispam-widget-total">%s</p>', esc_html(sprintf(_n('Last %d day', 'Last %d days', self::DAYS, 'gecka-antispam'), self::DAYS)));

        echo '<table class="widefat striped gecka-antispam-table"><tbody>';

        foreach ($rows as $label => $value) {
            printf('<tr><th scope="row">%s</th><td class="num">%s</td></tr>', wp_kses($label, []), esc_html(number_format_i18n($value)));
        }

        echo '</tbody></table>';

        if ($refused && current_user_can(SettingsPage::capability('refused'))) {
            printf(
                '<p><a href="%s">%s</a></p>',
                esc_url(SettingsPage::url('refused')),
                /* translators: %s: number of refused submissions */
                esc_html(sprintf(_n('%s refused submission to review', '%s refused submissions to review', $refused, 'gecka-antispam'), number_format_i18n($refused))),
            );
        }

        printf('<p><a href="%s">%s</a></p>', esc_url(SettingsPage::url('stats')), esc_html__('See the statistics', 'gecka-antispam'));
    }
}
