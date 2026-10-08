<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

namespace Gecka\WP\Plugin\Antispam\Admin;

use Gecka\WP\Plugin\Antispam\Guard;
use Gecka\WP\Plugin\Antispam\Plugin;
use Gecka\WP\Plugin\Antispam\Settings;
use Gecka\WP\Plugin\Antispam\StatisticalFilter;

/**
 * The list of the submissions refused, the most recent first, in two views:
 * those waiting for review, and those learnt. The text is the primary
 * column, keyed title as for the posts so the screen options cannot hide
 * it: on a small screen the other columns fold under it. Its row actions
 * learn, unlearn or delete the entry through the bulk actions. The number of
 * entries per page and the columns shown are screen options, and so is the
 * display mode: the compact view folds a long text after EXCERPT
 * characters, the extended view shows it whole.
 *
 * @author Laurent Dinclaux - Gecka <laurent@gecka.nc>
 */
class RefusedTable extends \WP_List_Table
{
    /**
     * Characters of a text shown in the compact view before the rest is
     * folded.
     */
    private const EXCERPT = 300;

    /**
     * @var Plugin
     */
    private Plugin $plugin;

    /**
     * Whether the entries learnt are listed, rather than those to review.
     *
     * @var bool
     */
    private bool $learntView;

    /**
     * Whether the statistical filter rates the texts of the page: switched on
     * and past the texts it learns first.
     *
     * @var bool
     */
    private bool $rates = false;

    /**
     * @param Plugin $plugin
     */
    public function __construct(Plugin $plugin)
    {
        $this->plugin = $plugin;
        $this->learntView = RefusedView::learntView();

        parent::__construct(
            [
                'singular' => 'refused-entry',
                'plural' => 'refused-entries',
                'ajax' => false,
            ],
        );
    }

    /**
     * Reads the entries of the page.
     *
     * @return void
     */
    public function prepare_items(): void
    {
        $journal = $this->plugin->journal();
        $perPage = $this->get_items_per_page(RefusedView::PER_PAGE_OPTION, RefusedView::PER_PAGE);

        $this->set_pagination_args(
            [
                'total_items' => $journal->count($this->learntView),
                'per_page' => $perPage,
            ],
        );

        $this->items = $journal->entries($this->get_pagenum(), $perPage, $this->learntView);
        $this->rates = $this->plugin->filterReady();
    }

    /**
     * @return array<string, string>
     */
    public function get_columns(): array
    {
        $columns = [
            'cb' => '<input type="checkbox">',
            'title' => __('Text', 'gecka-antispam'),
            'form' => __('Form', 'gecka-antispam'),
            'reason' => __('Reason', 'gecka-antispam'),
        ];

        if ($this->plugin->settings()->get('filter')) {
            $columns['score'] = __('Spam rating', 'gecka-antispam');
        }

        $columns['date'] = __('Date', 'gecka-antispam');

        if ($this->learntView) {
            $columns['learnt'] = __('Learnt as', 'gecka-antispam');
        }

        return $columns;
    }

    /**
     * @return string
     */
    protected function get_default_primary_column_name(): string
    {
        return 'title';
    }

    /**
     * @return string[]
     */
    protected function get_table_classes(): array
    {
        return [...parent::get_table_classes(), 'gecka-antispam-refused'];
    }

    /**
     * Links to the two views, with their counts
     *
     * @return array<string, string>
     */
    protected function get_views(): array
    {
        $journal = $this->plugin->journal();
        $views = [
            /* translators: %s: number of entries */
            'pending' => sprintf(__('To review (%s)', 'gecka-antispam'), number_format_i18n($journal->count())),
            /* translators: %s: number of entries */
            'learnt' => sprintf(__('Learnt (%s)', 'gecka-antispam'), number_format_i18n($journal->count(true))),
        ];
        $links = [];

        foreach ($views as $view => $label) {
            $current = ($view === 'learnt') === $this->learntView;
            $links[$view] = sprintf(
                '<a href="%s"%s>%s</a>',
                esc_url(SettingsPage::url('refused', $view === 'learnt' ? ['view' => 'learnt'] : [])),
                $current ? ' class="current" aria-current="page"' : '',
                esc_html($label),
            );
        }

        return $links;
    }

    /**
     * Learning while the statistical filter is on, deleting always
     *
     * @return array<string, string>
     */
    protected function get_bulk_actions(): array
    {
        $actions = [];

        if ($this->plugin->settings()->get('filter')) {
            $actions['learn_spam'] = __('Learn as spam', 'gecka-antispam');
            $actions['learn_ham'] = __('Learn as legitimate', 'gecka-antispam');

            if ($this->learntView) {
                $actions['unlearn'] = __('Unlearn', 'gecka-antispam');
            }
        }

        $actions['delete'] = __('Delete', 'gecka-antispam');

        return $actions;
    }

    /**
     * @return void
     */
    public function no_items(): void
    {
        echo esc_html($this->learntView ? __('No refused submission learnt.', 'gecka-antispam') : __('No refused submission to review.', 'gecka-antispam'));
    }

    /**
     * @param object $item
     *
     * @return string
     */
    protected function column_cb($item): string
    {
        $id = (int) ($item->id ?? 0);

        return sprintf(
            '<input type="checkbox" name="ids[]" value="%1$d" id="gecka-antispam-refused-%1$d"><label for="gecka-antispam-refused-%1$d"><span class="screen-reader-text">%2$s</span></label>',
            $id,
            esc_html__('Select this entry', 'gecka-antispam'),
        );
    }

    /**
     * When the text was last sent, and how many times
     *
     * @param object $item
     *
     * @return string
     */
    protected function column_date(object $item): string
    {
        $date = (string) ($item->updated ?? '');
        $hits = (int) ($item->hits ?? 1);
        $shown = wp_date(get_option('date_format') . ' ' . get_option('time_format'), (int) strtotime($date . ' UTC')) ?: $date;

        return esc_html($shown) . ($hits > 1
            /* translators: %s: number of times the same text was sent */
            ? '<br><span class="description">' . esc_html(sprintf(_n('sent %s time', 'sent %s times', $hits, 'gecka-antispam'), number_format_i18n($hits))) . '</span>'
            : '');
    }

    /**
     * @param object $item
     *
     * @return string
     */
    protected function column_form(object $item): string
    {
        return esc_html(Settings::surfaceLabel((string) ($item->surface ?? '')));
    }

    /**
     * @param object $item
     *
     * @return string
     */
    protected function column_reason(object $item): string
    {
        return esc_html(Guard::outcomeLabel((string) ($item->outcome ?? '')));
    }

    /**
     * What the statistical filter makes of the text now, for information:
     * a check of the form refused most entries before any rating, and the
     * rating moves as the filter learns. Nothing is rated while the column is
     * hidden.
     *
     * @param object $item
     *
     * @return string
     */
    protected function column_score(object $item): string
    {
        [, $hidden] = $this->get_column_info();

        if (in_array('score', (array) $hidden, true)) {
            return '';
        }

        $score = $this->rates ? $this->plugin->statisticalFilter()->classify((string) ($item->text ?? '')) : null;

        /* translators: %s: rating of the statistical filter, in percent */
        return $score === null ? '&mdash;' : esc_html(sprintf(__('%s %% spam', 'gecka-antispam'), number_format_i18n($score * 100, 1)));
    }

    /**
     * Links under the text doing to the entry what the bulk actions do:
     * learning it while the statistical filter is on, the other way when it
     * was learnt, unlearning it, deleting it.
     *
     * @param object $item
     * @param string $column_name
     * @param string $primary
     *
     * @return string
     */
    protected function handle_row_actions($item, $column_name, $primary): string
    {
        if ($column_name !== $primary) {
            return '';
        }

        $learnt = ($item->learnt ?? '') ?: null;
        $labels = [];

        if ($this->plugin->settings()->get('filter')) {
            if ($learnt !== StatisticalFilter::SPAM) {
                $labels['learn_spam'] = __('Learn as spam', 'gecka-antispam');
            }

            if ($learnt !== StatisticalFilter::HAM) {
                $labels['learn_ham'] = __('Learn as legitimate', 'gecka-antispam');
            }

            if ($learnt !== null) {
                $labels['unlearn'] = __('Unlearn', 'gecka-antispam');
            }
        }

        $labels['delete'] = __('Delete', 'gecka-antispam');
        $args = ($this->learntView ? ['view' => 'learnt'] : []) + ['ids' => [(int) ($item->id ?? 0)], '_wpnonce' => wp_create_nonce('bulk-' . $this->_args['plural'])];
        $actions = [];

        foreach ($labels as $op => $label) {
            $actions[$op] = sprintf('<a href="%s">%s</a>', esc_url(SettingsPage::url('refused', $args + ['action' => $op])), esc_html($label));
        }

        return $this->row_actions($actions);
    }

    /**
     * The text, folded past EXCERPT characters in the compact view
     *
     * @param object $item
     *
     * @return string
     */
    protected function column_title(object $item): string
    {
        $text = (string) ($item->text ?? '');

        if (RefusedView::mode() === 'list' && mb_strlen($text) > self::EXCERPT) {
            return sprintf(
                '<details><summary>%s…</summary><div class="gecka-antispam-refused-text">%s</div></details>',
                esc_html(mb_substr($text, 0, self::EXCERPT)),
                nl2br(esc_html($text)),
            );
        }

        return sprintf('<div class="gecka-antispam-refused-text">%s</div>', nl2br(esc_html($text)));
    }

    /**
     * @param object $item
     *
     * @return string
     */
    protected function column_learnt(object $item): string
    {
        return esc_html(($item->learnt ?? '') === StatisticalFilter::SPAM ? __('Spam', 'gecka-antispam') : __('Legitimate', 'gecka-antispam'));
    }
}
