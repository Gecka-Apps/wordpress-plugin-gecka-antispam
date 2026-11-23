<?php

declare(strict_types=1);

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

namespace Gecka\WP\Plugin\Antispam\Admin;

use Gecka\WP\Plugin\Antispam\Admin\RefusedView\View;
use Gecka\WP\Plugin\Antispam\Guard;
use Gecka\WP\Plugin\Antispam\Plugin;
use Gecka\WP\Plugin\Antispam\Settings;
use Gecka\WP\Plugin\Antispam\StatisticalFilter;
use Gecka\WP\Plugin\Antispam\Value;

/**
 * The list of the submissions refused, the most recent first, in three
 * views: those waiting for review that are worth learning, those waiting
 * that are plain spam, and those learnt. The text is the primary
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
     * The view listed.
     *
     * @var View
     */
    private View $view;

    /**
     * Whether the statistical filter rates the texts of the page: switched on
     * and past the texts it learns first.
     *
     * @var bool
     */
    private bool $rates;

    /**
     * The entries waiting for review, sorted into those worth learning and
     * plain spam, with their rating, once read.
     *
     * @var array{review: array<int, float|null>, spam: array<int, float|null>}|null
     */
    private ?array $triage = null;

    /**
     * Whether a row printed shows a country.
     *
     * @var bool
     */
    private bool $countries = false;

    /**
     * Lists the view the address names.
     *
     * @param Plugin $plugin
     */
    public function __construct(Plugin $plugin)
    {
        $this->plugin = $plugin;
        $this->rates = $plugin->filterReady();
        $this->view = RefusedView::view();

        parent::__construct(
            [
                'singular' => 'refused-entry',
                'plural' => 'refused-entries',
                'ajax' => false,
            ],
        );
    }

    /**
     * The view listed
     *
     * @return View
     */
    public function view(): View
    {
        return $this->view;
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
        $ids = match ($this->view) {
            View::Pending => array_keys($this->triage()['review']),
            View::Spam => array_keys($this->triage()['spam']),
            View::Learnt => null,
        };

        $this->set_pagination_args(
            [
                'total_items' => $ids === null ? $journal->count(true) : count($ids),
                'per_page' => $perPage,
            ],
        );

        $this->items = $ids === null
            ? $journal->entries($this->get_pagenum(), $perPage, true)
            : $journal->find(array_slice($ids, ($this->get_pagenum() - 1) * $perPage, $perPage));
    }

    /**
     * The entries waiting for review, sorted into those worth learning and
     * plain spam, read once for the request: the views, the pagination, the
     * page and the rating column need them, and reading them rates every
     * entry waiting that is not plain spam by its reason or its length
     *
     * @return array{review: array<int, float|null>, spam: array<int, float|null>} Ids of each set, the most recent first, with their rating when the filter gave one.
     */
    private function triage(): array
    {
        if ($this->triage === null) {
            $settings = $this->plugin->settings();
            $this->triage = $this->plugin->journal()->triage($this->rates ? $settings->int('filter_threshold') : null, $settings->int('min_words'));
        }

        return $this->triage;
    }

    /**
     * The columns of the view: the rating only while the filter is on, what
     * the entry was learnt as only in the Learnt view
     *
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

        $columns['information'] = __('Information', 'gecka-antispam');

        if ($this->view === View::Learnt) {
            $columns['learnt'] = __('Learnt as', 'gecka-antispam');
        }

        return $columns;
    }

    /**
     * The text is the primary column: the row actions hang under it, and
     * the other columns fold under it on a small screen.
     *
     * @return string
     */
    protected function get_default_primary_column_name(): string
    {
        return 'title';
    }

    /**
     * The classes of the table, with the one its style sheet targets
     *
     * @return string[]
     */
    protected function get_table_classes(): array
    {
        return [...parent::get_table_classes(), 'gecka-antispam-refused'];
    }

    /**
     * Links to the views, with their counts
     *
     * @return array<string, string>
     */
    protected function get_views(): array
    {
        $triage = $this->triage();
        $views = [
            /* translators: %s: number of entries */
            View::Pending->value => sprintf(__('To review (%s)', 'gecka-antispam'), number_format_i18n(count($triage['review']))),
            /* translators: %s: number of entries */
            View::Spam->value => sprintf(__('Spam (%s)', 'gecka-antispam'), number_format_i18n(count($triage['spam']))),
            /* translators: %s: number of entries */
            View::Learnt->value => sprintf(__('Learnt (%s)', 'gecka-antispam'), number_format_i18n($this->plugin->journal()->count(true))),
        ];
        $links = [];

        foreach ($views as $value => $label) {
            $view = View::from($value);
            $links[$value] = sprintf(
                '<a href="%s"%s>%s</a>',
                esc_url(SettingsPage::url('refused', $view->query())),
                $view === $this->view ? ' class="current" aria-current="page"' : '',
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

            if ($this->view === View::Learnt) {
                $actions['unlearn'] = __('Unlearn', 'gecka-antispam');
            }
        }

        $actions['delete'] = __('Delete', 'gecka-antispam');

        return $actions;
    }

    /**
     * Prints what stands for an empty view.
     *
     * @return void
     */
    public function no_items(): void
    {
        echo esc_html(
            match ($this->view) {
                View::Pending => __('No refused submission to review.', 'gecka-antispam'),
                View::Spam => __('No refused submission of plain spam.', 'gecka-antispam'),
                View::Learnt => __('No refused submission learnt.', 'gecka-antispam'),
            },
        );
    }

    /**
     * @param mixed $item An entry of the journal; untyped in WP_List_Table.
     *
     * @return string
     */
    protected function column_cb(mixed $item): string
    {
        $id = is_object($item) ? Value::int($item->id ?? null) : 0;

        return sprintf(
            '<input type="checkbox" name="ids[]" value="%1$d" id="gecka-antispam-refused-%1$d"><label for="gecka-antispam-refused-%1$d"><span class="screen-reader-text">%2$s</span></label>',
            $id,
            esc_html__('Select this entry', 'gecka-antispam'),
        );
    }

    /**
     * Whether a row of the page shows a country, which calls for the credit
     * of the geolocation data.
     *
     * @return bool
     */
    public function showsCountries(): bool
    {
        return $this->countries;
    }

    /**
     * When the text was last sent, how many times, and from which country
     * the last time
     *
     * @param object $item
     *
     * @return string
     */
    protected function column_information(object $item): string
    {
        $date = (string) ($item->updated ?? '');
        $hits = (int) ($item->hits ?? 1);
        $country = Value::string($item->country ?? null);
        $shown = wp_date(Value::string(get_option('date_format')) . ' ' . Value::string(get_option('time_format')), (int) strtotime($date . ' UTC')) ?: $date;

        return esc_html($shown) . ($hits > 1
            /* translators: %s: number of times the same text was sent */
            ? '<br><span class="description">' . esc_html(sprintf(_n('sent %s time', 'sent %s times', $hits, 'gecka-antispam'), number_format_i18n($hits))) . '</span>'
            : '') . ($country !== '' ? '<br>' . $this->country($country) : '');
    }

    /**
     * A country, its flag before its name when Gecka Geolocation provides
     * them, its code otherwise
     *
     * @param string $code ISO 3166-1 code.
     *
     * @return string Markup, escaped.
     */
    private function country(string $code): string
    {
        $this->countries = true;
        $flag = function_exists('gecka_geolocation_flag_url') ? gecka_geolocation_flag_url($code) : null;
        $name = function_exists('gecka_geolocation_country_name') ? (string) gecka_geolocation_country_name($code) : '';

        return sprintf(
            '<span class="gecka-antispam-country" data-country="%s">%s%s</span>',
            esc_attr($code),
            $flag ? sprintf('<img src="%s" alt="" width="16" height="12" loading="lazy"> ', esc_url($flag)) : '',
            esc_html($name !== '' ? $name : $code),
        );
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
     * hidden, and an entry waiting for review keeps the rating it was sorted
     * by.
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

        $id = Value::int($item->id ?? null);
        $score = $this->rates ? ($this->triage['review'][$id] ?? $this->triage['spam'][$id] ?? $this->plugin->statisticalFilter()->classify((string) ($item->text ?? ''))) : null;

        /* translators: %s: rating of the statistical filter, in percent */
        return $score === null ? '&mdash;' : esc_html(sprintf(__('%s %% spam', 'gecka-antispam'), number_format_i18n($score * 100, 1)));
    }

    /**
     * Links under the text doing to the entry what the bulk actions do:
     * learning it while the statistical filter is on, the other way when it
     * was learnt, unlearning it, deleting it.
     *
     * @param mixed $item        An entry of the journal; untyped in WP_List_Table.
     * @param mixed $column_name
     * @param mixed $primary
     *
     * @return string
     */
    protected function handle_row_actions(mixed $item, mixed $column_name, mixed $primary): string
    {
        if ($column_name !== $primary || ! is_object($item)) {
            return '';
        }

        $learnt = Value::string($item->learnt ?? null) ?: null;
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
        $args = $this->view->query() + ['ids' => [Value::int($item->id ?? null)], '_wpnonce' => wp_create_nonce('bulk-' . Value::string($this->_args['plural'] ?? null))];
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
