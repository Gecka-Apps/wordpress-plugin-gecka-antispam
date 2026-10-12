<?php

declare(strict_types=1);

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

namespace Gecka\WP\Plugin\Antispam\Admin;

use Gecka\WP\Plugin\Antispam\Journal;
use Gecka\WP\Plugin\Antispam\Plugin;
use Gecka\WP\Plugin\Antispam\Request;
use Gecka\WP\Plugin\Antispam\StatisticalFilter;
use Gecka\WP\Plugin\Antispam\Value;

/**
 * The Antispam tab of the Journal: the list of the submissions refused, its
 * screen options and its bulk actions. Those waiting for review are learnt
 * as spam or as legitimate, or deleted; those learnt stay in their own
 * view, where they can be learnt the other way, unlearnt back to review, or
 * deleted.
 *
 * @author Laurent Dinclaux - Gecka <laurent@gecka.nc>
 */
class RefusedView
{
    /**
     * User meta holding the entries per page, a screen option.
     */
    public const PER_PAGE_OPTION = 'gecka_antispam_refused_per_page';

    /**
     * Entries per page until the screen options say otherwise.
     */
    public const PER_PAGE = 50;

    /**
     * User setting holding the display mode, list or excerpt as for the
     * posts.
     */
    public const MODE_SETTING = 'gecka_antispam_refused_mode';

    /**
     * @var Plugin
     */
    private Plugin $plugin;

    /**
     * @var RefusedTable|null
     */
    private ?RefusedTable $table = null;

    /**
     * @param Plugin $plugin
     */
    public function __construct(Plugin $plugin)
    {
        $this->plugin = $plugin;
    }

    /**
     * The display mode of the current user: list, the compact view, or
     * excerpt, the extended one
     *
     * @return string
     */
    public static function mode(): string
    {
        return get_user_setting(self::MODE_SETTING, 'list') === 'excerpt' ? 'excerpt' : 'list';
    }

    /**
     * Whether the Learnt view is shown, rather than the entries to review
     *
     * @return bool
     */
    public static function learntView(): bool
    {
        return sanitize_key(Request::query('view')) === 'learnt';
    }

    /**
     * Sets the screen up before anything is printed: the screen options,
     * the display mode the screen options sent, and the bulk action
     * submitted, which redirects.
     *
     * @return void
     */
    public function load(): void
    {
        require_once ABSPATH . 'wp-admin/includes/class-wp-list-table.php';

        add_screen_option('per_page', ['default' => self::PER_PAGE, 'option' => self::PER_PAGE_OPTION]);
        add_filter('screen_settings', [$this, 'modeSettings']);

        // set_screen_options() checked the nonce before redirecting with the mode.
        $mode = sanitize_key(Request::query('mode'));

        if (in_array($mode, ['list', 'excerpt'], true)) {
            set_user_setting(self::MODE_SETTING, $mode);
        }

        $this->table = new RefusedTable($this->plugin);
        $this->bulk();
    }

    /**
     * Adds the display mode to the screen options, as WordPress shows it
     * for the posts: a radio named mode, which set_screen_options() carries
     * into its redirect.
     *
     * @param mixed $settings
     *
     * @return string
     */
    public function modeSettings(mixed $settings): string
    {
        $mode = self::mode();

        add_filter('screen_options_show_submit', '__return_true');

        return Value::string($settings) . sprintf(
            '<fieldset class="metabox-prefs view-mode"><legend>%1$s</legend><label for="list-view-mode"><input id="list-view-mode" type="radio" name="mode" value="list"%2$s> %3$s</label><label for="excerpt-view-mode"><input id="excerpt-view-mode" type="radio" name="mode" value="excerpt"%4$s> %5$s</label></fieldset>',
            esc_html__('Display mode', 'gecka-antispam'),
            checked($mode, 'list', false),
            esc_html__('Compact view', 'gecka-antispam'),
            checked($mode, 'excerpt', false),
            esc_html__('Extended view', 'gecka-antispam'),
        );
    }

    /**
     * Prints the tab.
     *
     * @return void
     */
    public function render(): void
    {
        $table = $this->table;

        if (! $table) {
            return;
        }

        $this->notice();

        printf(
            '<p>%s</p>',
            esc_html(
                sprintf(
                    /* translators: %d: number of days */
                    __('The submissions refused: those the checks of the form caught, and those the statistical filter rated past the rejection threshold. What the filter reads of each is kept, the subject and the message, with nothing of the sender, for %d days. Learn them as spam or as legitimate, or delete them. A submission learnt stays in the Learnt view, where it can be learnt the other way or unlearnt.', 'gecka-antispam'),
                    Journal::DAYS,
                ),
            ),
        );

        if ($this->plugin->settings()->get('filter')) {
            printf('<p>%s</p>', esc_html__('The spam rating is what the statistical filter makes of each text today, for information: it moves as the filter learns, and stays empty while the filter is still learning.', 'gecka-antispam'));
        }

        $table->prepare_items();
        $table->views();

        echo '<form method="get">';
        printf('<input type="hidden" name="page" value="%s">', esc_attr(SettingsPage::PAGES['refused']));
        printf('<input type="hidden" name="tab" value="%s">', esc_attr(SettingsPage::TAB));

        if (self::learntView()) {
            echo '<input type="hidden" name="view" value="learnt">';
        }

        $table->display();
        echo '</form>';

        if (! $this->plugin->journal()->count() && ! $this->plugin->journal()->count(true)) {
            return;
        }

        printf('<form method="post" action="%s" class="gecka-antispam-refused-clear">', esc_url(admin_url('admin-post.php')));
        echo '<input type="hidden" name="action" value="gecka_antispam_clear_refused">';
        wp_nonce_field('gecka_antispam_clear_refused');
        printf(
            '<button type="submit" class="button" onclick="return confirm(%s)">%s</button>',
            esc_attr((string) wp_json_encode(__('Delete every refused submission, learnt or not? What was learnt of them stays learnt.', 'gecka-antispam'))),
            esc_html__('Delete everything', 'gecka-antispam'),
        );
        echo '</form>';
    }

    /**
     * Runs the bulk action submitted, then redirects to the view with a
     * notice. A form submitted without an action, from the page number
     * field, comes back without the nonce and the referer in its address.
     *
     * @return void
     */
    private function bulk(): void
    {
        $op = $this->table ? $this->table->current_action() : false;
        $view = self::learntView() ? ['view' => 'learnt'] : [];

        if (! $op) {
            // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Only drops the arguments of a form submitted without an action.
            if (! empty($_GET['_wp_http_referer'])) {
                // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Passed to remove_query_arg() and wp_safe_redirect().
                wp_safe_redirect(remove_query_arg(['_wp_http_referer', '_wpnonce', 'action', 'action2', 'bulk_action', 'ids'], Value::string(wp_unslash($_SERVER['REQUEST_URI'] ?? ''))));
                exit;
            }

            return;
        }

        if (! current_user_can(SettingsPage::capability('refused'))) {
            wp_die(esc_html__('Sorry, you are not allowed to do that.', 'gecka-antispam'), 403);
        }

        check_admin_referer('bulk-refused-entries');

        // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Each id is read as an integer.
        $ids = array_filter(array_map(static fn(mixed $id): int => abs(Value::int($id)), Value::list(wp_unslash($_GET['ids'] ?? []))));

        if (! $ids) {
            wp_safe_redirect(SettingsPage::url('refused', $view));
            exit;
        }

        $journal = $this->plugin->journal();
        $done = 0;
        $old = 0;

        if ($op === 'learn_spam' || $op === 'learn_ham') {
            $done = $journal->learn($ids, $op === 'learn_spam' ? StatisticalFilter::SPAM : StatisticalFilter::HAM);
        } elseif ($op === 'unlearn') {
            [$done, $old] = $journal->unlearn($ids);
        } elseif ($op === 'delete') {
            $journal->delete($ids);
            $done = count($ids);
        }

        wp_safe_redirect(SettingsPage::url('refused', $view + ['done' => $done, 'op' => $op] + ($old ? ['old' => $old] : [])));
        exit;
    }

    /**
     * Prints the notice of the action done.
     *
     * @return void
     */
    private function notice(): void
    {
        // phpcs:disable WordPress.Security.NonceVerification.Recommended -- Only picks a notice.
        if (! isset($_GET['done'], $_GET['op'])) {
            return;
        }

        $count = absint(Request::query('done'));
        $op = sanitize_key(Request::query('op'));
        $old = absint(Request::query('old'));
        // phpcs:enable

        $messages = [
            /* translators: %s: number of entries */
            'learn_spam' => _n('%s entry learnt as spam.', '%s entries learnt as spam.', $count, 'gecka-antispam'),
            /* translators: %s: number of entries */
            'learn_ham' => _n('%s entry learnt as legitimate.', '%s entries learnt as legitimate.', $count, 'gecka-antispam'),
            /* translators: %s: number of entries */
            'delete' => _n('%s entry deleted.', '%s entries deleted.', $count, 'gecka-antispam'),
            /* translators: %s: number of entries */
            'unlearn' => _n('%s entry unlearnt, back to review.', '%s entries unlearnt, back to review.', $count, 'gecka-antispam'),
            'clear' => __('Every refused submission was deleted.', 'gecka-antispam'),
        ];

        if (isset($messages[$op])) {
            wp_admin_notice(sprintf($messages[$op], number_format_i18n($count)), ['type' => 'success', 'dismissible' => true]);
        }

        if ($op === 'unlearn' && $old) {
            wp_admin_notice(
                sprintf(
                    /* translators: %s: number of entries */
                    _n(
                        '%s entry was learnt before the previous rotation of the counters and has halved since: it cannot be unlearnt exactly and stays learnt. Learn it the other way to correct it.',
                        '%s entries were learnt before the previous rotation of the counters and have halved since: they cannot be unlearnt exactly and stay learnt. Learn them the other way to correct them.',
                        $old,
                        'gecka-antispam',
                    ),
                    number_format_i18n($old),
                ),
                ['type' => 'warning', 'dismissible' => true],
            );
        }
    }
}
