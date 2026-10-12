<?php

declare(strict_types=1);

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

namespace Gecka\WP\Plugin\Antispam\Admin;

use Gecka\WP\AdminMenu\Menus;
use Gecka\WP\AdminMenu\Tab;
use Gecka\WP\Plugin\Antispam\Base;
use Gecka\WP\Plugin\Antispam\Journal;
use Gecka\WP\Plugin\Antispam\Plugin;
use Gecka\WP\Plugin\Antispam\Settings;
use Gecka\WP\Plugin\Antispam\Setup;
use Gecka\WP\Plugin\Antispam\StatisticalFilter;

/**
 * The screens of the plugin: its statistics and its refused submissions as
 * Antispam tabs of the Statistics and Journal pages of the shared Security
 * menu, which other Gecka plugins add their own tabs to; the statistical
 * filter and the settings under Settings > Antispam; and the actions their
 * buttons post.
 *
 * @author Laurent Dinclaux - Gecka <laurent@gecka.nc>
 */
class SettingsPage extends Base
{
    use Controls;

    /**
     * Slug of the settings page, under Settings.
     */
    public const PAGE = 'gecka-antispam';

    /**
     * Slug of the shared menu. A plugin declaring the same slug shares it.
     */
    public const MENU = 'security';

    /**
     * Slugs of the shared pages, by the name their tab is known under in the
     * plugin.
     */
    public const PAGES = [
        'stats' => 'security-stats',
        'refused' => 'security-journal',
    ];

    /**
     * Slug of the tab of the plugin on each shared page.
     */
    public const TAB = 'gecka-antispam';

    /**
     * Periods offered on the statistics tab, in days.
     */
    public const PERIODS = [7, 30, 90, 365];

    /**
     * Seconds a click spends learning at most, batch after batch, when the
     * button posts the form; half the time limit of PHP when that is
     * shorter.
     */
    public const LEARN_SECONDS = 20;

    /**
     * Seconds a request of the REST route spends learning at most, so that
     * the page shows the progress between two of them.
     */
    public const REST_SECONDS = 5;

    /**
     * Namespace of the REST routes.
     */
    public const REST_NAMESPACE = 'gecka-antispam/v1';

    /**
     * The list of the refused submissions, set up when the Journal tab
     * loads.
     *
     * @var RefusedView|null
     */
    private ?RefusedView $refused = null;

    /**
     * Hooks the screens, the handlers of their buttons, the REST routes and
     * the screen options up.
     *
     * @return void
     */
    public function setup(): void
    {
        // On init and not before: the titles are translated, and WordPress
        // loads a text domain from init on. Everywhere, not in the admin
        // only: the REST requests and Site Health build addresses of the
        // screens. At the default priority: a plugin owning the Security menu
        // names it first.
        add_action('init', [$this, 'declare']);
        add_action('admin_init', [$this, 'registerSetting']);
        add_action('admin_notices', [$this, 'installFailedNotice']);
        add_filter('option_page_capability_' . self::PAGE, static fn(): string => self::capability('settings'));
        add_action('admin_post_gecka_antispam_reset_filter', [$this, 'resetFilter']);
        add_action('admin_post_gecka_antispam_update_backgrounds', [$this, 'updateBackgrounds']);
        add_action('admin_post_gecka_antispam_reset_stats', [$this, 'resetStats']);
        add_action('admin_post_gecka_antispam_learn_existing', [$this, 'learnExisting']);
        add_action('rest_api_init', [$this, 'registerRoutes']);
        add_filter('set_screen_option_' . RefusedView::PER_PAGE_OPTION, static fn(mixed $keep, mixed $option, mixed $value): int => min(999, max(1, (int) $value)), 10, 3);
        add_action('admin_post_gecka_antispam_clear_refused', [$this, 'clearRefused']);
        add_action('admin_post_gecka_antispam_reset_settings', [$this, 'resetSettings']);
        add_filter('plugin_action_links_' . plugin_basename($this->plugin->file()), [$this, 'actionLinks']);
        add_action('admin_init', [$this, 'privacyPolicy']);
    }

    /**
     * Offers a paragraph for the privacy policy of the site.
     *
     * @return void
     */
    public function privacyPolicy(): void
    {
        wp_add_privacy_policy_content(
            __('Gecka Antispam', 'gecka-antispam'),
            wp_kses_post(
                wpautop(
                    sprintf(
                        /* translators: %d: days a refused submission is kept */
                        __('The forms of this site are checked for spam on this server, with no external service, no cookie and no IP address kept. The check keeps daily counts of the submissions by form and by outcome, with nothing of who sent them. To tell spam from legitimate messages, it keeps counts on hashes of the words of the subject and the message of the submissions marked as spam or not spam: no text is kept in them, and nothing ties these counts to a person. The rating the filter gives and the reason for a refusal are stored with the comment or the entry they concern, and deleted with it. A refused submission keeps its subject and its message, without the name or the email address of the sender, for a moderator to review; that message may hold personal details the sender wrote in it. It is deleted %d days after it was last sent.', 'gecka-antispam'),
                        Journal::DAYS,
                    ),
                ),
            ),
        );
    }

    /**
     * Declares the tabs of the plugin to the shared admin menu: the
     * statistics and the refused submissions on pages of the Security menu,
     * the statistical filter and the settings under Settings > Antispam. The
     * menu and its pages are named here too, for a site where no other
     * plugin declares them.
     *
     * @return void
     */
    public function declare(): void
    {
        $menu = Menus::menu(self::MENU)
            ->title(__('Security', 'gecka-antispam'))
            ->icon('dashicons-shield')
            ->position(71);

        $menu->page(self::PAGES['stats'])
            ->title(__('Statistics', 'gecka-antispam'))
            ->order(10)
            ->wide()
            ->tab(self::TAB)
            ->title(__('Antispam', 'gecka-antispam'))
            ->order(20)
            ->capability(self::capability('stats'))
            ->load(fn() => $this->loadTab('stats'))
            ->render(fn() => $this->renderTab(fn() => (new StatsView($this->plugin))->render()));

        $menu->page(self::PAGES['refused'])
            ->title(__('Journal', 'gecka-antispam'))
            ->order(20)
            ->wide()
            ->tab(self::TAB)
            ->title(__('Antispam', 'gecka-antispam'))
            ->order(20)
            ->capability(self::capability('refused'))
            ->badge(fn(): int => $this->plugin->journal()->count())
            ->load(fn() => $this->loadTab('refused'))
            ->render(fn() => $this->renderTab(fn() => $this->refused?->render()));

        $settings = Menus::options(self::PAGE)->title(__('Antispam', 'gecka-antispam'));

        $settings->tab('filter')
            ->title(__('Statistical filter', 'gecka-antispam'))
            ->order(10)
            ->capability(self::capability('filter'))
            ->load(fn() => $this->loadTab('filter'))
            ->render(fn() => $this->renderTab(fn() => (new FilterView($this->plugin))->render()));

        $settings->tab('settings')
            ->title(__('Settings', 'gecka-antispam'))
            ->order(20)
            ->capability(self::capability('settings'))
            ->load(fn() => $this->loadTab('settings'))
            ->render(fn() => $this->renderTab(fn() => $this->renderSettings()));
    }

    /**
     * Capability a screen asks for, through the gecka_antispam_capability
     * filter: the statistics and the refused submissions are for those who
     * moderate comments, the statistical filter and the settings for
     * administrators. The two tabs of Settings > Antispam save the same
     * option, so they share the capability of settings.
     *
     * @param string $tab stats, refused, filter or settings.
     *
     * @return string
     */
    public static function capability(string $tab): string
    {
        $screen = isset(self::PAGES[$tab]) ? $tab : 'settings';

        /**
         * Filters the capability a screen of the plugin asks for.
         *
         * @param string $capability moderate_comments for stats and refused, manage_options for settings.
         * @param string $screen     stats, refused or settings: the statistical filter tab, its
         *                           buttons and its REST routes, the settings tab, and the
         *                           buttons resetting the statistics, the filter and the settings.
         */
        $capability = (string) apply_filters('gecka_antispam_capability', $screen === 'settings' ? 'manage_options' : 'moderate_comments', $screen);

        return $capability !== '' ? $capability : 'manage_options';
    }

    /**
     * Url of a screen of the plugin
     *
     * @param string               $tab  stats, refused, filter or settings.
     * @param array<string, mixed> $args
     *
     * @return string
     */
    public static function url(string $tab = 'stats', array $args = []): string
    {
        if (isset(self::PAGES[$tab])) {
            return Menus::menu(self::MENU)->page(self::PAGES[$tab])->url(self::TAB, $args);
        }

        return Menus::options(self::PAGE)->url($tab === 'filter' ? 'filter' : 'settings', $args);
    }

    /**
     * Registers the option of the plugin with its sanitizer, and the
     * paragraph offered for the privacy policy.
     *
     * @return void
     */
    public function registerSetting(): void
    {
        register_setting(
            self::PAGE,
            Settings::OPTION,
            [
                'type' => 'array',
                'sanitize_callback' => [$this->plugin->settings(), 'sanitize'],
            ],
        );
    }

    /**
     * Adds a link to the settings in the row of the plugin.
     *
     * @param array<string, string> $links
     *
     * @return array<string, string>
     */
    public function actionLinks(array $links): array
    {
        return array_merge(
            ['settings' => sprintf('<a href="%s">%s</a>', esc_url(self::url('settings')), esc_html__('Settings', 'gecka-antispam'))],
            $links,
        );
    }

    /**
     * Forgets everything the statistical filter learnt, so the comments and
     * messages already marked can be learnt again.
     *
     * @return void
     */
    public function resetFilter(): void
    {
        $this->authorize('gecka_antispam_reset_filter', 'filter');
        $this->plugin->resetFilter();

        wp_safe_redirect(self::url('filter', ['reset' => 'filter']));
        exit;
    }

    /**
     * Downloads the background tables missing or changed now.
     *
     * @return void
     */
    public function updateBackgrounds(): void
    {
        $this->authorize('gecka_antispam_update_backgrounds', 'filter');
        $backgrounds = $this->plugin->backgrounds();
        $done = $backgrounds->active() ? $backgrounds->update() : false;

        wp_safe_redirect(self::url('filter', ['backgrounds' => $done === null ? 'busy' : ($done ? 'updated' : 'failed')]));
        exit;
    }

    /**
     * Tells the administrators that the tables of the plugin could not be
     * set up, and why.
     *
     * @return void
     */
    public function installFailedNotice(): void
    {
        $failure = Setup::failure();

        if ($failure === '' || ! current_user_can(self::capability('settings'))) {
            return;
        }

        wp_admin_notice(
            sprintf(
                /* translators: %s: the error */
                __('Gecka Antispam could not set its tables up, and protects nothing until it can. The setup is tried again every hour. The database said: %s', 'gecka-antispam'),
                $failure,
            ),
            ['type' => 'error'],
        );
    }

    /**
     * Drops every counter.
     *
     * @return void
     */
    public function resetStats(): void
    {
        $this->authorize('gecka_antispam_reset_stats', 'settings');
        $this->plugin->stats()->reset();
        $this->plugin->origins()->reset();

        wp_safe_redirect(self::url('stats', ['reset' => 'stats']));
        exit;
    }

    /**
     * Puts the settings back to their defaults.
     *
     * @return void
     */
    public function resetSettings(): void
    {
        $this->authorize('gecka_antispam_reset_settings', 'settings');
        $this->plugin->settings()->reset();

        wp_safe_redirect(self::url('settings', ['reset' => 'settings']));
        exit;
    }

    /**
     * Deletes every refused submission.
     *
     * @return void
     */
    public function clearRefused(): void
    {
        $this->authorize('gecka_antispam_clear_refused', 'refused');
        $this->plugin->journal()->clear();

        wp_safe_redirect(self::url('refused', ['done' => 0, 'op' => 'clear']));
        exit;
    }

    /**
     * Has the statistical filter learn the comments, messages and entries
     * already marked as spam or as legitimate, the most recent first.
     *
     * @return void
     */
    public function learnExisting(): void
    {
        $this->authorize('gecka_antispam_learn_existing', 'filter');

        $limit = (int) ini_get('max_execution_time');
        $learnt = $this->plugin->learnExisting($limit > 0 ? min(self::LEARN_SECONDS, $limit / 2) : self::LEARN_SECONDS);

        $args = ['learnt_spam' => $learnt[StatisticalFilter::SPAM], 'learnt_ham' => $learnt[StatisticalFilter::HAM]];

        if ($this->plugin->statisticalFilter()->learningFailed()) {
            $args['learn_failed'] = 1;
        }

        wp_safe_redirect(self::url('filter', $args));
        exit;
    }

    /**
     * Registers the route learning what the site holds, one short request
     * at a time.
     *
     * @return void
     */
    public function registerRoutes(): void
    {
        register_rest_route(
            self::REST_NAMESPACE,
            '/learn-existing',
            [
                'methods' => \WP_REST_Server::CREATABLE,
                'callback' => [$this, 'learnExistingRest'],
                'permission_callback' => static fn(): bool => current_user_can(self::capability('filter')),
            ],
        );

        register_rest_route(
            self::REST_NAMESPACE,
            '/backgrounds/check',
            [
                'methods' => \WP_REST_Server::CREATABLE,
                'callback' => [$this, 'checkBackgroundsRest'],
                'permission_callback' => fn(): bool => current_user_can(self::capability('filter')) && $this->plugin->backgrounds()->active(),
            ],
        );

        register_rest_route(
            self::REST_NAMESPACE,
            '/backgrounds/next',
            [
                'methods' => \WP_REST_Server::CREATABLE,
                'callback' => [$this, 'nextBackgroundRest'],
                'permission_callback' => fn(): bool => current_user_can(self::capability('filter')) && $this->plugin->backgrounds()->active(),
            ],
        );
    }

    /**
     * Reads the release of the background tables and queues those to
     * download.
     *
     * @return \WP_REST_Response The tables queued, and the error of the release if any; busy while another request updates.
     */
    public function checkBackgroundsRest(): \WP_REST_Response
    {
        $backgrounds = $this->plugin->backgrounds();

        if (! $backgrounds->lock()) {
            return new \WP_REST_Response(['busy' => true]);
        }

        try {
            $queued = $backgrounds->check();
        } finally {
            $backgrounds->unlock();
        }

        return new \WP_REST_Response(['pending' => $queued ?? [], 'error' => $queued === null ? $backgrounds->state()['error'] : null]);
    }

    /**
     * Downloads the next background table of the queue.
     *
     * @return \WP_REST_Response The table, its error if any, and the tables left; done when none was queued, busy while another request updates.
     */
    public function nextBackgroundRest(): \WP_REST_Response
    {
        $backgrounds = $this->plugin->backgrounds();

        if (! $backgrounds->lock()) {
            return new \WP_REST_Response(['busy' => true]);
        }

        try {
            $step = $backgrounds->next();
        } finally {
            $backgrounds->unlock();
        }

        return new \WP_REST_Response($step ?? ['done' => true, 'left' => 0]);
    }

    /**
     * Learns for REST_SECONDS at most, and tells what was learnt, what is
     * left, and whether the filter failed to learn.
     *
     * @return \WP_REST_Response
     */
    public function learnExistingRest(): \WP_REST_Response
    {
        $learnt = $this->plugin->learnExisting(self::REST_SECONDS);
        $pending = $this->plugin->pendingTexts();

        return new \WP_REST_Response(
            [
                'learnt' => ['spam' => $learnt[StatisticalFilter::SPAM], 'ham' => $learnt[StatisticalFilter::HAM]],
                'pending' => ['spam' => $pending[StatisticalFilter::SPAM], 'ham' => $pending[StatisticalFilter::HAM]],
                'failed' => $this->plugin->statisticalFilter()->learningFailed(),
            ],
        );
    }

    /**
     * Sets a screen up before anything is printed: the style sheet; the
     * Help on the statistical filter and settings tabs; the scripts of the
     * learning and updating buttons, of the field of the languages and of
     * the settings the switch of the filter shows, on the statistical filter
     * tab; the list table of the Journal tab.
     *
     * @param string $tab stats, refused, filter or settings.
     *
     * @return void
     */
    private function loadTab(string $tab): void
    {
        add_action('admin_enqueue_scripts', [Styles::class, 'enqueue']);

        $screen = get_current_screen();

        if ($screen) {
            Help::add($this->plugin, $screen, $tab);
        }

        if ($tab === 'refused') {
            $this->refused = new RefusedView($this->plugin);
            $this->refused->load();
        }

        if ($tab !== 'filter') {
            return;
        }

        add_action(
            'admin_enqueue_scripts',
            function (): void {
                $defer = ['in_footer' => true, 'strategy' => 'defer'];

                wp_enqueue_script('gecka-antispam-learn', $this->plugin->url('assets/learn.js'), [], Plugin::VERSION, $defer);
                wp_enqueue_script('gecka-antispam-backgrounds', $this->plugin->url('assets/backgrounds.js'), [], Plugin::VERSION, $defer);
                wp_enqueue_script('gecka-antispam-languages', $this->plugin->url('assets/languages.js'), ['wp-element', 'wp-components'], Plugin::VERSION, $defer);
                wp_enqueue_script('gecka-antispam-shown-by', $this->plugin->url('assets/shown-by.js'), [], Plugin::VERSION, $defer);
                wp_enqueue_style('wp-components');
            },
        );
    }

    /**
     * Prints a tab inside the block the style sheet of the plugin reads.
     *
     * @param callable $render
     *
     * @return void
     */
    private function renderTab(callable $render): void
    {
        echo '<div class="gecka-antispam">';
        $render();
        echo '</div>';
    }

    /**
     * Prints the settings form.
     *
     * @return void
     */
    private function renderSettings(): void
    {
        $settings = $this->plugin->settings()->all();
        $name = Settings::OPTION;

        settings_errors($name);

        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Only picks a notice.
        if (sanitize_key($_GET['reset'] ?? '') === 'settings') {
            wp_admin_notice(__('Every setting is back to its default.', 'gecka-antispam'), ['type' => 'success', 'dismissible' => true]);
        }

        echo '<form action="options.php" method="post">';
        settings_fields(self::PAGE);
        printf('<input type="hidden" name="%s[form]" value="general">', esc_attr($name));

        printf('<h2>%s %s</h2>', esc_html__('Protected forms', 'gecka-antispam'), Help::link(Help::FIELDS)); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped by Help::link().
        echo '<table class="form-table" role="presentation">';

        foreach (Settings::groups() as $id => $group) {
            $available = $this->plugin->provides($id);

            printf('<tr><th scope="row">%s</th><td><fieldset><legend class="screen-reader-text">%1$s</legend>', esc_html($group['label']));

            foreach ($group['surfaces'] as $surface => $label) {
                if (in_array($surface, Settings::MARKED_SURFACES, true)) {
                    $this->modeChoice($surface, $settings, $available);

                    continue;
                }

                printf(
                    '<label class="gecka-admin-toggle-label"><input type="checkbox" class="gecka-admin-toggle" name="%s[surfaces][%s]" value="1" %s %s> %s</label>',
                    esc_attr($name),
                    esc_attr($surface),
                    checked(! empty($settings['surfaces'][$surface]), true, false),
                    disabled($available, false, false),
                    esc_html($label),
                );

                // A form of a plugin switched off keeps its setting.
                if (! $available && ! empty($settings['surfaces'][$surface])) {
                    printf('<input type="hidden" name="%s[surfaces][%s]" value="1">', esc_attr($name), esc_attr($surface));
                }
            }

            if (! $available) {
                printf('<p class="description">%s</p>', esc_html__('The plugin providing these forms is not active.', 'gecka-antispam'));
            }

            if ($id === 'woocommerce' && $available) {
                printf('<p class="description">%s</p>', esc_html__('Only the classic checkout, the [woocommerce_checkout] shortcode, is protected: the checkout block posts to the Store API.', 'gecka-antispam'));
            }

            echo '</fieldset></td></tr>';
        }

        echo '</table>';

        printf('<h2>%s</h2>', esc_html__('Honeypot and timing', 'gecka-antispam'));
        printf('<p>%s</p>', esc_html__('A submission these checks catch is refused with an error, which lets a person send it again, and kept in the Antispam tab of Security > Journal.', 'gecka-antispam'));
        echo '<table class="form-table" role="presentation">';

        $this->textRow(
            'honeypot_name',
            __('Honeypot field name', 'gecka-antispam'),
            (string) $settings['honeypot_name'],
            __('A field people never see, which bots fill in. Drawn at random on each site; a name a bot would fill in, and that no browser autofills.', 'gecka-antispam'),
        );
        $this->numberRow('min_delay', __('Minimum delay', 'gecka-antispam'), (int) $settings['min_delay'], __('seconds', 'gecka-antispam'), __('Time a form must stay on screen before it is sent: comments, contact forms, registration, checkout.', 'gecka-antispam'));
        $this->numberRow('sign_in_min_delay', __('Minimum delay to sign in', 'gecka-antispam'), (int) $settings['sign_in_min_delay'], __('seconds', 'gecka-antispam'), __('Same for the login and lost password forms, which password managers fill and send in a blink.', 'gecka-antispam'));
        $this->numberRow('max_age', __('Maximum age of a form', 'gecka-antispam'), (int) $settings['max_age'], __('hours', 'gecka-antispam'), __('8 days by default, which a page cache keeping its pages a week still fits in; 0 for no limit. A cached form is as old as the cache: when pages are cached longer, raise it or set it to 0.', 'gecka-antispam'));
        $this->checkboxRow('random_names', __('Random names', 'gecka-antispam'), (bool) $settings['random_names'], __('Catch names, and messages of a single word, made of letters whose case changes at random, like qASQAhqkpFGqnKkRROl.', 'gecka-antispam'));
        $this->numberRow('min_words', __('Minimum words in a message', 'gecka-antispam'), (int) $settings['min_words'], __('words', 'gecka-antispam'), __('A message with fewer words is refused: comments, contact forms. 0 accepts any length.', 'gecka-antispam'));

        echo '</table>';

        printf('<h2>%s</h2>', esc_html__('Statistics', 'gecka-antispam'));
        echo '<table class="form-table" role="presentation">';
        $this->numberRow('stats_days', __('Keep the statistics', 'gecka-antispam'), (int) $settings['stats_days'], __('days', 'gecka-antispam'), __('Only daily counts are kept, by form and by outcome, and by country, network and system: no address, no content.', 'gecka-antispam'));
        echo '</table>';

        // The reset button belongs to the form printed after this one, through
        // its form attribute, so that both buttons share a row.
        echo '<p class="submit gecka-admin-buttons">';
        submit_button('', 'primary', 'submit', false);
        echo ' ';
        printf(
            '<button type="submit" form="gecka-antispam-reset-settings" class="button" onclick="return confirm(%s)">%s</button>',
            esc_attr((string) wp_json_encode(__('Put every setting back to its default? The name of the honeypot field is kept.', 'gecka-antispam'))),
            esc_html__('Restore the default settings', 'gecka-antispam'),
        );
        echo '</p></form>';

        printf('<form method="post" action="%s" id="gecka-antispam-reset-settings">', esc_url(admin_url('admin-post.php')));
        echo '<input type="hidden" name="action" value="gecka_antispam_reset_settings">';
        wp_nonce_field('gecka_antispam_reset_settings');
        echo '</form>';
    }

    /**
     * Prints the choice of a plugin letting forms carry a marker: off, every
     * form, or the marked ones, and how to mark a form.
     *
     * @param string               $surface
     * @param array<string, mixed> $settings
     * @param bool                 $available Whether the plugin is active.
     *
     * @return void
     */
    private function modeChoice(string $surface, array $settings, bool $available): void
    {
        $current = empty($settings['surfaces'][$surface]) ? Settings::MODE_OFF : (string) $settings['modes'][$surface];
        $choices = [
            Settings::MODE_OFF => __('Off', 'gecka-antispam'),
            Settings::MODE_ALL => __('Every form', 'gecka-antispam'),
            Settings::MODE_MARKED => __('Only the forms holding the marker', 'gecka-antispam'),
        ];

        foreach ($choices as $value => $label) {
            printf(
                '<label class="gecka-admin-choice"><input type="radio" name="%s[modes][%s]" value="%s" %s %s> %s</label>',
                esc_attr(Settings::OPTION),
                esc_attr($surface),
                esc_attr($value),
                checked($current, $value, false),
                disabled($available, false, false),
                esc_html($label),
            );
        }

        // A plugin switched off keeps its choice.
        if (! $available) {
            printf('<input type="hidden" name="%s[modes][%s]" value="%s">', esc_attr(Settings::OPTION), esc_attr($surface), esc_attr($current));

            return;
        }

        $markers = [
            /* translators: %s: the form tag */
            'contact_form_7' => sprintf(__('Marker: the %s form tag, placed in the form where the fields go.', 'gecka-antispam'), '<code>[gecka_antispam]</code>'),
            'gravity_forms' => esc_html__('Marker: the Antispam field, among the advanced fields of the form editor.', 'gecka-antispam'),
            /* translators: 1: the argument, 2: function, 3: function */
            'acf' => sprintf(__('Marker: %1$s in the arguments of %2$s or %3$s.', 'gecka-antispam'), "<code>'gecka_antispam' =&gt; true</code>", '<code>acf_form()</code>', '<code>acf_register_form()</code>'),
        ];

        printf('<p class="description">%s</p>', wp_kses($markers[$surface] ?? '', ['code' => []]));
    }

    /**
     * Dies unless the current user may use the screen a button belongs to.
     *
     * @param string $action Nonce action.
     * @param string $tab    Screen of the button, as capability() takes it.
     *
     * @return void
     */
    private function authorize(string $action, string $tab): void
    {
        if (! current_user_can(self::capability($tab))) {
            wp_die(esc_html__('Sorry, you are not allowed to do that.', 'gecka-antispam'), 403);
        }

        check_admin_referer($action);
    }
}
