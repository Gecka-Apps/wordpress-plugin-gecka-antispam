<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

namespace Gecka\WP\Plugin\Antispam\Integrations;

use Gecka\WP\Plugin\Antispam\Guard;
use Gecka\WP\Plugin\Antispam\Plugin;
use Gecka\WP\Plugin\Antispam\StatisticalFilter;

/**
 * The inbox of Flamingo, where the messages of Contact Form 7 are kept.
 *
 * Flamingo has no hook of its own for "Mark as spam" and "Not spam", but
 * both save the message under another status, which WordPress announces:
 * publish to flamingo-spam, and back. Every path goes through it, the row
 * action, the bulk action and the button of the message screen.
 *
 * The inbox gets an Antispam column, and the message screen a box, showing
 * how the filter rates the message and what it learnt it as. A message of
 * the inbox, one held for review first, is confirmed as legitimate from a
 * link in that column, a button in that box, or a bulk action: it stays
 * where it is, and the filter learns it as ham. The messages already in the
 * inbox and in the spam can be learnt in one go.
 *
 * @author Laurent Dinclaux - Gecka <laurent@gecka.nc>
 */
class Flamingo extends Integration implements Learner
{
    /**
     * Post type of the messages.
     */
    private const POST_TYPE = 'flamingo_inbound';

    /**
     * Status of a message marked as spam.
     */
    private const SPAM_STATUS = 'flamingo-spam';

    /**
     * Column added to the inbox.
     */
    private const COLUMN = 'gecka_antispam';

    /**
     * Action confirming messages of the inbox as legitimate, from the bulk
     * actions, the Antispam column or the box of a message.
     */
    public const HAM_ACTION = 'gecka_antispam_ham';

    /**
     * Query argument carrying the messages learnt back to the screen.
     */
    private const HAM_DONE = 'gecka_antispam_ham_done';

    /**
     * @return bool
     */
    public function available(): bool
    {
        return defined('FLAMINGO_VERSION');
    }

    /**
     * @return void
     */
    public function setup(): void
    {
        add_action('transition_post_status', [$this, 'learn'], 10, 3);

        add_filter('manage_flamingo_inbound_posts_columns', [$this, 'addColumn']);
        add_action('manage_flamingo_inbound_posts_custom_column', [$this, 'renderColumn'], 10, 2);
        add_action('current_screen', [$this, 'screen']);
    }

    /**
     * Adds the box to the message screen of Flamingo. The screen id starts
     * with the title of the Flamingo menu, translated: only its end is read.
     *
     * @param mixed $screen \WP_Screen.
     *
     * @return void
     */
    public function screen(mixed $screen): void
    {
        if (! $screen instanceof \WP_Screen || ! str_ends_with($screen->id, '_page_flamingo_inbound')) {
            return;
        }

        $this->confirmRequested();
        $this->addMetaBox();
        add_filter('bulk_actions-' . $screen->id, [$this, 'bulkActions']);
        add_action('flamingo_admin_updated_message', [$this, 'confirmedNotice']);
    }

    /**
     * Adds the action confirming messages as legitimate, outside the spam
     * and the trash.
     *
     * @param mixed $actions
     *
     * @return mixed
     */
    public function bulkActions(mixed $actions): mixed
    {
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Only picks the view.
        $status = sanitize_key($_GET['post_status'] ?? '');

        if (! is_array($actions) || in_array($status, ['spam', 'trash'], true) || ! $this->plugin->settings()->get('filter')) {
            return $actions;
        }

        $actions[self::HAM_ACTION] = __('Learn as legitimate', 'gecka-antispam');

        return $actions;
    }

    /**
     * Confirms as legitimate a message of the inbox: the filter learns it as
     * ham, moving it from spam when it was learnt as such.
     *
     * @param int $postId
     *
     * @return int|null The generation it is learnt in, null when it was not.
     */
    public function confirmLegitimate(int $postId): ?int
    {
        $post = get_post($postId);

        if (! $post instanceof \WP_Post || $post->post_type !== self::POST_TYPE || $post->post_status !== 'publish' || ! self::byModerator(current_user_can('flamingo_unspam_inbound_message', $postId))) {
            return null;
        }

        $previous = $this->trained($postId);
        $generation = self::generation(get_post_meta($postId, Plugin::META_GENERATION, true));

        if ($previous === StatisticalFilter::HAM) {
            return $generation ?? 0;
        }

        $generation = $this->train($this->messageText($postId), $previous, $generation, StatisticalFilter::HAM);

        if ($generation !== null) {
            update_post_meta($postId, Plugin::META_TRAINED, StatisticalFilter::HAM);
            update_post_meta($postId, Plugin::META_GENERATION, $generation);
        }

        return $generation;
    }

    /**
     * Prints how many messages were confirmed as legitimate, among the
     * notices of Flamingo.
     *
     * @return void
     */
    public function confirmedNotice(): void
    {
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Only picks a notice.
        if (! isset($_GET[self::HAM_DONE])) {
            return;
        }

        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Only picks a notice.
        $count = absint($_GET[self::HAM_DONE]);

        wp_admin_notice(
            /* translators: %s: number of messages */
            esc_html(sprintf(_n('%s message learnt as legitimate.', '%s messages learnt as legitimate.', $count, 'gecka-antispam'), number_format_i18n($count))),
            ['type' => 'success', 'dismissible' => true],
        );
    }

    /**
     * Confirms the messages a request asks for, from the bulk actions or
     * from a link, then goes back where it came from.
     *
     * @return void
     */
    private function confirmRequested(): void
    {
        // phpcs:disable WordPress.Security.NonceVerification.Recommended -- Checked below, once the action is known.
        $action = sanitize_key(wp_unslash($_REQUEST['action'] ?? '-1'));
        $action = $action === '-1' ? sanitize_key(wp_unslash($_REQUEST['action2'] ?? '')) : $action;
        $posts = map_deep(wp_unslash($_REQUEST['post'] ?? []), 'absint');
        // phpcs:enable

        if ($action !== self::HAM_ACTION) {
            return;
        }

        if (is_array($posts)) {
            check_admin_referer('bulk-posts');
        } else {
            check_admin_referer(self::HAM_ACTION . '_' . $posts);
        }

        $learnt = 0;

        foreach ((array) $posts as $postId) {
            $learnt += $this->confirmLegitimate($postId) !== null ? 1 : 0;
        }

        $back = wp_get_referer() ?: menu_page_url('flamingo_inbound', false);

        wp_safe_redirect(add_query_arg(self::HAM_DONE, $learnt, remove_query_arg(['message', self::HAM_DONE], $back)));
        exit;
    }

    /**
     * Link confirming a message as legitimate, empty when it cannot be
     *
     * @param int  $postId
     * @param bool $button Drawn as a button.
     *
     * @return string
     */
    private function confirmLink(int $postId, bool $button = false): string
    {
        if (! $this->plugin->settings()->get('filter') || get_post_status($postId) !== 'publish' || $this->trained($postId) === StatisticalFilter::HAM || ! current_user_can('flamingo_unspam_inbound_message', $postId)) {
            return '';
        }

        $url = wp_nonce_url(add_query_arg(['action' => self::HAM_ACTION, 'post' => $postId], menu_page_url('flamingo_inbound', false)), self::HAM_ACTION . '_' . $postId);

        return sprintf(
            '<a href="%s"%s>%s</a>',
            esc_url($url),
            $button ? ' class="button"' : '',
            esc_html($button ? __('Confirm as legitimate', 'gecka-antispam') : __('Legitimate', 'gecka-antispam')),
        );
    }

    /**
     * Teaches the filter what a message was marked as.
     *
     * @param mixed $new  New status.
     * @param mixed $old  Previous status.
     * @param mixed $post \WP_Post.
     *
     * @return void
     */
    public function learn(mixed $new, mixed $old, mixed $post): void
    {
        if (! $post instanceof \WP_Post || $post->post_type !== self::POST_TYPE || $new === $old) {
            return;
        }

        if ($new === self::SPAM_STATUS && $old === 'publish') {
            $category = StatisticalFilter::SPAM;
        } elseif ($old === self::SPAM_STATUS && $new === 'publish') {
            $category = StatisticalFilter::HAM;
        } else {
            return;
        }

        if (! self::byModerator(current_user_can($category === StatisticalFilter::SPAM ? 'flamingo_spam_inbound_message' : 'flamingo_unspam_inbound_message', $post->ID))) {
            return;
        }

        $generation = $this->train($this->messageText($post->ID), $this->trained($post->ID), self::generation(get_post_meta($post->ID, Plugin::META_GENERATION, true)), $category);

        if ($generation !== null) {
            update_post_meta($post->ID, Plugin::META_TRAINED, $category);
            update_post_meta($post->ID, Plugin::META_GENERATION, $generation);
        }
    }

    /**
     * @param array<string, string> $columns
     *
     * @return array<string, string>
     */
    public function addColumn(array $columns): array
    {
        $columns[self::COLUMN] = __('Antispam', 'gecka-antispam');

        return $columns;
    }

    /**
     * @param string     $column
     * @param int|string $postId
     *
     * @return void
     */
    public function renderColumn(string $column, int|string $postId): void
    {
        if ($column === self::COLUMN) {
            echo wp_kses_post(implode('<br>', array_filter([...$this->summary((int) $postId), $this->confirmLink((int) $postId)])));
        }
    }

    /**
     * Adds the Antispam box to the screen of a message.
     *
     * @return void
     */
    public function addMetaBox(): void
    {
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Only picks the screen.
        $postId = absint($_GET['post'] ?? 0);

        if (! $postId || get_post_type($postId) !== self::POST_TYPE) {
            return;
        }

        add_meta_box(
            'gecka-antispam',
            __('Antispam', 'gecka-antispam'),
            function () use ($postId) {
                echo '<p>' . wp_kses_post(implode('<br>', $this->summary($postId, true))) . '</p>';

                $link = $this->confirmLink($postId, true);

                if ($link) {
                    echo '<p>' . wp_kses_post($link) . '</p>';
                }
            },
            null,
            'side',
        );
    }

    /**
     * Messages of the inbox or of the spam not learnt yet, recent enough to
     * be learnt
     *
     * @param string $category StatisticalFilter::SPAM or StatisticalFilter::HAM.
     *
     * @return int
     */
    public function pending(string $category): int
    {
        $query = new \WP_Query(array_merge($this->existingQuery($category), ['posts_per_page' => 1]));

        return (int) $query->found_posts;
    }

    /**
     * Learns the most recent messages of the inbox or of the spam not learnt
     * yet.
     *
     * @param string $category StatisticalFilter::SPAM or StatisticalFilter::HAM.
     * @param int    $limit    Messages read at most.
     *
     * @return int Messages learnt.
     */
    public function learnExisting(string $category, int $limit): int
    {
        $learnt = 0;
        $query = new \WP_Query(
            array_merge(
                $this->existingQuery($category),
                [
                    'posts_per_page' => $limit,
                    'no_found_rows' => true,
                ],
            ),
        );

        foreach ((array) $query->posts as $postId) {
            $postId = (int) ($postId instanceof \WP_Post ? $postId->ID : $postId);
            $generation = $this->learnMarked($this->messageText($postId), $category, $this->outcome($postId), (int) get_post_time('U', true, $postId), self::judged($postId));

            if ($generation === false) {
                break;
            }

            update_post_meta($postId, Plugin::META_TRAINED, $generation === null ? Plugin::TRAINED_SKIPPED : $category);

            if ($generation !== null) {
                update_post_meta($postId, Plugin::META_GENERATION, $generation);
                $learnt++;
            }
        }

        return $learnt;
    }

    /**
     * Query of the messages of the inbox or of the spam not learnt yet,
     * recent enough to be learnt
     *
     * @param string $category
     *
     * @return array<string, mixed>
     */
    private function existingQuery(string $category): array
    {
        return [
            'post_type' => self::POST_TYPE,
            'post_status' => $category === StatisticalFilter::SPAM ? self::SPAM_STATUS : 'publish',
            'fields' => 'ids',
            'orderby' => 'date',
            'order' => 'DESC',
            'date_query' => [
                [
                    'column' => 'post_date_gmt',
                    'after' => $this->learningCutoff(),
                    'inclusive' => true,
                ],
            ],
            'meta_query' => [ // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_query -- Run on demand, from the statistics screen.
                [
                    'key' => Plugin::META_TRAINED,
                    'compare' => 'NOT EXISTS',
                ],
            ],
        ];
    }

    /**
     * Whether a person, or Akismet, marked a message as spam, as the spam
     * log tells: Flamingo logs the person who marks a message, the Akismet
     * module of Contact Form 7 its verdict.
     *
     * @param int $postId
     *
     * @return bool
     */
    private static function judged(int $postId): bool
    {
        foreach ((array) get_post_meta($postId, '_spam_log', true) as $entry) {
            if (is_array($entry) && in_array($entry['agent'] ?? '', ['flamingo', 'akismet'], true)) {
                return true;
            }
        }

        return false;
    }

    /**
     * What caught a message, read from the spam log of Contact Form 7
     *
     * @param int $postId
     *
     * @return string|null
     */
    private function outcome(int $postId): ?string
    {
        foreach ((array) get_post_meta($postId, '_spam_log', true) as $entry) {
            if (is_array($entry) && ($entry['agent'] ?? '') === ContactForm7::AGENT && ! empty($entry['outcome'])) {
                return (string) $entry['outcome'];
            }
        }

        return null;
    }

    /**
     * Lines telling how the filter rates a message and what it learnt it as
     *
     * @param int  $postId
     * @param bool $long   Whether to explain an empty rating.
     *
     * @return string[]
     */
    private function summary(int $postId, bool $long = false): array
    {
        $lines = [];

        if ($this->plugin->filterReady()) {
            $score = $this->plugin->statisticalFilter()->classify($this->messageText($postId));

            if ($score !== null) {
                /* translators: %s: rating of the statistical filter, in percent */
                $lines[] = esc_html(sprintf(__('%s %% spam', 'gecka-antispam'), number_format_i18n($score * 100, 1)));

                if ($this->plugin->verdict($score) === Guard::REVIEW && $this->trained($postId) !== StatisticalFilter::HAM) {
                    $lines[] = esc_html__('To review', 'gecka-antispam');
                }
            }
        } elseif ($long) {
            $lines[] = esc_html__('The statistical filter has not learnt enough messages yet to rate this one.', 'gecka-antispam');
        }

        $trained = $this->trained($postId);

        if ($trained === StatisticalFilter::SPAM) {
            $lines[] = esc_html__('Learnt as spam', 'gecka-antispam');
        } elseif ($trained === StatisticalFilter::HAM) {
            $lines[] = esc_html__('Learnt as not spam', 'gecka-antispam');
        }

        return $lines ?: ['&mdash;'];
    }

    /**
     * What a message was learnt as
     *
     * @param int $postId
     *
     * @return string|null
     */
    private function trained(int $postId): ?string
    {
        return self::category(get_post_meta($postId, Plugin::META_TRAINED, true));
    }

    /**
     * What the filter reads of a message: the subject and the message as its
     * Contact Form 7 form defines them, the same text the filter read at the
     * submission; the names of the fields tell them apart only when the
     * form is gone
     *
     * @param int $postId
     *
     * @return string
     */
    private function messageText(int $postId): string
    {
        if (! class_exists('Flamingo_Inbound_Message')) {
            return '';
        }

        $message = new \Flamingo_Inbound_Message($postId);
        $fields = (array) $message->fields;
        $form = self::form((string) $message->channel);

        return $form ? ContactForm7::formText($form, $fields) : self::fieldsText($fields);
    }

    /**
     * The Contact Form 7 form whose messages go to a channel of Flamingo,
     * through the channel Contact Form 7 records on each form
     *
     * @param string $channel Slug of the channel.
     *
     * @return \WPCF7_ContactForm|null
     */
    private static function form(string $channel): ?\WPCF7_ContactForm
    {
        static $forms = null;

        if (! function_exists('wpcf7_contact_form') || ! class_exists('Flamingo_Inbound_Message')) {
            return null;
        }

        if ($forms === null) {
            $forms = [];

            foreach (get_posts(['post_type' => 'wpcf7_contact_form', 'numberposts' => -1, 'fields' => 'ids', 'post_status' => 'any']) as $formId) {
                $meta = get_post_meta((int) $formId, '_flamingo', true);
                $term = is_array($meta) && isset($meta['channel']) ? get_term((int) $meta['channel'], \Flamingo_Inbound_Message::channel_taxonomy) : null;

                if ($term instanceof \WP_Term) {
                    $forms[$term->slug] = (int) $formId;
                }
            }
        }

        $form = isset($forms[$channel]) ? wpcf7_contact_form($forms[$channel]) : null;

        return $form instanceof \WPCF7_ContactForm ? $form : null;
    }
}
