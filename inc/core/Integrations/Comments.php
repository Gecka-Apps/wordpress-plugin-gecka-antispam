<?php

declare(strict_types=1);

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

namespace Gecka\WP\Plugin\Antispam\Integrations;

use Gecka\WP\Plugin\Antispam\Guard;
use Gecka\WP\Plugin\Antispam\Plugin;
use Gecka\WP\Plugin\Antispam\Request;
use Gecka\WP\Plugin\Antispam\StatisticalFilter;
use Gecka\WP\Plugin\Antispam\Value;

/**
 * The comment form, the review form of WooCommerce products, which is a
 * comment form too, and the spam queue.
 *
 * Everybody gets the fields and all the checks, logged in or not, but those
 * who can moderate comments, who are not checked at all. A comment refused
 * gets an error page and lands in the journal; one
 * the statistical filter marks as spam lands in the spam queue; one it finds
 * doubtful waits for moderation. A moderator marking a comment as spam, or as
 * not spam, or approving one held for moderation, teaches the statistical
 * filter. The comments already in the spam queue, and those approved, can be
 * learnt in one go.
 *
 * @author Laurent Dinclaux - Gecka <laurent@gecka.nc>
 */
class Comments extends Integration implements Learner
{
    /**
     * Comment types the plugin checks and learns, and the form each comes from.
     * WooCommerce gives the type review to a comment on a product.
     */
    private const TYPES = [
        '' => 'comments',
        'comment' => 'comments',
        'review' => 'woocommerce_reviews',
    ];

    /**
     * Column added to the comments list.
     */
    private const COLUMN = 'gecka_antispam';

    /**
     * Outcome of the comment being posted, until it is saved, and what the
     * statistics count it as once saved.
     *
     * @var array{outcome: string|null, score: float|null, review: bool, text: string, surface: string, counted: string}|null
     */
    private ?array $pending = null;

    /**
     * Always: the comments are those of WordPress
     *
     * @return bool
     */
    public function available(): bool
    {
        return true;
    }

    /**
     * Hooks the fields into the comment form, the check ahead of the other
     * plugins, the approval, the count once the comment is saved, the
     * learning from moderation and the column of the comments list.
     *
     * @return void
     */
    public function setup(): void
    {
        add_action('comment_form', [$this, 'render']);
        // After WooCommerce, which sets the type of a product review at 1.
        add_filter('preprocess_comment', [$this, 'check'], 2);
        add_filter('pre_comment_approved', [$this, 'approval'], 99);
        add_action('comment_post', [$this, 'annotate'], 10, 2);
        add_action('transition_comment_status', [$this, 'learn'], 10, 3);
        add_filter('manage_edit-comments_columns', [$this, 'addColumn']);
        add_action('manage_comments_custom_column', [$this, 'renderColumn'], 10, 2);
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
     * Prints, in the comments list, the rating the statistical filter gave a
     * comment when it was posted, why the plugin sent it to spam or to
     * moderation, and what it was learnt as. Nothing is rated again.
     *
     * @param string     $column
     * @param int|string $commentId
     *
     * @return void
     */
    public function renderColumn(string $column, int|string $commentId): void
    {
        if ($column !== self::COLUMN) {
            return;
        }

        $commentId = (int) $commentId;
        $score = get_comment_meta($commentId, Plugin::META_SCORE, true);
        $reason = Value::string(get_comment_meta($commentId, Plugin::META_REASON, true));
        $trained = Value::string(get_comment_meta($commentId, Plugin::META_TRAINED, true));
        $lines = [];

        if (is_numeric($score)) {
            /* translators: %s: rating of the statistical filter, in percent */
            $lines[] = sprintf(__('%s %% spam', 'gecka-antispam'), number_format_i18n((float) $score * 100, 1));
        }

        if ($reason !== '') {
            $lines[] = Guard::outcomeLabel($reason);
        }

        if ($trained === StatisticalFilter::SPAM) {
            $lines[] = __('Learnt as spam', 'gecka-antispam');
        } elseif ($trained === StatisticalFilter::HAM) {
            $lines[] = __('Learnt as not spam', 'gecka-antispam');
        }

        echo $lines ? implode('<br>', array_map('esc_html', $lines)) : '&mdash;';
    }

    /**
     * Prints the fields in the comment form.
     *
     * @param mixed $postId Post the form comments on.
     *
     * @return void
     */
    public function render(mixed $postId = null): void
    {
        if (! current_user_can('moderate_comments')) {
            echo $this->fields(get_post_type(is_numeric($postId) ? (int) $postId : null) === 'product' ? 'woocommerce_reviews' : 'comments'); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped by Guard::fields().
        }
    }

    /**
     * Checks a comment posted from the comment form.
     *
     * @param array<string, mixed> $data
     *
     * @return array<string, mixed>
     */
    public function check(array $data): array
    {
        $this->pending = null;
        $surface = self::TYPES[Value::string($data['comment_type'] ?? null)] ?? null;

        if (current_user_can('moderate_comments')
            || ! $surface
            || ! Request::isFormPost('comment_post_ID')
            || ! $this->plugin->settings()->enabled($surface)
        ) {
            return $data;
        }

        // wp_new_comment() hands the filter slashed data; the comment saved,
        // and learnt later, is not.
        $comment = wp_unslash($data);
        $text = self::commentText($comment);

        // A comment let through is counted once saved: the flood and
        // duplicate checks of WordPress come after this filter.
        $outcome = $this->verify($surface, [Value::string($comment['comment_author'] ?? null)], $text, true, true, $text);

        if (Guard::refuses($outcome)) {
            wp_die(esc_html($this->message()), esc_html__('Comment refused', 'gecka-antispam'), ['response' => 403, 'back_link' => true]);
        }

        $this->pending = ['outcome' => $outcome, 'score' => $this->score, 'review' => $this->review, 'text' => $text, 'surface' => $surface, 'counted' => $this->counted($outcome)];

        return $data;
    }

    /**
     * Sends a comment the statistical filter marks as spam to the spam queue,
     * and one it finds doubtful to moderation unless it already waits there
     * or worse.
     *
     * @param mixed $approved 1, 0, spam, trash or \WP_Error, or whatever another filter returned.
     *
     * @return mixed
     */
    public function approval(mixed $approved): mixed
    {
        if (is_wp_error($approved)) {
            return $approved;
        }

        if (! empty($this->pending['outcome'])) {
            return 'spam';
        }

        if (! empty($this->pending['review']) && in_array($approved, [1, '1'], true)) {
            return 0;
        }

        return $approved;
    }

    /**
     * Counts the comment saved, and records next to it how the statistical
     * filter rated it, and why it went to the spam queue or to moderation.
     *
     * @param mixed $commentId
     * @param mixed $approved  Passed by the hook, not read: the approval was decided in approval().
     *
     * @return void
     */
    public function annotate(mixed $commentId, mixed $approved = null): void
    {
        if (! $this->pending || ! is_numeric($commentId)) {
            return;
        }

        $commentId = (int) $commentId;

        $pending = $this->pending;
        $this->pending = null;
        $this->plugin->stats()->record($pending['surface'], $pending['counted']);
        $this->plugin->origins()->count($pending['counted']);

        if ($pending['score'] !== null) {
            update_comment_meta($commentId, Plugin::META_SCORE, round($pending['score'], 4));
        }

        if (! $pending['outcome']) {
            if ($pending['review']) {
                update_comment_meta($commentId, Plugin::META_REASON, Guard::REVIEW);
            }

            return;
        }

        update_comment_meta($commentId, Plugin::META_REASON, $pending['outcome']);
    }

    /**
     * Teaches the filter what a moderator made of a comment: spam, not spam,
     * or approved.
     *
     * @param int|string  $new
     * @param int|string  $old
     * @param \WP_Comment $comment
     *
     * @return void
     */
    public function learn(int|string $new, int|string $old, \WP_Comment $comment): void
    {
        if ($new === $old || ! isset(self::TYPES[$comment->comment_type]) || ! self::byModerator(current_user_can('moderate_comments'))) {
            return;
        }

        $id = (int) $comment->comment_ID;
        $previous = self::category(get_comment_meta($id, Plugin::META_TRAINED, true));
        $category = null;

        if ($new === 'spam') {
            $category = StatisticalFilter::SPAM;
        } elseif ($old === 'spam' && in_array($new, ['approved', 'unapproved'], true)) {
            $category = StatisticalFilter::HAM;
        } elseif ($new === 'approved' && $old === 'unapproved' && ! $previous && $this->plugin->settings()->get('learn_approved')) {
            $category = StatisticalFilter::HAM;
        }

        if ($category) {
            $this->learnAndMark(self::commentText((array) $comment), $previous, self::generation(get_comment_meta($id, Plugin::META_GENERATION, true)), $category, self::marker($id));
        }
    }

    /**
     * What writes the mark of a comment: what it was learnt as, and the
     * generation when it was
     *
     * @param int $id
     *
     * @return callable(string, int|null): void
     */
    private static function marker(int $id): callable
    {
        return static function (string $trained, ?int $generation) use ($id): void {
            update_comment_meta($id, Plugin::META_TRAINED, $trained);

            if ($generation !== null) {
                update_comment_meta($id, Plugin::META_GENERATION, $generation);
            }
        };
    }

    /**
     * Spam or approved comments not learnt yet, recent enough to be learnt
     *
     * @param string $category StatisticalFilter::SPAM or StatisticalFilter::HAM.
     *
     * @return int
     */
    public function pending(string $category): int
    {
        return (int) get_comments(array_merge($this->existingQuery($category), ['count' => true]));
    }

    /**
     * Whether a person, or Akismet, marked a comment as spam. WordPress keeps
     * the status a comment had when a person sends it to spam, which a
     * comment filed as spam on arrival does not have; Akismet keeps its
     * verdict.
     *
     * @param int $id
     *
     * @return bool
     */
    private static function judged(int $id): bool
    {
        return metadata_exists('comment', $id, '_wp_trash_meta_status') || get_comment_meta($id, 'akismet_result', true) === 'true';
    }

    /**
     * Learns the most recent spam or approved comments not learnt yet.
     *
     * @param string $category StatisticalFilter::SPAM or StatisticalFilter::HAM.
     * @param int    $limit    Comments read at most.
     *
     * @return int Comments learnt.
     */
    public function learnExisting(string $category, int $limit): int
    {
        $learnt = 0;
        $comments = get_comments(
            array_merge(
                $this->existingQuery($category),
                [
                    'number' => $limit,
                    'orderby' => 'comment_date_gmt',
                    'order' => 'DESC',
                ],
            ),
        );

        foreach ($comments as $comment) {
            $id = (int) $comment->comment_ID;
            $outcome = Value::string(get_comment_meta($id, Plugin::META_REASON, true));
            $done = $this->learnItem(self::commentText((array) $comment), $category, $outcome ?: null, (int) strtotime($comment->comment_date_gmt . ' UTC'), self::judged($id), self::marker($id));

            if ($done === null) {
                break;
            }

            $learnt += (int) $done;
        }

        return $learnt;
    }

    /**
     * Query of the spam or approved comments not learnt yet, recent enough
     * to be learnt
     *
     * @param string $category
     *
     * @return array{status: string, type: string[], date_query: array<int, array{column: string, after: string, inclusive: bool}>, meta_query: array<int, array{key: string, compare: string}>}
     */
    private function existingQuery(string $category): array
    {
        return [
            'status' => $category === StatisticalFilter::SPAM ? 'spam' : 'approve',
            'type' => ['comment', 'review'],
            'date_query' => [
                [
                    'column' => 'comment_date_gmt',
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
     * What the filter reads of a comment: its content, nothing of its author
     *
     * @param array<string, mixed> $comment Comment data, or a WP_Comment cast to an array.
     *
     * @return string
     */
    private static function commentText(array $comment): string
    {
        return trim(Value::string($comment['comment_content'] ?? null));
    }
}
