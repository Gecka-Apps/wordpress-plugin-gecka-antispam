<?php

declare(strict_types=1);

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

use Gecka\WP\Plugin\Antispam\Guard;
use Gecka\WP\Plugin\Antispam\Integrations\Comments;
use Gecka\WP\Plugin\Antispam\Plugin;
use Gecka\WP\Plugin\Antispam\StatisticalFilter;
use Mantle\Testing\Exceptions\WP_Die_Exception;

beforeEach(function () {
    gecka_antispam()->statisticalFilter()->reset();
    gecka_antispam()->stats()->reset();
    // The comments posted here are short, on purpose: the filter is what
    // most of these tests exercise.
    antispam_settings(['min_words' => 0]);
    $this->post = static::factory()->post->create();
});

afterEach(function () {
    $_POST = [];
    wp_set_current_user(0);
});

/**
 * Logs in a user who can moderate comments.
 *
 * @return void
 */
function as_moderator(): void
{
    wp_set_current_user(test()->factory()->user->create(['role' => 'editor']));
}

/**
 * Comments of a post, whatever their status
 *
 * @param int $post
 *
 * @return int
 */
function comments_of(int $post): int
{
    return (int) get_comments(['post_id' => $post, 'status' => 'all', 'count' => true]);
}

/**
 * Posts a comment through the comment form.
 *
 * @param int    $post
 * @param string $content
 * @param string $type    comment, or review for a WooCommerce product.
 *
 * @return int Id of the comment.
 */
function post_comment(int $post, string $content = 'Merci pour cet article très clair.', string $type = 'comment'): int
{
    $_POST['comment_post_ID'] = $post;

    return (int) wp_new_comment(
        [
            'comment_post_ID' => $post,
            'comment_author' => 'Marie Dupont',
            'comment_author_email' => 'marie@example.org',
            'comment_author_url' => '',
            'comment_content' => $content,
            'comment_type' => $type,
        ],
    );
}

/**
 * Teaches the filter a few spam comments and a few legitimate ones, and has
 * WordPress approve a comment that passes, whoever wrote it.
 *
 * @return void
 */
function teach_comments(): void
{
    update_option('comment_previously_approved', '0');

    for ($i = 0; $i < 3; $i++) {
        gecka_antispam()->statisticalFilter()->learn("casino bonus viagra pills cheap $i", StatisticalFilter::SPAM);
        gecka_antispam()->statisticalFilter()->learn("merci pour cet article sur la mairie $i", StatisticalFilter::HAM);
    }
}

it('passes on what another filter made of the approval, whatever its type', function (mixed $approved) {
    $comments = new Comments(gecka_antispam());

    expect($comments->approval($approved))->toBe($approved);

    $comments->annotate(null, $approved);
})->with([[null], [false], [1], ['trash']]);

it('prints the fields in the comment form of everybody but a moderator', function () {
    $form = function (): string {
        ob_start();
        comment_form([], $this->post);

        return (string) ob_get_clean();
    };

    expect($form())->toContain('name="' . Guard::TOKEN_FIELD . '"');

    wp_set_current_user(static::factory()->user->create(['role' => 'subscriber']));
    expect($form())->toContain('name="' . Guard::TOKEN_FIELD . '"');

    as_moderator();
    expect($form())->not->toContain('name="' . Guard::TOKEN_FIELD . '"');
});

it('lets a comment of a person through', function () {
    post_form('comments');
    $id = post_comment($this->post);

    expect(wp_get_comment_status($id))->not->toBe('spam')
        ->and(gecka_antispam()->stats()->totals(1)['comments'])->toBe([Guard::PASSED => 1]);
});

it('refuses a comment caught by the honeypot and keeps it with the refused submissions', function () {
    gecka_antispam()->journal()->clear();
    post_form('comments', honeypot: 'https://spam.example');

    expect(fn() => post_comment($this->post, 'Buy cheap pills online'))->toThrow(WP_Die_Exception::class)
        ->and(comments_of($this->post))->toBe(0)
        ->and(gecka_antispam()->journal()->count())->toBe(1)
        ->and(gecka_antispam()->journal()->entries(1, 10)[0]->outcome)->toBe(Guard::HONEYPOT)
        ->and(gecka_antispam()->journal()->entries(1, 10)[0]->text)->toBe('Buy cheap pills online')
        ->and(gecka_antispam()->statisticalFilter()->counts()['spam'])->toBe(0)
        ->and(gecka_antispam()->stats()->totals(1)['comments'])->toBe([Guard::HONEYPOT => 1]);
});

it('refuses a comment shorter than the minimum of words, and one of a single random word', function () {
    gecka_antispam()->journal()->clear();
    antispam_settings(['min_words' => 5]);
    post_form('comments');

    expect(fn() => post_comment($this->post, 'Great product'))->toThrow(WP_Die_Exception::class, 'Your message is too short: write at least 5 words.')
        ->and(fn() => post_comment($this->post, 'fWxBIRsgipbaeRuKXpLXpU'))->toThrow(WP_Die_Exception::class, 'Your submission could not be verified.')
        ->and(comments_of($this->post))->toBe(0)
        ->and(gecka_antispam()->journal()->count())->toBe(2)
        ->and(gecka_antispam()->stats()->totals(1)['comments'])->toBe([Guard::RANDOM_TEXT => 1, Guard::SHORT => 1]);

    expect(wp_get_comment_status(post_comment($this->post, 'Merci pour cet article très clair.')))->not->toBe('spam')
        ->and(comments_of($this->post))->toBe(1);
});

it('signs the form of a product as a comment form when WooCommerce is not there', function () {
    $product = static::factory()->post->create(['post_type' => 'product', 'comment_status' => 'open']);
    antispam_settings(['min_delay' => 0]);

    ob_start();
    comment_form([], $product);
    preg_match('/name="' . Guard::TOKEN_FIELD . '" value="([^"]+)"/', (string) ob_get_clean(), $token);
    $_POST = [Guard::TOKEN_FIELD => $token[1], gecka_antispam()->guard()->honeypotName() => ''];

    expect(gecka_antispam()->guard()->check('comments'))->toBeNull()
        ->and(gecka_antispam()->guard()->check('woocommerce_reviews'))->toBe(Guard::TOKEN);
});

it('checks a product review as a form of WooCommerce', function () {
    $product = static::factory()->post->create(['post_type' => 'product', 'comment_status' => 'open']);

    ob_start();
    comment_form([], $product);
    $html = ob_get_clean();

    post_form('woocommerce_reviews', honeypot: 'https://spam.example');

    expect($html)->toContain('name="' . Guard::TOKEN_FIELD . '"')
        ->and(fn() => post_comment($product, 'Great product', 'review'))->toThrow(WP_Die_Exception::class)
        ->and(comments_of($product))->toBe(0)
        ->and(gecka_antispam()->stats()->totals(1))->toBe(['woocommerce_reviews' => [Guard::HONEYPOT => 1]]);
});

it('lets a comment on a product through with the token its form printed, WooCommerce not being there', function () {
    antispam_settings(['min_delay' => 0]);
    $product = static::factory()->post->create(['post_type' => 'product', 'comment_status' => 'open']);

    ob_start();
    comment_form([], $product);
    preg_match('/name="' . Guard::TOKEN_FIELD . '" value="([^"]+)"/', (string) ob_get_clean(), $token);
    $_POST = [Guard::TOKEN_FIELD => $token[1]];

    expect(wp_get_comment_status(post_comment($product, 'Great product')))->not->toBe('spam')
        ->and(gecka_antispam()->stats()->totals(1))->toBe(['comments' => [Guard::PASSED => 1]]);
});

it('leaves the product reviews alone when their form is switched off', function () {
    antispam_settings(['surfaces' => ['woocommerce_reviews' => false]]);
    $product = static::factory()->post->create(['post_type' => 'product', 'comment_status' => 'open']);
    $_POST = [];

    $id = post_comment($product, 'Great product', 'review');

    expect(wp_get_comment_status($id))->not->toBe('spam')
        ->and(gecka_antispam()->stats()->totals(1))->toBe([]);
});

it('leaves alone the comments posted with no form', function () {
    $id = (int) wp_new_comment(
        [
            'comment_post_ID' => $this->post,
            'comment_author' => 'Import',
            'comment_author_email' => 'import@example.org',
            'comment_author_url' => '',
            'comment_content' => 'Imported comment',
            'comment_type' => 'comment',
        ],
    );

    expect(wp_get_comment_status($id))->not->toBe('spam')
        ->and(gecka_antispam()->stats()->totals(1))->toBe([]);
});

it('learns what a moderator marks as spam and as not spam', function () {
    post_form('comments');
    $id = post_comment($this->post, 'Visit my casino https://casino.example');

    as_moderator();
    wp_spam_comment($id);

    expect(get_comment_meta($id, Plugin::META_TRAINED, true))->toBe(StatisticalFilter::SPAM)
        ->and(gecka_antispam()->statisticalFilter()->counts())->toMatchArray(['spam' => 1, 'ham' => 0]);

    wp_unspam_comment($id);

    expect(get_comment_meta($id, Plugin::META_TRAINED, true))->toBe(StatisticalFilter::HAM)
        ->and(gecka_antispam()->statisticalFilter()->counts())->toMatchArray(['spam' => 0, 'ham' => 1]);
});

it('learns a comment approved from the moderation queue as ham', function () {
    $id = static::factory()->comment->create(['comment_post_ID' => $this->post, 'comment_approved' => '0']);

    as_moderator();
    wp_set_comment_status($id, 'approve');

    expect(get_comment_meta($id, Plugin::META_TRAINED, true))->toBe(StatisticalFilter::HAM);
});

it('rates a pingback or a trackback by the filter alone, with no form behind it', function () {
    antispam_settings(['filter_min_spam' => 3, 'filter_min_ham' => 3, 'filter_threshold' => 55]);
    teach_comments();

    $spam = post_comment($this->post, 'casino bonus viagra', 'trackback');
    add_filter('comment_flood_filter', '__return_false');
    $ham = post_comment($this->post, 'merci pour cet article sur la mairie', 'pingback');
    remove_filter('comment_flood_filter', '__return_false');

    expect(wp_get_comment_status($spam))->toBe('spam')
        ->and(get_comment_meta($spam, Plugin::META_REASON, true))->toBe(Guard::FILTER_SPAM)
        ->and(wp_get_comment_status($ham))->not->toBe('spam');
});

it('catches a comment the trained filter rates as spam', function () {
    antispam_settings(['filter_min_spam' => 3, 'filter_min_ham' => 3, 'filter_threshold' => 55]);
    teach_comments();

    post_form('comments');
    $id = post_comment($this->post, 'casino bonus viagra');

    expect(wp_get_comment_status($id))->toBe('spam')
        ->and(get_comment_meta($id, Plugin::META_REASON, true))->toBe(Guard::FILTER_SPAM)
        ->and((float) get_comment_meta($id, Plugin::META_SCORE, true))->toBeGreaterThan(0.55);
});

it('holds for moderation a comment the trained filter finds doubtful', function () {
    antispam_settings(['filter_min_spam' => 3, 'filter_min_ham' => 3, 'filter_threshold' => 99, 'filter_review' => 55]);
    teach_comments();

    post_form('comments');
    $id = post_comment($this->post, 'casino bonus viagra');

    expect(wp_get_comment_status($id))->toBe('unapproved')
        ->and(get_comment_meta($id, Plugin::META_REASON, true))->toBe(Guard::REVIEW)
        ->and(gecka_antispam()->stats()->totals(1)['comments'][Guard::REVIEW] ?? 0)->toBe(1);

    as_moderator();
    wp_set_comment_status($id, 'approve');

    expect(get_comment_meta($id, Plugin::META_TRAINED, true))->toBe(StatisticalFilter::HAM);
});

it('lets through a comment the trained filter finds legitimate', function () {
    antispam_settings(['filter_min_spam' => 3, 'filter_min_ham' => 3, 'filter_threshold' => 99, 'filter_review' => 55]);
    teach_comments();

    post_form('comments');
    $id = post_comment($this->post, 'merci pour cet article');

    expect(wp_get_comment_status($id))->toBe('approved')
        ->and(metadata_exists('comment', $id, Plugin::META_REASON))->toBeFalse();
});

it('learns the comments already marked, once, leaving the honeypot catches out', function () {
    $spam = marked_spam(static::factory()->comment->create(['comment_post_ID' => $this->post, 'comment_approved' => 'spam', 'comment_content' => 'Cheap casino pills online']));
    $ham = static::factory()->comment->create(['comment_post_ID' => $this->post, 'comment_approved' => '1', 'comment_content' => 'Merci pour cet article sur la mairie']);
    $trap = static::factory()->comment->create(['comment_post_ID' => $this->post, 'comment_approved' => 'spam', 'comment_content' => 'SEO backlinks']);
    update_comment_meta($trap, Plugin::META_REASON, Guard::HONEYPOT);

    $comments = new Comments(gecka_antispam());

    expect($comments->pending(StatisticalFilter::SPAM))->toBe(2)
        ->and($comments->learnExisting(StatisticalFilter::SPAM, 50))->toBe(1)
        ->and($comments->learnExisting(StatisticalFilter::HAM, 50))->toBeGreaterThanOrEqual(1)
        ->and(get_comment_meta($spam, Plugin::META_TRAINED, true))->toBe(StatisticalFilter::SPAM)
        ->and(get_comment_meta($ham, Plugin::META_TRAINED, true))->toBe(StatisticalFilter::HAM)
        ->and(get_comment_meta($trap, Plugin::META_TRAINED, true))->toBe(Plugin::TRAINED_SKIPPED)
        ->and($comments->pending(StatisticalFilter::SPAM))->toBe(0)
        ->and($comments->pending(StatisticalFilter::HAM))->toBe(0)
        ->and(gecka_antispam()->statisticalFilter()->counts()['spam'])->toBe(1);

    expect($comments->learnExisting(StatisticalFilter::SPAM, 50))->toBe(0)
        ->and(gecka_antispam()->statisticalFilter()->counts()['spam'])->toBe(1);
});

it('learns in one go only the spam a person or Akismet judged, never what the filter caught', function () {
    $spam = fn(string $content): int => static::factory()->comment->create(['comment_post_ID' => $this->post, 'comment_approved' => 'spam', 'comment_content' => $content]);
    $moderated = marked_spam($spam('Cheap casino pills online'));
    $akismet = $spam('Free spins, best casino bonus');
    update_comment_meta($akismet, 'akismet_result', 'true');
    $filtered = marked_spam($spam('Bitcoin mining tools download'));
    update_comment_meta($filtered, Plugin::META_REASON, Guard::FILTER_SPAM);
    $unknown = $spam('Buy followers now');

    $comments = new Comments(gecka_antispam());

    expect($comments->learnExisting(StatisticalFilter::SPAM, 50))->toBe(2)
        ->and(get_comment_meta($moderated, Plugin::META_TRAINED, true))->toBe(StatisticalFilter::SPAM)
        ->and(get_comment_meta($akismet, Plugin::META_TRAINED, true))->toBe(StatisticalFilter::SPAM)
        ->and(get_comment_meta($filtered, Plugin::META_TRAINED, true))->toBe(Plugin::TRAINED_SKIPPED)
        ->and(get_comment_meta($unknown, Plugin::META_TRAINED, true))->toBe(Plugin::TRAINED_SKIPPED);
});

it('counts a comment let through once WordPress saved it, not the duplicate it refuses', function () {
    gecka_antispam()->stats()->reset();

    post_form('comments');
    post_comment($this->post, 'Une question sur les horaires de la mairie');
    post_form('comments');

    expect(fn() => post_comment($this->post, 'Une question sur les horaires de la mairie'))->toThrow(WP_Die_Exception::class)
        ->and(gecka_antispam()->stats()->totals(1)['comments'])->toBe([Guard::PASSED => 1]);
});

it('shows in the comments list how a comment was rated, why it was held and what it was learnt as', function () {
    $comment = static::factory()->comment->create(['comment_post_ID' => $this->post, 'comment_approved' => 'spam']);
    update_comment_meta($comment, Plugin::META_SCORE, 0.8734);
    update_comment_meta($comment, Plugin::META_REASON, Guard::FILTER_SPAM);
    update_comment_meta($comment, Plugin::META_TRAINED, StatisticalFilter::SPAM);
    $plain = static::factory()->comment->create(['comment_post_ID' => $this->post]);
    $column = function (int $id): string {
        ob_start();
        do_action('manage_comments_custom_column', 'gecka_antispam', $id);

        return (string) ob_get_clean();
    };

    expect(apply_filters('manage_edit-comments_columns', []))->toHaveKey('gecka_antispam')
        ->and($column($comment))->toBe('87.3 % spam<br>Statistical filter: spam<br>Learnt as spam')
        ->and($column($plain))->toBe('&mdash;');
});

it('learns nothing from a status change made without a moderator', function () {
    post_form('comments');
    $id = post_comment($this->post, 'Visit my casino https://casino.example');

    wp_spam_comment($id);

    expect(get_comment_meta($id, Plugin::META_TRAINED, true))->toBe('')
        ->and(gecka_antispam()->statisticalFilter()->counts()['spam'])->toBe(0);
});

it('refuses a comment the trained filter rates past the rejection threshold', function () {
    gecka_antispam()->journal()->clear();
    antispam_settings(['filter_min_spam' => 3, 'filter_min_ham' => 3, 'filter_reject' => 55, 'filter_threshold' => 55]);
    teach_comments();

    post_form('comments');

    expect(fn() => post_comment($this->post, 'casino bonus viagra'))->toThrow(WP_Die_Exception::class)
        ->and(comments_of($this->post))->toBe(0)
        ->and(gecka_antispam()->journal()->entries(1, 10)[0]->outcome)->toBe(Guard::FILTER_REJECT);
});

it('checks the comment of a user logged in like one of a visitor, and leaves a moderator alone', function () {
    antispam_settings(['filter_min_spam' => 3, 'filter_min_ham' => 3, 'filter_threshold' => 55, 'filter_reject' => 100]);
    teach_comments();

    wp_set_current_user(static::factory()->user->create(['role' => 'subscriber']));
    $_POST = ['comment_post_ID' => $this->post];

    expect(fn() => post_comment($this->post, 'casino bonus viagra'))->toThrow(WP_Die_Exception::class);

    post_form('comments');
    $member = post_comment($this->post, 'casino bonus viagra');

    as_moderator();
    $_POST = ['comment_post_ID' => $this->post];
    $moderator = post_comment($this->post, 'casino bonus viagra pills');

    expect(wp_get_comment_status($member))->toBe('spam')
        ->and(get_comment_meta($member, Plugin::META_REASON, true))->toBe(Guard::FILTER_SPAM)
        ->and(wp_get_comment_status($moderator))->not->toBe('spam')
        ->and(gecka_antispam()->stats()->totals(1)['comments'])->toEqual([Guard::TOKEN => 1, Guard::FILTER_SPAM => 1]);
});

it('reads the most recent comments first, a batch at a time', function () {
    $old = static::factory()->comment->create(['comment_post_ID' => $this->post, 'comment_approved' => 'spam', 'comment_content' => 'old spam text', 'comment_date_gmt' => '2020-01-01 00:00:00']);
    $new = marked_spam(static::factory()->comment->create(['comment_post_ID' => $this->post, 'comment_approved' => 'spam', 'comment_content' => 'new spam text', 'comment_date_gmt' => gmdate('Y-m-d H:i:s', time() - 30 * DAY_IN_SECONDS)]));

    (new Comments(gecka_antispam()))->learnExisting(StatisticalFilter::SPAM, 1);

    expect(get_comment_meta($new, Plugin::META_TRAINED, true))->toBe(StatisticalFilter::SPAM)
        ->and(metadata_exists('comment', $old, Plugin::META_TRAINED))->toBeFalse();
});

it('learns the comments again once the filter was reset', function () {
    $spam = marked_spam(static::factory()->comment->create(['comment_post_ID' => $this->post, 'comment_approved' => 'spam', 'comment_content' => 'Cheap casino pills online']));
    $comments = new Comments(gecka_antispam());
    $comments->learnExisting(StatisticalFilter::SPAM, 50);

    gecka_antispam()->resetFilter();

    expect(metadata_exists('comment', $spam, Plugin::META_TRAINED))->toBeFalse()
        ->and(gecka_antispam()->statisticalFilter()->counts()['spam'])->toBe(0)
        ->and($comments->pending(StatisticalFilter::SPAM))->toBe(1)
        ->and($comments->learnExisting(StatisticalFilter::SPAM, 50))->toBe(1)
        ->and(gecka_antispam()->statisticalFilter()->counts()['spam'])->toBe(1);
});

it('learns the comments already marked in the generation their date belongs to, and leaves the oldest alone', function () {
    $dated = function (int $months, string $content): int {
        return marked_spam(
            static::factory()->comment->create(
                [
                    'comment_post_ID' => $this->post,
                    'comment_approved' => 'spam',
                    'comment_content' => $content,
                    'comment_date_gmt' => gmdate('Y-m-d H:i:s', time() - $months * MONTH_IN_SECONDS),
                ],
            ),
        );
    };
    $recent = $dated(2, 'Cheap pills online, best price, order now');
    $older = $dated(8, 'Casino bonus, free spins every day, visit now');
    $oldest = $dated(14, 'Bitcoin mining tools, free download today');
    $comments = new Comments(gecka_antispam());

    expect($comments->pending(StatisticalFilter::SPAM))->toBe(2)
        ->and($comments->learnExisting(StatisticalFilter::SPAM, 10))->toBe(2)
        ->and(get_comment_meta($recent, Plugin::META_GENERATION, true))->toBe('0')
        ->and(get_comment_meta($older, Plugin::META_GENERATION, true))->toBe('-1')
        ->and(get_comment_meta($oldest, Plugin::META_TRAINED, true))->toBe('')
        ->and(gecka_antispam()->statisticalFilter()->tally()->recent(\Gecka\SpamFilter\Label::Spam))->toBe(1);
});

it('records the generation a comment was learnt in, and moves it exactly after a rotation', function () {
    post_form('comments');
    $id = post_comment($this->post, 'Visit my casino https://casino.example');

    as_moderator();
    wp_spam_comment($id);

    expect(get_comment_meta($id, Plugin::META_GENERATION, true))->toBe('0');

    gecka_antispam()->statisticalFilter()->rotate();
    wp_unspam_comment($id);

    expect(get_comment_meta($id, Plugin::META_TRAINED, true))->toBe(StatisticalFilter::HAM)
        ->and(get_comment_meta($id, Plugin::META_GENERATION, true))->toBe('1')
        ->and(gecka_antispam()->statisticalFilter()->counts())->toMatchArray(['spam' => 0, 'ham' => 1]);
});
