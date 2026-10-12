<?php

declare(strict_types=1);

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

namespace Gecka\WP\Plugin\Antispam;

/**
 * The fields the plugin adds to a form, and the checks it runs on what the
 * form sends back.
 *
 * Two fields: a signed timestamp, hidden, and a text field people never see
 * nor reach, which a bot filling every field fills too. The text field is
 * hidden by a class rather than moved off screen: browsers autofill a field
 * off screen, never one that is not rendered. Its label asks to leave it
 * empty, for whoever meets it with no style sheet. The rule hiding it goes
 * in the head of the page; a form printed where no head is, an Ajax response
 * for one, carries the rule itself.
 *
 * The timestamp is refused past the maximum age, 8 days by default, which a
 * page cache keeping its pages a week still fits in: a page served from a
 * cache carries the timestamp of the moment it was cached.
 *
 * @author Laurent Dinclaux - Gecka <laurent@gecka.nc>
 */
class Guard
{
    /**
     * Field holding the signed timestamp. Contact Form 7 and Flamingo leave
     * out the fields whose name starts with an underscore.
     */
    public const TOKEN_FIELD = '_gecka_antispam';

    /**
     * The submission went through every check.
     */
    public const PASSED = 'passed';

    /**
     * The honeypot field was filled in.
     */
    public const HONEYPOT = 'honeypot';

    /**
     * The timestamp is missing, or its signature does not match.
     */
    public const TOKEN = 'token';

    /**
     * The form was sent faster than anybody types.
     */
    public const TOO_FAST = 'too_fast';

    /**
     * The form was sent after the timestamp expired.
     */
    public const EXPIRED = 'expired';

    /**
     * A name looks like random letters.
     */
    public const RANDOM_NAME = 'random_name';

    /**
     * The message is a single word of random letters.
     */
    public const RANDOM_TEXT = 'random_text';

    /**
     * The message holds fewer words than the minimum set.
     */
    public const SHORT = 'short';

    /**
     * The statistical filter rated the text as spam.
     */
    public const FILTER_SPAM = 'filter_spam';

    /**
     * The statistical filter rated the text past the rejection threshold.
     */
    public const FILTER_REJECT = 'filter_reject';

    /**
     * The statistical filter rated the text as doubtful: it went through, held
     * for review where the form allows it.
     */
    public const REVIEW = 'review';

    /**
     * The outcomes of a submission that went through: accepted, or held
     * for review.
     */
    public const ACCEPTED = [self::PASSED, self::REVIEW];

    /**
     * Seconds a timestamp may be ahead of the server clock.
     */
    private const CLOCK_SKEW = 60;

    /**
     * Handle of the inline style sheet hiding the honeypot.
     */
    private const STYLE = 'gecka-antispam';

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
     * What each check catches, as shown in the administration
     *
     * @return array<string, string>
     */
    public static function outcomes(): array
    {
        return [
            self::PASSED => __('Accepted', 'gecka-antispam'),
            self::REVIEW => __('To review', 'gecka-antispam'),
            self::HONEYPOT => __('Honeypot filled in', 'gecka-antispam'),
            self::TOKEN => __('Timestamp missing or forged', 'gecka-antispam'),
            self::TOO_FAST => __('Sent too fast', 'gecka-antispam'),
            self::EXPIRED => __('Timestamp expired', 'gecka-antispam'),
            self::RANDOM_NAME => __('Random name', 'gecka-antispam'),
            self::RANDOM_TEXT => __('Message of random letters', 'gecka-antispam'),
            self::SHORT => __('Message too short', 'gecka-antispam'),
            self::FILTER_SPAM => __('Statistical filter: spam', 'gecka-antispam'),
            self::FILTER_REJECT => __('Statistical filter: refused', 'gecka-antispam'),
        ];
    }

    /**
     * Whether an outcome refuses the submission: a check of the form caught
     * it, or the statistical filter rated it past the rejection threshold.
     * A submission marked as spam, held for review or accepted goes through.
     *
     * @param string|null $outcome
     *
     * @return bool
     */
    public static function refuses(?string $outcome): bool
    {
        return $outcome !== null && ! in_array($outcome, [...self::ACCEPTED, self::FILTER_SPAM], true);
    }

    /**
     * Label of an outcome
     *
     * @param string $outcome
     *
     * @return string
     */
    public static function outcomeLabel(string $outcome): string
    {
        return self::outcomes()[$outcome] ?? $outcome;
    }

    /**
     * The fields added to a form
     *
     * @param string $surface The form they go in.
     * @param bool   $carry   Keep the time of a valid timestamp the request posts for
     *                        the same form, for a form shown again after a post: the next
     *                        page of a multipage form, or the form back with its errors.
     *
     * @return string
     */
    public function fields(string $surface, bool $carry = false): string
    {
        $time = ($carry ? $this->postedTime($surface) : null) ?? time();
        $class = $this->hidingClass();
        $html = $this->styleInForm() ? '<style>' . $this->hidingRule() . '</style>' : '';

        $html .= sprintf(
            '<input type="hidden" name="%s" value="%s">',
            esc_attr(self::TOKEN_FIELD),
            esc_attr($time . '.' . $this->sign($surface, $time)),
        );

        $html .= sprintf(
            '<div class="%1$s" aria-hidden="true"><label>%2$s <input type="text" name="%3$s" value="" tabindex="-1" autocomplete="off" data-1p-ignore data-lpignore="true" data-bwignore data-form-type="other"></label></div>',
            esc_attr($class),
            esc_html__('Leave this field empty', 'gecka-antispam'),
            esc_attr($this->honeypotName()),
        );

        return $html;
    }

    /**
     * Queues the rule hiding the honeypot for the head of the page.
     *
     * @return void
     */
    public function enqueueStyle(): void
    {
        wp_register_style(self::STYLE, false, [], Plugin::VERSION);
        wp_add_inline_style(self::STYLE, $this->hidingRule());
        wp_enqueue_style(self::STYLE);
    }

    /**
     * Runs the checks on the submission of a form.
     *
     * @param string      $surface The form being sent.
     * @param string[]    $names   Names typed in the form, checked for random letters.
     * @param string|null $message The message typed, null for a form without one.
     *
     * @return string|null What caught the submission, null when it went through.
     */
    public function check(string $surface, array $names = [], ?string $message = null): ?string
    {
        if ($this->honeypotFilled()) {
            return self::HONEYPOT;
        }

        $age = $this->tokenAge($surface);

        if ($age === null) {
            return self::TOKEN;
        }

        if ($age < $this->plugin->settings()->minDelay($surface)) {
            return self::TOO_FAST;
        }

        $maxAge = (int) $this->plugin->settings()->get('max_age') * HOUR_IN_SECONDS;

        if ($maxAge && $age > $maxAge) {
            return self::EXPIRED;
        }

        $random = (bool) $this->plugin->settings()->get('random_names');

        if ($random) {
            foreach ($names as $name) {
                if (self::isRandomName($name)) {
                    return self::RANDOM_NAME;
                }
            }
        }

        if ($message !== null) {
            $words = self::words($message);

            if ($random && count($words) === 1 && self::isRandomName(trim($words[0], '.,;:!?'))) {
                return self::RANDOM_TEXT;
            }

            if (count($words) < (int) $this->plugin->settings()->get('min_words')) {
                return self::SHORT;
            }
        }

        return null;
    }

    /**
     * The words of a text: what its blanks separate
     *
     * @param string $text
     *
     * @return string[]
     */
    public static function words(string $text): array
    {
        return preg_split('/\s+/u', trim($text), -1, PREG_SPLIT_NO_EMPTY) ?: [];
    }

    /**
     * Whether the honeypot field came back filled in
     *
     * @return bool
     */
    public function honeypotFilled(): bool
    {
        // phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput -- Only tested for emptiness, never stored nor printed.
        $value = $_POST[$this->honeypotName()] ?? '';

        return is_array($value) ? $value !== [] : trim((string) $value) !== '';
    }

    /**
     * Name of the honeypot field on this site
     *
     * @return string
     */
    public function honeypotName(): string
    {
        return (string) $this->plugin->settings()->get('honeypot_name');
    }

    /**
     * A name in one block, with no space, whose case changes at random, like
     * qASQAhqkpFGqnKkRROl: three switches from lower to upper case at least,
     * and two capitals followed by a capital. A CamelCase name, like
     * MarieClaireDeLaFontaine, hardly ever has two capitals in a row.
     *
     * @param string $name
     *
     * @return bool
     */
    public static function isRandomName(string $name): bool
    {
        $name = trim($name);

        return (bool) preg_match('/^[A-Za-z]{12,}$/', $name)
            && preg_match_all('/[a-z][A-Z]/', $name) >= 3
            && preg_match_all('/[A-Z](?=[A-Z])/', $name) >= 2;
    }

    /**
     * Seconds since the form was displayed, null when the timestamp is
     * missing, forged, or ahead of the clock
     *
     * @param string $surface
     *
     * @return int|null
     */
    private function tokenAge(string $surface): ?int
    {
        $time = $this->postedTime($surface);

        return $time === null ? null : max(0, time() - $time);
    }

    /**
     * Time the timestamp posted for a form was issued at, null when there is
     * none, or a forged one, or one from the future
     *
     * @param string $surface
     *
     * @return int|null
     */
    private function postedTime(string $surface): ?int
    {
        $parts = explode('.', Request::post(self::TOKEN_FIELD), 2);

        if (count($parts) !== 2 || ! ctype_digit($parts[0]) || ! hash_equals($this->sign($surface, (int) $parts[0]), $parts[1])) {
            return null;
        }

        return (int) $parts[0] - time() > self::CLOCK_SKEW ? null : (int) $parts[0];
    }

    /**
     * Signature of a timestamp, bound to the form it was issued for
     *
     * @param string $surface
     * @param int    $time
     *
     * @return string
     */
    private function sign(string $surface, int $time): string
    {
        return substr(hash_hmac('sha256', $surface . '|' . get_current_blog_id() . '|' . $time, wp_salt('nonce')), 0, 24);
    }

    /**
     * Whether a form carries the rule hiding the honeypot: the head of the
     * page holds it, or will, unless it was printed without it
     *
     * @return bool
     */
    private function styleInForm(): bool
    {
        if (wp_style_is(self::STYLE, 'done')) {
            return false;
        }

        return ! wp_style_is(self::STYLE, 'enqueued') || did_action('wp_head') || did_action('login_head');
    }

    /**
     * CSS rule hiding the honeypot
     *
     * @return string
     */
    private function hidingRule(): string
    {
        return '.' . $this->hidingClass() . '{display:none!important}';
    }

    /**
     * Class hiding the honeypot, drawn from its name so it differs between
     * sites and reads like any other class
     *
     * @return string
     */
    private function hidingClass(): string
    {
        return 'f' . substr(md5($this->honeypotName()), 0, 7);
    }
}
