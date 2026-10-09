<?php

declare(strict_types=1);

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

namespace Gecka\WP\Plugin\Antispam\Integrations;

use Gecka\WP\Plugin\Antispam\Base;
use Gecka\WP\Plugin\Antispam\Guard;
use Gecka\WP\Plugin\Antispam\Plugin;
use Gecka\WP\Plugin\Antispam\StatisticalFilter;

/**
 * A form plugin, or WordPress itself, whose forms the plugin protects.
 *
 * @author Laurent Dinclaux - Gecka <laurent@gecka.nc>
 */
abstract class Integration extends Base
{
    /**
     * Priority of the checks on hooks other plugins check too, a captcha
     * or a spam service: ahead of their default 10, so a submission refused
     * here goes to the journal and never reaches a remote verification.
     */
    public const PRIORITY = 5;

    /**
     * Names of the fields that hold the subject or the message.
     */
    private const MESSAGE_NAME = '/(?:^|[-_ ])(?:subject|sujet|objet|title|titre|message|msg|comments?|commentaires?|demande|question|request|enquiry|inquiry|details?|texte|textarea|body|content|contenu|description|remarques?|precisions?|précisions?)(?:$|[-_ \d])/iu';

    /**
     * Names of the fields that hold something of the sender.
     */
    private const SENDER_NAME = '/(?:^|[-_ ])(?:e?-?mail|courriel|tel|t[eé]l[eé]phone|phone|mobile|portable|fax|url|website|site|web|name|nom|pr[eé]nom|first|last|company|soci[eé]t[eé]|entreprise|organi[sz]ation|address|adresse|street|rue|city|ville|zip|postcode|postal|cp|country|pays|birth|naissance|siret|siren|tva|vat)(?:$|[-_ \d])/iu';

    /**
     * Rating the statistical filter gave the last text it read.
     *
     * @var float|null
     */
    protected ?float $score = null;

    /**
     * Whether the statistical filter found the last text it read doubtful, rated
     * between the review threshold and the threshold.
     *
     * @var bool
     */
    protected bool $review = false;

    /**
     * Whether the plugin providing the forms is active.
     *
     * @return bool
     */
    abstract public function available(): bool;

    /**
     * The fields added to a form
     *
     * @param string $surface
     * @param bool   $carry   Keep the time of a valid timestamp the request posts.
     *
     * @return string
     */
    protected function fields(string $surface, bool $carry = false): string
    {
        return $this->plugin->settings()->enabled($surface) ? $this->plugin->guard()->fields($surface, $carry) : '';
    }

    /**
     * Runs the checks on a submission, the statistical filter last, and
     * counts it. A submission refused that carries a text goes to the
     * journal, for review.
     *
     * @param string      $surface   The form being sent.
     * @param string[]    $names     Names typed in the form.
     * @param string|null $text      What the statistical filter reads, null for a form it does not rate.
     * @param bool        $guarded   Whether the form carries the fields; without them only the text is rated.
     * @param bool        $countLater Whether a submission let through is counted by the caller, once saved.
     *
     * @return string|null What caught the submission, null when it went through.
     */
    protected function verify(string $surface, array $names = [], ?string $text = null, bool $guarded = true, bool $countLater = false): ?string
    {
        $this->score = null;
        $this->review = false;
        $outcome = $guarded ? $this->plugin->guard()->check($surface, $names) : null;

        if (! $outcome && $text !== null && $this->plugin->filterReady()) {
            $this->score = $this->plugin->statisticalFilter()->classify($text);
            $outcome = $this->plugin->verdict($this->score);
            $this->review = $outcome === Guard::REVIEW;
            $outcome = $this->review ? null : $outcome;
        }

        if (Guard::refuses($outcome) && $text !== null) {
            $this->plugin->journal()->record($surface, (string) $outcome, $text);
        }

        if (! $countLater || Guard::refuses($outcome)) {
            $this->plugin->stats()->record($surface, $this->counted($outcome));
            $this->plugin->origins()->count($this->counted($outcome));
        }

        /**
         * Fires once a submission was checked.
         *
         * @param string|null $outcome What caught it, null when it went through.
         * @param string      $surface The form it was sent from.
         */
        do_action('gecka_antispam_checked', $outcome, $surface);

        return $outcome;
    }

    /**
     * Learns a text marked as spam or as ham by someone.
     *
     * @param string      $text
     * @param string|null $previous   What it was learnt as before, null when it never was.
     * @param int|null    $generation The generation it was learnt in before.
     * @param string      $category   StatisticalFilter::SPAM or StatisticalFilter::HAM.
     *
     * @return int|null The generation it is now learnt in as $category, null when it is not.
     */
    protected function train(string $text, ?string $previous, ?int $generation, string $category): ?int
    {
        if (! $this->plugin->settings()->get('filter')) {
            return null;
        }

        return $this->plugin->statisticalFilter()->relearn($text, $previous ?: null, $generation, $category);
    }

    /**
     * Learns an item someone, or a filter, already marked as spam or as
     * legitimate, in the generation its date belongs to. A spam is learnt
     * only when a person, or Akismet, judged it: one a check of the form or
     * a check for bots caught says a bot sent it, not that its words are
     * those of spam, and one this filter caught would only teach it what it
     * already believes, its mistakes included. An item older than two
     * rotation periods is left out too: it would have halved since.
     *
     * @param string      $text
     * @param string      $category StatisticalFilter::SPAM or StatisticalFilter::HAM.
     * @param string|null $outcome  What caught the item, when the plugin did.
     * @param int         $time     When the item was sent, Unix time.
     * @param bool        $judged   Whether a person, or Akismet, marked the item as spam.
     *
     * @return int|false|null The generation it was learnt in, null when it was left out, false when the filter failed and the item is still to learn.
     */
    protected function learnMarked(string $text, string $category, ?string $outcome, int $time, bool $judged = false): int|false|null
    {
        $archive = $this->plugin->archives($time);

        if ($archive === null || ($category === StatisticalFilter::SPAM && (! $judged || $outcome === Guard::FILTER_SPAM || Guard::refuses($outcome)))) {
            return null;
        }

        $filter = $this->plugin->statisticalFilter();
        $generation = $filter->learn($text, $category, $archive);

        return $generation === null && $filter->learningFailed() ? false : $generation;
    }

    /**
     * Oldest date of an item learnt in one go, GMT, as WordPress and Gravity
     * Forms store dates
     *
     * @return string
     */
    protected function learningCutoff(): string
    {
        return gmdate('Y-m-d H:i:s', time() - 2 * $this->plugin->rotationPeriod());
    }

    /**
     * What the statistics count a submission checked as
     *
     * @param string|null $outcome What caught it, null when it went through.
     *
     * @return string
     */
    protected function counted(?string $outcome): string
    {
        return $outcome ?? ($this->review ? Guard::REVIEW : Guard::PASSED);
    }

    /**
     * Why a submission was caught, as recorded next to it
     *
     * @param string $outcome
     *
     * @return string
     */
    protected function reason(string $outcome): string
    {
        if (in_array($outcome, [Guard::FILTER_SPAM, Guard::FILTER_REJECT, Guard::REVIEW], true) && $this->score !== null) {
            /* translators: %s: rating of the statistical filter, in percent */
            return sprintf(__('Statistical filter: %s %% spam', 'gecka-antispam'), number_format_i18n($this->score * 100, 1));
        }

        return Guard::outcomeLabel($outcome);
    }

    /**
     * Error shown to someone whose submission was refused
     *
     * @return string
     */
    protected function message(): string
    {
        return __('Your submission could not be verified. Please reload the page and try again.', 'gecka-antispam');
    }

    /**
     * Whether the change being made comes from a person allowed to make it:
     * a user logged in with the capability, outside the cron. The status a
     * scheduled task or another plugin, Akismet for one, gives an item is a
     * verdict, not a correction, and is not learnt.
     *
     * @param bool $allowed Whether the current user has the capability.
     *
     * @return bool
     */
    protected static function byModerator(bool $allowed): bool
    {
        return $allowed && ! wp_doing_cron();
    }

    /**
     * What the statistical filter reads of the fields of a form: the subject and
     * the message, in the order of the form.
     *
     * The rule reads names and values only, so it gives the same text for a
     * submission and for the copy Flamingo keeps of it.
     *
     * @param array<mixed> $fields Values keyed by field name.
     *
     * @return string
     */
    protected static function fieldsText(array $fields): string
    {
        $lines = [];

        foreach ($fields as $name => $value) {
            $value = self::flatten($value);

            if ($value !== '' && self::isMessageField((string) $name, $value)) {
                $lines[] = $value;
            }
        }

        return implode("\n", $lines);
    }

    /**
     * Whether a field holds the subject or the message: its name says so, or
     * its name says nothing of the sender and its value reads as prose, five
     * words or more. Names, addresses, phone numbers and the like are left
     * out, whatever their length.
     *
     * @param string $name  Name or label of the field.
     * @param string $value
     *
     * @return bool
     */
    protected static function isMessageField(string $name, string $value): bool
    {
        if (preg_match(self::MESSAGE_NAME, $name)) {
            return true;
        }

        if (preg_match(self::SENDER_NAME, $name)) {
            return false;
        }

        return preg_match_all('/\S+/u', $value) >= 5;
    }

    /**
     * A value as one line of text, the choices of a multiple field joined
     *
     * @param mixed $value
     *
     * @return string
     */
    protected static function flatten(mixed $value): string
    {
        if (is_array($value)) {
            $value = implode(' ', array_filter(array_map(static fn(mixed $item): string => is_scalar($item) ? trim((string) $item) : '', $value)));
        }

        return is_scalar($value) ? trim((string) $value) : '';
    }

    /**
     * Whether a text was learnt as spam or ham
     *
     * @param mixed $value Value of the meta holding it.
     *
     * @return string|null
     */
    protected static function category(mixed $value): ?string
    {
        return in_array($value, [StatisticalFilter::SPAM, StatisticalFilter::HAM], true) ? $value : null;
    }

    /**
     * A generation number read from a meta, null when there is none
     *
     * @param mixed $value
     *
     * @return int|null
     */
    protected static function generation(mixed $value): ?int
    {
        return is_numeric($value) ? (int) $value : null;
    }
}
