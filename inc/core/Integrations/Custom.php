<?php

declare(strict_types=1);

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

namespace Gecka\WP\Plugin\Antispam\Integrations;

use Gecka\WP\Plugin\Antispam\Guard;
use Gecka\WP\Plugin\Antispam\Settings;

/**
 * The forms a developer protects through gecka_antispam_fields() and
 * gecka_antispam_check(). Each is named by the developer and recorded as
 * custom:{name}; no setting switches it off, the gecka_antispam_protect
 * filter does. The plugin hooks nothing: the developer prints the fields
 * and checks the submission, and decides what a refusal or a spam becomes.
 *
 * @author Laurent Dinclaux - Gecka <laurent@gecka.nc>
 */
class Custom extends Integration
{
    /**
     * Always: the custom forms are those of the developers of the site
     *
     * @return bool
     */
    public function available(): bool
    {
        return true;
    }

    /**
     * Nothing to hook: a custom form calls the plugin itself, through
     * gecka_antispam_fields() and gecka_antispam_check().
     *
     * @return void
     */
    public function setup(): void {}

    /**
     * The fields of a custom form, empty when it is not protected
     *
     * @param string $form
     * @param bool   $carry Keep the time of a valid timestamp the request posts for the form.
     *
     * @return string HTML, escaped.
     */
    public function fields(string $form, bool $carry = false): string
    {
        $surface = Settings::customSurface($form);

        return $this->plugin->settings()->enabled($surface) ? $this->plugin->guard()->fields($surface, $carry) : '';
    }

    /**
     * Checks a submission of a custom form. A form that is not protected
     * goes through unchecked and uncounted.
     *
     * @param string      $form
     * @param string      $text    Subject and message.
     * @param string[]    $names   Names the sender typed.
     * @param string|null $message The message alone, when the text also carries a subject; the whole text without it.
     *
     * @return array{refused: bool, spam: bool, review: bool, reason: string|null, score: float|null, message: string}
     *     refused: a check of the form caught it, or the filter rated it past the rejection threshold;
     *     spam: the filter rated it spam, below that threshold;
     *     review: the filter finds it doubtful;
     *     reason: what caught it, as Guard names outcomes, null when it went through;
     *     score: the rating of the filter, from 0 to 1, null when it did not rate;
     *     message: the error to show for a refusal or a spam, empty otherwise.
     */
    public function check(string $form, string $text = '', array $names = [], ?string $message = null): array
    {
        $surface = Settings::customSurface($form);

        if (! $this->plugin->settings()->enabled($surface)) {
            return ['refused' => false, 'spam' => false, 'review' => false, 'reason' => null, 'score' => null, 'message' => ''];
        }

        $text = trim($text);
        $message = trim($message ?? $text);
        $outcome = $this->verify($surface, array_map('strval', $names), $text !== '' ? $text : null, message: $message !== '' ? $message : null);
        $refused = Guard::refuses($outcome);
        $spam = $outcome === Guard::FILTER_SPAM;

        return [
            'refused' => $refused,
            'spam' => $spam,
            'review' => $this->review,
            'reason' => $outcome ?? ($this->review ? Guard::REVIEW : null),
            'score' => $this->score,
            'message' => $refused || $spam ? $this->message() : '',
        ];
    }
}
