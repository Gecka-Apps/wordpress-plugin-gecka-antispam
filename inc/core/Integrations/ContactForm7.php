<?php

declare(strict_types=1);

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

namespace Gecka\WP\Plugin\Antispam\Integrations;

use Gecka\WP\Plugin\Antispam\Guard;

/**
 * Contact Form 7 forms: every form, or the forms holding the [gecka_antispam]
 * form tag only, as the settings say. Where the tag stands, the fields go;
 * a form without it gets them before its submit button.
 *
 * A submission the checks of the form catch, or the statistical filter
 * rates past the rejection threshold, is refused with an error and kept in
 * the Journal; one the filter marks as spam is flagged as spam: Contact
 * Form 7 sends no mail, and Flamingo, when active, keeps it in its spam with
 * the reason. Contact Form 7 submits through its REST route, so the checks
 * do not skip REST requests here.
 *
 * The statistical filter reads the subject and the message, as the form
 * defines them, never a field by its name: the subject is the fields the
 * subject of the mail cites, the message the textarea fields. The additional
 * settings gecka_antispam_subject and gecka_antispam_message, written as mail
 * tags, override both; flamingo_subject stands for the subject when set.
 * Fields Contact Form 7 takes for the sender, through flamingo_name and
 * flamingo_email, and fields typed as an address, a number, a date or a file,
 * never count as the subject.
 *
 * The random names check reads the text fields the additional setting
 * gecka_antispam_name cites, else those flamingo_name cites, else the text
 * fields named as a name: your-name, nom, votre-prenom and the like.
 *
 * Contact Form 7 keeps every posted field whose name does not start with an
 * underscore, so the honeypot is taken out of the posted data: neither the
 * mail, nor Flamingo, nor the statistical filter see it. The checks read it
 * from the request.
 *
 * Contact Form 7 warns about a mail sent to an address the sender typed,
 * a Mail (2) to [your-email] say, unless its own reCAPTCHA or Turnstile is
 * active. The checks of this plugin stand in the same place, so the warning
 * is left out of the forms they protect. Contact Form 7 records it when a
 * form is saved: saving the form again brings it up to date.
 *
 * @author Laurent Dinclaux - Gecka <laurent@gecka.nc>
 */
class ContactForm7 extends Integration
{
    /**
     * Agent named in the spam log of a submission.
     */
    public const AGENT = 'gecka-antispam';

    /**
     * Whether the submission being sent was refused.
     *
     * @var bool
     */
    private bool $refused = false;

    /**
     * Names of the fields that hold the name of a person: name, your-name,
     * first-name, lastname, nom, votre-prenom... but not username nor
     * company-name.
     */
    private const NAME_FIELD = '/^(?:(?:your|votre)[-_]?)?(?:(?:first|last|full|given|family|sur)[-_]?)?(?:name|nom|pr[eé]nom)$/iu';

    /**
     * Form tag marking a form to protect, and placing its fields.
     */
    public const TAG = 'gecka_antispam';

    /**
     * Error of the configuration validator of Contact Form 7 about a mail
     * sent to an address the sender typed.
     */
    public const UNSAFE_EMAIL = 'unsafe_email_without_protection';

    /**
     * Base types of the form tags that may stand for the subject.
     */
    private const SUBJECT_TYPES = ['text', 'textarea', 'select', 'radio', 'checkbox'];

    /**
     * Whether Contact Form 7 is active
     *
     * @return bool
     */
    public function available(): bool
    {
        return defined('WPCF7_VERSION');
    }

    /**
     * Hooks the tag, the fields, the spam check and the configuration
     * validator of Contact Form 7 up.
     *
     * @return void
     */
    public function setup(): void
    {
        add_action('wpcf7_init', [$this, 'registerTag']);
        add_filter('wpcf7_form_elements', [$this, 'render']);
        add_filter('wpcf7_posted_data', [$this, 'removeHoneypot']);
        add_filter('wpcf7_spam', [$this, 'check'], self::PRIORITY, 2);
        add_filter('wpcf7_flamingo_submit_if', [$this, 'flamingoStatuses']);
        add_filter('wpcf7_config_validator_available_error_codes', [$this, 'errorCodes'], 10, 2);
    }

    /**
     * Keeps a submission refused out of Flamingo: it lands in the journal of
     * the plugin instead. A spam of the statistical filter stays in Flamingo,
     * where it can be marked as not spam.
     *
     * @param mixed $statuses Statuses of the submissions Flamingo keeps.
     *
     * @return mixed
     */
    public function flamingoStatuses(mixed $statuses): mixed
    {
        return $this->refused && is_array($statuses) ? array_values(array_diff($statuses, ['spam'])) : $statuses;
    }

    /**
     * Declares the form tag.
     *
     * @return void
     */
    public function registerTag(): void
    {
        if (function_exists('wpcf7_add_form_tag')) {
            wpcf7_add_form_tag(self::TAG, [$this, 'renderTag']);
        }
    }

    /**
     * The fields, where the form tag stands.
     *
     * @return string
     */
    public function renderTag(): string
    {
        return $this->plugin->settings()->enabled('contact_form_7') ? $this->fields('contact_form_7') : '';
    }

    /**
     * Adds the fields before the submit button of a form protected without
     * holding the tag.
     *
     * @param mixed $html
     *
     * @return mixed
     */
    public function render(mixed $html): mixed
    {
        $form = $this->currentForm();

        if (! is_string($html) || self::hasTag($form) || ! $this->plugin->settings()->protects('contact_form_7', false)) {
            return $html;
        }

        $fields = $this->fields('contact_form_7');
        $html = preg_replace_callback(
            '/<(?:input|button)[^>]*type=(["\'])submit\1/i',
            static fn(array $match): string => $fields . $match[0],
            $html,
            1,
            $count,
        ) ?? $html;

        return $count ? $html : $html . $fields;
    }

    /**
     * Leaves the warning about a mail sent to an address the sender typed
     * out of the errors the configuration validator may record for a form
     * the plugin protects.
     *
     * @param mixed $codes Error codes.
     * @param mixed $form  \WPCF7_ContactForm
     *
     * @return mixed
     */
    public function errorCodes(mixed $codes, mixed $form = null): mixed
    {
        if (! is_array($codes) || ! $form instanceof \WPCF7_ContactForm || ! $this->plugin->settings()->protects('contact_form_7', self::hasTag($form))) {
            return $codes;
        }

        return array_values(array_diff($codes, [self::UNSAFE_EMAIL]));
    }

    /**
     * Takes the honeypot out of the posted data.
     *
     * @param mixed $posted
     *
     * @return mixed
     */
    public function removeHoneypot(mixed $posted): mixed
    {
        if (is_array($posted)) {
            unset($posted[$this->plugin->guard()->honeypotName()]);
        }

        return $posted;
    }

    /**
     * Flags a submission as spam when it does not pass the checks.
     *
     * @param mixed $spam       Whether a check that ran before flagged it.
     * @param mixed $submission \WPCF7_Submission
     *
     * @return mixed
     */
    public function check(mixed $spam, mixed $submission = null): mixed
    {
        if ($spam || ! $submission instanceof \WPCF7_Submission) {
            return $spam;
        }

        $form = $submission->get_contact_form();

        if (! $this->plugin->settings()->protects('contact_form_7', self::hasTag($form))) {
            return $spam;
        }

        $posted = (array) $submission->get_posted_data();
        $text = self::formText($form, $posted);
        $outcome = $this->verify('contact_form_7', $this->names($form, $posted), $text);
        $this->refused = Guard::refuses($outcome);

        if (! $outcome) {
            return false;
        }

        $submission->add_spam_log(['agent' => self::AGENT, 'reason' => $this->reason($outcome), 'outcome' => $outcome]);

        return true;
    }

    /**
     * What the statistical filter reads of a submission of a form, or of a
     * message Flamingo kept: the subject, then the message
     *
     * @param \WPCF7_ContactForm   $form
     * @param array<string, mixed> $fields Posted or kept values, by field name.
     *
     * @return string
     */
    public static function formText(\WPCF7_ContactForm $form, array $fields): string
    {
        $mail = (array) $form->prop('mail');

        return self::pick(
            self::stored($form, $fields),
            self::types($form),
            self::setting($form, ['gecka_antispam_subject', 'flamingo_subject']) ?? (string) ($mail['subject'] ?? ''),
            self::setting($form, ['gecka_antispam_message']),
            array_merge(self::cited(self::setting($form, ['flamingo_name']) ?? '[your-name]'), self::cited(self::setting($form, ['flamingo_email']) ?? '[your-email]')),
        );
    }

    /**
     * The values of the subject and of the message, one per line, the
     * subject first, each field once
     *
     * @param array<string, mixed>  $fields  Values by field name.
     * @param array<string, string> $types   Base type of each form tag, by name.
     * @param string                $subject Template citing the subject fields as mail tags.
     * @param string|null           $message Template citing the message fields, null for every textarea.
     * @param string[]              $sender  Fields that hold the sender, never the subject.
     *
     * @return string
     */
    public static function pick(array $fields, array $types, string $subject, ?string $message, array $sender): string
    {
        $subjects = array_filter(
            self::cited($subject),
            static fn(string $name): bool => ! in_array($name, $sender, true) && in_array($types[$name] ?? '', self::SUBJECT_TYPES, true),
        );
        $messages = $message === null
            ? array_keys(array_filter($types, static fn(string $type): bool => $type === 'textarea'))
            : self::cited($message);
        $lines = [];

        foreach (array_unique([...$subjects, ...$messages]) as $name) {
            $value = self::flatten($fields[$name] ?? '');

            if ($value !== '') {
                $lines[] = $value;
            }
        }

        return implode("\n", $lines);
    }

    /**
     * The first of the additional settings of a form that is set
     *
     * @param \WPCF7_ContactForm $form
     * @param string[]           $names
     *
     * @return string|null
     */
    private static function setting(\WPCF7_ContactForm $form, array $names): ?string
    {
        foreach ($names as $name) {
            $value = $form->pref($name);

            if (is_string($value) && trim($value) !== '') {
                return $value;
            }
        }

        return null;
    }

    /**
     * Names of the fields a template cites as mail tags; the special mail
     * tags, which start with an underscore, are left out
     *
     * @param string $template
     *
     * @return string[]
     */
    private static function cited(string $template): array
    {
        preg_match_all('/\[\s*([a-zA-Z][0-9a-zA-Z:._-]*)\s*\]/', $template, $matches);

        return array_values(array_unique($matches[1]));
    }

    /**
     * Whether a form holds the form tag
     *
     * @param mixed $form \WPCF7_ContactForm|null
     *
     * @return bool
     */
    private static function hasTag(mixed $form): bool
    {
        return $form instanceof \WPCF7_ContactForm && $form->scan_form_tags(['type' => [self::TAG]]) !== [];
    }

    /**
     * Names the sender typed, for the random names check
     *
     * @param mixed                $form   \WPCF7_ContactForm
     * @param array<string, mixed> $posted
     *
     * @return string[]
     */
    private function names(mixed $form, array $posted): array
    {
        if (! $form instanceof \WPCF7_ContactForm) {
            return [];
        }

        return self::pickNames($posted, self::types($form), self::setting($form, ['gecka_antispam_name', 'flamingo_name']));
    }

    /**
     * The names among the values posted: the text fields a template cites,
     * or, with no template, the text fields named as a name
     *
     * @param array<string, mixed>  $fields Posted values, by field name.
     * @param array<string, string> $types  Base type of each field of the form, by name.
     * @param string|null           $named  Mail tags naming the fields, from gecka_antispam_name or flamingo_name.
     *
     * @return string[]
     */
    public static function pickNames(array $fields, array $types, ?string $named): array
    {
        $candidates = $named !== null
            ? self::cited($named)
            : array_filter(array_keys($types), static fn(string $name): bool => (bool) preg_match(self::NAME_FIELD, $name));
        $names = [];

        foreach ($candidates as $name) {
            $value = $fields[$name] ?? null;

            if (($types[$name] ?? '') === 'text' && is_string($value) && trim($value) !== '') {
                $names[] = $value;
            }
        }

        return $names;
    }

    /**
     * Base type of each field of a form, by name
     *
     * @param \WPCF7_ContactForm $form
     *
     * @return array<string, string>
     */
    private static function types(\WPCF7_ContactForm $form): array
    {
        $types = [];

        foreach ($form->scan_form_tags() as $tag) {
            if ((string) $tag->name !== '') {
                $types[(string) $tag->name] = (string) $tag->basetype;
            }
        }

        return $types;
    }

    /**
     * The posted values Flamingo keeps: those of the fields marked
     * do-not-store are left out, as Contact Form 7 leaves them out of what it
     * hands Flamingo
     *
     * @param mixed                $form   \WPCF7_ContactForm.
     * @param array<string, mixed> $posted
     *
     * @return array<string, mixed>
     */
    private static function stored(mixed $form, array $posted): array
    {
        if (! $form instanceof \WPCF7_ContactForm) {
            return $posted;
        }

        foreach ($form->scan_form_tags(['feature' => 'do-not-store']) as $tag) {
            unset($posted[(string) $tag->name]);
        }

        return $posted;
    }

    /**
     * The form being rendered
     *
     * @return \WPCF7_ContactForm|null
     */
    private function currentForm(): ?\WPCF7_ContactForm
    {
        return class_exists('WPCF7_ContactForm') ? \WPCF7_ContactForm::get_current() : null;
    }
}
