<?php

declare(strict_types=1);

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

namespace Gecka\WP\Plugin\Antispam\Integrations;

use Gecka\WP\Plugin\Antispam\Guard;
use Gecka\WP\Plugin\Antispam\Request;

/**
 * The front-end forms of ACF, ACF Pro and Secure Custom Fields, printed by
 * acf_form(): every form, or the forms whose arguments hold
 * `'gecka_antispam' => true` only, as the settings say.
 *
 * The fields go after the fields of the form. The checks run on the form
 * submitted, as ACF rebuilds it from its registry or from the encrypted copy
 * the form posts: the marker cannot be added nor removed by the visitor. A
 * submission caught is refused with an error page, as ACF does with the
 * errors of its own checks.
 *
 * The statistical filter reads the subject and the message among the fields
 * the form shows, and the sub fields of its groups, repeaters and flexible
 * contents, every row: by default the title of the post, and its content
 * with the textarea and editor fields. The marker, given as an array, names them
 * instead: 'gecka_antispam' => ['subject' => ['post_title'], 'message' =>
 * ['post_content', 'description']], field names or keys. With no inbox to
 * send spam to, the filter refuses from the rejection threshold only, and
 * learns nothing from these forms. The random names check reads the text
 * fields the marker names under 'name', and nothing without it.
 *
 * @author Laurent Dinclaux - Gecka <laurent@gecka.nc>
 */
class Acf extends Integration
{
    /**
     * Argument of acf_form() marking a form to protect.
     */
    public const ARGUMENT = 'gecka_antispam';

    /**
     * Field types holding a message by default.
     */
    private const MESSAGE_TYPES = ['textarea', 'wysiwyg'];

    /**
     * Field types that can hold a subject.
     */
    private const SUBJECT_TYPES = ['text', 'textarea', 'select', 'radio', 'checkbox', 'button_group'];

    /**
     * Keys ACF gives the title and the content of the post, by the names the
     * marker uses for them.
     */
    private const POST_FIELDS = ['post_title' => '_post_title', 'post_content' => '_post_content'];

    /**
     * Types of the fields holding other fields: once for a group, row after
     * row for a repeater and a flexible content.
     */
    private const CONTAINER_TYPES = ['group', 'repeater', 'flexible_content'];

    /**
     * Whether ACF or Secure Custom Fields is active
     *
     * @return bool
     */
    public function available(): bool
    {
        return class_exists('ACF');
    }

    /**
     * Hooks the fields into acf_form() and the check into its validation.
     *
     * @return void
     */
    public function setup(): void
    {
        add_filter('acf/validate_form', [$this, 'render']);
        add_filter('acf/pre_submit_form', [$this, 'check']);
    }

    /**
     * Adds the fields after the fields of a protected form.
     *
     * @param mixed $args Arguments of the form.
     *
     * @return mixed
     */
    public function render(mixed $args): mixed
    {
        if (! is_array($args) || ! $this->protects($args)) {
            return $args;
        }

        $args['html_after_fields'] = (string) ($args['html_after_fields'] ?? '') . $this->fields('acf');

        return $args;
    }

    /**
     * Refuses a submission of a protected form that did not pass the checks.
     *
     * @param mixed $form Arguments of the form submitted.
     *
     * @return mixed
     */
    public function check(mixed $form): mixed
    {
        if (! is_array($form) || Request::isNonInteractive() || ! $this->protects($form)) {
            return $form;
        }

        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- ACF checked its nonce before submitting the form.
        $posted = (array) map_deep(wp_unslash($_POST['acf'] ?? []), 'sanitize_textarea_field');
        [$fields, $values] = self::expand(self::shownFields($form, $posted), $posted);
        $text = self::formText($fields, $values, $form[self::ARGUMENT] ?? null);

        if (Guard::refuses($this->verify('acf', self::formNames($fields, $values, $form[self::ARGUMENT] ?? null), $text !== '' ? $text : null))) {
            wp_die(esc_html($this->message()), esc_html__('Submission refused', 'gecka-antispam'), ['response' => 403, 'back_link' => true]);
        }

        return $form;
    }

    /**
     * The subject and the message among the fields a form shows, one value
     * per line, the subject first, each field once, without HTML. The marker
     * names them when it is an array; a part it leaves out keeps the
     * default: the title of the post for the subject, its content and the
     * textarea and editor fields for the message. A subject is a text,
     * textarea, select, radio, checkbox or button group field.
     *
     * @param array<string, array{name: string, type: string}> $fields The fields the form shows, by key.
     * @param array<mixed>                                     $posted Values by field key.
     * @param mixed                                            $marker The gecka_antispam argument of the form.
     *
     * @return string
     */
    public static function formText(array $fields, array $posted, mixed $marker): string
    {
        $marker = is_array($marker) ? $marker : [];
        $subjects = self::named($fields, $marker['subject'] ?? null)
            ?? (isset($fields['_post_title']) ? ['_post_title'] : []);
        $messages = self::named($fields, $marker['message'] ?? null)
            ?? array_keys(array_filter($fields, static fn(array $field, string $key): bool => $key !== '_post_title' && in_array($field['type'], self::MESSAGE_TYPES, true), ARRAY_FILTER_USE_BOTH));
        $subjects = array_filter($subjects, static fn(string $key): bool => in_array($fields[$key]['type'], self::SUBJECT_TYPES, true));
        $lines = [];

        foreach (array_unique([...$subjects, ...$messages]) as $key) {
            $value = trim(wp_strip_all_tags(self::flatten($posted[$key] ?? '')));

            if ($value !== '') {
                $lines[] = $value;
            }
        }

        return implode("\n", $lines);
    }

    /**
     * Names typed in a form, for the random names check: the text fields the
     * marker names under 'name', by name or by key; none without it
     *
     * @param array<string, array{name: string, type: string}> $fields The fields the form shows, by key.
     * @param array<mixed>                                     $posted Values by field key.
     * @param mixed                                            $marker The gecka_antispam argument of the form.
     *
     * @return string[]
     */
    public static function formNames(array $fields, array $posted, mixed $marker): array
    {
        $names = [];

        foreach (self::named($fields, is_array($marker) ? ($marker['name'] ?? null) : null) ?? [] as $key) {
            $value = trim(self::flatten($posted[$key] ?? ''));

            if ($fields[$key]['type'] === 'text' && $value !== '') {
                $names[] = $value;
            }
        }

        return $names;
    }

    /**
     * Keys of the fields a part of the marker names, by name or by key,
     * post_title and post_content standing for the title and the content of
     * the post; null when the marker leaves the part out
     *
     * @param array<string, array{name: string, type: string}> $fields
     * @param mixed                                            $selectors
     *
     * @return string[]|null
     */
    private static function named(array $fields, mixed $selectors): ?array
    {
        if (! is_array($selectors) && ! is_string($selectors)) {
            return null;
        }

        $keys = [];

        foreach ((array) $selectors as $selector) {
            $selector = self::POST_FIELDS[(string) $selector] ?? (string) $selector;

            foreach ($fields as $key => $field) {
                if ($key === $selector || $field['name'] === $selector) {
                    $keys[] = $key;
                }
            }
        }

        return $keys;
    }

    /**
     * The fields a form shows, by key, as ACF lists them for the save; with
     * an ACF too old to list them, the fields posted that exist
     *
     * @param array<string, mixed> $form
     * @param array<mixed>         $posted
     *
     * @return array<string, array{key: string, name: string, type: string, sub_fields: array<mixed>}>
     */
    private static function shownFields(array $form, array $posted): array
    {
        $front = function_exists('acf') ? (acf()->form_front ?? null) : null;
        $keys = is_object($front) && method_exists($front, 'get_allowed_field_keys')
            ? (array) $front->get_allowed_field_keys($form)
            : array_keys($posted);
        $fields = [];

        foreach ($keys as $key) {
            $key = (string) $key;
            $field = in_array($key, self::POST_FIELDS, true)
                ? ['key' => $key, 'name' => $key, 'type' => $key === '_post_title' ? 'text' : 'wysiwyg']
                : (function_exists('acf_get_field') ? acf_get_field($key) : null);

            if (is_array($field)) {
                $fields[$key] = self::described($field + ['key' => $key]);
            }
        }

        return $fields;
    }

    /**
     * A field as the filter reads it: key, name, type, and the fields it
     * holds, read from ACF for a group, a repeater or a flexible content
     *
     * @param array<mixed> $field Field of ACF.
     *
     * @return array{key: string, name: string, type: string, sub_fields: array<mixed>}
     */
    private static function described(array $field): array
    {
        $subFields = in_array($field['type'] ?? '', self::CONTAINER_TYPES, true) && function_exists('acf_get_fields') ? (array) acf_get_fields($field) : [];

        return [
            'key' => (string) ($field['key'] ?? ''),
            'name' => (string) ($field['name'] ?? $field['key'] ?? ''),
            'type' => (string) ($field['type'] ?? ''),
            'sub_fields' => array_map([self::class, 'described'], array_filter($subFields, 'is_array')),
        ];
    }

    /**
     * The fields and the values posted, the groups, repeaters and flexible
     * contents replaced by their sub fields, a sub field holding its values
     * of every row joined
     *
     * @param array<string, array{name: string, type: string, sub_fields?: array<mixed>}> $fields By key.
     * @param array<string, mixed>                                                       $posted Values posted, by key.
     *
     * @return array{0: array<string, array{name: string, type: string}>, 1: array<string, mixed>}
     */
    public static function expand(array $fields, array $posted): array
    {
        $flat = [];
        $values = [];

        foreach ($fields as $key => $field) {
            self::gather((string) $key, $field, $posted[$key] ?? null, $flat, $values);
        }

        return [$flat, $values];
    }

    /**
     * Adds a field and its value, or the sub fields of a field holding
     * others with their value in each row.
     *
     * @param string                                                   $key
     * @param array{name: string, type: string, sub_fields?: array<mixed>} $field
     * @param mixed                                                    $value  Null when none was posted.
     * @param array<string, array{name: string, type: string}>         $fields
     * @param array<string, mixed>                                     $values
     *
     * @return void
     */
    private static function gather(string $key, array $field, mixed $value, array &$fields, array &$values): void
    {
        $subFields = array_filter((array) ($field['sub_fields'] ?? []), static fn(mixed $sub): bool => is_array($sub) && (string) ($sub['key'] ?? '') !== '');

        if (! in_array($field['type'], self::CONTAINER_TYPES, true) || ! $subFields) {
            $fields[$key] = ['name' => $field['name'], 'type' => $field['type']];

            if ($value !== null) {
                $values[$key] = isset($values[$key]) ? self::flatten($values[$key]) . ' ' . self::flatten($value) : $value;
            }

            return;
        }

        $rows = $field['type'] === 'group' ? [$value] : array_values(is_array($value) ? $value : []);

        foreach ($subFields as $sub) {
            $subKey = (string) $sub['key'];
            $subField = ['name' => (string) ($sub['name'] ?? $subKey), 'type' => (string) ($sub['type'] ?? ''), 'sub_fields' => (array) ($sub['sub_fields'] ?? [])];
            self::gather($subKey, $subField, null, $fields, $values);

            foreach ($rows as $row) {
                if (is_array($row) && array_key_exists($subKey, $row)) {
                    self::gather($subKey, $subField, $row[$subKey], $fields, $values);
                }
            }
        }
    }

    /**
     * Whether a form is to be protected
     *
     * @param array<string, mixed> $form
     *
     * @return bool
     */
    private function protects(array $form): bool
    {
        return $this->plugin->settings()->protects('acf', ! empty($form[self::ARGUMENT]));
    }
}
