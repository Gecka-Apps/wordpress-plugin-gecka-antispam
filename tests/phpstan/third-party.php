<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

/*
 * The classes and functions of Contact Form 7, Flamingo and Gravity Forms the
 * plugin calls, as PHPStan needs to know them. Read by PHPStan only.
 */

class WPCF7_ContactForm
{
    public static function get_current(): ?self {}

    /**
     * @return string[]|false
     */
    public function additional_setting(string $name, int $max = 1): array|false {}

    /**
     * @param array<string, mixed> $cond
     *
     * @return WPCF7_FormTag[]
     */
    public function scan_form_tags(array $cond = []): array {}

    public function pref(string $name): ?string {}

    public function prop(string $name): mixed {}
}

class WPCF7_FormTag
{
    public string $name = '';

    public string $basetype = '';
}

function wpcf7_contact_form(mixed $post): ?WPCF7_ContactForm {}

class WPCF7_Mail
{
    public function name(): string {}
}

class WPCF7_Submission
{
    public function get_contact_form(): WPCF7_ContactForm {}

    /**
     * @return array<string, mixed>
     */
    public function get_posted_data(string $name = ''): array {}

    /**
     * @param array<string, mixed> $data
     */
    public function add_spam_log(array $data = []): void {}
}

class Flamingo_Inbound_Message
{
    public const channel_taxonomy = 'flamingo_inbound_channel';

    /**
     * @var array<string, mixed>
     */
    public $fields = [];

    /**
     * @var string
     */
    public $channel = '';

    public function __construct(int $post = 0) {}
}

class GFForms {}

class GFFormDisplay
{
    /**
     * @param array<string, mixed> $form
     */
    public static function is_last_page(array $form, string $mode = 'submit'): bool {}
}

class GFFormsModel
{
    /**
     * @param array<string, mixed> $form
     *
     * @return array<string, mixed>|false
     */
    public static function get_current_lead(array $form = []): array|false {}
}

class GFCommon
{
    public static function set_spam_filter(int $form_id, string $name, string $reason): void {}

    /**
     * @param string|string[] $caps
     */
    public static function current_user_can_any(string|array $caps): bool {}
}

class GFAPI
{
    /**
     * @return array<string, mixed>|WP_Error
     */
    public static function get_entry(int $entry_id): array|WP_Error {}

    /**
     * @return array<string, mixed>|false
     */
    public static function get_form(int $form_id): array|false {}

    public static function add_note(int $entry_id, int $user_id, string $user_name, string $note, string $note_type = 'user', ?string $sub_type = null): int|WP_Error {}

    /**
     * @param array<string, mixed> $search_criteria
     *
     * @return object[]|false
     */
    public static function get_notes(array $search_criteria = [], ?array $sorting = null): array|false {}
}

function gform_get_meta(int $entry_id, string $meta_key): mixed {}

function gform_update_meta(int $entry_id, string $meta_key, mixed $meta_value): void {}

class GF_Field
{
    /**
     * @var int|string
     */
    public $id = 0;

    /**
     * @var string
     */
    public $type = '';

    /**
     * @return bool
     */
    public function is_form_editor() {}

    /**
     * @param bool       $force_frontend_label
     * @param int|string $value
     *
     * @return string
     */
    public function get_field_label($force_frontend_label = true, $value = '') {}
}

class GF_Fields
{
    public static function register(GF_Field $field): void {}
}
