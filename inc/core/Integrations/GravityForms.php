<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

namespace Gecka\WP\Plugin\Antispam\Integrations;

use Gecka\WP\Plugin\Antispam\Guard;
use Gecka\WP\Plugin\Antispam\Integrations\GravityForms\AntispamField;
use Gecka\WP\Plugin\Antispam\Plugin;
use Gecka\WP\Plugin\Antispam\Request;
use Gecka\WP\Plugin\Antispam\StatisticalFilter;

/**
 * Gravity Forms forms, and the spam of their entries: every form, or the
 * forms holding the Antispam field only, as the settings say.
 *
 * The Antispam field prints the fields where it stands; a form protected
 * without it gets them before its submit button, on its last page. The
 * checks run when the last page is validated, before any entry exists. A
 * submission refused fails the validation with an error, and no entry is
 * saved; one the statistical filter marks as spam is saved as spam; one it
 * finds doubtful is saved as usual, with a note saying so. Marking an entry
 * as spam, or as not spam, teaches the statistical filter, as does the bulk
 * action confirming active entries as legitimate; the entries already saved
 * can be learnt in one go.
 *
 * @author Laurent Dinclaux - Gecka <laurent@gecka.nc>
 */
class GravityForms extends Integration implements Learner
{
    /**
     * Entry meta holding what the filter learnt an entry as.
     */
    public const META_TRAINED = 'gecka_antispam_trained';

    /**
     * Entry meta holding the generation of the statistical filter an entry
     * was learnt in.
     */
    public const META_GENERATION = 'gecka_antispam_generation';

    /**
     * Entry meta holding what caught an entry.
     */
    public const META_REASON = 'gecka_antispam_reason';

    /**
     * CSS class of the fields holding the subject, over what the
     * notifications cite.
     */
    public const SUBJECT_CLASS = 'gecka-antispam-subject';

    /**
     * CSS class of the fields holding the message, over the field types.
     */
    public const MESSAGE_CLASS = 'gecka-antispam-message';

    /**
     * CSS class of the fields holding a name, for the random names check,
     * over the Name fields.
     */
    public const NAME_CLASS = 'gecka-antispam-name';

    /**
     * Field types that can hold a name.
     */
    private const NAME_TYPES = ['text', 'name'];

    /**
     * Field types holding a message.
     */
    private const MESSAGE_TYPES = ['textarea', 'post_title', 'post_content', 'post_excerpt'];

    /**
     * Field types that can hold a subject.
     */
    private const SUBJECT_TYPES = ['text', 'select', 'radio', 'checkbox'];

    /**
     * What caught the entry being saved, or Guard::REVIEW for an entry the
     * filter finds doubtful.
     *
     * @var string|null
     */
    private ?string $outcome = null;

    /**
     * Form whose submission the checks ran on, in this request.
     *
     * @var int
     */
    private int $checked = 0;

    /**
     * Note to add to the entry being saved.
     *
     * @var string
     */
    private string $note = '';

    /**
     * Tables of the entries found, by table prefix, for the request.
     *
     * @var array<string, array{0: string, 1: string}>
     */
    private static array $tables = [];

    /**
     * @return bool
     */
    public function available(): bool
    {
        return class_exists('GFForms');
    }

    /**
     * @return void
     */
    public function setup(): void
    {
        if (did_action('gform_loaded')) {
            $this->registerField();
        } else {
            add_action('gform_loaded', [$this, 'registerField'], 5);
        }

        add_filter('gform_submit_button', [$this, 'render'], 10, 2);
        add_filter('gform_validation', [$this, 'validate'], self::PRIORITY, 2);
        add_filter('gform_entry_is_spam', [$this, 'check'], self::PRIORITY, 3);
        add_action('gform_entry_created', [$this, 'annotate']);
        add_action('gform_update_status', [$this, 'learn'], 10, 3);
        add_filter('gform_entry_list_bulk_actions', [$this, 'bulkActions'], 10, 2);
        add_action('gform_entry_list_action', [$this, 'listAction'], 10, 3);
    }

    /**
     * Adds the action confirming entries as legitimate, outside the spam and
     * the trash.
     *
     * @param mixed $actions
     * @param mixed $formId
     *
     * @return mixed
     */
    public function bulkActions(mixed $actions, mixed $formId = 0): mixed
    {
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Only picks the view.
        $filter = sanitize_key($_GET['filter'] ?? '');

        if (! is_array($actions) || in_array($filter, ['spam', 'trash'], true) || ! $this->plugin->settings()->get('filter')) {
            return $actions;
        }

        $actions[Flamingo::HAM_ACTION] = __('Learn as legitimate', 'gecka-antispam');

        return $actions;
    }

    /**
     * Confirms the entries chosen as legitimate, once Gravity Forms checked
     * the request, and says how many were learnt.
     *
     * @param mixed $action
     * @param mixed $entries Entry ids.
     * @param mixed $formId
     *
     * @return void
     */
    public function listAction(mixed $action, mixed $entries, mixed $formId = 0): void
    {
        if ($action !== Flamingo::HAM_ACTION) {
            return;
        }

        $learnt = 0;

        foreach (array_map('absint', (array) $entries) as $entryId) {
            $learnt += $this->confirmLegitimate($entryId) !== null ? 1 : 0;
        }

        printf(
            '<div class="alert success"><p>%s</p></div>',
            /* translators: %s: number of Gravity Forms entries */
            esc_html(sprintf(_nx('%s entry learnt as legitimate.', '%s entries learnt as legitimate.', $learnt, 'Gravity Forms entries', 'gecka-antispam'), number_format_i18n($learnt))),
        );
    }

    /**
     * Confirms an active entry as legitimate: the filter learns it as ham,
     * moving it from spam when it was learnt as such.
     *
     * @param int $entryId
     *
     * @return int|null The generation it is learnt in, null when it was not.
     */
    public function confirmLegitimate(int $entryId): ?int
    {
        if (! class_exists('GFAPI') || ! function_exists('gform_get_meta') || ! self::byModerator(\GFCommon::current_user_can_any('gravityforms_edit_entries'))) {
            return null;
        }

        $entry = \GFAPI::get_entry($entryId);

        if (is_wp_error($entry) || ($entry['status'] ?? '') !== 'active') {
            return null;
        }

        $previous = self::category(gform_get_meta($entryId, self::META_TRAINED));
        $generation = self::generation(gform_get_meta($entryId, self::META_GENERATION));

        if ($previous === StatisticalFilter::HAM) {
            return $generation ?? 0;
        }

        $generation = $this->train(self::entryText($entry), $previous, $generation, StatisticalFilter::HAM);

        if ($generation !== null) {
            gform_update_meta($entryId, self::META_TRAINED, StatisticalFilter::HAM);
            gform_update_meta($entryId, self::META_GENERATION, $generation);
        }

        return $generation;
    }

    /**
     * Adds the Antispam field to the editor.
     *
     * @return void
     */
    public function registerField(): void
    {
        if (class_exists('GF_Fields') && class_exists('GF_Field')) {
            \GF_Fields::register(new AntispamField());
        }
    }

    /**
     * Adds the fields before the submit button of a form protected without
     * holding the Antispam field.
     *
     * @param mixed $button
     * @param mixed $form
     *
     * @return mixed
     */
    public function render(mixed $button, mixed $form = []): mixed
    {
        if (! is_string($button) || ! is_array($form) || self::hasField($form) || ! $this->plugin->settings()->protects('gravity_forms', false)) {
            return $button;
        }

        return $this->fields('gravity_forms', Request::isFormPost('gform_submit')) . $button;
    }

    /**
     * Runs the checks on the last page of a form, the other fields valid,
     * before any entry exists. A submission refused fails the validation, with
     * the error of the plugin in place of the one of Gravity Forms. A
     * submission made by code, through GFAPI::submit_form() or the
     * submissions route of the REST API, comes without the fields: only its
     * text is rated.
     *
     * @param mixed $result  is_valid, form, failed_validation_page.
     * @param mixed $context form-submit, api-submit or api-validate.
     *
     * @return mixed
     */
    public function validate(mixed $result, mixed $context = 'form-submit'): mixed
    {
        $this->checked = 0;
        $this->outcome = null;
        $this->note = '';

        $form = is_array($result) ? ($result['form'] ?? null) : null;
        $rest = $context === 'api-submit' || self::isRestSubmission();

        if (! is_array($result)
            || empty($result['is_valid'])
            || ! is_array($form)
            || $context === 'api-validate'
            || ! ($rest || Request::isFormPost('gform_submit'))
            || ! self::isLastPage($form)
            || ! $this->plugin->settings()->protects('gravity_forms', self::hasField($form))
            || ! class_exists('GFFormsModel')
        ) {
            return $result;
        }

        $lead = \GFFormsModel::get_current_lead($form);
        $entry = is_array($lead) ? $lead : [];
        $outcome = $this->verify('gravity_forms', self::names($form, $entry), self::entryText($entry, $form), ! $rest);
        $this->checked = (int) $form['id'];
        $this->outcome = $this->review ? Guard::REVIEW : $outcome;
        $this->note = $this->review ? $this->reason(Guard::REVIEW) : '';

        if (Guard::refuses($outcome)) {
            $message = $this->message();

            add_filter(
                'gform_validation_message_' . $this->checked,
                static fn() => sprintf("<h2 class='gform_submission_error'>%s</h2>", esc_html($message)),
            );

            $result['is_valid'] = false;
        }

        return $result;
    }

    /**
     * Whether a submission ends the form, as Gravity Forms resolves it: the
     * target page posted, past the pages its conditional logic hides, a page
     * beyond the last one meaning the end.
     *
     * @param array<string, mixed> $form
     *
     * @return bool
     */
    private static function isLastPage(array $form): bool
    {
        if (class_exists('GFFormDisplay')) {
            return \GFFormDisplay::is_last_page($form);
        }

        return in_array(Request::post('gform_target_page_number_' . (int) ($form['id'] ?? 0)), ['', '0'], true);
    }

    /**
     * Saves as spam the entry the statistical filter marked as spam when its
     * form was validated.
     *
     * @param mixed $spam  Whether a check that ran before flagged it.
     * @param mixed $form
     * @param mixed $entry
     *
     * @return mixed
     */
    public function check(mixed $spam, mixed $form = [], mixed $entry = []): mixed
    {
        if ($spam || ! is_array($form) || (int) ($form['id'] ?? 0) !== $this->checked || $this->outcome !== Guard::FILTER_SPAM) {
            return $spam;
        }

        // Gravity Forms 2.7 and later show the reason next to the entry.
        if (method_exists('GFCommon', 'set_spam_filter')) { // @phpstan-ignore function.alreadyNarrowedType
            \GFCommon::set_spam_filter($this->checked, __('Antispam', 'gecka-antispam'), $this->reason(Guard::FILTER_SPAM));
        }

        return true;
    }
    /**
     * Records on the entry saved why the statistical filter marked it as
     * spam, or that it finds it doubtful.
     *
     * @param array<string, mixed> $entry
     *
     * @return void
     */
    public function annotate(array $entry): void
    {
        if ($this->outcome && (int) ($entry['form_id'] ?? 0) === $this->checked && ! empty($entry['id']) && function_exists('gform_update_meta')) {
            gform_update_meta((int) $entry['id'], self::META_REASON, $this->outcome);

            if ($this->note && method_exists('GFAPI', 'add_note')) { // @phpstan-ignore function.alreadyNarrowedType
                \GFAPI::add_note((int) $entry['id'], 0, __('Antispam', 'gecka-antispam'), __('To review.', 'gecka-antispam') . ' ' . $this->note, 'gecka-antispam', 'warning');
            }
        }

        $this->checked = 0;
        $this->outcome = null;
        $this->note = '';
    }

    /**
     * Spam or active entries not learnt yet, recent enough to be learnt
     *
     * @param string $category StatisticalFilter::SPAM or StatisticalFilter::HAM.
     *
     * @return int
     */
    public function pending(string $category): int
    {
        global $wpdb;

        [$entries, $meta] = self::tables();

        if (! $entries) {
            return 0;
        }

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Tables of Gravity Forms, read on demand from the statistics screen.
        return (int) $wpdb->get_var($wpdb->prepare('SELECT COUNT(*) FROM %i e LEFT JOIN %i m ON m.entry_id = e.id AND m.meta_key = %s WHERE e.status = %s AND e.date_created >= %s AND m.id IS NULL', $entries, $meta, self::META_TRAINED, self::status($category), $this->learningCutoff()));
    }

    /**
     * Learns the most recent spam or active entries not learnt yet.
     *
     * The entries are picked in the tables of Gravity Forms: GFAPI cannot
     * look for an entry lacking a meta.
     *
     * @param string $category StatisticalFilter::SPAM or StatisticalFilter::HAM.
     * @param int    $limit    Entries read at most.
     *
     * @return int Entries learnt.
     */
    public function learnExisting(string $category, int $limit): int
    {
        global $wpdb;

        [$entries, $meta] = self::tables();

        if (! $entries || ! class_exists('GFAPI') || ! function_exists('gform_get_meta')) {
            return 0;
        }

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Tables of Gravity Forms, read on demand from the statistics screen.
        $ids = $wpdb->get_col($wpdb->prepare('SELECT e.id FROM %i e LEFT JOIN %i m ON m.entry_id = e.id AND m.meta_key = %s WHERE e.status = %s AND e.date_created >= %s AND m.id IS NULL ORDER BY e.date_created DESC LIMIT %d', $entries, $meta, self::META_TRAINED, self::status($category), $this->learningCutoff(), $limit));
        $learnt = 0;

        foreach ((array) $ids as $id) {
            $entry = \GFAPI::get_entry((int) $id);
            $generation = null;

            if (! is_wp_error($entry)) {
                $outcome = (string) gform_get_meta((int) $id, self::META_REASON);
                $generation = $this->learnMarked(self::entryText($entry), $category, $outcome ?: null, (int) strtotime($entry['date_created'] . ' UTC'), self::judged((int) $id));
            }

            if ($generation === false) {
                break;
            }

            gform_update_meta((int) $id, self::META_TRAINED, $generation === null ? Plugin::TRAINED_SKIPPED : $category);

            if ($generation !== null) {
                gform_update_meta((int) $id, self::META_GENERATION, $generation);
                $learnt++;
            }
        }

        return $learnt;
    }

    /**
     * Status of the entries of a category
     *
     * @param string $category
     *
     * @return string
     */
    private static function status(string $category): string
    {
        return $category === StatisticalFilter::SPAM ? 'spam' : 'active';
    }

    /**
     * Whether a person, or Akismet, marked an entry as spam. A spam filter
     * of Gravity Forms leaves a note signed with its name and no user; a
     * person marking an entry leaves none.
     *
     * @param int $id
     *
     * @return bool
     */
    private static function judged(int $id): bool
    {
        $notes = method_exists('GFAPI', 'get_notes') ? \GFAPI::get_notes(['entry_id' => $id]) : []; // @phpstan-ignore function.alreadyNarrowedType

        foreach ((array) $notes as $note) {
            if (is_object($note) && (int) ($note->user_id ?? 0) === 0 && ($note->note_type ?? '') === 'user' && stripos((string) ($note->user_name ?? ''), 'akismet') === false) {
                return false;
            }
        }

        return true;
    }

    /**
     * Tables of the entries and of their meta, empty when Gravity Forms has
     * not created them
     *
     * @return array{0: string, 1: string}
     */
    private static function tables(): array
    {
        global $wpdb;

        if (isset(self::$tables[$wpdb->prefix])) {
            return self::$tables[$wpdb->prefix];
        }

        $entries = $wpdb->prefix . 'gf_entry';

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Checked once per request.
        if ($wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s', $wpdb->esc_like($entries))) !== $entries) {
            return ['', ''];
        }

        return self::$tables[$wpdb->prefix] = [$entries, $wpdb->prefix . 'gf_entry_meta'];
    }

    /**
     * Teaches the filter what an entry was marked as.
     *
     * @param mixed $entryId
     * @param mixed $new     New status.
     * @param mixed $old     Previous status.
     *
     * @return void
     */
    public function learn(mixed $entryId, mixed $new = '', mixed $old = ''): void
    {
        if (! is_numeric($entryId)) {
            return;
        }

        if ($new === 'spam' && $old !== 'spam') {
            $category = StatisticalFilter::SPAM;
        } elseif ($old === 'spam' && $new === 'active') {
            $category = StatisticalFilter::HAM;
        } else {
            return;
        }

        if (! class_exists('GFAPI') || ! function_exists('gform_get_meta') || ! self::byModerator(\GFCommon::current_user_can_any('gravityforms_edit_entries'))) {
            return;
        }

        $entry = \GFAPI::get_entry((int) $entryId);

        if (is_wp_error($entry)) {
            return;
        }

        $previous = self::category(gform_get_meta((int) $entryId, self::META_TRAINED));
        $generation = $this->train(self::entryText($entry), $previous, self::generation(gform_get_meta((int) $entryId, self::META_GENERATION)), $category);

        if ($generation !== null) {
            gform_update_meta((int) $entryId, self::META_TRAINED, $category);
            gform_update_meta((int) $entryId, self::META_GENERATION, $generation);
        }
    }

    /**
     * What the filter reads of an entry: the subject and the message, one
     * value per line, the subject first, each field once.
     *
     * The subject is the fields the subject of an active notification cites
     * as merge tags, the message every paragraph and post content field.
     * Fields carrying the CSS class SUBJECT_CLASS, or MESSAGE_CLASS, stand
     * for them when the form has some. A subject is a single line text, a
     * drop down, a radio or a checkbox field, and never a field a
     * notification takes its sender or its recipient from.
     *
     * @param array<string, mixed>      $entry
     * @param array<string, mixed>|null $form  The form of the entry, read when not given.
     *
     * @return string
     */
    public static function entryText(array $entry, ?array $form = null): string
    {
        if ($form === null && class_exists('GFAPI')) {
            $form = \GFAPI::get_form((int) ($entry['form_id'] ?? 0)) ?: null;
        }

        $fields = [];

        foreach ((array) ($form['fields'] ?? []) as $field) {
            $id = is_object($field) ? (int) ($field->id ?? 0) : 0;

            if ($id > 0) {
                $fields[$id] = $field;
            }
        }

        [$cited, $sender] = self::notified((array) ($form['notifications'] ?? []));
        $subjects = array_filter(
            self::marked($fields, self::SUBJECT_CLASS) ?: $cited,
            static fn(int $id): bool => isset($fields[$id]) && ! in_array($id, $sender, true) && in_array(self::type($fields[$id]), self::SUBJECT_TYPES, true),
        );
        $messages = self::marked($fields, self::MESSAGE_CLASS)
            ?: array_keys(array_filter($fields, static fn(object $field): bool => in_array(self::type($field), self::MESSAGE_TYPES, true)));
        $lines = [];

        foreach (array_unique([...$subjects, ...$messages]) as $id) {
            $value = self::value($fields[$id], $entry);

            if ($value !== '') {
                $lines[] = $value;
            }
        }

        return implode("\n", $lines);
    }

    /**
     * Fields the active notifications of a form cite in their subject, and
     * those they take their sender or their recipient from
     *
     * @param array<mixed> $notifications
     *
     * @return array{0: int[], 1: int[]}
     */
    private static function notified(array $notifications): array
    {
        $subject = [];
        $sender = [];

        foreach ($notifications as $notification) {
            if (! is_array($notification) || (isset($notification['isActive']) && ! $notification['isActive'])) {
                continue;
            }

            $subject = [...$subject, ...self::cited((string) ($notification['subject'] ?? ''))];
            $sender = [...$sender, ...self::cited(implode(' ', array_map(static fn(string $key): string => (string) ($notification[$key] ?? ''), ['fromName', 'from', 'replyTo', 'to', 'bcc'])))];

            if (($notification['toType'] ?? '') === 'field') {
                $sender[] = (int) ($notification['toField'] ?? 0);
            }
        }

        return [array_values(array_unique($subject)), array_values(array_unique($sender))];
    }

    /**
     * Ids of the fields a text cites as merge tags, {Label:3} or {:3.1}
     *
     * @param string $text
     *
     * @return int[]
     */
    private static function cited(string $text): array
    {
        preg_match_all('/{[^{}]*?:(\d+)(?:\.\w+)?(?::[^{}]*)?}/', $text, $matches);

        return array_values(array_unique(array_map('intval', $matches[1])));
    }

    /**
     * Ids of the fields carrying a CSS class
     *
     * @param array<int, object> $fields
     * @param string             $class
     *
     * @return int[]
     */
    private static function marked(array $fields, string $class): array
    {
        return array_keys(array_filter($fields, static fn(object $field): bool => in_array($class, preg_split('/\s+/', (string) ($field->cssClass ?? '')) ?: [], true)));
    }

    /**
     * Type of a field, its input type when it has one
     *
     * @param object $field
     *
     * @return string
     */
    private static function type(object $field): string
    {
        return (string) (($field->inputType ?? '') ?: ($field->type ?? ''));
    }

    /**
     * Value of a field in an entry, the inputs of a field holding several
     * joined, as are the choices of a multiple select, kept as JSON, and the
     * rows of a list, kept serialized
     *
     * @param object               $field
     * @param array<string, mixed> $entry
     *
     * @return string
     */
    private static function value(object $field, array $entry): string
    {
        $inputs = $field->inputs ?? null;

        if (! is_array($inputs) || $inputs === []) {
            $value = $entry[(string) ($field->id ?? '')] ?? '';
            $type = self::type($field);

            if (is_string($value) && in_array($type, ['multiselect', 'list'], true)) {
                $items = $type === 'list' ? maybe_unserialize($value) : json_decode($value, true);
                $value = is_array($items) ? array_merge(...array_map(static fn($item): array => array_values((array) $item), array_values($items))) : $value;
            }

            return self::flatten($value);
        }

        return self::flatten(array_map(static fn($input): mixed => $entry[(string) (is_array($input) ? ($input['id'] ?? '') : '')] ?? '', $inputs));
    }
    /**
     * Whether the request posts to the public submissions route of the REST
     * API of Gravity Forms, /gf/v2/forms/{id}/submissions
     *
     * @return bool
     */
    private static function isRestSubmission(): bool
    {
        $route = isset($GLOBALS['wp']) && $GLOBALS['wp'] instanceof \WP ? (string) ($GLOBALS['wp']->query_vars['rest_route'] ?? '') : '';

        return wp_is_serving_rest_request() && (bool) preg_match('#^/gf/v2/forms/\d+/submissions/?$#', $route);
    }

    /**
     * Whether a form holds the Antispam field
     *
     * @param array<string, mixed> $form
     *
     * @return bool
     */
    private static function hasField(array $form): bool
    {
        foreach ((array) ($form['fields'] ?? []) as $field) {
            if (is_object($field) && ($field->type ?? '') === AntispamField::TYPE) {
                return true;
            }
        }

        return false;
    }

    /**
     * Names typed in a form, for the random names check: the single line
     * text and Name fields carrying NAME_CLASS, or without any, the Name
     * fields; the first and last names of a Name field
     *
     * @param array<string, mixed> $form
     * @param array<string, mixed> $entry
     *
     * @return string[]
     */
    public static function names(array $form, array $entry): array
    {
        $fields = [];

        foreach ((array) ($form['fields'] ?? []) as $field) {
            $id = is_object($field) ? (int) ($field->id ?? 0) : 0;

            if ($id > 0 && in_array(self::type($field), self::NAME_TYPES, true)) {
                $fields[$id] = $field;
            }
        }

        $ids = self::marked($fields, self::NAME_CLASS)
            ?: array_keys(array_filter($fields, static fn(object $field): bool => self::type($field) === 'name'));
        $names = [];

        foreach ($ids as $id) {
            $keys = self::type($fields[$id]) === 'name' ? [$id . '.3', $id . '.6'] : [(string) $id];

            foreach ($keys as $key) {
                $value = $entry[$key] ?? '';

                if (is_string($value) && trim($value) !== '') {
                    $names[] = $value;
                }
            }
        }

        return $names;
    }
}
