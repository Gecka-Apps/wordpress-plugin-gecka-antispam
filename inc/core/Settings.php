<?php

declare(strict_types=1);

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

namespace Gecka\WP\Plugin\Antispam;

/**
 * The settings of the plugin, held in one option, and the forms it protects.
 *
 * @author Laurent Dinclaux - Gecka <laurent@gecka.nc>
 */
class Settings
{
    /**
     * Option holding every setting.
     */
    public const OPTION = 'gecka_antispam_settings';

    /**
     * Forms whose submission is a sign-in rather than something typed: a
     * password manager fills and submits them in a blink.
     */
    public const SIGN_IN_SURFACES = ['login', 'lost_password', 'woocommerce_login', 'woocommerce_lost_password'];

    /**
     * Forms of plugins letting a form carry a marker: they protect either
     * every form, or the forms holding the marker only.
     */
    public const MARKED_SURFACES = ['contact_form_7', 'gravity_forms', 'acf'];

    /**
     * Prefix of the forms a developer protects with gecka_antispam_fields()
     * and gecka_antispam_check(), followed by the name given to the form.
     */
    public const CUSTOM_PREFIX = 'custom:';

    /**
     * Characters the name of a form may take: the width of its column in
     * the tables.
     */
    public const SURFACE_LENGTH = 40;

    /**
     * Every form of the plugin is protected.
     */
    public const MODE_ALL = 'all';

    /**
     * Only the forms holding the marker are protected.
     */
    public const MODE_MARKED = 'marked';

    /**
     * Value of the settings form for a plugin whose forms are not protected.
     */
    public const MODE_OFF = 'off';

    /**
     * Lowest and highest value of each number setting.
     */
    public const BOUNDS = [
        'min_delay' => [0, 60],
        'sign_in_min_delay' => [0, 60],
        'max_age' => [0, 720],
        'min_words' => [0, 100],
        'filter_reject' => [51, 100],
        'filter_threshold' => [51, 100],
        'filter_review' => [51, 100],
        'filter_min_spam' => [1, 1000],
        'filter_min_ham' => [1, 1000],
        'filter_rotation' => [1, 60],
        'stats_days' => [30, 3650],
    ];

    /**
     * Settings each form of the settings page posts, by the value of its form
     * field. A box of that form left unticked is not posted at all: it reads
     * as false for the settings of the form, and leaves the others as stored.
     */
    public const SECTIONS = [
        'general' => ['surfaces', 'honeypot_name', 'min_delay', 'sign_in_min_delay', 'max_age', 'random_names', 'min_words', 'stats_days'],
        'filter' => ['filter', 'filter_reject', 'filter_threshold', 'filter_review', 'filter_min_spam', 'filter_min_ham', 'filter_rotation', 'learn_approved'],
        'backgrounds' => ['background_languages'],
    ];

    /**
     * Names a form of WordPress or of a form plugin already posts, which the
     * honeypot must not take.
     */
    private const TAKEN_NAMES = [
        'author', 'comment', 'email', 'url', 'name', 'log', 'pwd', 'user_login', 'user_email', 'username',
        'password', 'website', 'phone', 'company', 'address', 'subject', 'message', 'first_name', 'last_name',
        'action', 'page', 'post', 'redirect_to', 'rememberme', 'testcookie', 's', 'p', 'cat', 'tag', 'm', 'paged',
        'register', 'login', 'submit',
    ];

    /**
     * Words the honeypot name is made of: a field a bot would fill in, and that
     * no browser autofills.
     */
    private const DECOY_WORDS = ['homepage', 'fax', 'nickname', 'job_title', 'referral', 'extension'];

    /**
     * Settings read, kept for the request.
     *
     * @var array<string, mixed>|null
     */
    private ?array $settings = null;

    /**
     * Every form the plugin knows of, in the order of groups(): the
     * identifiers alone, which the defaults and the sanitizing read on every
     * request, where the labels are not needed.
     */
    public const SURFACES = [
        'comments', 'login', 'registration', 'lost_password',
        'woocommerce_checkout', 'woocommerce_reviews', 'woocommerce_login', 'woocommerce_registration', 'woocommerce_lost_password',
        'contact_form_7', 'gravity_forms', 'acf',
    ];

    /**
     * The forms the plugin protects, by integration, with their labels
     *
     * @return array<string, array{label: string, surfaces: array<string, string>}>
     */
    public static function groups(): array
    {
        return [
            'wordpress' => [
                'label' => __('WordPress', 'gecka-antispam'),
                'surfaces' => [
                    'comments' => __('Comments', 'gecka-antispam'),
                    'login' => __('Login', 'gecka-antispam'),
                    'registration' => __('Registration', 'gecka-antispam'),
                    'lost_password' => __('Lost password', 'gecka-antispam'),
                ],
            ],
            'woocommerce' => [
                'label' => 'WooCommerce',
                'surfaces' => [
                    'woocommerce_checkout' => __('Checkout', 'gecka-antispam'),
                    'woocommerce_reviews' => __('Product reviews', 'gecka-antispam'),
                    'woocommerce_login' => __('My account: login', 'gecka-antispam'),
                    'woocommerce_registration' => __('My account: registration', 'gecka-antispam'),
                    'woocommerce_lost_password' => __('My account: lost password', 'gecka-antispam'),
                ],
            ],
            'contact_form_7' => [
                'label' => 'Contact Form 7',
                'surfaces' => [
                    'contact_form_7' => __('Forms', 'gecka-antispam'),
                ],
            ],
            'gravity_forms' => [
                'label' => 'Gravity Forms',
                'surfaces' => [
                    'gravity_forms' => __('Forms', 'gecka-antispam'),
                ],
            ],
            'acf' => [
                'label' => 'ACF / Secure Custom Fields',
                'surfaces' => [
                    'acf' => __('Front-end forms', 'gecka-antispam'),
                ],
            ],
        ];
    }

    /**
     * Name of a form, with the name of its integration when it needs one
     *
     * @param string $surface
     *
     * @return string
     */
    public static function surfaceLabel(string $surface): string
    {
        if (str_starts_with($surface, self::CUSTOM_PREFIX)) {
            /* translators: %s: name a developer gave the form */
            return sprintf(__('Custom form: %s', 'gecka-antispam'), substr($surface, strlen(self::CUSTOM_PREFIX)));
        }

        foreach (self::groups() as $id => $group) {
            if (isset($group['surfaces'][$surface])) {
                return $id === 'wordpress'
                    ? $group['surfaces'][$surface]
                    /* translators: 1: plugin providing the form, 2: the form */
                    : sprintf(__('%1$s: %2$s', 'gecka-antispam'), $group['label'], $group['surfaces'][$surface]);
            }
        }

        return $surface;
    }

    /**
     * The form a developer named, as the statistics and the journal record
     * it: the name as a key, cut to fit their column
     *
     * @param string $form
     *
     * @return string
     */
    public static function customSurface(string $form): string
    {
        return self::CUSTOM_PREFIX . (substr(sanitize_key($form), 0, self::SURFACE_LENGTH - strlen(self::CUSTOM_PREFIX)) ?: 'form');
    }

    /**
     * Every form the plugin knows of
     *
     * @return string[]
     */
    public static function surfaces(): array
    {
        return self::SURFACES;
    }

    /**
     * Default values
     *
     * @return array<string, mixed>
     */
    public function defaults(): array
    {
        return [
            'surfaces' => array_fill_keys(self::surfaces(), true),
            'modes' => array_fill_keys(self::MARKED_SURFACES, self::MODE_ALL),

            'honeypot_name' => '',
            'min_delay' => 5,
            'sign_in_min_delay' => 0,
            'max_age' => 192,
            'random_names' => true,
            'min_words' => 0,
            'filter' => true,
            'filter_reject' => 95,
            'filter_threshold' => 75,
            'filter_review' => 55,
            'filter_min_spam' => 20,
            'filter_min_ham' => 10,
            'filter_rotation' => 6,
            'background_languages' => [],

            'learn_approved' => true,
            'stats_days' => 365,
        ];
    }

    /**
     * Every setting, the defaults filling the gaps
     *
     * @return array<string, mixed>
     */
    public function all(): array
    {
        if ($this->settings === null) {
            $settings = $this->stored();

            // The honeypot name is drawn when the plugin is set up; a site
            // whose settings lost it gets one here, the first time it is
            // needed. Saving it runs sanitize() and flushes the settings, so
            // they are kept once saved.
            if (! $settings['honeypot_name']) {
                $settings['honeypot_name'] = self::randomFieldName();
                update_option(self::OPTION, array_merge((array) get_option(self::OPTION, []), ['honeypot_name' => $settings['honeypot_name']]));
            }

            $this->settings = $settings;
        }

        return $this->settings;
    }

    /**
     * The settings saved, the defaults filling the gaps, nothing drawn
     *
     * @return array<string, mixed>
     */
    private function stored(): array
    {
        $saved = (array) get_option(self::OPTION, []);
        $defaults = $this->defaults();

        $settings = array_merge($defaults, array_intersect_key($saved, $defaults));
        $settings['surfaces'] = array_merge($defaults['surfaces'], (array) ($saved['surfaces'] ?? []));
        $settings['modes'] = array_merge($defaults['modes'], (array) ($saved['modes'] ?? []));

        return $settings;
    }

    /**
     * One setting
     *
     * @param string $key
     *
     * @return mixed
     */
    public function get(string $key): mixed
    {
        return $this->all()[$key] ?? null;
    }

    /**
     * Whether a form is protected
     *
     * @param string $surface
     *
     * @return bool
     */
    public function enabled(string $surface): bool
    {
        $enabled = str_starts_with($surface, self::CUSTOM_PREFIX) || ! empty($this->all()['surfaces'][$surface]);

        /**
         * Filters whether a form is protected.
         *
         * @param bool   $enabled Whether the form is ticked in the settings, always for a custom form.
         * @param string $surface The form: comments, login, contact_form_7, custom:{name}...
         */
        return (bool) apply_filters('gecka_antispam_protect', $enabled, $surface);
    }

    /**
     * Whether a form of a plugin letting forms carry a marker is protected
     *
     * @param string $surface One of MARKED_SURFACES.
     * @param bool   $marked  Whether the form holds the marker.
     *
     * @return bool
     */
    public function protects(string $surface, bool $marked): bool
    {
        return $this->enabled($surface) && ($marked || $this->mode($surface) === self::MODE_ALL);
    }

    /**
     * Whether a plugin protects every form or the marked ones only
     *
     * @param string $surface One of MARKED_SURFACES.
     *
     * @return string self::MODE_ALL or self::MODE_MARKED.
     */
    public function mode(string $surface): string
    {
        return ($this->all()['modes'][$surface] ?? '') === self::MODE_MARKED ? self::MODE_MARKED : self::MODE_ALL;
    }

    /**
     * Seconds a form must stay on screen before it is sent
     *
     * @param string $surface
     *
     * @return int
     */
    public function minDelay(string $surface): int
    {
        $key = in_array($surface, self::SIGN_IN_SURFACES, true) ? 'sign_in_min_delay' : 'min_delay';

        return (int) $this->get($key);
    }

    /**
     * Puts every setting back to its default, but the name of the honeypot:
     * the forms already shown, or kept in a page cache, carry that name.
     *
     * @return void
     */
    public function reset(): void
    {
        $name = (string) $this->get('honeypot_name');

        delete_option(self::OPTION);
        $this->flush();
        update_option(self::OPTION, ['honeypot_name' => $name]);
        $this->flush();
    }

    /**
     * Forgets the settings read, once they were saved.
     *
     * @return void
     */
    public function flush(): void
    {
        $this->settings = null;
    }

    /**
     * Cleans the settings before they are saved.
     *
     * A form of the settings page posts every field it shows, a box left
     * unticked being absent, along with its `form` field naming its section
     * of SECTIONS. Any other write only holds the keys it changes, the others
     * keep their value.
     *
     * @param mixed $input
     *
     * @return array<string, mixed>
     */
    public function sanitize(mixed $input): array
    {
        $input = is_array($input) ? $input : [];
        $posted = self::SECTIONS[(string) ($input['form'] ?? '')] ?? [];
        $surfacesPosted = in_array('surfaces', $posted, true);
        $current = $this->stored();

        $flag = static fn(string $key): bool => in_array($key, $posted, true) ? ! empty($input[$key]) : (bool) ($input[$key] ?? $current[$key]);
        $number = static fn(string $key): int => self::clamp($input[$key] ?? $current[$key], ...self::BOUNDS[$key]);

        $surfaces = [];

        foreach (self::surfaces() as $surface) {
            $surfaces[$surface] = $surfacesPosted
                ? ! empty($input['surfaces'][$surface])
                : (bool) ($input['surfaces'][$surface] ?? $current['surfaces'][$surface]);
        }

        $modes = [];

        // The settings page posts one choice per plugin with a marker: off,
        // every form, or the marked ones.
        foreach (self::MARKED_SURFACES as $surface) {
            $choice = (string) ($input['modes'][$surface] ?? $current['modes'][$surface]);

            if ($surfacesPosted) {
                $surfaces[$surface] = $choice !== self::MODE_OFF;
            }

            $modes[$surface] = $choice === self::MODE_MARKED ? self::MODE_MARKED : ($choice === self::MODE_OFF ? (string) $current['modes'][$surface] : self::MODE_ALL);
        }

        $name = strtolower(trim((string) ($input['honeypot_name'] ?? '')));

        if (! self::isValidFieldName($name)) {
            if ($name !== '') {
                add_settings_error(
                    self::OPTION,
                    'honeypot_name',
                    __('The honeypot field name must start with a letter, hold 3 to 40 lowercase letters, digits or underscores, and not be a name a form already uses. The previous name is kept.', 'gecka-antispam'),
                );
            }

            $name = (string) $current['honeypot_name'];
        }

        $reject = $number('filter_reject');
        $threshold = min($number('filter_threshold'), $reject);

        return [
            'surfaces' => $surfaces,
            'modes' => $modes,

            'honeypot_name' => $name,
            'min_delay' => $number('min_delay'),
            'sign_in_min_delay' => $number('sign_in_min_delay'),
            'max_age' => $number('max_age'),
            'random_names' => $flag('random_names'),
            'min_words' => $number('min_words'),
            'filter' => $flag('filter'),
            'filter_reject' => $reject,
            'filter_threshold' => $threshold,
            'filter_review' => min($number('filter_review'), $threshold),
            'filter_min_spam' => $number('filter_min_spam'),
            'filter_min_ham' => $number('filter_min_ham'),
            'filter_rotation' => $number('filter_rotation'),
            'background_languages' => self::languageCodes($input['background_languages'] ?? $current['background_languages']),

            'learn_approved' => $flag('learn_approved'),
            'stats_days' => $number('stats_days'),
        ];
    }

    /**
     * Language codes of a setting, written as a list separated by commas or
     * spaces: the valid ones, each once, StatisticalFilter::MAX_LANGUAGES at
     * most
     *
     * @param mixed $value A string, or a list.
     *
     * @return string[]
     */
    public static function languageCodes(mixed $value): array
    {
        $codes = is_array($value) ? $value : preg_split('/[\s,;]+/', (string) $value);
        $codes = array_map(static fn(mixed $code): string => strtolower(trim((string) $code)), $codes ?: []);
        $codes = array_filter($codes, static fn(string $code): bool => (bool) preg_match(StatisticalFilter::LANGUAGE_CODE, $code));

        return array_slice(array_values(array_unique($codes)), 0, StatisticalFilter::MAX_LANGUAGES);
    }

    /**
     * Whether a name can be given to the honeypot field
     *
     * @param string $name
     *
     * @return bool
     */
    public static function isValidFieldName(string $name): bool
    {
        return (bool) preg_match('/^[a-z][a-z0-9_]{2,39}$/', $name)
            && ! in_array($name, self::TAKEN_NAMES, true)
            && ! str_starts_with($name, 'wp');
    }

    /**
     * A name for the honeypot field, different on each site
     *
     * @return string
     */
    public static function randomFieldName(): string
    {
        return self::DECOY_WORDS[array_rand(self::DECOY_WORDS)] . '_' . strtolower(wp_generate_password(4, false));
    }

    /**
     * An integer kept within bounds
     *
     * @param mixed $value
     * @param int   $min
     * @param int   $max
     *
     * @return int
     */
    private static function clamp(mixed $value, int $min, int $max): int
    {
        return max($min, min($max, (int) $value));
    }
}
