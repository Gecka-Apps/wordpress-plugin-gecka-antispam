<?php

declare(strict_types=1);

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

namespace Gecka\WP\Plugin\Antispam\Admin;

use Gecka\WP\Plugin\Antispam\Plugin;

/**
 * The tabs of the Help of the settings page: what the filter reads of each
 * form, the rules finding the subject and the message of each integration
 * in the order they apply, and, on the statistical filter tab, the
 * background tables.
 *
 * @author Laurent Dinclaux - Gecka <laurent@gecka.nc>
 */
class Help
{
    /**
     * Id of the tab saying what the filter reads.
     */
    public const FIELDS = 'gecka-antispam-fields';

    /**
     * Id of the tab of the background tables.
     */
    public const BACKGROUNDS = 'gecka-antispam-backgrounds';

    /**
     * Adds the tabs of a tab of the settings page to the Help of the screen.
     *
     * @param Plugin     $plugin
     * @param \WP_Screen $screen
     * @param string     $tab    Tab of the settings page.
     *
     * @return void
     */
    public static function add(Plugin $plugin, \WP_Screen $screen, string $tab): void
    {
        if (! in_array($tab, ['settings', 'filter'], true)) {
            return;
        }

        $tabs = [self::FIELDS => [__('What the filter reads', 'gecka-antispam'), self::fields()]];

        if ($plugin->provides('contact_form_7')) {
            $tabs['gecka-antispam-contact-form-7'] = ['Contact Form 7', self::contactForm7()];
        }

        if ($plugin->provides('gravity_forms')) {
            $tabs['gecka-antispam-gravity-forms'] = ['Gravity Forms', self::gravityForms()];
        }

        if ($plugin->provides('acf')) {
            $tabs['gecka-antispam-acf'] = ['ACF / SCF', self::acf()];
        }

        $tabs['gecka-antispam-comments'] = [__('Comments and reviews', 'gecka-antispam'), self::comments()];
        $tabs['gecka-antispam-other-forms'] = [__('Other forms', 'gecka-antispam'), self::otherForms($plugin)];

        if ($tab === 'filter') {
            $tabs[self::BACKGROUNDS] = [__('Background tables', 'gecka-antispam'), FilterView::backgroundsHelp()];
        }

        foreach ($tabs as $id => [$title, $content]) {
            $screen->add_help_tab(['id' => $id, 'title' => $title, 'content' => $content]);
        }
    }

    /**
     * A link opening a tab of the Help, through the script of the shared
     * admin menu, which reads data-help-tab; its stylesheet draws the link as
     * a question mark. Its text is what screen readers announce, its title
     * the tooltip.
     *
     * @param string $id Id of the tab.
     *
     * @return string HTML.
     */
    public static function link(string $id): string
    {
        return sprintf(
            '<a href="#tab-panel-%1$s" class="gecka-admin-help-link" data-help-tab="%1$s" title="%2$s">%3$s</a>',
            esc_attr($id),
            esc_attr__('Learn more', 'gecka-antispam'),
            esc_html__('Learn more', 'gecka-antispam'),
        );
    }

    /**
     * What the checks and the filter read of a form
     *
     * @return string HTML.
     */
    private static function fields(): string
    {
        return self::paragraphs(
            [
                __('The checks of the forms, the honeypot, the signed timestamp and the delays, read no field. The random names check reads the names of the sender.', 'gecka-antispam'),
                __('The statistical filter reads the subject and the message of a submission, and nothing of the sender: no name, email address, phone number nor address. Each integration finds them by the structure of its forms, never by the names of the fields; the tabs beside give its rules, the first that applies winning. A field found twice is read once, the subject first.', 'gecka-antispam'),
            ],
        );
    }

    /**
     * The rules of Contact Form 7 and of its Flamingo messages
     *
     * @return string HTML.
     */
    private static function contactForm7(): string
    {
        return sprintf('<p><strong>%s</strong></p>', esc_html__('Subject, the first rule that applies:', 'gecka-antispam'))
            . self::steps(
                [
                    /* translators: 1: additional setting, 2: example */
                    self::code(__('the fields the additional setting %1$s of the form cites as mail tags, for instance %2$s;', 'gecka-antispam'), 'gecka_antispam_subject', 'gecka_antispam_subject: "[text-735]"'),
                    /* translators: %s: additional setting */
                    self::code(__('the fields the additional setting %s cites, the subject Flamingo keeps;', 'gecka-antispam'), 'flamingo_subject'),
                    esc_html__('the fields the subject of the Mail tab cites.', 'gecka-antispam'),
                ],
            )
            /* translators: 1, 2: additional settings, 3, 4: mail tags */
            . '<p>' . self::code(__('Only text, textarea, drop-down menu, radio button and checkbox fields count as the subject. The fields of the sender never do: those %1$s and %2$s cite, or %3$s and %4$s without them.', 'gecka-antispam'), 'flamingo_name', 'flamingo_email', '[your-name]', '[your-email]') . '</p>'
            . sprintf('<p><strong>%s</strong></p>', esc_html__('Message, the first rule that applies:', 'gecka-antispam'))
            . self::steps(
                [
                    /* translators: 1: additional setting, 2: example */
                    self::code(__('the fields the additional setting %1$s cites, as many as needed, of any type, for instance %2$s;', 'gecka-antispam'), 'gecka_antispam_message', 'gecka_antispam_message: "[textarea-120] [text-9]"'),
                    esc_html__('every textarea field of the form.', 'gecka-antispam'),
                ],
            )
            /* translators: %s: form tag option */
            . '<p>' . self::code(__('A field marked %s is never read. A Flamingo message is read by the same rules, through the form it came from; once that form is deleted, by the names of its fields.', 'gecka-antispam'), 'do-not-store') . '</p>'
            . sprintf('<p><strong>%s</strong></p>', esc_html__('Random names, the first rule that applies:', 'gecka-antispam'))
            . self::steps(
                [
                    /* translators: 1: additional setting, 2: example */
                    self::code(__('the text fields the additional setting %1$s cites, for instance %2$s;', 'gecka-antispam'), 'gecka_antispam_name', 'gecka_antispam_name: "[text-12] [text-13]"'),
                    /* translators: %s: additional setting */
                    self::code(__('the text fields the additional setting %s cites;', 'gecka-antispam'), 'flamingo_name'),
                    /* translators: 1, 2, 3, 4: field names */
                    self::code(__('the text fields named as a name, %1$s, %2$s, %3$s, %4$s and the like.', 'gecka-antispam'), 'your-name', 'first-name', 'nom', 'votre-prenom'),
                ],
            );
    }

    /**
     * The rules of Gravity Forms
     *
     * @return string HTML.
     */
    private static function gravityForms(): string
    {
        return sprintf('<p><strong>%s</strong></p>', esc_html__('Subject, the first rule that applies:', 'gecka-antispam'))
            . self::steps(
                [
                    /* translators: %s: CSS class */
                    self::code(__('the fields carrying the CSS class %s, set under Appearance in the form editor;', 'gecka-antispam'), 'gecka-antispam-subject'),
                    /* translators: %s: merge tag */
                    self::code(__('the fields the subject of an active notification cites as merge tags, such as %s.', 'gecka-antispam'), '{Subject:3}'),
                ],
            )
            /* translators: %s: subject of the default notification */
            . '<p>' . self::code(__('Only single line text, drop down, radio button and checkbox fields count as the subject, and never a field a notification takes its sender or recipient from: From Name, From Email, Reply To, Send To, BCC. The default notification, %s, cites no field: such a form has no subject until a notification cites one or a field carries the class.', 'gecka-antispam'), 'New submission from {form_title}') . '</p>'
            . sprintf('<p><strong>%s</strong></p>', esc_html__('Message, the first rule that applies:', 'gecka-antispam'))
            . self::steps(
                [
                    /* translators: %s: CSS class */
                    self::code(__('the fields carrying the CSS class %s, of any type;', 'gecka-antispam'), 'gecka-antispam-message'),
                    esc_html__('every paragraph, post title, post content and post excerpt field.', 'gecka-antispam'),
                ],
            )
            . sprintf('<p><strong>%s</strong></p>', esc_html__('Random names, the first rule that applies:', 'gecka-antispam'))
            . self::steps(
                [
                    /* translators: %s: CSS class */
                    self::code(__('the single line text and Name fields carrying the CSS class %s;', 'gecka-antispam'), 'gecka-antispam-name'),
                    esc_html__('the first and last names of the Name fields.', 'gecka-antispam'),
                ],
            );
    }

    /**
     * The rules of the front-end forms of ACF and Secure Custom Fields
     *
     * @return string HTML.
     */
    private static function acf(): string
    {
        return sprintf('<p><strong>%s</strong></p>', esc_html__('Subject, the first rule that applies:', 'gecka-antispam'))
            . self::steps(
                [
                    /* translators: 1: argument of acf_form(), 2: example */
                    self::code(__('the fields the %1$s argument of acf_form() names under subject, by name or by key, for instance %2$s;', 'gecka-antispam'), 'gecka_antispam', "'subject' => ['post_title']"),
                    esc_html__('the title of the post, when the form shows it.', 'gecka-antispam'),
                ],
            )
            . self::paragraphs([__('Only text, textarea, select, radio button, checkbox and button group fields count as the subject.', 'gecka-antispam')])
            . sprintf('<p><strong>%s</strong></p>', esc_html__('Message, the first rule that applies:', 'gecka-antispam'))
            . self::steps(
                [
                    /* translators: 1: argument of acf_form(), 2: example */
                    self::code(__('the fields the %1$s argument names under message, of any type, for instance %2$s;', 'gecka-antispam'), 'gecka_antispam', "'message' => ['post_content', 'description']"),
                    esc_html__('the content of the post when the form shows it, and every textarea and editor field.', 'gecka-antispam'),
                ],
            )
            . self::paragraphs(
                [
                    __('Only the fields the form shows are read, with the sub fields of its groups, repeaters and flexible contents, every row, without their HTML; the argument names a sub field as any other. A part the argument leaves out keeps its default. The argument given as an array also marks the form for protection.', 'gecka-antispam'),
                    __('These forms create or change content and have no spam queue: the filter refuses a submission from the rejection threshold, lets the others through, and learns nothing from them.', 'gecka-antispam'),
                ],
            )
            /* translators: 1: argument of acf_form(), 2: example */
            . '<p>' . self::code(__('Random names: the text fields the %1$s argument names under name, for instance %2$s; none without it.', 'gecka-antispam'), 'gecka_antispam', "'name' => ['seller']") . '</p>';
    }

    /**
     * What the filter reads of comments and product reviews
     *
     * @return string HTML.
     */
    private static function comments(): string
    {
        return self::paragraphs(
            [
                __('The statistical filter reads the content of a comment, and of a WooCommerce product review, which is a comment: there is no subject.', 'gecka-antispam'),
                __('Random names: the name of the author.', 'gecka-antispam'),
            ],
        );
    }

    /**
     * The forms the statistical filter does not read
     *
     * @param Plugin $plugin
     *
     * @return string HTML.
     */
    private static function otherForms(Plugin $plugin): string
    {
        $lines = [
            __('Login and lost password: the checks only, with nothing to read.', 'gecka-antispam'),
            __('Registration: the checks, and the random names check on the username.', 'gecka-antispam'),
        ];

        if ($plugin->provides('woocommerce')) {
            $lines[] = __('WooCommerce checkout and My account: the checks, and the random names check on the first and last names of the billing address, or on the username of a registration.', 'gecka-antispam');
        }

        return self::paragraphs([__('These forms carry no message: the statistical filter does not read them.', 'gecka-antispam')]) . self::steps(array_map('esc_html', $lines), 'ul');
    }

    /**
     * Paragraphs of plain text
     *
     * @param string[] $texts
     *
     * @return string HTML.
     */
    private static function paragraphs(array $texts): string
    {
        return implode('', array_map(static fn(string $text): string => '<p>' . esc_html($text) . '</p>', $texts));
    }

    /**
     * A list of escaped HTML
     *
     * @param string[] $items
     * @param string   $tag   ol or ul.
     *
     * @return string HTML.
     */
    private static function steps(array $items, string $tag = 'ol'): string
    {
        return "<$tag>" . implode('', array_map(static fn(string $item): string => '<li>' . $item . '</li>', $items)) . "</$tag>";
    }

    /**
     * A text with names of settings, fields or classes in it, escaped, the
     * names as code
     *
     * @param string $text     Holding a placeholder for each name.
     * @param string ...$codes
     *
     * @return string HTML.
     */
    private static function code(string $text, string ...$codes): string
    {
        return vsprintf(esc_html($text), array_map(static fn(string $code): string => '<code>' . esc_html($code) . '</code>', $codes));
    }
}
