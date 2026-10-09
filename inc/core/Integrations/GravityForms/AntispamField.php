<?php

declare(strict_types=1);

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

namespace Gecka\WP\Plugin\Antispam\Integrations\GravityForms;

use Gecka\WP\Plugin\Antispam\Request;

/**
 * The Antispam field of the Gravity Forms editor: dropped in a form, it marks
 * the form to protect and prints the honeypot and the timestamp where it
 * stands. Visitors see nothing, the field has no label and no value.
 *
 * Gravity Forms builds its fields from the form saved, with no way to hand
 * them a dependency: the field reaches the plugin through gecka_antispam().
 * The method names and the untyped parameters are those of GF_Field, which
 * declares none; a parameter type would narrow the parent's.
 *
 * @author Laurent Dinclaux - Gecka <laurent@gecka.nc>
 */
class AntispamField extends \GF_Field
{
    /**
     * Field type, also the marker the integration looks for.
     */
    public const TYPE = 'gecka_antispam';

    /**
     * @var string
     */
    public $type = self::TYPE;

    /**
     * Nothing of the field goes into the entries.
     *
     * @var bool
     */
    public $displayOnly = true;

    /**
     * @return string
     */
    public function get_form_editor_field_title(): string
    {
        return esc_attr__('Antispam', 'gecka-antispam');
    }

    /**
     * @return string
     */
    public function get_form_editor_field_description(): string
    {
        return esc_attr__('Protects the form with the honeypot and the timestamp of Gecka Antispam. Visitors see nothing.', 'gecka-antispam');
    }

    /**
     * @return array{group: string, text: string}
     */
    public function get_form_editor_button(): array
    {
        return [
            'group' => 'advanced_fields',
            'text' => $this->get_form_editor_field_title(),
        ];
    }

    /**
     * @return string[]
     */
    public function get_form_editor_field_settings(): array
    {
        return ['admin_label_setting', 'css_class_setting'];
    }

    /**
     * @return bool
     */
    public function is_conditional_logic_supported(): bool
    {
        return false;
    }

    /**
     * The label shows in the editor only. Both parameters stay optional, as
     * Gravity Forms 3 declares them.
     *
     * @param bool       $force_frontend_label
     * @param int|string $value
     *
     * @return string
     */
    public function get_field_label($force_frontend_label = true, $value = ''): string
    {
        return $this->is_form_editor() ? (string) parent::get_field_label($force_frontend_label, $value) : '';
    }

    /**
     * The honeypot and the timestamp, or a line telling what the field does
     * in the editor.
     *
     * @param array<string, mixed>      $form
     * @param string|array<mixed>       $value
     * @param array<string, mixed>|null $entry
     *
     * @return string
     */
    public function get_field_input($form, $value = '', $entry = null): string
    {
        if ($this->is_form_editor()) {
            return '<p>' . esc_html__('Honeypot and timestamp, invisible to visitors.', 'gecka-antispam') . '</p>';
        }

        $plugin = gecka_antispam();

        return $plugin->settings()->enabled('gravity_forms') ? $plugin->guard()->fields('gravity_forms', Request::isFormPost('gform_submit')) : '';
    }
}
