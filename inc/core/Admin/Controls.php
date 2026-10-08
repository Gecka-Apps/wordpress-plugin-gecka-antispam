<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

namespace Gecka\WP\Plugin\Antispam\Admin;

use Gecka\WP\Plugin\Antispam\Settings;

/**
 * Rows of a settings form, and buttons posting an action to admin-post.php.
 *
 * @author Laurent Dinclaux - Gecka <laurent@gecka.nc>
 */
trait Controls
{
    /**
     * @param string $key
     * @param string $label
     * @param string $value
     * @param string $description
     *
     * @return void
     */
    private function textRow(string $key, string $label, string $value, string $description): void
    {
        printf(
            '<tr><th scope="row"><label for="gecka-antispam-%1$s">%2$s</label></th><td><input type="text" class="regular-text code" id="gecka-antispam-%1$s" name="%3$s[%1$s]" value="%4$s" aria-describedby="gecka-antispam-%1$s-description"><p class="description" id="gecka-antispam-%1$s-description">%5$s</p></td></tr>',
            esc_attr($key),
            esc_html($label),
            esc_attr(Settings::OPTION),
            esc_attr($value),
            esc_html($description),
        );
    }

    /**
     * @param string $key
     * @param string $label
     * @param int    $value
     * @param string $unit
     * @param string $description
     *
     * @return void
     */
    private function numberRow(string $key, string $label, int $value, string $unit, string $description): void
    {
        printf(
            '<tr><th scope="row"><label for="gecka-antispam-%1$s">%2$s</label></th><td><input type="number" class="small-text" id="gecka-antispam-%1$s" name="%3$s[%1$s]" value="%4$d" min="%5$d" max="%6$d" aria-describedby="gecka-antispam-%1$s-description">&nbsp;%7$s<p class="description" id="gecka-antispam-%1$s-description">%8$s</p></td></tr>',
            esc_attr($key),
            esc_html($label),
            esc_attr(Settings::OPTION),
            (int) $value,
            (int) Settings::BOUNDS[$key][0],
            (int) Settings::BOUNDS[$key][1],
            esc_html($unit),
            esc_html($description),
        );
    }

    /**
     * @param string $key
     * @param string $label
     * @param bool   $checked
     * @param string $description
     *
     * @return void
     */
    private function checkboxRow(string $key, string $label, bool $checked, string $description): void
    {
        printf(
            '<tr><th scope="row" id="gecka-antispam-%3$s-label">%1$s</th><td><label class="gecka-admin-toggle-label"><input type="checkbox" class="gecka-admin-toggle" id="gecka-antispam-%3$s" name="%2$s[%3$s]" value="1" %4$s aria-labelledby="gecka-antispam-%3$s-label" aria-describedby="gecka-antispam-%3$s-description"> <span id="gecka-antispam-%3$s-description">%5$s</span></label></td></tr>',
            esc_html($label),
            esc_attr(Settings::OPTION),
            esc_attr($key),
            checked($checked, true, false),
            esc_html($description),
        );
    }

    /**
     * Prints a form holding only a button, which posts an action to
     * admin-post.php, followed by white space, as WordPress separates its
     * buttons. Several in a row go in a .gecka-admin-buttons block.
     *
     * @param string      $action
     * @param string      $label
     * @param string|null $confirm Question asked before, if any.
     * @param bool        $primary
     *
     * @return void
     */
    private function actionButton(string $action, string $label, ?string $confirm = null, bool $primary = false): void
    {
        printf('<form method="post" action="%s">', esc_url(admin_url('admin-post.php')));
        printf('<input type="hidden" name="action" value="%s">', esc_attr($action));
        wp_nonce_field($action);
        printf(
            '<button type="submit" class="button%s"%s>%s</button>',
            $primary ? ' button-primary' : '',
            $confirm ? ' onclick="return confirm(' . esc_attr((string) wp_json_encode($confirm)) . ')"' : '',
            esc_html($label),
        );
        echo "</form>\n";
    }
}
