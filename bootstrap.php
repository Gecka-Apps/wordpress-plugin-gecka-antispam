<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

/*
 * Plugin Name: Gecka Antispam
 * Plugin URI: https://github.com/Gecka-Apps/wordpress-plugin-gecka-antispam
 * Description: Stops spam on comments, login, registration, WooCommerce, Contact Form 7, Gravity Forms and ACF forms with a honeypot, a signed timestamp and a statistical filter trained by what you mark as spam. No external service.
 * Version: 1.0.0
 * Author: Gecka
 * Author URI: https://gecka.nc
 * License: GPL-3.0-or-later
 * License URI: https://www.gnu.org/licenses/gpl-3.0.html
 * Requires at least: 6.8
 * Requires PHP: 8.2
 * Text Domain: gecka-antispam
 * Domain Path: /languages/
 */

// Basic security, prevents file from being loaded directly.
defined('ABSPATH') || exit;

use Gecka\WP\Plugin\Antispam\Plugin;
use Gecka\WP\Plugin\Antispam\Setup;

if (! class_exists('\Gecka\WP\Plugin\Antispam\Plugin')) {
    require_once __DIR__ . '/vendor/autoload.php';
}

/**
 * Plugin instance
 *
 * @return Plugin
 */
function gecka_antispam(): Plugin
{
    static $plugin = null;

    if (! $plugin) {
        $plugin = new Plugin(__FILE__);
    }

    return $plugin;
}

/**
 * The fields of the antispam checks, a honeypot and a signed timestamp, for
 * a form a developer writes: printed inside the form, they go back with it
 * as POST fields. Empty when the gecka_antispam_protect filter turns the
 * form off.
 *
 * @param string $form  Name of the form, as the statistics and the Refused
 *                      list show it; the same name goes to
 *                      gecka_antispam_check().
 * @param bool   $carry For a form shown again after a post, the next step
 *                      or the form back with its errors: keep the time the
 *                      form was first shown at, so the minimum delay counts
 *                      from there.
 *
 * @return string HTML, escaped.
 */
function gecka_antispam_fields(string $form, bool $carry = false): string
{
    return gecka_antispam()->custom()->fields($form, $carry);
}

/**
 * Checks a submission of a form printed with gecka_antispam_fields(): the
 * honeypot, the timestamp and the delays, the random names, then the
 * statistical filter on the text. The submission is counted in the
 * statistics, and one refused that carries a text goes to the Refused list.
 *
 * @param string   $form  Name given to gecka_antispam_fields().
 * @param string   $text  What the filter reads: the subject and the message, nothing of the sender.
 * @param string[] $names Names the sender typed, for the random names check.
 *
 * @return array{refused: bool, spam: bool, review: bool, reason: string|null, score: float|null, message: string}
 */
function gecka_antispam_check(string $form, string $text = '', array $names = []): array
{
    return gecka_antispam()->custom()->check($form, $text, $names);
}

add_action(
    'plugins_loaded',
    static function (): void {
        gecka_antispam();
    },
);

add_action(
    'init',
    static function () {
        load_plugin_textdomain('gecka-antispam', false, dirname(plugin_basename(__FILE__)) . '/languages'); // phpcs:ignore PluginCheck.CodeAnalysis.DiscouragedFunctions.load_plugin_textdomainFound -- The translations ship in the languages folder of the plugin.
    },
);

Setup::hooks(__FILE__);
