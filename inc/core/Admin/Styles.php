<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

namespace Gecka\WP\Plugin\Antispam\Admin;

use Gecka\WP\Plugin\Antispam\Plugin;

/**
 * Style sheet of the settings page and of the dashboard widget.
 *
 * @author Laurent Dinclaux - Gecka <laurent@gecka.nc>
 */
class Styles
{
    /**
     * Handle of the style sheet.
     */
    public const HANDLE = 'gecka-antispam-admin';

    /**
     * Enqueues the style sheet.
     *
     * @return void
     */
    public static function enqueue(): void
    {
        wp_enqueue_style(self::HANDLE, gecka_antispam()->url('assets/admin.css'), [], Plugin::VERSION);
    }
}
