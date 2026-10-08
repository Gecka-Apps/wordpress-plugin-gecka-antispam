<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

/**
 * Removes what the plugin left on the installation, when it is deleted.
 */

defined('WP_UNINSTALL_PLUGIN') || exit;

require_once __DIR__ . '/vendor/autoload.php';

Gecka\WP\Plugin\Antispam\Setup::uninstall();
