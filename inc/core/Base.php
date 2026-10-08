<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

namespace Gecka\WP\Plugin\Antispam;

/**
 * Base of the pieces the plugin hooks up.
 *
 * @author Laurent Dinclaux - Gecka <laurent@gecka.nc>
 */
abstract class Base
{
    /**
     * @var Plugin
     */
    protected Plugin $plugin;

    /**
     * @param Plugin $plugin
     */
    public function __construct(Plugin $plugin)
    {
        $this->plugin = $plugin;
    }

    /**
     * Hooks the piece up.
     *
     * @return void
     */
    abstract public function setup(): void;
}
