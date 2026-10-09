<?php

declare(strict_types=1);

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

namespace Gecka\WP\Plugin\Antispam;

/**
 * Something the plugin could not do, with the reason as a plain sentence
 * for the administrators. The message is raw text: the screen that shows
 * it, a notice, the filter tab, Site Health or a REST answer, escapes it
 * once, like any other text it prints.
 *
 * @author Laurent Dinclaux - Gecka <laurent@gecka.nc>
 */
final class Failure extends \RuntimeException
{
    /**
     * A failure with its reason.
     *
     * @param string $reason Plain text, unescaped.
     *
     * @return self
     */
    public static function because(string $reason): self
    {
        return new self($reason);
    }
}
