<?php

declare(strict_types=1);

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

namespace Gecka\WP\Plugin\Antispam\Admin\RefusedView;

/**
 * The views of the list of the submissions refused, named by the view
 * argument of the address. Those waiting for review show without one.
 *
 * @author Laurent Dinclaux - Gecka <laurent@gecka.nc>
 */
enum View: string
{
    /**
     * The entries waiting for review that are worth learning.
     */
    case Pending = 'pending';

    /**
     * The entries waiting for review that are plain spam, which teaches the
     * statistical filter nothing it lacks.
     */
    case Spam = 'spam';

    /**
     * The entries learnt, as spam or as legitimate.
     */
    case Learnt = 'learnt';

    /**
     * The arguments of an address showing the view
     *
     * @return array{view?: string} Empty for the entries waiting for review, the default view.
     */
    public function query(): array
    {
        // phpcs:ignore PHPCompatibility.Variables.ForbiddenThisUseContexts.OutsideObjectContext -- PHPCompatibility 9.3 predates enums and takes their methods for plain functions.
        return $this === self::Pending ? [] : ['view' => $this->value];
    }
}
