<?php

declare(strict_types=1);

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

namespace Gecka\WP\Plugin\Antispam\Integrations;

/**
 * A source whose comments, messages or entries, already marked as spam or as
 * legitimate, the statistical filter can learn from in one go.
 *
 * Each item learnt, or left out, is marked, so it is never read twice. Items
 * older than two rotation periods are not read: they would have halved
 * since.
 *
 * @author Laurent Dinclaux - Gecka <laurent@gecka.nc>
 */
interface Learner
{
    /**
     * Items of a category not learnt yet, recent enough to be learnt
     *
     * @param string $category StatisticalFilter::SPAM or StatisticalFilter::HAM.
     *
     * @return int
     */
    public function pending(string $category): int;

    /**
     * Learns the most recent items of a category not learnt yet.
     *
     * @param string $category StatisticalFilter::SPAM or StatisticalFilter::HAM.
     * @param int    $limit    Items read at most.
     *
     * @return int Items learnt.
     */
    public function learnExisting(string $category, int $limit): int;
}
