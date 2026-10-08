/*
 * SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * A block carrying data-gecka-antispam-shown-by, the id of a checkbox, shows
 * while the box is ticked. The page prints it hidden when the box is not, so
 * without this script it follows the saved setting.
 */
(() => {
    document.querySelectorAll('[data-gecka-antispam-shown-by]').forEach((block) => {
        const box = document.getElementById(block.dataset.geckaAntispamShownBy);

        if (!box) {
            return;
        }

        box.addEventListener('change', () => {
            block.hidden = !box.checked;
        });
    });
})();
