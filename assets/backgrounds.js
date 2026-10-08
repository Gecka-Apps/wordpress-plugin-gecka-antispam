/*
 * SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Updates the background tables through the REST routes: one request reads
 * the release and queues the tables to download, then one request per
 * table, the progress showing which. It starts by itself when the page
 * says the languages saved queued downloads. Without this script, the
 * button posts its form, and the scheduled event does the rest.
 */
(() => {
    const box = document.querySelector('.gecka-antispam-backgrounds-update');
    const field = box && box.querySelector('input[name="action"][value="gecka_antispam_update_backgrounds"]');

    if (!field || !window.fetch) {
        return;
    }

    const form = field.form;
    const button = form.querySelector('button[type="submit"]');
    const progress = box.querySelector('progress');
    const status = box.querySelector('.gecka-antispam-learn-status');

    const fill = (template, values) => template.replace(/%(\d)\$s/g, (match, index) => values[index - 1] ?? match);

    const post = async (url) => {
        const response = await fetch(url, {
            method: 'POST',
            credentials: 'same-origin',
            headers: { 'X-WP-Nonce': box.dataset.nonce },
        });

        if (!response.ok) {
            throw new Error(String(response.status));
        }

        return response.json();
    };

    const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

    // Another request, the scheduled event or another tab, holds the lock:
    // the step is posted again every 3 s, for two minutes at most.
    const step = async (url, label) => {
        for (let tries = 0; ; tries++) {
            const data = await post(url);

            if (!data.busy) {
                return data;
            }

            if (tries >= 40) {
                throw new Error('busy');
            }

            status.textContent = box.dataset.busy;
            await wait(3000);
            status.textContent = label;
        }
    };

    const run = async (clicked) => {
        let failed = false;

        // After a click, the focus leaves the button it disables for the
        // status, which tells the progress.
        if (clicked) {
            status.tabIndex = -1;
            status.focus();
        }

        button.disabled = true;
        progress.hidden = false;
        progress.removeAttribute('value');
        status.textContent = box.dataset.checking;

        try {
            const plan = await step(box.dataset.check, box.dataset.checking);
            const tables = plan.pending || [];

            failed = Boolean(plan.error);
            progress.max = Math.max(1, tables.length);
            progress.value = 0;

            for (let index = 0; index < tables.length; index++) {
                const label = fill(box.dataset.progress, [tables[index].name, index + 1, tables.length]);

                status.textContent = label;

                const result = await step(box.dataset.next, label);

                failed = failed || Boolean(result.error);
                progress.value = index + 1;

                if (result.done) {
                    break;
                }
            }

            const done = new URL(box.dataset.done, window.location.href);

            done.searchParams.set('backgrounds', failed ? 'failed' : 'updated');
            window.location.assign(done.toString());
        } catch (error) {
            status.textContent = box.dataset.error;
            button.disabled = false;

            if (clicked) {
                button.focus();
            }
        }
    };

    form.addEventListener('submit', (event) => {
        event.preventDefault();
        run(true);
    });

    if (box.dataset.autostart) {
        run(false);
    }
})();
