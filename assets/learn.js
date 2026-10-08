/*
 * SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Learns what the site holds through the REST route, one short request after
 * another, showing the progress, instead of posting the form of the button
 * and waiting for one long request. Without this script, the form still
 * works.
 */
(() => {
    const box = document.querySelector('.gecka-antispam-learn');
    const field = box && box.querySelector('input[name="action"][value="gecka_antispam_learn_existing"]');

    if (!field || !window.fetch) {
        return;
    }

    const form = field.form;
    const button = form.querySelector('button[type="submit"]');
    const progress = box.querySelector('progress');
    const status = box.querySelector('.gecka-antispam-learn-status');
    const total = Number(box.dataset.total) || 0;

    const fill = (template, values) => template.replace(/%(\d)\$s/g, (match, index) => values[index - 1] ?? match);

    form.addEventListener('submit', async (event) => {
        event.preventDefault();

        const learnt = { spam: 0, ham: 0 };
        let left = total;
        let failed = false;

        // The focus leaves the button it disables for the status, which
        // tells the progress.
        status.tabIndex = -1;
        status.focus();
        button.disabled = true;
        progress.hidden = false;
        status.textContent = '';

        try {
            for (;;) {
                const response = await fetch(box.dataset.url, {
                    method: 'POST',
                    credentials: 'same-origin',
                    headers: { 'X-WP-Nonce': box.dataset.nonce },
                });

                if (!response.ok) {
                    throw new Error(String(response.status));
                }

                const data = await response.json();
                const before = left;

                learnt.spam += data.learnt.spam;
                learnt.ham += data.learnt.ham;
                left = data.pending.spam + data.pending.ham;
                progress.value = total ? Math.min(1, (total - left) / total) : 1;
                status.textContent = fill(box.dataset.progress, [learnt.spam, learnt.ham, left]);

                failed = Boolean(data.failed);

                // Nothing left, a round that left as much as before it, or
                // a failure of the filter: what remains cannot be learnt now.
                if (failed || left === 0 || left >= before) {
                    break;
                }
            }

            const done = new URL(box.dataset.done, window.location.href);

            done.searchParams.set('learnt_spam', String(learnt.spam));
            done.searchParams.set('learnt_ham', String(learnt.ham));

            if (failed) {
                done.searchParams.set('learn_failed', '1');
            }

            window.location.assign(done.toString());
        } catch (error) {
            status.textContent = box.dataset.error;
            button.disabled = false;
            button.focus();
        }
    });
})();
