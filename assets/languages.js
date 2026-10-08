/*
 * SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Turns the text field of the background languages into the field of tags
 * of WordPress, suggesting the languages of the release with the sentences
 * of their tables. The codes chosen go back into the text field, which the
 * form posts; without this script, the codes are typed in it. The
 * description of the text field becomes the help of the field of tags, and
 * a language saved that the release no longer offers stays until removed.
 */
(() => {
    const box = document.querySelector('.gecka-antispam-languages-field');
    const wp = window.wp;

    if (!box || !wp || !wp.element || !wp.components || !wp.components.FormTokenField) {
        return;
    }

    const input = box.querySelector('input[type="text"]');
    const offered = JSON.parse(box.dataset.languages || '{}');
    const codes = {};

    Object.entries(offered).forEach(([code, language]) => {
        codes[language.label] = code;
    });

    if (!input || !Object.keys(codes).length) {
        return;
    }

    const { createElement, createRoot, useState } = wp.element;
    const label = (code) => (offered[code] ? offered[code].label : code);
    const code = (token) => {
        const text = typeof token === 'string' ? token : token.value;

        return codes[text] || text;
    };
    const saved = input.value.split(/[\s,;]+/).filter(Boolean);
    const initial = saved.map(label);
    const kept = (token) => code(token) in offered || saved.includes(code(token));
    const description = document.getElementById(input.getAttribute('aria-describedby') || '');
    const heading = document.querySelector('label[for="' + input.id + '"]');
    const mount = document.createElement('div');

    input.type = 'hidden';
    input.after(mount);

    if (heading) {
        heading.removeAttribute('for');
    }

    if (description) {
        description.hidden = true;
    }

    const Field = () => {
        const [tokens, setTokens] = useState(initial);

        return createElement(wp.components.FormTokenField, {
            label: box.dataset.label,
            value: tokens,
            suggestions: Object.keys(codes),
            maxLength: Number(box.dataset.max) || 5,
            maxSuggestions: 20,
            help: description ? description.textContent : '',
            __experimentalValidateInput: (token) => token in codes,
            __experimentalRenderItem: ({ item }) =>
                createElement(
                    'span',
                    null,
                    item,
                    createElement('span', { className: 'gecka-antispam-languages-detail' }, ' ' + offered[codes[item]].detail),
                ),
            onChange: (next) => {
                const chosen = next.filter(kept);

                setTokens(chosen);
                input.value = chosen.map(code).join(', ');
            },
        });
    };

    createRoot(mount).render(createElement(Field));
})();
