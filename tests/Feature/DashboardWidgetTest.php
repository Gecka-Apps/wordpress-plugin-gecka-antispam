<?php

declare(strict_types=1);

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

use Gecka\WP\Plugin\Antispam\Admin\DashboardWidget;
use Gecka\WP\Plugin\Antispam\Guard;
use Gecka\WP\Plugin\Antispam\StatisticalFilter;

beforeEach(function () {
    require_once ABSPATH . 'wp-admin/includes/dashboard.php';
    gecka_antispam()->stats()->reset();
    gecka_antispam()->statisticalFilter()->reset();
    gecka_antispam()->journal()->clear();
    $this->widget = new DashboardWidget(gecka_antispam());
});

afterEach(function () {
    wp_set_current_user(0);
    unset($GLOBALS['wp_dashboard_control_callbacks'], $GLOBALS['wp_meta_boxes']);
});

it('sums the last seven days up, with what the filter learnt and the refused submissions', function () {
    gecka_antispam()->stats()->record('comments', Guard::PASSED);
    gecka_antispam()->stats()->record('comments', Guard::HONEYPOT);
    gecka_antispam()->stats()->record('contact_form_7', Guard::REVIEW);
    gecka_antispam()->statisticalFilter()->learn('Buy cheap watches now, limited offer, click here today', StatisticalFilter::SPAM);
    gecka_antispam()->journal()->record('comments', Guard::HONEYPOT, 'Buy cheap watches now');
    wp_set_current_user(static::factory()->user->create(['role' => 'editor']));

    ob_start();
    $this->widget->render();
    $html = (string) ob_get_clean();

    expect($html)->toContain('<th scope="row">Submissions checked</th><td class="num">3</td>')
        ->and($html)->toContain('<th scope="row">Caught</th><td class="num">1</td>')
        ->and($html)->toContain('<th scope="row">To review</th><td class="num">1</td>')
        ->and($html)->toContain('<th scope="row">Spam texts learnt</th><td class="num">1</td>')
        ->and($html)->toContain('<th scope="row">Legitimate texts learnt</th><td class="num">0</td>')
        ->and($html)->toContain('page=security-journal');
});

it('is added for those who moderate comments only', function () {
    set_current_screen('dashboard');

    wp_set_current_user(static::factory()->user->create(['role' => 'author']));
    $this->widget->add();

    expect($GLOBALS['wp_meta_boxes']['dashboard']['normal']['core']['gecka_antispam'] ?? null)->toBeNull();

    wp_set_current_user(static::factory()->user->create(['role' => 'editor']));
    $this->widget->add();

    expect($GLOBALS['wp_meta_boxes']['dashboard']['normal']['core']['gecka_antispam']['title'] ?? null)->toBe('Antispam');
});
