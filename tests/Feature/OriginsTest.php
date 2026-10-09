<?php

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

use Gecka\WP\Plugin\Antispam\Guard;
use Gecka\WP\Plugin\Antispam\Origins;
use Gecka\WP\Plugin\Antispam\Schema;

// Gecka Geolocation is not loaded here: this stands for it, locating the
// visitor as $GLOBALS['gecka_antispam_geolocation'] says, and nobody else.
if (! function_exists('gecka_geolocation')) {
    function gecka_geolocation(?string $ip = null, ?string $provider = null): ?object
    {
        $visitor = $GLOBALS['gecka_antispam_geolocation'] ?? null;

        if (! is_array($visitor)) {
            return null;
        }

        return new class ($visitor) {
            public function __construct(private array $data) {}

            public function country(): ?string
            {
                return $this->data['country'] ?? null;
            }

            public function asn(): ?int
            {
                return $this->data['asn'] ?? null;
            }

            public function asOrganization(): ?string
            {
                return $this->data['organization'] ?? null;
            }
        };
    }
}

beforeEach(function () {
    $this->origins = gecka_antispam()->origins();
    $this->origins->reset();
    gecka_antispam()->stats()->reset();
    $GLOBALS['gecka_antispam_geolocation'] = null;
    $_SERVER['HTTP_USER_AGENT'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36';
});

afterEach(function () {
    unset($GLOBALS['gecka_antispam_geolocation'], $_SERVER['HTTP_USER_AGENT']);
    $_POST = [];
});

it('tells the system a user agent names', function (string $agent, string $system) {
    expect(Origins::system($agent))->toBe($system);
})->with([
    ['Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X)', 'ipados'],
    ['Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)', 'ios'],
    ['Mozilla/5.0 (Linux; Android 14; Pixel 8)', 'android'],
    ['Mozilla/5.0 (X11; CrOS x86_64 15633.69.0)', 'chromeos'],
    ['Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0)', 'macos'],
    ['Mozilla/5.0 (Windows NT 10.0; Win64; x64)', 'windows'],
    ['Mozilla/5.0 (X11; Linux x86_64)', 'linux'],
    ['python-requests/2.31', 'other'],
    ['', ''],
]);

it('tells the outcomes caught from those accepted', function () {
    expect(Origins::caught())->toContain(Guard::HONEYPOT, Guard::TOKEN, Guard::FILTER_SPAM, Guard::FILTER_REJECT)
        ->and(Origins::caught())->not->toContain(Guard::PASSED, Guard::REVIEW);
});

it('counts the system alone without a geolocation', function () {
    $this->origins->count(Guard::HONEYPOT);

    expect($this->origins->top(Origins::SYSTEM, 7, Origins::caught()))->toBe([['value' => 'windows', 'name' => '', 'hits' => 1]])
        ->and($this->origins->top(Origins::COUNTRY, 7, Origins::caught()))->toBe([])
        ->and($this->origins->top(Origins::NETWORK, 7, Origins::caught()))->toBe([]);
});

it('counts the country and the network the geolocation gives', function () {
    $GLOBALS['gecka_antispam_geolocation'] = ['country' => 'NC', 'asn' => 17480, 'organization' => 'CANL'];
    $this->origins->count(Guard::HONEYPOT);
    $this->origins->count(Guard::TOO_FAST);
    $this->origins->count(Guard::PASSED);

    $GLOBALS['gecka_antispam_geolocation'] = ['country' => 'DE', 'asn' => 3320, 'organization' => 'Deutsche Telekom AG'];
    $this->origins->count(Guard::FILTER_REJECT);

    $GLOBALS['gecka_antispam_geolocation'] = [];
    $this->origins->count(Guard::HONEYPOT);

    expect($this->origins->top(Origins::COUNTRY, 7, Origins::caught()))->toBe([
        ['value' => 'NC', 'name' => '', 'hits' => 2],
        ['value' => '', 'name' => '', 'hits' => 1],
        ['value' => 'DE', 'name' => '', 'hits' => 1],
    ])
        ->and($this->origins->top(Origins::NETWORK, 7, Origins::caught())[0])->toBe(['value' => '17480', 'name' => 'CANL', 'hits' => 2])
        ->and($this->origins->top(Origins::COUNTRY, 7, Origins::ACCEPTED))->toBe([['value' => 'NC', 'name' => '', 'hits' => 1]])
        ->and($this->origins->total(Origins::COUNTRY, 7, Origins::caught()))->toBe(4)
        ->and($this->origins->total(Origins::SYSTEM, 7, Origins::ACCEPTED))->toBe(1);
});

it('counts a submission checked, as the statistics count it', function () {
    $GLOBALS['gecka_antispam_geolocation'] = ['country' => 'NC', 'asn' => 17480, 'organization' => 'CANL'];

    gecka_antispam_check('devis', 'Bonjour, je voudrais un devis.');
    post_form('custom:devis');
    gecka_antispam_check('devis', 'Bonjour, je voudrais un devis.', ['Marie Dupont']);

    expect($this->origins->top(Origins::COUNTRY, 7, [Guard::TOKEN]))->toBe([['value' => 'NC', 'name' => '', 'hits' => 1]])
        ->and($this->origins->top(Origins::NETWORK, 7, Origins::ACCEPTED))->toBe([['value' => '17480', 'name' => 'CANL', 'hits' => 1]])
        ->and($this->origins->total(Origins::SYSTEM, 7, [...Origins::caught(), ...Origins::ACCEPTED]))->toBe(2);
});

it('shows the origins on the statistics tab', function () {
    $GLOBALS['gecka_antispam_geolocation'] = ['country' => 'NC', 'asn' => 17480, 'organization' => 'CANL'];
    $this->origins->count(Guard::HONEYPOT);

    ob_start();
    (new \Gecka\WP\Plugin\Antispam\Admin\StatsView(gecka_antispam()))->render();
    $html = (string) ob_get_clean();

    expect($html)->toContain('gecka-antispam-origins')
        ->and($html)->toContain('CANL <span class="gecka-antispam-origin-asn">AS17480</span>')
        ->and($html)->toContain('>Windows<')
        ->and($html)->toContain('origins=accepted');
});

it('drops the old counters and every one on a reset', function () {
    global $wpdb;

    $wpdb->insert(Schema::origins(), ['day' => '2001-01-01', 'facet' => Origins::SYSTEM, 'value' => 'linux', 'outcome' => Guard::HONEYPOT, 'hits' => 3]);
    $this->origins->record(Origins::SYSTEM, 'linux', Guard::HONEYPOT);
    $this->origins->purge(30);

    expect($this->origins->total(Origins::SYSTEM, 7, Origins::caught()))->toBe(1)
        ->and((int) $wpdb->get_var($wpdb->prepare('SELECT SUM(hits) FROM %i', Schema::origins())))->toBe(1);

    $this->origins->reset();

    expect($this->origins->total(Origins::SYSTEM, 7, Origins::caught()))->toBe(0);
});
