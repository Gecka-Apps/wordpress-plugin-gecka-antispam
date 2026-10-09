<?php

declare(strict_types=1);

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

use Gecka\SpamFilter\Model\Background;
use Gecka\SpamFilter\Model\BackgroundDownloader;
use Gecka\SpamFilter\Tokenizer\FeatureHasher;
use Gecka\WP\Plugin\Antispam\Admin\SiteHealth;
use Gecka\WP\Plugin\Antispam\Backgrounds;
use Gecka\WP\Plugin\Antispam\Settings;
use Gecka\WP\Plugin\Antispam\Setup;
use Gecka\WP\Plugin\Antispam\StatisticalFilter;

beforeEach(function () {
    $this->directory = get_temp_dir() . 'gecka-antispam-downloads-' . wp_generate_password(6, false);
    $GLOBALS['gecka_antispam_requests'] = [];
    add_filter('pre_http_request', fn() => new WP_Error('offline', 'No network in the tests.'));
    add_filter('gecka_antispam_background_directory', fn() => $this->directory);
    delete_option(Backgrounds::OPTION);
    antispam_settings(['background_languages' => ['fr', 'en']]);
});

afterEach(function () {
    remove_all_filters('gecka_antispam_background_directory');
    remove_all_filters('pre_http_request');
    array_map('unlink', glob($this->directory . '/*') ?: []);

    if (is_dir($this->directory)) {
        rmdir($this->directory);
    }
});

/**
 * Serves a release of background tables to the HTTP API of WordPress, and
 * records the URLs requested.
 *
 * @param array<string, string> $tables      Bytes by language code.
 * @param array<string, mixed>  $manifest    Keys overriding those of the manifest.
 * @param array<string, string> $corruptions Bytes served instead of those the manifest announces, by language code.
 * @param array<string, int>    $sentences   Sentences each table was drawn from, 300,000 when not given.
 *
 * @return void
 */
function serve_release(array $tables, array $manifest = [], array $corruptions = [], array $sentences = []): void
{
    $base = dirname(BackgroundDownloader::DEFAULT_MANIFEST) . '/';
    $languages = [];

    foreach ($tables as $code => $binary) {
        $languages[$code] = ['name' => strtoupper($code), 'url' => $base . "$code.bin", 'bytes' => strlen($binary), 'sha256' => hash('sha256', $binary), 'sentences' => $sentences[$code] ?? 300000];
    }

    $bodies = [BackgroundDownloader::DEFAULT_MANIFEST => (string) wp_json_encode($manifest + ['hash_version' => FeatureHasher::VERSION, 'version' => 'v9.9', 'languages' => $languages])];

    foreach ($tables as $code => $binary) {
        $bodies[$base . "$code.bin"] = $corruptions[$code] ?? $binary;
    }

    remove_all_filters('pre_http_request');
    add_filter(
        'pre_http_request',
        function ($response, $args, $url) use ($bodies) {
            $GLOBALS['gecka_antispam_requests'][] = $url;

            return isset($bodies[$url])
                ? ['headers' => [], 'body' => $bodies[$url], 'response' => ['code' => 200, 'message' => 'OK'], 'cookies' => [], 'filename' => null]
                : ['headers' => [], 'body' => '', 'response' => ['code' => 404, 'message' => 'Not Found'], 'cookies' => [], 'filename' => null];
        },
        10,
        3,
    );
}

it('downloads the tables of the languages wanted that the release offers', function () {
    serve_release(['fr' => Background::toBinary(french_table()), 'en' => Background::toBinary(french_table()), 'de' => Background::toBinary(french_table())]);
    antispam_settings(['background_languages' => ['fr', 'en', 'xx']]);

    $backgrounds = gecka_antispam()->backgrounds();

    expect($backgrounds->update())->toBeTrue()
        ->and(array_keys($backgrounds->state()['tables']))->toBe(['fr', 'en'])
        ->and($backgrounds->state()['release'])->toBe('v9.9')
        ->and(is_file($this->directory . '/fr.bin'))->toBeTrue()
        ->and(is_file($this->directory . '/de.bin'))->toBeFalse()
        ->and(gecka_antispam()->statisticalFilter()->languages())->toEqualCanonicalizing(['fr', 'en'])
        ->and($backgrounds->due())->toBeFalse();
});

it('downloads only the tables the release changed', function () {
    serve_release(['fr' => Background::toBinary(french_table()), 'en' => Background::toBinary(french_table())]);
    gecka_antispam()->backgrounds()->update();

    $table = french_table();
    $table->add(12345, 3);
    serve_release(['fr' => Background::toBinary(french_table()), 'en' => Background::toBinary($table)]);
    $GLOBALS['gecka_antispam_requests'] = [];

    expect(gecka_antispam()->backgrounds()->update())->toBeTrue()
        ->and(array_map('basename', $GLOBALS['gecka_antispam_requests']))->toBe(['manifest.json', 'en.bin'])
        ->and(hash_file('sha256', $this->directory . '/en.bin'))->toBe(hash('sha256', Background::toBinary($table)));
});

it('keeps the table in place when a download does not match its checksum', function () {
    serve_release(['fr' => Background::toBinary(french_table()), 'en' => Background::toBinary(french_table())]);
    gecka_antispam()->backgrounds()->update();
    $before = hash_file('sha256', $this->directory . '/en.bin');

    $table = french_table();
    $table->add(12345, 3);
    serve_release(['fr' => Background::toBinary(french_table()), 'en' => Background::toBinary($table)], [], ['en' => Background::toBinary(french_table()) . 'x']);

    $backgrounds = gecka_antispam()->backgrounds();

    expect($backgrounds->update())->toBeFalse()
        ->and($backgrounds->errors())->toStartWith('en: ')
        ->and(hash_file('sha256', $this->directory . '/en.bin'))->toBe($before)
        ->and(array_keys($backgrounds->state()['tables']))->toBe(['fr', 'en'])
        ->and(glob($this->directory . '/*.part'))->toBe([]);
});

it('refuses a release built for another feature hash version, and a table from elsewhere', function () {
    serve_release(['fr' => Background::toBinary(french_table())], ['hash_version' => FeatureHasher::VERSION + 1]);

    expect(gecka_antispam()->backgrounds()->update())->toBeFalse()
        ->and(is_file($this->directory . '/fr.bin'))->toBeFalse();

    serve_release(['fr' => Background::toBinary(french_table())], ['languages' => ['fr' => ['name' => 'French', 'url' => 'https://example.com/fr.bin', 'bytes' => 10, 'sha256' => str_repeat('a', 64)]]]);

    expect(gecka_antispam()->backgrounds()->update())->toBeFalse()
        ->and($GLOBALS['gecka_antispam_requests'])->not->toContain('https://example.com/fr.bin');
});

it('deletes a table it installed once its language is no longer wanted, and leaves one copied by hand', function () {
    serve_release(['fr' => Background::toBinary(french_table()), 'en' => Background::toBinary(french_table())]);
    gecka_antispam()->backgrounds()->update();
    Background::write(french_table(), $this->directory . '/es.bin');

    antispam_settings(['background_languages' => ['fr']]);

    expect(gecka_antispam()->backgrounds()->update())->toBeTrue()
        ->and(is_file($this->directory . '/en.bin'))->toBeFalse()
        ->and(is_file($this->directory . '/es.bin'))->toBeTrue()
        ->and(array_keys(gecka_antispam()->backgrounds()->state()['tables']))->toBe(['fr']);
});

it('downloads nothing while the languages are saved, but queues them and drops the tables no longer wanted', function () {
    serve_release(['fr' => Background::toBinary(french_table()), 'en' => Background::toBinary(french_table()), 'de' => Background::toBinary(french_table())]);
    gecka_antispam()->backgrounds()->update();
    $GLOBALS['gecka_antispam_requests'] = [];
    wp_clear_scheduled_hook(Backgrounds::EVENT);
    wp_set_current_user(static::factory()->user->create(['role' => 'administrator']));

    update_option(Settings::OPTION, gecka_antispam()->settings()->sanitize(['form' => 'backgrounds', 'background_languages' => 'de, FR, de']));
    gecka_antispam()->settings()->flush();

    $backgrounds = gecka_antispam()->backgrounds();

    expect(gecka_antispam()->settings()->get('background_languages'))->toBe(['de', 'fr'])
        ->and($GLOBALS['gecka_antispam_requests'])->toBe([])
        ->and(is_file($this->directory . '/en.bin'))->toBeFalse()
        ->and(wp_next_scheduled(Backgrounds::EVENT))->not->toBeFalse()
        ->and($backgrounds->takeQueued())->toBeTrue()
        ->and($backgrounds->takeQueued())->toBeFalse();

    wp_clear_scheduled_hook(Backgrounds::EVENT);
    wp_set_current_user(0);
});

it('downloads the tables queued one per step', function () {
    serve_release(['fr' => Background::toBinary(french_table()), 'en' => Background::toBinary(french_table())]);
    $backgrounds = gecka_antispam()->backgrounds();

    expect(array_column((array) $backgrounds->check(), 'code'))->toBe(['fr', 'en']);

    $first = $backgrounds->next();

    expect($first['code'] ?? null)->toBe('fr')
        ->and($first['left'] ?? null)->toBe(1)
        ->and(is_file($this->directory . '/fr.bin'))->toBeTrue()
        ->and(is_file($this->directory . '/en.bin'))->toBeFalse()
        ->and($backgrounds->next()['left'] ?? null)->toBe(0)
        ->and($backgrounds->next())->toBeNull()
        ->and($backgrounds->check())->toBe([]);
});

it('runs the steps through the REST routes, for administrators only', function () {
    serve_release(['fr' => Background::toBinary(french_table()), 'en' => Background::toBinary(french_table())]);
    $call = static fn(string $route) => rest_do_request(new WP_REST_Request('POST', '/gecka-antispam/v1/backgrounds/' . $route));

    wp_set_current_user(static::factory()->user->create(['role' => 'editor']));
    expect($call('check')->get_status())->toBe(403);

    wp_set_current_user(static::factory()->user->create(['role' => 'administrator']));
    $check = $call('check');

    expect($check->get_status())->toBe(200)
        ->and(array_column($check->get_data()['pending'], 'code'))->toBe(['fr', 'en'])
        ->and($call('next')->get_data()['code'])->toBe('fr')
        ->and($call('next')->get_data()['left'])->toBe(0)
        ->and($call('next')->get_data()['done'])->toBeTrue();

    wp_set_current_user(0);
});

it('tells Site Health of a table drawn from few sentences', function () {
    serve_release(['fr' => Background::toBinary(french_table()), 'en' => Background::toBinary(french_table())], [], [], ['en' => 800]);
    gecka_antispam()->backgrounds()->update();

    $result = (new SiteHealth(gecka_antispam()))->testBackground();

    expect($result['status'])->toBe('recommended')
        ->and($result['description'])->toContain('en: 800');
});

it('rates the quality of a table by its sentences', function () {
    expect(Backgrounds::quality(300000))->toBe('solid')
        ->and(Backgrounds::quality(50000))->toBe('average')
        ->and(Backgrounds::quality(5000))->toBe('weak')
        ->and(Backgrounds::quality(56))->toBe('poor');
});

it('takes the languages of the site and English when none is chosen', function () {
    antispam_settings(['background_languages' => []]);
    add_filter('locale', fn() => 'pt_BR');

    expect(gecka_antispam()->backgrounds()->requested())->toBe(['pt', 'en']);

    remove_all_filters('locale');
});

it('schedules the first download when the plugin is set up', function () {
    wp_clear_scheduled_hook(Backgrounds::EVENT);
    Setup::install('1.0.0');

    expect(wp_next_scheduled(Backgrounds::EVENT))->not->toBeFalse();

    wp_clear_scheduled_hook(Backgrounds::EVENT);
});

it('tries a check that failed again the next day', function () {
    serve_release(['fr' => Background::toBinary(french_table()), 'en' => Background::toBinary(french_table())]);
    $backgrounds = gecka_antispam()->backgrounds();
    $backgrounds->update();

    $checked = time() - Backgrounds::INTERVAL - 1;
    update_option(Backgrounds::OPTION, ['checked' => $checked] + get_option(Backgrounds::OPTION));
    remove_all_filters('pre_http_request');
    add_filter('pre_http_request', fn() => new WP_Error('offline', 'No network.'));

    expect($backgrounds->update())->toBeFalse()
        ->and($backgrounds->state()['checked'])->toBe($checked)
        ->and($backgrounds->state()['error'])->toContain('No network')
        ->and($backgrounds->due())->toBeTrue();
});

it('refuses a table announced larger than a table can be, or out of the directory of the manifest', function () {
    $base = dirname(BackgroundDownloader::DEFAULT_MANIFEST) . '/';
    $entry = ['name' => 'French', 'bytes' => 10, 'sha256' => str_repeat('a', 64)];

    foreach ([['url' => $base . 'fr.bin', 'bytes' => StatisticalFilter::FILE_BYTES + 1], ['url' => $base . '../other/fr.bin'], ['url' => $base . 'fr.bin?raw=1'], ['url' => str_replace('https://', 'http://', $base) . 'fr.bin']] as $override) {
        $GLOBALS['gecka_antispam_requests'] = [];
        serve_release(['fr' => Background::toBinary(french_table())], ['languages' => ['fr' => $override + $entry]]);

        expect(gecka_antispam()->backgrounds()->update())->toBeFalse()
            ->and($GLOBALS['gecka_antispam_requests'])->toBe([BackgroundDownloader::DEFAULT_MANIFEST]);
    }
});

it('follows the redirections of a download itself, within one time budget', function () {
    $binary = Background::toBinary(french_table());
    serve_release(['fr' => $binary]);
    antispam_settings(['background_languages' => ['fr']]);
    $base = dirname(BackgroundDownloader::DEFAULT_MANIFEST) . '/';
    $mirror = 'https://release-assets.githubusercontent.com/fr.bin';

    add_filter(
        'pre_http_request',
        function ($response, $args, $url) use ($base, $mirror, $binary) {
            expect($args['redirection'])->toBe(0)
                ->and($args['timeout'])->toBeLessThanOrEqual(Backgrounds::TIMEOUT);

            return match ($url) {
                $base . 'fr.bin' => ['headers' => ['location' => $mirror], 'body' => '', 'response' => ['code' => 302, 'message' => 'Found'], 'cookies' => [], 'filename' => null],
                $mirror => ['headers' => [], 'body' => $binary, 'response' => ['code' => 200, 'message' => 'OK'], 'cookies' => [], 'filename' => null],
                default => $response,
            };
        },
        20,
        3,
    );

    expect(gecka_antispam()->backgrounds()->update())->toBeTrue()
        ->and(is_file($this->directory . '/fr.bin'))->toBeTrue();
});

it('leaves the update to the request holding the lock, and takes over the lock of one that died', function () {
    global $wpdb;

    serve_release(['fr' => Background::toBinary(french_table()), 'en' => Background::toBinary(french_table())]);
    $backgrounds = gecka_antispam()->backgrounds();
    wp_set_current_user(static::factory()->user->create(['role' => 'administrator']));

    expect($backgrounds->lock())->toBeTrue()
        ->and($backgrounds->update())->toBeNull()
        ->and(rest_do_request(new WP_REST_Request('POST', '/gecka-antispam/v1/backgrounds/check'))->get_data())->toBe(['busy' => true])
        ->and($GLOBALS['gecka_antispam_requests'])->toBe([]);

    $wpdb->update($wpdb->options, ['option_value' => (string) (time() - 2 * Backgrounds::TIMEOUT - 1)], ['option_name' => Backgrounds::LOCK]);

    expect($backgrounds->update())->toBeTrue()
        ->and($backgrounds->lock())->toBeTrue();

    $backgrounds->unlock();
    wp_set_current_user(0);
});

it('downloads nothing while the filter is off', function () {
    serve_release(['fr' => Background::toBinary(french_table())]);
    antispam_settings(['filter' => false]);
    wp_set_current_user(static::factory()->user->create(['role' => 'administrator']));

    expect(rest_do_request(new WP_REST_Request('POST', '/gecka-antispam/v1/backgrounds/check'))->get_status())->toBe(403)
        ->and(gecka_antispam()->backgrounds()->due())->toBeFalse();

    wp_set_current_user(0);
});

it('refuses a download redirected off HTTPS', function () {
    $binary = Background::toBinary(french_table());
    serve_release(['fr' => $binary]);
    antispam_settings(['background_languages' => ['fr']]);
    $base = dirname(BackgroundDownloader::DEFAULT_MANIFEST) . '/';

    add_filter(
        'pre_http_request',
        fn($response, $args, $url) => $url === $base . 'fr.bin'
            ? ['headers' => ['location' => 'http://mirror.example/fr.bin'], 'body' => '', 'response' => ['code' => 302, 'message' => 'Found'], 'cookies' => [], 'filename' => null]
            : $response,
        20,
        3,
    );

    expect(gecka_antispam()->backgrounds()->update())->toBeFalse()
        ->and(gecka_antispam()->backgrounds()->errors())->toContain('off HTTPS')
        ->and(is_file($this->directory . '/fr.bin'))->toBeFalse()
        ->and(array_filter($GLOBALS['gecka_antispam_requests'], fn(string $url): bool => str_starts_with($url, 'http://')))->toBe([]);
});

it('releases the lock only for the request holding it', function () {
    global $wpdb;

    $backgrounds = gecka_antispam()->backgrounds();
    $other = new Backgrounds(gecka_antispam()->statisticalFilter(), gecka_antispam()->settings());

    expect($backgrounds->lock())->toBeTrue();

    $other->unlock();

    expect($wpdb->get_var($wpdb->prepare('SELECT COUNT(*) FROM %i WHERE option_name = %s', $wpdb->options, Backgrounds::LOCK)))->toBe('1')
        ->and($other->lock())->toBeFalse();

    $backgrounds->unlock();

    expect($other->lock())->toBeTrue();
    $other->unlock();
});

it('keeps a bounded account of a release: codes anchored, texts cut', function () {
    serve_release(['fr' => Background::toBinary(french_table())], ['languages' => ['fr' => ['name' => str_repeat('x', 300), 'sources' => array_fill(0, 20, str_repeat('s', 200)), 'url' => dirname(BackgroundDownloader::DEFAULT_MANIFEST) . '/fr.bin'], "de\n" => ['name' => 'Deutsch']]]);
    antispam_settings(['background_languages' => ['fr']]);

    gecka_antispam()->backgrounds()->check();
    $languages = gecka_antispam()->backgrounds()->state()['languages'];

    expect(array_keys($languages))->toBe(['fr'])
        ->and(strlen($languages['fr']['name']))->toBe(100)
        ->and($languages['fr']['sources'])->toHaveCount(10)
        ->and(strlen($languages['fr']['sources'][0]))->toBe(100);
});
