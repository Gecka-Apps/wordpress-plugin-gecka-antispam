# Gecka Antispam for developers

What the plugin offers to code: protecting a form of your own, keeping its
protection on a form of WordPress written by hand, the markers of the form
plugins, what the statistical filter reads of each form, the hooks, the REST
routes, what it stores, and how to work on it.
What a site administrator needs is in [README.md](../README.md); the forms and their checks are in [FORMS.md](FORMS.md), the statistical filter in [STATISTICAL-FILTER.md](STATISTICAL-FILTER.md).

## Protecting a form of your own

Two functions protect a form the plugin does not know: one prints the fields
in the form, the other checks what the form posts.

```php
<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
    <input type="hidden" name="action" value="quote_request">
    <?php wp_nonce_field( 'quote_request' ); ?>
    <input type="text" name="your_name">
    <input type="text" name="subject">
    <textarea name="message"></textarea>
    <?php echo gecka_antispam_fields( 'quote' ); // Escaped already. ?>
    <button type="submit">Send</button>
</form>
```

```php
add_action( 'admin_post_nopriv_quote_request', 'my_quote_request' );
add_action( 'admin_post_quote_request', 'my_quote_request' );

function my_quote_request() {
    check_admin_referer( 'quote_request' );

    $name    = sanitize_text_field( wp_unslash( $_POST['your_name'] ?? '' ) );
    $subject = sanitize_text_field( wp_unslash( $_POST['subject'] ?? '' ) );
    $message = sanitize_textarea_field( wp_unslash( $_POST['message'] ?? '' ) );

    $check = gecka_antispam_check( 'quote', $subject . "\n" . $message, [ $name ], $message );

    if ( $check['refused'] ) {
        wp_die( esc_html( $check['message'] ), '', [ 'response' => 403, 'back_link' => true ] );
    }

    if ( $check['spam'] ) {
        // Keep it where the form keeps its spam, or refuse it too when there
        // is no such place.
    }

    // Send the mail, save the request...
}
```

### `gecka_antispam_fields( string $form, bool $carry = false ): string`

The hidden signed timestamp and the honeypot, as escaped HTML, to print
inside the form.

- `$form` is a name of your choosing. The statistics and the Journal show
  the form as "Custom form: quote"; the plugin records it as
  `custom:quote`, the name passed through `sanitize_key()` and cut to 33
  characters. The timestamp is signed for that name: one taken from another
  form is refused.
- `$carry`, for a form shown again after a post, its next step or the form
  back with its errors: the timestamp keeps the time the form was first shown
  at, so the minimum delay counts from there.

The honeypot is hidden by a style sheet the plugin prints in the head of
every page of the site and of the login screen; a form printed where no head
is, an Ajax response for one, carries the rule itself.

### `gecka_antispam_check( string $form, string $text = '', array $names = [], ?string $message = null ): array`

Runs the checks on what the form posted, in this order: the honeypot, the
user agent (none, or one no browser sends), the timestamp, the minimum
delay (5 seconds by default), the maximum age (8 days by default, a
timestamp more than 60 seconds ahead of the clock counting as forged), the
random names check on `$names`, the checks of the message on `$message`
(a single word of random letters, then fewer words than the minimum, 5 by
default), then the statistical filter on `$text`, once it has learnt enough
to rate. The submission is counted in the statistics; one refused
that carries a text goes to Security > Journal, where a moderator can learn
it.

Pass the subject and the message as `$text`, nothing of the sender: the
filter rates the words of a message, and a name or an address only blurs
its rating and keeps personal data in its counters. With no text, only the
checks of the form run. Pass the message alone as `$message` when the text
also carries a subject: a message of a single word of random letters is
refused, and one shorter than the minimum of words set; without it, the
whole text is read as the message.

| Key | Value |
|---|---|
| `refused` | True when a check of the form caught the submission, or the filter rated it past the rejection threshold (95 % by default). Refuse it with an error the sender sees: a person refused by mistake can send again. |
| `spam` | True when the filter rated it spam, from the spam threshold (75 %) to the rejection one. Keep it where the form keeps spam, or refuse it as well. |
| `review` | True when the filter finds it doubtful (55 % to 75 %): let it through and have a person look at it. |
| `reason` | What caught it: `honeypot`, `token`, `too_fast`, `expired`, `bad_browser`, `random_name`, `random_text`, `short`, `filter_spam`, `filter_reject`, or `review`; null when it went through. |
| `score` | The rating of the filter, from 0 to 1; null when the filter did not rate. |
| `message` | The error the plugin shows for a refusal or a spam, translated; empty otherwise. |

The fields have to reach PHP as POST fields: a form posted the usual way, or
by `fetch()` with a `FormData` body, works; a JSON body does not.

No setting switches a custom form off. The `gecka_antispam_protect` filter
does, given `custom:quote`: `gecka_antispam_fields()` then prints nothing,
and `gecka_antispam_check()` lets everything through, uncounted.

A custom form learns nothing by itself, as nothing marks its submissions as
spam or not spam: what the filter learns from it comes from Security > Journal.

## Forms of WordPress written by hand

The fields go into the forms of WordPress and WooCommerce through the hooks
those forms fire. A form written by hand that does not fire them posts no
timestamp, and every submission is refused:

| Form | Hook to fire inside the form |
|---|---|
| Comments | `comment_form()`, or `do_action( 'comment_form', $post_id )` |
| Login posted to `wp-login.php` | `wp_login_form()`, or `do_action( 'login_form' )` |
| Registration posted to `wp-login.php` | `do_action( 'register_form' )` |
| Lost password posted to `wp-login.php` | `do_action( 'lostpassword_form' )` |
| Network registration (`wp-signup.php`) | `do_action( 'signup_extra_fields', $errors )`, and `do_action( 'signup_blogform', $errors )` on the site step |
| WooCommerce My account | `do_action( 'woocommerce_login_form' )`, `woocommerce_register_form`, `woocommerce_lostpassword_form`, as its templates do |
| WooCommerce checkout | `do_action( 'woocommerce_after_checkout_billing_form', $checkout )` |

A form that cannot fire them is better turned off with the
`gecka_antispam_protect` filter than left refusing everyone.

## Markers of the form plugins

When the settings protect only the marked forms of a plugin, a form is
marked this way:

| Plugin | Marker |
|---|---|
| Contact Form 7 | The `[gecka_antispam]` form tag, placed where the fields go |
| Gravity Forms | The Antispam field, among the advanced fields of the form editor |
| ACF / Secure Custom Fields | `'gecka_antispam' => true` in the arguments of `acf_form()` or `acf_register_form()`, or an array naming the subject and the message |

The array names the fields the statistical filter reads, by field name or
key, sub fields of groups, repeaters and flexible contents included;
`post_title` and `post_content` stand for the title and the content of the
post, and a part left out keeps its default (the title as the subject, the
content and the textarea and editor fields as the message). Under `name`, it
names the text fields the random names check reads, which reads none
without it:

```php
acf_form( [
    'post_id'        => 'new_post',
    'post_title'     => true,
    'post_content'   => true,
    'gecka_antispam' => [
        'subject' => [ 'post_title' ],
        'message' => [ 'post_content', 'description', 'field_64f1a2b3c4d5e' ],
        'name'    => [ 'seller' ],
    ],
] );
```

Contact Form 7 and Gravity Forms find the subject and the message in the
form itself, and can be pointed elsewhere: see below.

## What the statistical filter reads

The filter reads the subject and the message of a submission, never the
sender. Each integration finds them in the structure of its forms, not in the
names of the fields. For each part the first rule that applies wins, and a
field found as both is read once, as the subject. Values are joined one per
line. The random names check reads the names of the sender only.

### Contact Form 7, and the Flamingo messages of its forms

Subject, the first rule that applies:

1. the fields the additional setting `gecka_antispam_subject` cites as mail
   tags: `gecka_antispam_subject: "[text-735]"`;
2. the fields the additional setting `flamingo_subject` cites;
3. the fields the subject of the Mail tab cites.

Only text, textarea, drop-down menu, radio and checkbox fields count as the
subject, whatever the rule, and never the fields of the sender: those
`flamingo_name` and `flamingo_email` cite, or `[your-name]` and
`[your-email]` without them.

Message, the first rule that applies:

1. the fields the additional setting `gecka_antispam_message` cites, as many
   as needed, of any type: `gecka_antispam_message: "[textarea-120] [text-9]"`;
2. every textarea field of the form.

A field marked `do-not-store` is never read. A Flamingo message is read by
the same rules, through the form it came from. Once that form is deleted, by
the names of its fields: a field counts when its name says subject or
message, or says nothing of the sender and its value reads as prose.

Random names, the first rule that applies:

1. the text fields the additional setting `gecka_antispam_name` cites:
   `gecka_antispam_name: "[text-12] [text-13]"`;
2. the text fields the additional setting `flamingo_name` cites;
3. the text fields named as a name, `your-name`, `first-name`, `nom`,
   `votre-prenom` and the like.

### Gravity Forms

Subject, the first rule that applies:

1. the fields carrying the CSS class `gecka-antispam-subject`, set under
   Appearance in the form editor;
2. the fields the subject of an active notification cites as merge tags,
   `{Subject:3}` for instance.

Only single line text, drop down, radio and checkbox fields count as the
subject, whatever the rule, and never a field a notification takes its
sender or recipient from: From Name, From Email, Reply To, Send To, BCC. The
default notification, "New submission from {form_title}", cites no field:
such a form has no subject until a notification cites one or a field carries
the class.

Message, the first rule that applies:

1. the fields carrying the CSS class `gecka-antispam-message`, of any type;
2. every paragraph, post title, post content and post excerpt field.

Random names, the first rule that applies:

1. the single line text and Name fields carrying the CSS class
   `gecka-antispam-name`;
2. the first and last names of the Name fields.

A submission made by code, through `GFAPI::submit_form()` or the submissions
route of the REST API, comes without the fields of the plugin: only the
filter rates its text, and the random names check does not run. The REST
route exists once the REST API is enabled in the settings of Gravity Forms,
and answers anyone.

### ACF and Secure Custom Fields

Subject, the first rule that applies:

1. the fields the `gecka_antispam` argument names under `subject`, by name
   or by key;
2. the title of the post, when the form shows it.

Only text, textarea, select, radio, checkbox and button group fields count
as the subject.

Message, the first rule that applies:

1. the fields the `gecka_antispam` argument names under `message`, of any
   type;
2. the content of the post when the form shows it, and every textarea and
   editor field.

Only the fields the form shows are read, from ACF's own list of them
(`get_allowed_field_keys()`), with the sub fields of its groups, repeaters
and flexible contents, every row, without their HTML. A field posted that the
form does not show is never read.

Random names: the text fields the `gecka_antispam` argument names under
`name`, by name or by key; none without it.

### Comments and product reviews

The content, with no subject. Random names: the name of the author. A
pingback or a trackback, which carries no form, is rated by the filter
alone.

### Login, registration, lost password, checkout, My account

These forms carry no message: the filter reads none of them, only the
checks of the form run. Random names: the username of a registration; on
WooCommerce, the first and last names of the billing address, or the
username of a registration.

### Your own forms

The `$text` passed to `gecka_antispam_check()`, the random names check on
`$names`, and the checks of the message on `$message`, or on the text
without it.

## Filters and actions

| Hook | Description |
|---|---|
| `gecka_antispam_protect` | Filter: whether a form is protected. Receives the setting, always true for a custom form, and the form (`comments`, `login`, `contact_form_7`, `custom:quote`...) |
| `gecka_antispam_checked` | Action: a submission was checked. Receives what caught it, null when it went through (a text held for review went through), and the form |
| `gecka_antispam_background_directory` | Filter: the directory the background tables are read from |
| `gecka_antispam_background_updates` | Filter: whether the plugin downloads the background tables and keeps them up to date, true by default |
| `gecka_antispam_background_manifest` | Filter: the URL of the manifest of the background tables, for a mirror; the tables come from its directory |
| `gecka_antispam_memory_limit` | Filter of WordPress, through `wp_raise_memory_limit()`: the memory limit set while the filter rates a text |
| `gecka_antispam_capability` | Filter: the capability a screen asks for. Receives `moderate_comments` for `stats` (statistics, dashboard widget) and `refused` (the Journal, its actions), `manage_options` for `settings` (both tabs of Settings > Antispam, the REST routes, the buttons resetting the statistics, the filter or the settings), and the screen. Both tabs of Settings > Antispam save one option, hence one capability |

```php
// Leave the login form of a membership site alone.
add_filter( 'gecka_antispam_protect', function ( $enabled, $surface ) {
    return 'login' === $surface ? false : $enabled;
}, 10, 2 );

// Keep the Journal, which holds the messages refused, to administrators.
add_filter( 'gecka_antispam_capability', function ( $capability, $screen ) {
    return 'refused' === $screen ? 'manage_options' : $capability;
}, 10, 2 );
```

The capabilities are read on `init`, when the screens are declared: add the
filter from a plugin or the `functions.php` of the theme.

The forms the hooks name are `comments`, `login`, `registration` (the
network signup of a multisite included), `lost_password`,
`woocommerce_checkout`, `woocommerce_reviews`, `woocommerce_login`,
`woocommerce_registration`, `woocommerce_lost_password`, `contact_form_7`,
`gravity_forms`, `acf`, and `custom:{name}` for a form of your own.

## REST routes

The settings page drives its long tasks through three routes of the
`gecka-antispam/v1` namespace, `POST`, for a user who has the capability of
the `settings` screen (`manage_options` by default), with the `X-WP-Nonce`
header of the REST API:

| Route | Does |
|---|---|
| `/learn-existing` | Learns what the site already holds for 5 seconds at most; answers what was learnt, what is left, and whether the filter failed |
| `/backgrounds/check` | Reads the release of the background tables and queues the tables to download; answers `busy` while another request updates |
| `/backgrounds/next` | Downloads the next table of the queue; answers `done` once the queue is empty, `busy` while another request updates |

The background routes answer 403 while the statistical filter is off, the
`gecka_antispam_background_updates` filter returns false, or PHP lacks the
intl or mbstring extension the filter needs.

## Data

| Where | What |
|---|---|
| `{prefix}gecka_antispam_stats` | Daily counters, by form and outcome |
| `{prefix}gecka_antispam_origins` | Daily counters, by country, network and operating system of the senders and by outcome: the code of the country, the number of the network with the name of its organisation, never the address |
| `{prefix}gecka_antispam_journal` | Refused submissions |
| `{prefix}gecka_antispam_counts`, `{prefix}gecka_antispam_meta` | Counters of the statistical filter |
| `wp-content/uploads/gecka-antispam/` | Background tables and snapshot of the counters |
| `gecka_antispam_settings`, `gecka_antispam_version`, `gecka_antispam_rotated`, `gecka_antispam_backgrounds` | Options |
| `gecka_antispam_backgrounds_lock` | Option held while a request checks or downloads the background tables |
| `gecka_antispam_backgrounds_queued_{user}` | Transient, one hour: the statistical filter tab of that administrator starts the downloads a save queued |
| `gecka_antispam_install_failed` | Transient, one hour: why the tables could not be set up, shown in a notice and in Site Health; the setup is tried again once it expires |
| `gecka_antispam_refused_per_page`, `gecka_antispam_refused_mode` | User meta and user setting: the screen options of the Journal tab; its hidden columns belong to the Journal screen, shared with other plugins, and stay |
| `_gecka_antispam_trained` | Comment and Flamingo message meta: `spam`, `ham`, or `skipped` for an item read in one go and left out |
| `_gecka_antispam_generation` | Comment and Flamingo message meta: the generation of the counters the item was learnt in |
| `_gecka_antispam_reason`, `_gecka_antispam_score` | Comment meta, shown in the Antispam column of the comments list |
| `gecka_antispam_trained`, `gecka_antispam_generation`, `gecka_antispam_reason` | Gravity Forms entry meta |
| `gecka_antispam_purge` | Daily event dropping the old counters and refused submissions, rotating the counters of the filter and checking the background tables |
| `gecka_antispam_backgrounds` | Event downloading the background tables once the plugin is set up |

Deleting the plugin removes all of it, on every site of a network. The
reason it gave in the spam log of a Flamingo message, or in the spam note of a
Gravity Forms entry, belongs to those plugins and stays.

## Development

```sh
composer install
composer format    # Pint
composer lint:php  # Pint check, then PHPCS
composer analyse   # PHPStan
composer test      # Pest
```

Translations, with WP-CLI:

```sh
composer i18n            # template, catalogs, .mo and .l10n.php, from the code
composer i18n:check      # what the CI runs: every string in the template, translated and compiled
```

WordPress loads the `.l10n.php` file before the `.mo` one; the `.mo` still
ships for the tools that read it, Loco Translate for one.

gecka/spamfilter and gecka/wp-admin-menu, which draws the screens, come from
[Packagist](https://packagist.org/packages/gecka/), at the versions
`composer.lock` pins.

## Package and release

What ships is what `.distignore` leaves: no tests, CI, tooling nor
`README.md`, and the dependencies without the dev ones. `bin/package <dir>`
copies it into a directory, from a tree whose `vendor/` was installed with
`composer install --no-dev`; `bin/zip <dir> <archive>` zips such a
directory as the top folder of the archive, as WordPress installs a plugin
from a zip; `bin/build [dir]` does both, into `builds/` by default.
`bin/changelog <version>` prints the changelog entry of a version from
`readme.txt`.
`bin/check-version [version]` checks that the header of `bootstrap.php`,
`Plugin::VERSION` and the Stable tag of `readme.txt` agree, and match the
version given.

WordPress.org reads the Stable tag in `trunk/readme.txt`, then shows the
`readme.txt` of `tags/<version>/`: a change to the page goes out with a
release. Banners, icons and screenshots of the page go in `.wordpress-org/`
(`icon-256x256.png`, `banner-772x250.png`, `banner-1544x500.png`,
`screenshot-1.png`...), published to the `assets` directory of the SVN.

A release:

1. set the version in the header of `bootstrap.php`, in `Plugin::VERSION` and
   in the Stable tag of `readme.txt`, and add its changelog entry;
2. tag it `vX.Y.Z` and push the tag to GitHub and GitLab: each makes the
   release of the tag, titled after the message of the tag, with the
   changelog entry and `gecka-antispam-X.Y.Z.zip`, the zip to install from
   the admin of WordPress (on GitLab, the zip sits in the package registry
   of the project);
3. start the publication by hand, on that tag, on one side only: the
   "Publish on WordPress.org" workflow on GitHub (Actions, Run workflow, the
   tag as ref), or the `wordpress.org` job of the tag pipeline on GitLab.

Both check the versions, refuse a version WordPress.org already has, then
copy the package to `trunk`, `.wordpress-org/` to `assets`, and `trunk` to
`tags/X.Y.Z`. They need the WordPress.org account and its SVN password
(Account & Security on WordPress.org) as `SVN_USERNAME` and `SVN_PASSWORD`:
secrets of the GitHub repository, masked and protected variables on GitLab,
where the `v*` tags must then be protected.

The first version is not published this way: the zip of its release goes
through the submission form of WordPress.org, and the SVN repository exists
once the plugin is approved.
