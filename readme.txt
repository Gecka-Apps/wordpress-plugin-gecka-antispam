=== Gecka Antispam ===
Contributors: gecka, ldinclaux
Tags: spam, antispam, honeypot, comments, contact form 7
Requires at least: 6.8
Tested up to: 7.1
Requires PHP: 8.2
Stable tag: 1.0.0
License: GPL-3.0-or-later
License URI: https://www.gnu.org/licenses/gpl-3.0.html

Stops spam on comments, login, registration, WooCommerce, Contact Form 7, Gravity Forms and ACF forms. No captcha, submissions stay on the site.

== Description ==

Every protected form gets a signed timestamp and a honeypot, a field people never see and bots fill in. A submission without the timestamp, sent faster than anybody types, with the honeypot filled in, or with a name, or a message of a single word, made of random letters, like qASQAhqkpFGqnKkRROl, is refused with an error, which lets a person send it again. A minimum of words can be set for the message, and a submission sent with no user agent, or with one no browser sends, is refused too.

Protected forms:

* WordPress: comments, login, registration, lost password
* WooCommerce: classic checkout (not the checkout block, nor the payment buttons of product and cart pages), product reviews, My account login, registration and lost password, the login of the app authorization screen
* Contact Form 7: every form, or the forms holding the `[gecka_antispam]` form tag
* Gravity Forms: every form, or the forms holding the Antispam field
* ACF, ACF Pro and Secure Custom Fields: every front-end form, or the forms whose `acf_form()` arguments hold `'gecka_antispam' => true`
* WordPress multisite: the network registration form
* Your own forms, through `gecka_antispam_fields()` and `gecka_antispam_check()`: see docs/DEVELOPERS.md, in the folder of the plugin

= Statistical filter =

The plugin ships gecka/spamfilter, a statistical filter for short texts. It rates the subject and the message of the comments, the Contact Form 7 messages, the Gravity Forms entries and the ACF front-end forms, from 0 to 100 % spam, against three thresholds:

* from 95 %, the text is refused, as by the checks of the form
* from 75 %, it is marked as spam: it goes to the spam queue, the spam of Flamingo or the spam of Gravity Forms, where it can be marked as not spam
* from 55 %, it goes through flagged for review: a comment waits for moderation, a Gravity Forms entry gets a note, a Contact Form 7 message shows it in the Antispam column of Flamingo

An ACF front-end form has no spam queue: it is refused from 95 % and goes through below.

It learns from what a moderator marks as spam or as not spam in the comments, in Flamingo, in Gravity Forms and in Security > Journal, from the comments approved, and from the Flamingo messages and Gravity Forms entries confirmed as legitimate. A button of the statistical filter tab has it learn, in one go and with a progress bar, the comments, messages and entries already marked on the site. Spam is learnt that way only when a person or Akismet marked it, never what the filter caught itself. It rates nothing until it has learnt 20 spam texts and 10 legitimate ones, two settings. Its counters age: a text counts in full for 6 to 12 months, then its weight halves every 6 months, so the spam of today outweighs the campaigns of past years. Flamingo gets an Antispam column showing the rating of each message.

The filter needs the intl and mbstring extensions of PHP. It compares what it learnt with background tables, which tell a common word from a rare one in each language: the plugin downloads those of the languages of the site and English, or of the languages a setting names, with a progress bar, and keeps them up to date. The statistical filter tab shows each table, the sentences it was drawn from and its quality.

= Refused submissions =

The submissions refused, by a check of the form or by the filter, land in the Antispam tab of Security > Journal, nowhere else: not in the spam queue, nor in Flamingo, nor in Gravity Forms. Each can be learnt as spam, or as legitimate, or deleted, from the links under its text or in bulk; one learnt the wrong way can be learnt the other way or unlearnt. While the filter is on, a column shows, for information, how it rates each text now. They are kept 30 days.

= Statistics =

The Antispam tab of Security > Statistics shows the submissions checked, accepted, to review and caught over 7, 30, 90 or 365 days, by form and by check; the statistical filter tab of Settings > Antispam shows what the filter learnt. A dashboard widget sums up the last seven days. The submissions caught or accepted are also counted by operating system and, with the Gecka Geolocation plugin, by country and by network, with their flags and logos: the address itself is never read nor kept. Only daily counts are kept: no address, no content. Site Health tests the tables of the plugin, the daily task, the statistical filter, its background tables and the snapshot of its counters, and its Info tab sums up the plugin for support.

= Privacy =

Nothing of the submissions leaves the site: the only requests the plugin makes download its background tables, see External services. It keeps daily counts of the submissions it checks, counts on hashes of the words of the subject and message of the texts marked as spam or not spam, and the subject and message of the submissions refused, until 30 days after the text was last sent. It keeps no name, no email address and no IP address of a sender, and sets no cookie, though a refused message may hold personal details the sender wrote in it. Words a sender typed in a message, a phone number in a signature for one, enter the counts as hashes and cannot be erased for one person. A paragraph for the privacy policy of the site is offered under Settings > Privacy.

The statistical filter is gecka/spamfilter, under the AGPL-3.0-or-later.

= External services =

The plugin downloads the background tables of the statistical filter from the releases of the spamfilter-backgrounds project on GitHub (https://github.com/Gecka-Apps/spamfilter-backgrounds): the manifest of the latest release, then the table of each language wanted, about 1 MB each. It does so once activated, when the languages setting changes, from the button of the statistical filter tab, and once a week from its daily task, while the statistical filter is on. The requests send nothing but what any download sends, the IP address of the server among it, under a user agent naming the plugin; nothing of the site, its visitors or its submissions. GitHub terms of service: https://docs.github.com/en/site-policy/github-terms/github-terms-of-service, privacy statement: https://docs.github.com/en/site-policy/privacy-policies/github-general-privacy-statement. The `gecka_antispam_background_updates` filter returning false stops the downloads.

= Development =

The plugin is developed on GitHub, where bugs can be reported and changes suggested: https://github.com/Gecka-Apps/wordpress-plugin-gecka-antispam. Questions on using it are welcome in the support forum.

== Installation ==

Copy the plugin folder into `wp-content/plugins/` and activate it, or install it from the plugins screen. Every form is protected at once; Settings > Antispam lets you switch forms off and tune the checks.

== Frequently Asked Questions ==

= My pages are served from a cache. Does it work? =

Yes, as long as the cache keeps a page less than 8 days, the default maximum age of a form: a cached form carries the time it was cached at. With a longer cache, raise the "Maximum age of a form" setting, or set it to 0 for no limit.

= A password manager fills the login form at once. Will it be caught? =

No. The login and lost password forms have no minimum delay by default.

= Does it stop every bot? =

No. The honeypot and the timestamp stop the bots that post without loading the form, or fill in every field. A bot that reads the page first can get past them: the statistical filter is there for those. So is a bot posting to the submissions route of the REST API of Gravity Forms, which skips the form, once that API is enabled in the settings of Gravity Forms: leave it off unless something needs it.

= Can I protect a form I wrote myself? =

Yes. `gecka_antispam_fields( 'my-form' )` prints the fields inside the form, `gecka_antispam_check( 'my-form', $text, $names )` checks what it posts and tells whether to refuse it. docs/DEVELOPERS.md, in the folder of the plugin, explains both, the hooks a comment or login form written by hand has to fire, the filters and actions, and what the plugin stores.

= Contact Form 7 warns "Unsafe email config is used without sufficient protection". =

Contact Form 7 shows it for a form whose mail goes to the address the sender typed, unless its own reCAPTCHA or Turnstile is active. Gecka Antispam leaves the warning out of the forms it protects; save the form again for Contact Form 7 to check it anew. Keep such a mail to an acknowledgement that repeats nothing the sender wrote: the checks stop bots, not a person.

= What is left behind when the plugin is deleted? =

Its tables, refused submissions, options, scheduled events, meta and its directory under uploads, background tables included, are removed, on every site of a network. The reason it gave in the spam log of a Flamingo message, or in the spam note of a Gravity Forms entry, belongs to those plugins and stays.

== Screenshots ==

1. The statistics: submissions checked, accepted and caught over the period, with the share of each check.
2. Where the spam comes from: countries, networks and systems, with the flags and logos of Gecka Geolocation.
3. The refused submissions, to review, learn from or delete.
4. The dashboard widget: the last seven days at a glance.
5. The Antispam column of the comments, with the spam rating of each one.
6. The statistical filter: what it learnt, when it rotates, and the comments and messages of the site it can still learn from.
7. The background tables: the word frequencies of each language of the site, downloaded and kept up to date.
8. The thresholds of the filter: refused, marked as spam, flagged for review, the texts it needs before it rates anything, and the rotation period.
9. The forms protected: WordPress, WooCommerce, Contact Form 7, Gravity Forms and ACF, every form or only those holding the marker.
10. The checks for bots: honeypot, timing, random names and texts, browsers that are none.
11. How long the statistics are kept.

== Changelog ==

= 1.0.0 =

* Honeypot, signed timestamp and random name check on the forms of WordPress, WooCommerce (product reviews included), Contact Form 7, Gravity Forms and ACF.
* Contact Form 7, Gravity Forms and ACF protect every form, or only the forms holding a marker.
* Submissions caught by a check of the form refused with an error, and kept for review in Security > Journal.
* Statistical filter trained by moderators from the spam marked in the comments, Flamingo, Gravity Forms and Security > Journal, and from what the site already holds, in one go. Three thresholds: refused, spam, flagged for review.
* Statistics screen and dashboard widget.
* Privacy policy paragraph, and a button restoring the default settings.
