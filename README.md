![](.github/banner.svg)

[![CI](https://github.com/Gecka-Apps/wordpress-plugin-gecka-antispam/actions/workflows/ci.yml/badge.svg)](https://github.com/Gecka-Apps/wordpress-plugin-gecka-antispam/actions/workflows/ci.yml)
[![WordPress 6.8+](https://img.shields.io/badge/WordPress-6.8%2B-21759b?logo=wordpress&logoColor=white)](readme.txt)
[![PHP 8.2+](https://img.shields.io/badge/PHP-8.2%2B-777bb4?logo=php&logoColor=white)](readme.txt)
[![License](https://img.shields.io/badge/license-GPL--3.0--or--later-blue.svg)](LICENSE)

# Gecka Antispam for WordPress

Every form of a site exposed to the internet receives spam: comments,
contact forms, registrations, reviews. Gecka Antispam refuses the
submissions that look automated, and rates the others with a filter trained
on your own moderation. It shows no captcha, keeps what your visitors write
on your server, and requires no external account.

## 🛡️ Principles

- **No captcha.** The checks tell a browser from a bot by what each one
  sends with the form. The visitor is asked nothing.
- **Nothing leaves the server.** The checks and the statistical filter run
  on your site. No name, email address or IP address of a sender is kept,
  and no cookie is set.
- **It learns from your moderation.** Each comment, Flamingo message or
  Gravity Forms entry marked as spam, or as legitimate, trains the filter on
  the spam your site receives, in its languages.
- **No silent refusal.** A refused submission gets an error, and the sender
  can send again. A person caught by mistake loses nothing.
- **Sensible defaults.** Every form is protected on activation. Most sites
  need no configuration beyond it.

## 📝 Protected forms

| Plugin | Forms |
|---|---|
| WordPress | Comments, login, registration, lost password, network registration (`wp-signup.php`) |
| WooCommerce | Classic checkout, product reviews, My account login, registration and lost password |
| Contact Form 7 | Every form, or the forms holding the `[gecka_antispam]` tag |
| Gravity Forms | Every form, or the forms holding the Antispam field |
| ACF, ACF Pro, Secure Custom Fields | Every front-end form (`acf_form()`), or the forms holding the marker |
| Your own forms | Those whose code calls `gecka_antispam_fields()` and `gecka_antispam_check()` |

Each form of WordPress and WooCommerce can be switched off in
Settings > Antispam; each of the other plugins protects every form, or only
the forms holding its marker. The markers, what each form shows the sender
when it is refused, and the cases a plugin handles its own way, are in
[docs/FORMS.md](docs/FORMS.md).

## 🚦 What happens to a submission

Two kinds of checks run, in this order: the checks of the form, then the
statistical filter.

| Verdict | Who | The sender sees | The submission goes |
|---|---|---|---|
| ⛔ Refused | A check of the form; the filter, from the rejection threshold (95 %) | An error, and can send again | Nowhere but Security > Journal, when it carries a text |
| 🗑️ Spam | The filter, from the spam threshold (75 %) | What the form shows for spam | To the spam of its plugin: the spam queue, the spam of Flamingo, the spam of Gravity Forms |
| 👀 To review | The filter, from the acceptance threshold (55 %) | Nothing | Through, flagged: a comment waits for moderation, a Gravity Forms entry gets a note, a Contact Form 7 message shows it in the Antispam column of Flamingo |
| ✅ Accepted | | Nothing | Through |

The login, registration, lost password and checkout forms carry no text to
rate: only the checks of the form run. A moderator is never checked.

## 🍯 Checks of the form

Every protected form gets two hidden fields, and every submission is read:

- **Signed timestamp.** A form sent without it, with a forged one, in less
  than 5 seconds (none on the login forms) or more than 8 days after it was
  shown is refused. A page served from a cache carries the time it was
  cached at; the delay and the maximum age are settings.
- **Honeypot.** A text field people never see, under a name drawn at random
  on each site, which bots fill in. Browsers and password managers leave it
  alone.
- **Random letters.** A name like `qASQAhqkpFGqnKkRROl` in the author of a
  comment, the user name of a registration, the billing names of a checkout
  or the name fields of a form, and a message made of a single such word.
- **Too few words.** A message of fewer than five words is refused, on every
  form that has one, and the sender is told how many words it takes. The
  number is a setting, 0 for none.
- **Bad browsers.** A submission sent with no user agent, or with one
  wrapped in quotes, is refused: no browser sends either.

These checks stop the bots that post without loading the form, or fill in
every field. A bot that loads the page before posting gets a valid timestamp
and can read which field to leave empty: the statistical filter covers
those. What each check reads on each form is in
[docs/FORMS.md](docs/FORMS.md).

## 🧠 Statistical filter

The plugin ships [gecka/spamfilter](https://github.com/Gecka-Apps/spamfilter),
a statistical filter for short texts, and keeps its counters in your
database. It rates the subject and the message of the comments, the Contact
Form 7 messages, the Gravity Forms entries, the ACF front-end forms and your
own forms, from 0 to 100 % spam.

- **Trained on your site.** It learns each time a moderator marks a comment,
  a Flamingo message or a Gravity Forms entry as spam or not spam, or learns
  a refused submission from the Journal. What the site already moderated
  can be learnt in one go, from the settings.
- **Three thresholds.** From 95 % a message is refused, from 75 % it goes to
  the spam of its plugin, from 55 % it passes flagged for review. All three
  are settings.
- **Background tables.** The word frequencies of each language of the site,
  downloaded from the releases of
  [spamfilter-backgrounds](https://github.com/Gecka-Apps/spamfilter-backgrounds),
  tell a common word from a rare one before the site has learnt much. This
  is the only external request the plugin makes, and it waits for an
  administrator to allow it.
- **Counters that age.** Every six months the counters rotate and the older
  ones halve, so the spam of today outweighs the campaigns of past years.
- **A learning period.** It rates nothing before it has learnt 20 spam
  texts and 10 legitimate ones.

What the filter reads on each form, where its tables live, how it learns
and rotates: [docs/STATISTICAL-FILTER.md](docs/STATISTICAL-FILTER.md).

## 🗂️ Refused submissions

The Antispam tab of Security > Journal lists the submissions refused that
carry a text: the subject and the message, with the form, the reason and the
dates, nothing of the sender. From there an entry is learnt as spam, learnt
as legitimate when a person was refused, or deleted, one by one or in bulk;
a learning can be undone. Entries are kept 30 days, 5,000 at most.
Whoever moderates comments sees the Journal; the `gecka_antispam_capability`
filter keeps it to administrators.

## 📊 Statistics

- **Statistics** over 7, 30, 90 or 365 days, in the Antispam tab of
  Security > Statistics: the submissions checked, accepted, to review and
  caught, day by day, the share of each check in what was caught, and the
  counts by form.
- **Origins**: the submissions caught, or accepted, by operating system and,
  with [Gecka Geolocation](https://github.com/Gecka-Apps/wordpress-plugin-gecka-geolocation),
  by country and by network, with their flags and logos. The address itself
  is never read nor kept.
- **Dashboard widget** summing up the last seven days.
- **Antispam column** in the comments and in Flamingo, with the rating of
  each message, why the plugin held it and what it was learnt as.

Only daily counts are kept, by form, outcome, country, network and system:
no address, no content. They are kept 365 days by default.

## ⚙️ Settings

The settings and the statistical filter are the two tabs of
Settings > Antispam; the statistics and the refused submissions are Antispam
tabs of the Security menu, which the Gecka plugins share. Whoever moderates
comments, editors included, sees the statistics, the widget and the Journal;
the settings and the filter are for administrators. "Restore the default
settings" puts every setting back but the name of the honeypot, which the
forms already shown or cached carry.

## 🩺 Site Health

Tools > Site Health reports what keeps the plugin from working: a table the
database refused to create, the daily task not running, a filter switched
on but unable to rate, background tables missing, left out or weak, a
snapshot of the counters it cannot write. The Info tab sums up the plugin
for support, with nothing of the senders.

## 🔒 Privacy

No cookie is set and no IP address is kept. The filter keeps counts on
hashes of the words it read, never the text, and nothing ties a count to a
sender. The Journal keeps the subject and the message of the submissions
refused, without the name or the email address of the sender, for 30 days.
The rating and the reason are stored with the comment or the Gravity Forms
entry, and go with it. A paragraph for the privacy policy of the site is
offered under Settings > Privacy.

## 🧩 Works with

- **[Gecka Geolocation](https://github.com/Gecka-Apps/wordpress-plugin-gecka-geolocation)**
  locates the submissions on your server, and breaks the statistics down by
  country and network, with their flags and logos.
- **[Gecka Security](https://github.com/Gecka-Apps/wordpress-plugin-gecka-security)**
  locks out the addresses that keep failing logins. The two cover different
  ground: Antispam refuses the submissions that look automated, Security
  limits what an address can try. A login refused by Antispam is not counted
  as a failed password. Both plugins share the Security menu, each adding
  its tabs to the Statistics and Journal pages.
- **Flamingo** keeps the Contact Form 7 messages, and gives the filter its
  inbox and its spam to learn from.

## 🙅 Out of scope

Gecka Antispam does not show a captcha, limit what an address can try or
lock addresses out, which is what Gecka Security does. Comments and
logins made through the REST API or XML-RPC, the checkout block and the
payment buttons of WooCommerce take routes that run no form and are not
checked; a pingback or a trackback is rated by the filter alone. The
submissions route of the REST API of Gravity Forms skips the form too: leave
it off unless something needs it.

## 📋 Requirements

- WordPress 6.8 or later, single site or multisite
- PHP 8.2 or later, with the intl and mbstring extensions for the
  statistical filter. Installed from its zip, the plugin runs without them,
  the filter switched off; installed with Composer, it needs them
- Composer 2, if you install the plugin with Composer

Protecting a form of your own, the hooks a form written by hand has to
fire, the filters, the REST routes and the stored data are documented in
[docs/DEVELOPERS.md](docs/DEVELOPERS.md).

## 📜 License

Copyright 2026 Gecka. GPL-3.0-or-later. gecka/spamfilter is under the
AGPL-3.0-or-later.

---
Built with 🥥 and ☕ by [Gecka](https://gecka.nc) — Kanaky-New Caledonia 🇳🇨
