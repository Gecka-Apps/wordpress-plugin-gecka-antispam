# Gecka Antispam for WordPress

Stops spam on the forms of WordPress, WooCommerce, Contact Form 7, Gravity
Forms and ACF. No captcha to solve, and nothing of the submissions goes to an
external service: the checks and the statistical filter run on your server.
Its settings are under Settings > Antispam, its statistics and the submissions
it refused in the Security menu.

This file is for whoever runs a site. Developers protecting a form of their
own, writing a form by hand, or looking for the hooks and the data, will find
it all in [docs/DEVELOPERS.md](docs/DEVELOPERS.md).

## 📋 Requirements

- WordPress 6.8 or later
- PHP 8.2 or later, with the intl and mbstring extensions for the statistical
  filter. Installed from its zip, the plugin runs without them, the filter
  switched off; installed with Composer, it needs them, as the library does
- Composer 2, if you install the plugin with Composer

## 🛡️ Protected forms

| Plugin | Forms |
|---|---|
| WordPress | Comments (visitors not logged in), login, registration, lost password, network registration (`wp-signup.php`) |
| WooCommerce | Classic checkout, product reviews (visitors not logged in), My account login, registration and lost password |
| Contact Form 7 | Every form, or the forms holding the marker |
| Gravity Forms | Every form, or the forms holding the marker |
| ACF, ACF Pro, Secure Custom Fields | Every front-end form (`acf_form()`), or the forms holding the marker |
| Your own forms | Those whose code calls `gecka_antispam_fields()` and `gecka_antispam_check()`, see [docs/DEVELOPERS.md](docs/DEVELOPERS.md) |

Each form of WordPress and WooCommerce can be switched off in
Settings > Antispam. Each of the other plugins is off, protects every form, or
protects only the forms holding its marker:

| Plugin | Marker |
|---|---|
| Contact Form 7 | The `[gecka_antispam]` form tag, placed where the fields go. Without it, the fields go before the submit button |
| Gravity Forms | The Antispam field, among the advanced fields of the form editor. Without it, the fields go before the submit button |
| ACF / Secure Custom Fields | `'gecka_antispam' => true` in the arguments of `acf_form()` or `acf_register_form()`, or an array naming the subject and the message ([docs/DEVELOPERS.md](docs/DEVELOPERS.md)) |

The ACF marker is read back from the form ACF rebuilds on submission, from
its registry or from the encrypted copy the form posts: a visitor can neither
add nor remove it. A submission caught is refused with an error page, as ACF
does with the errors of its own checks.

Contact Form 7 warns about a form whose mail goes to the address the sender
typed, a Mail (2) to `[your-email]` for instance, unless its own reCAPTCHA or
Turnstile is active ([unsafe email without protection](https://contactform7.com/configuration-errors/unsafe-email-without-protection/)).
The plugin leaves that warning out of the forms it protects, since its
checks play the same part. Contact Form 7 records the warning when a form is
saved: save the form again after installing the plugin. The checks stop
bots, not a person, so a Mail (2) is best kept to an acknowledgement that
repeats nothing the sender wrote.

The WooCommerce checkout block posts to the Store API, which runs none of the
hooks of the classic checkout: only the `[woocommerce_checkout]` shortcode is
protected. Payment buttons that place an order from a product or cart page,
Apple Pay or Google Pay for instance, do not go through its form and are left
alone. The login form of the app authorization screen (`/wc-auth/`) gets the
fields and the checks of the My account login: WooCommerce processes a login
form posted to any address, so none is exempt.

A POST to `wp-login.php` is checked whatever fields it carries: the login,
registration and lost password screens act on the request method alone. A
login is checked once WordPress has found the user name; a name that does not
exist gets the error of WordPress and is not counted. The registration of a
network, `wp-signup.php`, is checked like that of `wp-login.php`, at its user
step and at its site step, which keeps the time the first step was shown at;
the network administration creating users is left alone.

## 🚦 What happens to a submission

Two kinds of checks run, in this order: the checks of the form, then the
statistical filter.

| Verdict | Who | The sender sees | The submission goes |
|---|---|---|---|
| ⛔ Refused | A check of the form; the filter, from the rejection threshold (95 %) | An error, and can send again | Nowhere but Security > Journal, when it carries a text |
| 🗑️ Spam | The filter, from the spam threshold (75 %) | What the form shows for spam | To the spam of its plugin: the spam queue, the spam of Flamingo, the spam of Gravity Forms |
| 👀 To review | The filter, from the acceptance threshold (55 %) | Nothing | Through, flagged: a comment waits for moderation, a Gravity Forms entry gets a note, a Contact Form 7 message shows it in the Antispam column of Flamingo |
| ✅ Accepted | | Nothing | Through |

The login, registration and lost password forms, of WordPress and of
WooCommerce, and the checkout carry no text to rate: only the checks of the
form run, and a submission they catch is refused with an error and counted,
with no entry in the Journal. The forms of ACF have no spam queue: the
filter refuses them from the rejection threshold and lets the others through.

A comment is refused with an error page; a Contact Form 7 message with the
message its form shows for spam, and no copy in Flamingo; a Gravity Forms
submission fails its validation, and no entry is saved.

## 🍯 Checks of the form

Every protected form gets two fields:

- a **signed timestamp**, hidden. A submission without it, or with a forged
  one, is caught. So is a form sent faster than the minimum delay: 5 seconds
  by default, none for the login and lost password forms, which password
  managers fill and send at once. A timestamp older than 8 days is caught
  too, so that one taken from the page cannot serve for ever. A page served
  from a cache carries the timestamp of the moment it was cached: when pages
  stay cached longer than a week, raise the setting, or set it to 0 for no
  limit. A form shown again after a post, the next page of a multipage
  Gravity Forms form or a form back with its errors, keeps the time it was
  first shown at.
- a **honeypot**, a text field people never see. Bots fill it in.

The honeypot follows the usual advice:

- it is hidden by a class set to `display: none`, not moved off screen:
  browsers autofill a field off screen, never one that is not rendered
- its name is drawn at random on each site, from words a bot fills in and no
  browser autofills (`fax_x7k2`, `homepage_q3zt`...)
- `tabindex="-1"`, `aria-hidden="true"`, `autocomplete="off"`, and the
  attributes 1Password, LastPass, Bitwarden and Dashlane read to leave a
  field alone
- its label asks to leave it empty, for whoever meets it with no style sheet

A third check catches **names made of random letters**, like
`qASQAhqkpFGqnKkRROl`: in the comment author, the user name of a
registration, the billing names of a checkout, the name fields of Contact
Form 7 and Gravity Forms, and the fields the marker of an ACF form names.
A form can point it at its own fields: the additional setting
`gecka_antispam_name` (or `flamingo_name`) of Contact Form 7, the CSS class
`gecka-antispam-name` of Gravity Forms, the `name` key of the ACF marker
([docs/DEVELOPERS.md](docs/DEVELOPERS.md#what-the-statistical-filter-reads)).

A user logged in gets no fields in the comment form: the comments of a user
who cannot moderate them are rated by the statistical filter alone, those of
a moderator are not checked. A Gravity Forms submission made by code, through
the submissions route of its REST API or `GFAPI::submit_form()`, is rated by
the filter alone too.

That route answers anyone, with no login, once the REST API is enabled in the
settings of Gravity Forms: a bot posting there skips the honeypot, the
timestamp and the random names check, and the filter, until it has learnt
enough to rate, lets it through. Leave the REST API of Gravity Forms off
unless something needs it.

These checks stop the bots that post without loading the form, or fill in
every field. The timestamp is bound to no visitor and can be sent again
until it is 8 days old: a bot that loads the page once in a while gets a
valid one, and can read which field to leave empty. The statistical filter
is there for those. 🧠

## 🗂️ Refused submissions

The Antispam tab of Security > Journal lists the submissions refused that
carry a text, the most recent first, and the Security menu shows how many
wait. Each holds what the filter reads of the submission, the subject and
the message, with the form, the reason and the dates; nothing of the sender.
The same text sent again counts on the entry it already has. An entry can be
learnt as spam, or as legitimate when a person was refused, or deleted, from
the links under its text or in bulk. An entry learnt moves to the Learnt view, marked with
what it was learnt as: there it can be learnt the other way, which takes
back the first learning, or unlearnt back to review, as long as the counters
did not rotate twice since; deleting an entry leaves what was learnt of it.
Entries are kept 30 days, 5,000 at most, learnt or not.

While the statistical filter is on, a column gives the spam rating of each
text, for information: what the filter makes of it now, rated as the page
loads. Most entries were refused by a check of the form before any rating,
and the rating moves as the filter learns; it stays empty while the filter
is still learning.

The list is a WordPress list table, paged above and below. Its Screen
Options set the columns shown, the entries per page (50 by default) and the
display mode: the compact view folds a text past 300 characters, the
extended view shows it whole.

## 🧠 Statistical filter

The plugin ships [gecka/spamfilter](https://github.com/Gecka-Apps/spamfilter),
a statistical filter for short texts, and keeps its counters in two tables of
the site. It rates the subject and the message of the comments, the Contact
Form 7 messages, the Gravity Forms entries, the front-end forms of ACF and
your own forms, from 0 to 100 % spam; 50 % means it knows nothing of the
text. It reads the first 20,000 characters of a text.

### 🔎 What it reads

What counts as subject and message comes from the form itself, never from
the name of a field:

- **Contact Form 7**, and the Flamingo messages of its forms: the subject is
  the fields the subject of the mail cites, the message every `textarea`
  field. Two additional settings of the form, written as mail tags, override
  them, each citing as many fields as needed:

  ```
  gecka_antispam_subject: "[text-735]"
  gecka_antispam_message: "[textarea-120] [textarea-121] [text-9]"
  ```

  `flamingo_subject` stands for the subject when set. The fields Contact
  Form 7 takes for the sender (`flamingo_name`, `flamingo_email`, or
  `[your-name]` and `[your-email]`) and the fields typed as an email address,
  a phone number, a URL, a number, a date or a file never count as the
  subject. Fields marked `do-not-store` are left out.
- **Gravity Forms**: the subject is the fields the subject of an active
  notification cites as merge tags (`{Subject:3}`), the message every
  paragraph, post title, post content and post excerpt field. The CSS classes
  `gecka-antispam-subject` and `gecka-antispam-message`, set on fields under
  Appearance in the form editor, override them, on as many fields as needed.
  A subject is a single line text, drop down, radio or checkbox field, never
  a field a notification takes its sender or recipient from (From name, From
  email, Reply to, Send to, BCC). The default notification, "New submission
  from {form_title}", cites no field: such a form is read by its paragraph
  fields until a notification cites the subject or a field carries the class.
- **ACF and Secure Custom Fields**: among the fields the form shows, and
  the sub fields of its groups, repeaters and flexible contents, every row,
  the subject is the title of the post, the message its content with every
  textarea and editor field, without their HTML. The marker, given as an
  array in the code of the form, names them instead
  ([docs/DEVELOPERS.md](docs/DEVELOPERS.md)). A subject is a text,
  textarea, select, radio, checkbox or button group field. The fields come
  from ACF's own list of the fields the form shows
  (`get_allowed_field_keys()`), so a field posted that the form does not
  show is never read. These forms teach the filter nothing: nothing marks
  their submissions as spam or not spam.
- **Comments**: the content.
- **Your own forms**: the text their code passes to `gecka_antispam_check()`.

When several rules could apply, the first wins: the order of the rules,
form by form, and the fields the random names check reads, are in
[docs/DEVELOPERS.md](docs/DEVELOPERS.md#what-the-statistical-filter-reads)
and in the Help of the settings page.

A Flamingo message whose form was deleted is read by the names of its
fields: a field counts when its name says subject or message, or says
nothing of the sender and its value reads as prose. The counters are
counts on hashes of the words, links, mail domains and the like: no text is
stored in them.

### 🌍 Background tables

The filter compares what it learnt with **background tables**, one per
language, which tell a common word from a rare one before the site has
learnt much. They are published with the library, one `.bin` file per
language
([spamfilter-backgrounds](https://github.com/Gecka-Apps/spamfilter-backgrounds)),
and the plugin downloads them into
`wp-content/uploads/gecka-antispam/background/`, named after their language
code (`fr.bin`, `en.bin`). Without them the filter still works, but a text in
a language it learnt from spam only is taken for spam. Each table costs 4 MB
of memory when a text is rated, as do the counters of each class.

The background tables sit in the State section of the statistical filter
tab, with their languages: a field of tags suggesting the languages of the
release with the sentences of their tables, five at most. What the tables
are, why the filter needs them and which languages to choose is in the
Background tables tab of the Help, which the question mark next to the
heading opens. Left empty, the languages are those of the site, those of WPML or
Polylang when one of them is active, and English, which most sites receive.

Saving the languages downloads nothing: the tables no longer wanted go at
once, and the tab, back from the save, downloads the others through the REST
API, one table per request with its progress; the "Update the background
tables" button does the same. The scheduled event does it outside a visit,
once the plugin is activated, after a save, and every week from the daily
task, which reads the manifest of the latest release again, or the next day
while a table is missing or the release could not be read, starting tables
for 20 seconds per run. Two requests never download at once. Each download,
redirections included, takes 25 seconds at most, refuses a size larger than
a table can be, is checked against the size, the SHA-256 and the feature
hash version the manifest announces, and comes only from the directory of
the manifest; it replaces the file in place in one step, and a failed one
leaves the table in place. A table the plugin installed goes when its
language is no longer wanted; one copied by hand stays. The requests go to
GitHub through the HTTP API of WordPress, with a user agent naming the
plugin and nothing of the site. With `WP_HTTP_BLOCK_EXTERNAL`,
`WP_ACCESSIBLE_HOSTS` must hold `github.com` and `*.githubusercontent.com`,
where GitHub serves the files of a release.

The State section lists each table with its sources, the sentences it was
drawn from and its quality: solid from 100,000 sentences, average from
10,000, weak from 1,000, poor below (the release ranges from 56 sentences to
300,000). These thresholds are estimates: the benchmarks only measured
tables of 300,000 sentences. It also shows the words of the dictionary of
the language, the counters the table fills, and whether it is up to date,
has an update, was copied by hand or failed.

The `gecka_antispam_background_directory` filter moves the directory, and
`gecka_antispam_background_updates` returning false stops the downloads, for
a server that fills the directory itself.

The filter reads five tables at most, the language of the site first. A file
whose name is not a language code, one that is not a background table, and
one holding more counters than a class of the site (2^20) are left out; the
filter reads on with the others, and the statistical filter tab and Site
Health name the files left out and why.

### 🎓 What it learns

As things happen, it learns from what a moderator marks, as long as the
person who makes the change can moderate that kind of item; a status a
scheduled task or another plugin gives, Akismet for one, is not learnt:

- **comments and product reviews**: "Mark as spam" and "Not spam" in the
  comments screen, and a comment approved from the moderation queue
  (setting). The comments list gets an Antispam column showing the rating the
  comment got when it was posted, why the plugin held it, and what it was
  learnt as
- **Flamingo**: "Mark as spam" and "Not spam", from the row, the bulk actions
  or the message screen. The inbox gets an Antispam column, and the message
  screen a box, showing the rating of the message, whether it is to review,
  and what it was learnt as. A message of the inbox, one held for review
  first, is confirmed as legitimate without leaving it: the "Legitimate" link
  of the Antispam column, "Confirm as legitimate" in the box, or the bulk
  action "Learn as legitimate"
- **Gravity Forms**: marking an entry as spam or not spam, and the bulk
  action "Learn as legitimate" on active entries
- **Security > Journal**: "Learn as spam" and "Learn as legitimate"

A text marked the other way round later is forgotten as the first category
before it is learnt as the second.

The counters age, so that the spam of today outweighs the campaigns of past
years. They come in two generations: what was learnt since the last rotation
counts in full, and every 6 months (setting), or sooner once 5,000 texts of
one kind were learnt since, a daily task rotates them: the archive halves and
the recent counters join it. A text counts in full for 6 to 12 months, then
its weight halves every 6 months. Each item learnt records its generation:
marked the other way within one rotation of being learnt, it comes off the
counters exactly; older, it was halved since, and only the new category is
learnt.

What a site already holds can be learnt in one go, from the statistical
filter tab: the spam queue and the approved comments, the spam and the inbox
of Flamingo, the spam and active Gravity Forms entries. Each item goes to the
generation its date belongs to: sent after the last rotation, to the recent
one; before, to the archive (until the first rotation, its age decides);
older than two periods, it is left out, it would have halved since. The
most recent are learnt first, 50 of each kind and source at a time. The
button calls a REST route (`POST /wp-json/gecka-antispam/v1/learn-existing`,
`manage_options`) again and again, each call learning for 5 seconds at
most, and shows the progress until nothing is left; without JavaScript, it
posts a form that learns for 20 seconds at most (half the time limit of PHP
when that is shorter), and a site holding more takes another click. A
failure of the filter stops the learning, and what was not learnt stays to
learn.

Each item learnt is marked and never read twice. A spam is learnt only when
a person or Akismet marked it: WordPress keeps the status of a comment a
person sent to spam, Flamingo logs who marked a message, and the spam
filters of Gravity Forms sign a note, which a person marking an entry does
not leave. Spam this filter caught is left out, as it would only teach the
filter what it already believes, its mistakes included; so is spam a check
of the form or a check for bots caught (honeypot, reCAPTCHA, Turnstile):
that check says a bot sent it, not that its words are those of spam.
"Forget everything learnt" drops the marks along with the counters, so it
can all be learnt again.

### 🎚️ Thresholds

The filter rates nothing until it has learnt 20 spam texts and 10 legitimate
ones, two settings, counted in all: a rotation never brings a site back
under them. The three thresholds are rejection (95 %, 100 refuses none), spam
(75 %) and acceptance (55 %). These settings, the rotation period, and what
the filter learnt, are on the statistical filter tab of Settings > Antispam.

The counters are read from a snapshot file in
`wp-content/uploads/gecka-antispam/cache/`, under a name drawn from the salts
of the site, rewritten when something was learnt since. The directory gets a
`.htaccess` refusing web requests; on a server that ignores those files,
nginx for one, deny `/wp-content/uploads/gecka-antispam/` in its
configuration. When PHP cannot write there, each rating reads the counters
from the database, and the statistical filter tab says so.

## 📊 Statistics

The Antispam tab of Security > Statistics shows, over 7, 30, 90 or 365
days, the submissions checked, accepted, to review and caught, day by day,
or week by week over 365 days, the share of each check in what was caught,
and the counts by form and by check. A dashboard widget sums up the last seven days.

Below the chart, the submissions caught, or those accepted, are counted by
operating system, from the user agent, and, when the
[Gecka Geolocation](https://github.com/Gecka-Apps/wordpress-plugin-gecka-geolocation)
plugin is active, by country and by network, with their flags, the logos
of the networks when its setting is on, and the credit its data asks for.
The plugin never reads the address: the geolocation locates the visitor
and gives back the code of the country and the number of the network with
the name of its organisation, which are all the counters hold.

Only daily counts are kept, by form and by outcome, and by country, network
and system: no address, no content. They are kept 365 days (setting).

## ⚙️ Settings

The statistics and the refused submissions are Antispam tabs of the
Statistics and Journal pages of the Security menu, a menu the Gecka plugins
share, each adding its tab to these pages. The statistical filter and the
settings are the two tabs of Settings > Antispam.

Whoever moderates comments, editors included, sees the statistics, the
dashboard widget and the Journal, and can learn and delete the refused
submissions there, as from the comments screen. The statistical filter, the
settings and the buttons resetting the statistics, the filter or the
settings are for administrators. A developer can change that through the
`gecka_antispam_capability` filter, see
[docs/DEVELOPERS.md](docs/DEVELOPERS.md).

"Restore the default settings", at the bottom of the settings tab, puts
every setting back but the name of the honeypot, which the forms already
shown or cached carry.

## 🩺 Site Health

Tools > Site Health tests what keeps the plugin from working as it should:

- the tables of the plugin: critical when the database refused to create or
  alter them, in which case the setup is tried again every hour, the
  administrators see a notice, and the plugin protects nothing meanwhile
- the daily task, which purges the statistics and the refused submissions and
  rotates the counters: not scheduled, which the plugin repairs on the next
  page load, or more than a day late because the scheduled tasks of
  WordPress do not run
- while the statistical filter is on: whether it works (critical when it is
  on but cannot rate nor learn), whether it reads background tables (none,
  some left out, the last download failed, or a table read is weak or poor),
  and whether it can keep the snapshot of its counters

A filter still learning is a state, not a problem: it shows in the Info tab,
whose Gecka Antispam section sums up the plugin for support, version, forms
protected, state of the filter, thresholds, texts learnt, rotation,
background tables, snapshot and refused submissions, with nothing of the
senders.

## 🔒 Privacy

The statistical filter keeps counts on hashes of the subject and the message
it read, never the text, and nothing ties a count to a sender, so a count
cannot be erased for one person. The Journal keeps the subject and the
message of the submissions refused, without the name or the email address
of the sender, though the message may hold personal details the sender wrote
in it; an entry goes 30 days after its text was last sent, through the daily
task. The rating and the reason are stored with the comment or the Gravity
Forms entry, and go with it. No cookie is set and no IP address is kept. The
plugin offers a paragraph for the privacy policy of the site (Settings >
Privacy).

## 🧑‍💻 For developers

[docs/DEVELOPERS.md](docs/DEVELOPERS.md) covers protecting a form of your
own with `gecka_antispam_fields()` and `gecka_antispam_check()`, the hooks
a form written by hand has to fire, the markers of the form plugins, the
filters and actions (`gecka_antispam_protect` turns a form off), the REST
routes, every table, option, meta and event the plugin keeps, and how to
build, test and translate it. Deleting the plugin removes all it keeps, on
every site of a network; the reason it gave in the spam log of a Flamingo
message, or in the spam note of a Gravity Forms entry, belongs to those
plugins and stays.

## 📜 License

Copyright 2026 Gecka. GPL-3.0-or-later. gecka/spamfilter is under the
AGPL-3.0-or-later.

---
Built with 🥥 and ☕ by [Gecka](https://gecka.nc) — Kanaky-New Caledonia 🇳🇨
