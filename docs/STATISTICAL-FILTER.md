# The statistical filter

The plugin ships [gecka/spamfilter](https://github.com/Gecka-Apps/spamfilter),
a statistical filter for short texts, and keeps its counters in two tables of
the site. It rates the subject and the message of the comments, the Contact
Form 7 messages, the Gravity Forms entries, the front-end forms of ACF and
your own forms, from 0 to 100 % spam; 50 % means it knows nothing of the
text. It reads the first 20,000 characters of a text.

What a site administrator needs is in [README.md](../README.md), the hooks
and the stored data in [DEVELOPERS.md](DEVELOPERS.md).

## What it reads

What counts as subject and message comes from the form itself, never from
the name of a field: the fields the mail of a Contact Form 7 form cites, the
merge tags of a Gravity Forms notification, the title and content of an ACF
form, the content of a comment, the text your own form passes to
`gecka_antispam_check()`. Each form plugin lets a form name its own fields
instead, through its marker. The rules, form by form, in the order they
apply, and the fields the random names check reads, are in
[DEVELOPERS.md](DEVELOPERS.md#what-the-statistical-filter-reads) and in the
Help of the settings page.

A Flamingo message whose form was deleted is read by the names of its
fields: a field counts when its name says subject or message, or says
nothing of the sender and its value reads as prose.

The counters are counts on hashes of the words, links, mail domains and the
like: no text is stored in them.

## Background tables

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

### Languages

The background tables sit in the State section of the statistical filter
tab, with their languages: a field of tags suggesting the languages of the
release with the sentences of their tables, five at most. What the tables
are, why the filter needs them and which languages to choose is in the
Background tables tab of the Help, which the question mark next to the
heading opens. Left empty, the languages are those of the site, those of
WPML or Polylang when one of them is active, and English, which most sites
receive.

The filter reads five tables at most, the language of the site first. A file
whose name is not a language code, one that is not a background table, and
one holding more counters than a class of the site (2^20) are left out; the
filter reads on with the others, and the statistical filter tab and Site
Health name the files left out and why.

### Downloads

Nothing reaches GitHub before an administrator allows it: the setting
`background_downloads` is off by default, and the "Download the background
tables" button (`admin_post_gecka_antispam_allow_backgrounds`) switches it on.
Until then a warning stands on the plugins screen and the settings of the
plugin, the statistical filter tab shows the button instead of the
languages, and Site Health reports a critical issue. The box under the
languages switches the downloads off again, the tables in place kept.

Saving the languages downloads nothing: the tables no longer wanted go at
once, and the tab, back from the save, downloads the others through the REST
API, one table per request with its progress; the "Update the background
tables" button does the same. The scheduled event does it outside a visit,
once the downloads are allowed, after a save, and every week from the daily
task, which reads the manifest of the latest release again, or the next day
while a table is missing or the release could not be read, starting tables
for 20 seconds per run. Two requests never download at once.

Each download, redirections included, takes 25 seconds at most, refuses a
size larger than a table can be, is checked against the size, the SHA-256
and the feature hash version the manifest announces, and comes only from the
directory of the manifest; it replaces the file in place in one step, and a
failed one leaves the table in place. A table the plugin installed goes when
its language is no longer wanted; one copied by hand stays.

The requests go to GitHub through the HTTP API of WordPress, with a user
agent naming the plugin and nothing of the site. With
`WP_HTTP_BLOCK_EXTERNAL`, `WP_ACCESSIBLE_HOSTS` must hold `github.com` and
`*.githubusercontent.com`, where GitHub serves the files of a release.

The `gecka_antispam_background_directory` filter moves the directory, and
`gecka_antispam_background_updates` returning false stops the downloads, for
a server that fills the directory itself.

### Quality

The State section lists each table with its sources, the sentences it was
drawn from and its quality: solid from 100,000 sentences, average from
10,000, weak from 1,000, poor below. These thresholds are estimates, not
measured. It also shows the words of the dictionary of the language, the
counters the table fills, and whether it is up to date, has an update, was
copied by hand or failed.

## What it learns

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

The forms of ACF teach the filter nothing: nothing marks their submissions
as spam or not spam.

A text marked the other way round later is forgotten as the first category
before it is learnt as the second.

### Generations

The counters age, so that the spam of today outweighs the campaigns of past
years. They come in two generations: what was learnt since the last rotation
counts in full, and every 6 months (setting), or sooner once 5,000 texts of
one kind were learnt since, a daily task rotates them: the archive halves and
the recent counters join it. A text counts in full for 6 to 12 months, then
its weight halves every 6 months. Each item learnt records its generation:
marked the other way within one rotation of being learnt, it comes off the
counters exactly; older, it was halved since, and only the new category is
learnt.

### Learning what the site already holds

What a site already holds can be learnt in one go, from the statistical
filter tab: the spam queue and the approved comments, the spam and the inbox
of Flamingo, the spam and active Gravity Forms entries. Each item goes to the
generation its date belongs to: sent after the last rotation, to the recent
one; before, to the archive (until the first rotation, its age decides);
older than two periods, it is left out, it would have halved since. The
most recent are learnt first, 50 of each kind and source at a time.

The button calls a REST route (`POST /wp-json/gecka-antispam/v1/learn-existing`,
`manage_options` by default) again and again, each call learning for 5
seconds at most, and shows the progress until nothing is left; without
JavaScript, it posts a form that learns for 20 seconds at most (half the
time limit of PHP when that is shorter), and a site holding more takes
another click. A failure of the filter stops the learning, and what was not
learnt stays to learn.

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

## Thresholds

The filter rates nothing until it has learnt 20 spam texts and 10 legitimate
ones, two settings, counted in all: a rotation never brings a site back
under them. The three thresholds are rejection (95 %, 100 refuses none), spam
(75 %) and acceptance (55 %). These settings, the rotation period, and what
the filter learnt, are on the statistical filter tab of Settings > Antispam.

The forms of ACF have no spam queue: the filter refuses them from the
rejection threshold and lets the others through.

## Snapshot

The counters are read from a snapshot file in
`wp-content/uploads/gecka-antispam/cache/`, under a name drawn from the salts
of the site, rewritten when something was learnt since. The directory gets a
`.htaccess` refusing web requests; on a server that ignores those files,
nginx for one, deny `/wp-content/uploads/gecka-antispam/` in its
configuration. When PHP cannot write there, each rating reads the counters
from the database, and the statistical filter tab says so.
