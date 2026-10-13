# The forms, and the checks they get

How Gecka Antispam protects each form, what each check reads, and the cases
a plugin handles its own way. What a site administrator needs is in
[README.md](../README.md), the hooks and the stored data in
[DEVELOPERS.md](DEVELOPERS.md).

## Markers

Each form of WordPress and WooCommerce can be switched off in
Settings > Antispam. Each of the other plugins is off, protects every form,
or protects only the forms holding its marker:

| Plugin | Marker |
|---|---|
| Contact Form 7 | The `[gecka_antispam]` form tag, placed where the fields go. Without it, the fields go before the submit button |
| Gravity Forms | The Antispam field, among the advanced fields of the form editor. Without it, the fields go before the submit button |
| ACF / Secure Custom Fields | `'gecka_antispam' => true` in the arguments of `acf_form()` or `acf_register_form()`, or an array naming the subject and the message ([DEVELOPERS.md](DEVELOPERS.md#markers-of-the-form-plugins)) |

The ACF marker is read back from the form ACF rebuilds on submission, from
its registry or from the encrypted copy the form posts: a visitor can neither
add nor remove it.

## The checks

Every protected form gets two fields:

- a **signed timestamp**, hidden. A submission without it, or with a forged
  one, is caught. So is a form sent faster than the minimum delay: 5 seconds
  by default, none for the login and lost password forms, of WordPress and
  of WooCommerce, which password managers fill and send at once. A timestamp
  older than 8 days is caught too, so that one taken from the page cannot
  serve for ever. A page served from a cache carries the timestamp of the
  moment it was cached: when pages stay cached longer than a week, raise the
  setting, or set it to 0 for no limit. A form shown again after a post, the
  next page of a multipage Gravity Forms form or a form back with its errors,
  keeps the time it was first shown at, until that time is past the maximum
  age.
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
([DEVELOPERS.md](DEVELOPERS.md#what-the-statistical-filter-reads)).

The same rule reads a **message of a single word**: a bot that types one
burst of random letters where a message goes is caught even when its name
reads as one. A **minimum of words** applies to the message too, five by
default, 0 for none: a message shorter than that is refused, on every form
that has a message, comments included. A message field left empty is not a
message, and not counted. Chinese, Japanese and Thai are written without
blanks: each of their characters counts as a word.

A check run right after the honeypot reads the **user agent**: a submission
sent with none, or with one wrapped in quotes, is refused. No browser sends
either; a script whose user agent setting was copied with its quotes does.

The checks run in this order: honeypot, user agent, timestamp (missing,
forged, too fast, expired), random name, random single word, too few words,
then the statistical filter.

These checks stop the bots that post without loading the form, or fill in
every field. The timestamp is bound to no visitor and can be sent again
until it is 8 days old: a bot that loads the page once in a while gets a
valid one, and can read which field to leave empty. The statistical filter
is there for those ([STATISTICAL-FILTER.md](STATISTICAL-FILTER.md)).

## What the sender sees

A submission caught by a check of the form is refused with an error and
counted. A comment is refused with an error page, with a link back; a
Contact Form 7 message with the message its form shows for spam, and no
copy in Flamingo; a Gravity Forms submission fails its validation, and no
entry is saved; an ACF form gets an error page, as ACF does with the errors
of its own checks. The login, registration, lost password and checkout forms
get the error of their own screen.

A submission refused that carries a text is kept in the Antispam tab of
Security > Journal; one caught on a form with no text, a login for one, is
counted and nothing more.

## WordPress

A POST to `wp-login.php` is checked whatever fields it carries: the login,
registration and lost password screens act on the request method alone. A
login is checked once WordPress has found the user name; a name that does not
exist gets the error of WordPress and is not counted.

The registration of a network, `wp-signup.php`, is checked like that of
`wp-login.php`, at its user step and at its site step, which keeps the time
the first step was shown at and is not counted a second time; the network
administration creating users is left alone.

A comment, or a product review, gets the fields and every check whoever
posts it, logged in or not, unless the author can moderate comments: a
moderator is not checked at all. A pingback or a trackback, which another
site sends with no form, is rated by the statistical filter alone.

Comments and logins made through the REST API or XML-RPC run no form and
are not checked.

## WooCommerce

The classic checkout, the `[woocommerce_checkout]` shortcode, is protected.
The checkout block posts to the Store API, which runs none of the hooks of
the classic checkout, and payment buttons that place an order from a product
or cart page, Apple Pay or Google Pay for instance, do not go through its
form: both are left alone.

The login form of the app authorization screen (`/wc-auth/`) gets the
fields and the checks of the My account login: WooCommerce processes a login
form posted to any address, so none is exempt. The account forms are checked
on the fields WooCommerce reads, whatever nonce field is posted.

A comment on a product is checked as a product review while WooCommerce is
active, as a comment otherwise.

## Contact Form 7

Contact Form 7 warns about a form whose mail goes to the address the sender
typed, a Mail (2) to `[your-email]` for instance, unless its own reCAPTCHA or
Turnstile is active ([unsafe email without protection](https://contactform7.com/configuration-errors/unsafe-email-without-protection/)).
The plugin leaves that warning out of the forms it protects, since its
checks play the same part. Contact Form 7 records the warning when a form is
saved: save the form again after installing the plugin. The checks stop
bots, not a person, so a Mail (2) is best kept to an acknowledgement that
repeats nothing the sender wrote.

## Gravity Forms

A Gravity Forms submission made by code, through the submissions route of
its REST API or `GFAPI::submit_form()`, carries no fields and no browser: it
is rated by the filter alone.

That route answers anyone, with no login, once the REST API is enabled in the
settings of Gravity Forms: a bot posting there skips the honeypot, the
timestamp and the random names check, and the filter, until it has learnt
enough to rate, lets it through. Leave the REST API of Gravity Forms off
unless something needs it.
