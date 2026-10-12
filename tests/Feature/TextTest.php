<?php

declare(strict_types=1);

// SPDX-FileCopyrightText: 2026 Gecka <contact@gecka.nc>
// SPDX-License-Identifier: GPL-3.0-or-later

use Gecka\WP\Plugin\Antispam\Integrations\Acf;
use Gecka\WP\Plugin\Antispam\Integrations\Comments;
use Gecka\WP\Plugin\Antispam\Integrations\ContactForm7;
use Gecka\WP\Plugin\Antispam\Integrations\GravityForms;
use Gecka\WP\Plugin\Antispam\Integrations\Integration;

/**
 * What the filter reads of the fields of a form.
 *
 * @param array<mixed> $fields
 *
 * @return string
 */
function fields_text(array $fields): string
{
    $probe = new class (gecka_antispam()) extends Integration {
        public function available(): bool
        {
            return true;
        }

        public function setup(): void {}

        /**
         * @param array<mixed> $fields
         */
        public static function read(array $fields): string
        {
            return self::fieldsText($fields);
        }
    };

    return $probe::read($fields);
}

it('reads the subject and the message of the default Contact Form 7 form', function () {
    expect(
        fields_text(
            [
                'your-name' => 'Marie Dupont',
                'your-email' => 'marie@example.org',
                'your-subject' => 'Devis',
                'your-message' => 'Bonjour, je souhaite un devis pour notre site.',
            ],
        ),
    )->toBe("Devis\nBonjour, je souhaite un devis pour notre site.");
});

it('reads a field of any name whose value reads as prose, but nothing of the sender', function () {
    expect(
        fields_text(
            [
                'text-512' => 'Jean',
                'tel-77' => '+687 12 34 56',
                'votre-adresse' => '12 rue de la Paix, 98800 Nouméa, Nouvelle-Calédonie',
                'societe' => 'Les Ateliers Réunis du Grand Nouméa',
                'textarea-130' => 'Pouvez-vous me rappeler demain matin, merci ?',
                'checkbox-1' => ['Formation', 'Conseil'],
                'acceptance-9' => '1',
            ],
        ),
    )->toBe('Pouvez-vous me rappeler demain matin, merci ?');
});

it('reads the content of a comment, nothing of its author', function () {
    $read = (new ReflectionMethod(Comments::class, 'commentText'))->getClosure();

    expect(
        $read(
            [
                'comment_author' => 'Cheap Pills',
                'comment_author_email' => 'pills@spam.example',
                'comment_author_url' => 'https://pills.example',
                'comment_content' => ' Merci pour cet article. ',
            ],
        ),
    )->toBe('Merci pour cet article.');
});

it('reads the subject the mail cites and every textarea of a Contact Form 7 form, whatever their names', function () {
    $types = ['text-735' => 'text', 'email-12' => 'email', 'textarea-120' => 'textarea', 'textarea-121' => 'textarea', 'text-9' => 'text'];
    $fields = ['text-735' => 'Offre spéciale', 'email-12' => 'bot@example.com', 'textarea-120' => 'Premier message', 'textarea-121' => 'Second message', 'text-9' => 'Gecka SARL'];

    expect(ContactForm7::pick($fields, $types, '[_site_title] "[text-735]"', null, ['your-name', 'your-email']))
        ->toBe(['text' => "Offre spéciale\nPremier message\nSecond message", 'message' => "Premier message\nSecond message"])
        ->and(ContactForm7::pick(['text-735' => 'Offre spéciale'], ['text-735' => 'text'], '[text-735]', null, []))
        ->toBe(['text' => 'Offre spéciale', 'message' => null]);
});

it('never takes the sender, nor a typed field, for the subject of a Contact Form 7 form', function () {
    $types = ['your-name' => 'text', 'your-email' => 'email', 'your-subject' => 'text', 'your-message' => 'textarea'];
    $fields = ['your-name' => 'Jean Dupont', 'your-email' => 'jean@example.com', 'your-subject' => 'Devis', 'your-message' => 'Bonjour'];

    expect(ContactForm7::pick($fields, $types, 'Message de [your-name] <[your-email]> : [your-subject]', null, ['your-name', 'your-email'])['text'])
        ->toBe("Devis\nBonjour");
});

it('reads the fields the settings of a Contact Form 7 form name, several of them, and a field once', function () {
    $types = ['sujet' => 'text', 'besoin' => 'text', 'details' => 'textarea', 'options' => 'checkbox', 'notes' => 'textarea'];
    $fields = ['sujet' => 'Refonte', 'besoin' => 'Un site vitrine', 'details' => 'Trois pages', 'options' => ['SEO', 'Blog'], 'notes' => 'Interne'];

    expect(ContactForm7::pick($fields, $types, '[sujet]', '[besoin] [details] [options] [sujet]', []))
        ->toBe(['text' => "Refonte\nUn site vitrine\nTrois pages\nSEO Blog", 'message' => "Refonte\nUn site vitrine\nTrois pages\nSEO Blog"]);
});

/**
 * A Gravity Forms form of plain field objects.
 *
 * @param array<int, array<string, mixed>> $fields        Properties of each field.
 * @param array<int, array<string, mixed>> $notifications
 *
 * @return array<string, mixed>
 */
function gravity_form(array $fields, array $notifications = []): array
{
    return [
        'id' => 1,
        'fields' => array_map(static fn(array $field): object => (object) $field, $fields),
        'notifications' => $notifications,
    ];
}

it('reads the subject a Gravity Forms notification cites and every paragraph field, whatever their labels', function () {
    $form = gravity_form(
        [
            ['id' => 1, 'type' => 'text', 'label' => 'Votre nom'],
            ['id' => 2, 'type' => 'email', 'label' => 'Email'],
            ['id' => 3, 'type' => 'text', 'label' => 'Objet de la demande'],
            ['id' => 4, 'type' => 'textarea', 'label' => 'Détails'],
            ['id' => 5, 'type' => 'text', 'label' => 'Message court', 'cssClass' => 'large'],
            ['id' => 6, 'type' => 'textarea', 'label' => 'Remarques'],
        ],
        [
            ['subject' => 'Demande : {Objet de la demande:3}', 'fromName' => '{Votre nom:1}', 'replyTo' => '{Email:2}'],
            ['subject' => '{Ancien sujet:5}', 'isActive' => false],
        ],
    );
    $entry = ['1' => 'Jean Dupont', '2' => 'jean@example.com', '3' => 'Devis', '4' => 'Trois pages', '5' => 'Bonjour à toute l’équipe de Gecka, merci', '6' => 'Urgent'];

    expect(GravityForms::entryText($entry, $form))->toBe("Devis\nTrois pages\nUrgent");
});

it('never takes the sender, nor a typed field, for the subject of a Gravity Forms form', function () {
    $form = gravity_form(
        [
            ['id' => 1, 'type' => 'text', 'label' => 'Sujet'],
            ['id' => 2, 'type' => 'email', 'label' => 'Email'],
            ['id' => 3, 'type' => 'phone', 'label' => 'Téléphone'],
            ['id' => 4, 'type' => 'textarea', 'label' => 'Message'],
        ],
        [['subject' => '{Sujet:1} de {Email:2} ({:3})', 'toType' => 'field', 'toField' => '1']],
    );

    expect(GravityForms::entryText(['1' => 'contact@example.com', '2' => 'bot@example.com', '3' => '+687 12 34 56', '4' => 'Bonjour'], $form))->toBe('Bonjour');
});

it('reads the fields of a Gravity Forms form marked by their CSS class, and the inputs of a checkbox field', function () {
    $form = gravity_form(
        [
            ['id' => 1, 'type' => 'text', 'label' => 'Besoin', 'cssClass' => 'gf_left_half gecka-antispam-subject'],
            ['id' => 2, 'type' => 'checkbox', 'label' => 'Options', 'cssClass' => 'gecka-antispam-message', 'inputs' => [['id' => '2.1'], ['id' => '2.2'], ['id' => '2.3']]],
            ['id' => 3, 'type' => 'textarea', 'label' => 'Notes internes'],
            ['id' => 4, 'type' => 'text', 'label' => 'Sujet', 'cssClass' => 'gecka-antispam-message'],
        ],
        [['subject' => '{Notes internes:3}']],
    );
    $entry = ['1' => 'Un site vitrine', '2.1' => 'SEO', '2.2' => '', '2.3' => 'Blog', '3' => 'Interne', '4' => 'Refonte'];

    expect(GravityForms::entryText($entry, $form))->toBe("Un site vitrine\nSEO Blog\nRefonte");
});

it('reads the choices of a multiple select and the rows of a list marked as the message, not their JSON', function () {
    $form = gravity_form(
        [
            ['id' => 1, 'type' => 'multiselect', 'label' => 'Services', 'cssClass' => 'gecka-antispam-message'],
            ['id' => 2, 'type' => 'list', 'label' => 'Pages', 'cssClass' => 'gecka-antispam-message'],
            ['id' => 3, 'type' => 'list', 'label' => 'Contacts', 'cssClass' => 'gecka-antispam-message'],
        ],
    );
    $entry = ['1' => '["SEO","Blog"]', '2' => serialize(['Accueil', 'Tarifs']), '3' => serialize([['Nom' => 'Paul', 'Rôle' => 'Gérant']])];

    expect(GravityForms::entryText($entry, $form))->toBe("SEO Blog\nAccueil Tarifs\nPaul Gérant");
});

it('reads only the paragraph fields of a Gravity Forms form whose notifications cite no field', function () {
    $form = gravity_form(
        [
            ['id' => 1, 'type' => 'text', 'label' => 'Name'],
            ['id' => 3, 'type' => 'textarea', 'label' => 'Message'],
        ],
        [['subject' => 'New submission from {form_title}']],
    );

    expect(GravityForms::entryText(['1' => 'Cheap Pills Online Store Worldwide', '3' => 'Buy now'], $form))->toBe('Buy now');
});

/**
 * Fields an ACF front-end form shows: the title and the content of the post,
 * a description, an email address and a price.
 *
 * @return array<string, array{name: string, type: string}>
 */
function acf_fields(): array
{
    return [
        '_post_title' => ['name' => '_post_title', 'type' => 'text'],
        '_post_content' => ['name' => '_post_content', 'type' => 'wysiwyg'],
        'field_desc' => ['name' => 'description', 'type' => 'textarea'],
        'field_mail' => ['name' => 'contact_email', 'type' => 'email'],
        'field_price' => ['name' => 'price', 'type' => 'number'],
    ];
}

it('reads the title, the content and the textarea fields of an ACF form by default', function () {
    $posted = ['_post_title' => 'Vends vélo', '_post_content' => '<p>Bon <strong>état</strong></p>', 'field_desc' => 'Révisé en mars', 'field_mail' => 'bot@example.com', 'field_price' => '120'];

    expect(Acf::formText(acf_fields(), $posted, true))->toBe("Vends vélo\nBon état\nRévisé en mars")
        ->and(Acf::formText(acf_fields(), $posted, ['message' => ['description']]))->toBe("Vends vélo\nRévisé en mars");
});

it('reads the fields the marker of an ACF form names, by name or by key, never a typed field as the subject', function () {
    $posted = ['_post_title' => 'Vends vélo', '_post_content' => 'Bon état', 'field_desc' => 'Révisé en mars', 'field_mail' => 'bot@example.com', 'field_price' => '120'];
    $marker = ['subject' => ['price', 'field_desc'], 'message' => ['post_content', 'field_price']];

    expect(Acf::formText(acf_fields(), $posted, $marker))->toBe("Révisé en mars\nBon état\n120")
        ->and(Acf::formText(acf_fields(), $posted, ['subject' => [], 'message' => 'post_content']))->toBe('Bon état');
});

it('reads the sub fields of the groups, repeaters and flexible contents of an ACF form, every row, and lets the marker name them', function () {
    $fields = [
        'field_about' => ['name' => 'about', 'type' => 'group', 'sub_fields' => [['key' => 'field_topic', 'name' => 'topic', 'type' => 'text'], ['key' => 'field_details', 'name' => 'details', 'type' => 'textarea']]],
        'field_items' => ['name' => 'items', 'type' => 'repeater', 'sub_fields' => [['key' => 'field_note', 'name' => 'note', 'type' => 'textarea'], ['key' => 'field_qty', 'name' => 'qty', 'type' => 'number']]],
        'field_blocks' => ['name' => 'blocks', 'type' => 'flexible_content', 'sub_fields' => [['key' => 'field_body', 'name' => 'body', 'type' => 'wysiwyg']]],
    ];
    $posted = [
        'field_about' => ['field_topic' => 'Devis', 'field_details' => 'Un site vitrine'],
        'field_items' => ['row-0' => ['field_note' => 'Accueil', 'field_qty' => '1'], 'row-1' => ['field_note' => 'Tarifs', 'field_qty' => '2']],
        'field_blocks' => ['row-0' => ['acf_fc_layout' => 'text', 'field_body' => '<p>Livraison en mai</p>']],
    ];

    [$flat, $values] = Acf::expand($fields, $posted);

    expect(array_keys($flat))->toBe(['field_topic', 'field_details', 'field_note', 'field_qty', 'field_body'])
        ->and(Acf::formText($flat, $values, true))->toBe("Un site vitrine\nAccueil Tarifs\nLivraison en mai")
        ->and(Acf::formText($flat, $values, ['subject' => ['topic'], 'message' => ['note']]))->toBe("Devis\nAccueil Tarifs");
});

it('reads no subject from an ACF form without a title', function () {
    $fields = acf_fields();
    unset($fields['_post_title']);

    expect(Acf::formText($fields, ['_post_title' => 'Injected', 'field_desc' => 'Révisé en mars'], true))->toBe('Révisé en mars');
});

it('takes the names of a Contact Form 7 form from gecka_antispam_name, else flamingo_name, else the text fields named as a name', function () {
    $types = ['your-name' => 'text', 'contact' => 'text', 'societe' => 'text', 'your-email' => 'email', 'nom' => 'text'];
    $fields = ['your-name' => 'qASQAhqkpFGqnKkRROl', 'contact' => 'Jean Dupont', 'societe' => 'Gecka', 'your-email' => 'bot@example.com', 'nom' => ''];

    expect(ContactForm7::pickNames($fields, $types, null))->toBe(['qASQAhqkpFGqnKkRROl'])
        ->and(ContactForm7::pickNames($fields, $types, '[contact] [your-email]'))->toBe(['Jean Dupont'])
        ->and(ContactForm7::pickNames($fields, $types, '[societe] [contact] [nom]'))->toBe(['Gecka', 'Jean Dupont']);
});

it('takes the names of a Gravity Forms form from the fields carrying gecka-antispam-name, else the Name fields', function () {
    $fields = [
        ['id' => 1, 'type' => 'name'],
        ['id' => 2, 'type' => 'text'],
        ['id' => 3, 'type' => 'email'],
    ];
    $entry = ['1.3' => 'Jean', '1.6' => 'Dupont', '2' => 'qASQAhqkpFGqnKkRROl', '3' => 'bot@example.com'];

    expect(GravityForms::names(gravity_form($fields), $entry))->toBe(['Jean', 'Dupont']);

    $fields[1]['cssClass'] = 'large gecka-antispam-name';
    $fields[2]['cssClass'] = 'gecka-antispam-name';

    expect(GravityForms::names(gravity_form($fields), $entry))->toBe(['qASQAhqkpFGqnKkRROl']);
});

it('reads no name from an ACF form unless its marker names the text fields holding one', function () {
    $fields = acf_fields() + ['field_seller' => ['name' => 'seller', 'type' => 'text']];
    $posted = ['field_seller' => 'qASQAhqkpFGqnKkRROl', 'field_mail' => 'bot@example.com', 'field_desc' => 'Bon état'];

    expect(Acf::formNames($fields, $posted, true))->toBe([])
        ->and(Acf::formNames($fields, $posted, ['subject' => ['post_title']]))->toBe([])
        ->and(Acf::formNames($fields, $posted, ['name' => ['seller', 'contact_email', 'field_desc']]))->toBe(['qASQAhqkpFGqnKkRROl'])
        ->and(Acf::formNames($fields, $posted, ['name' => 'field_seller']))->toBe(['qASQAhqkpFGqnKkRROl']);
});
