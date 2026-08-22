/*
 * Copyright (C) 2026 Julian Pawlowski - BSD-2-Clause, see LICENSE at the repository root.
 *
 * Browser side of the OpenID Connect settings, under System > Access > Servers.
 *
 * The form there renders every pluggable option as a single-line <input>; it knows text,
 * dropdown and checkbox and nothing else. Fields that need more are upgraded here, after
 * the fact. Kept in its own file rather than in a PHP string: heredoc interpolation eats
 * anything starting with $ and turns \r\n into real control characters, and neither
 * mistake is visible to a syntax check.
 *
 * Settings arrive in window.__oidcForm, set by the PHP side just before this runs.
 */
(function () {
    'use strict';

    var options = window.__oidcForm || {};

    function field(name) {
        return document.getElementsByName(name)[0] || null;
    }

    /* An <input> value has been through the browser's value sanitisation, which strips
     * CR and LF. Read the attribute to see what was actually stored. */
    function storedValue(element) {
        var attribute = element.getAttribute('value');

        return (attribute === null ? element.value : attribute) || '';
    }

    function listEntries(value) {
        return value.split(/[\r\n,]+/)
            .map(function (entry) { return entry.trim(); })
            .filter(function (entry) { return entry.length > 0; });
    }

    /* ------------------------------------------------------------------ upgrades */

    function asTextarea(name, rows) {
        var input = field(name);
        if (!input) {
            return;
        }
        var area = $('<textarea>');
        $.each(input.attributes, function (_, attribute) { area.attr(attribute.name, attribute.value); });
        area.attr('rows', rows).val(storedValue(input));
        $(input).replaceWith(area);
    }

    function asTokenizer(name, hint) {
        var input = field(name);
        if (!input || input.tagName === 'SELECT') {
            return;
        }
        var entries = listEntries(input.value);
        var picker = $('<select multiple="multiple" class="tokenize">').attr({
            'data-allownew': 'true',
            'data-sortable': 'true',
            'data-width': '100%',
            'data-hint': hint || ''
        });
        entries.forEach(function (entry) {
            picker.append($('<option>').attr({ value: entry, selected: 'selected' }).text(entry));
        });

        /* the original input stays put as the field that gets submitted */
        $(input).attr('type', 'hidden').after(picker);
        picker.on('tokenize:tokens:change change', function () {
            $(input).val((picker.val() || []).join(','));
        });
    }

    function asGroupPicker(name) {
        var input = field(name);
        var groups = options.groups || [];
        if (!input || groups.length === 0) {
            return;
        }
        var chosen = listEntries(input.value);
        var picker = $('<select multiple="multiple" class="selectpicker">');
        groups.forEach(function (group) {
            picker.append($('<option>').val(group).text(group).prop('selected', chosen.indexOf(group) !== -1));
        });
        $(input).attr('type', 'hidden').after(picker);
        picker.on('change', function () {
            $(input).val((picker.val() || []).join(','));
        }).selectpicker();
    }

    function withDiscoveryTest() {
        var submit = $('#submit');
        if (submit.length === 0) {
            return;
        }
        $('<button>')
            .attr({ type: 'button', class: 'btn btn-default auth_options auth_openidconnect', style: 'margin-left: 10px' })
            .text(options.testLabel || 'Test')
            .on('click', function () {
                /* a read, and only the address: the client secret has no business here */
                var url = $(field('openidconnect_provider_url')).val();
                $.ajax({ type: 'GET', url: '/api/openidconnect/discovery/probe', data: { url: url } })
                    .done(function (answer) {
                        if (answer && answer.status === 'ok') {
                            BootstrapDialog.show({
                                title: options.testLabel,
                                message: $('<pre>').text(answer.summary || '').html(),
                                type: BootstrapDialog.TYPE_SUCCESS
                            });
                        } else {
                            BootstrapDialog.show({
                                title: options.testLabel,
                                message: $('<div>').text((answer && answer.message) || 'unknown error').html(),
                                type: BootstrapDialog.TYPE_DANGER
                            });
                        }
                    })
                    .fail(function (xhr) {
                        BootstrapDialog.show({
                            title: options.testLabel,
                            message: $('<div>').text(xhr.responseText || 'request failed').html(),
                            type: BootstrapDialog.TYPE_DANGER
                        });
                    });
            })
            .insertAfter(submit);
    }

    /* --------------------------------------------------------------------- start */

    $(function () {
        $('[name=openidconnect_client_secret]').attr({ type: 'password', autocomplete: 'off' });
        asTextarea('openidconnect_custom_button', 10);
        asTextarea('openidconnect_icon_svg', 6);
        asGroupPicker('openidconnect_default_groups');
        asGroupPicker('openidconnect_assignable_groups');
        withDiscoveryTest();

        /* Normalise the list fields first: if the tokenizer never arrives, what stays
         * behind is a readable comma separated field rather than one long string. */
        var lists = [
            { name: 'openidconnect_redirect_urls', hint: options.redirectHint },
            { name: 'openidconnect_scopes', hint: 'openid' }
        ];
        lists.forEach(function (list) {
            var input = field(list.name);
            if (input) {
                input.value = listEntries(storedValue(input)).join(',');
            }
        });

        if (options.tokenizerCss) {
            $('<link rel="stylesheet" type="text/css">').attr('href', options.tokenizerCss).appendTo('head');
        }
        $.getScript('/ui/js/tokenize2.js')
            .then(function () { return $.getScript('/ui/js/opnsense_ui.js'); })
            .then(function () {
                lists.forEach(function (list) { asTokenizer(list.name, list.hint); });
                formatTokenizersUI();
            });
    });
}());
