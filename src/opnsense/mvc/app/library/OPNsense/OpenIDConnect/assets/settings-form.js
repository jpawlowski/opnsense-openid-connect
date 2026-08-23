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

    function row(name) {
        var input = field(name);
        return input ? $(input).closest('tr') : $();
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

    /* A deliberately tiny Markdown-like convention for trusted UI copy. Backticks
     * become code elements, but every character still enters the DOM as text. */
    function inlineCode(value) {
        var output = $('<span>');
        var input = String(value || '');
        var pattern = /`([^`\n]+)`/g;
        var offset = 0;
        var match;
        while ((match = pattern.exec(input)) !== null) {
            output.append(document.createTextNode(input.slice(offset, match.index)));
            output.append($('<code>').text(match[1]));
            offset = pattern.lastIndex;
        }
        output.append(document.createTextNode(input.slice(offset)));
        return output;
    }

    function normalizedOrigin(value) {
        try {
            var parsed = new URL(value);
            if (parsed.protocol !== 'https:' || parsed.username || parsed.password
                || parsed.pathname !== '/' || parsed.search || parsed.hash) {
                return null;
            }
            return parsed.origin;
        } catch (_) {
            return null;
        }
    }

    function uniqueOrigins(values) {
        var origins = [];
        values.forEach(function (value) {
            var normalized = normalizedOrigin(value);
            if (normalized && origins.indexOf(normalized) === -1) {
                origins.push(normalized);
            }
        });
        return origins;
    }

    function effectiveOrigins() {
        var policy = field('openidconnect_origin_policy');
        var entered = listEntries(field('openidconnect_redirect_urls').value);
        var origins = !policy || policy.value !== 'custom'
            ? uniqueOrigins((options.opnsenseOrigins || []).concat(entered))
            : uniqueOrigins(entered);
        var current = normalizedOrigin(window.location.origin);
        var currentIndex = current ? origins.indexOf(current) : -1;
        if (currentIndex > 0) {
            origins.splice(currentIndex, 1);
            origins.unshift(current);
        }
        return origins;
    }

    function currentTransportReady() {
        if (options.webGuiProtocol !== 'http') {
            return true;
        }
        var offloading = field('openidconnect_tls_offloading');
        var policy = field('openidconnect_origin_policy');
        return !!offloading && $(offloading).is(':checked')
            && !!policy && policy.value === 'custom' && effectiveOrigins().length > 0;
    }

    function sectorOriginOptions() {
        var select = field('openidconnect_sector_origin');
        if (!select) {
            return;
        }
        var selected = select.value || storedValue(select);
        $(select).empty().append($('<option>').attr('value', '').text(options.sectorOffLabel || 'Off'));
        effectiveOrigins().forEach(function (origin) {
            $(select).append($('<option>').attr('value', origin).text(origin));
        });
        select.value = effectiveOrigins().indexOf(selected) === -1 ? '' : selected;

        function update() {
            selected = select.value;
            $(select).empty().append($('<option>').attr('value', '').text(options.sectorOffLabel || 'Off'));
            effectiveOrigins().forEach(function (origin) {
                $(select).append($('<option>').attr('value', origin).text(origin));
            });
            select.value = effectiveOrigins().indexOf(selected) === -1 ? '' : selected;
        }
        $(field('openidconnect_redirect_urls')).on('input change', update);
        $(field('openidconnect_origin_policy')).on('change', update);
    }

    function currentServerId() {
        var id = field('id');
        var value = id ? id.value : '';
        if (!/^(?:0|[1-9][0-9]*)$/.test(value)) {
            var address = new URL(window.location.href);
            value = address.searchParams.get('act') === 'edit'
                ? (address.searchParams.get('id') || '') : '';
        }
        return /^(?:0|[1-9][0-9]*)$/.test(value) ? Number(value) : null;
    }

    function applicationCodeConflict(value) {
        var code = String(value || '').trim().toLowerCase();
        var ownPosition = currentServerId();
        var entries = options.applicationCodes || [];
        for (var index = 0; index < entries.length; index++) {
            if (entries[index].position !== ownPosition
                && String(entries[index].code || '').toLowerCase() === code) {
                return entries[index];
            }
        }
        return null;
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

    function resultStatus(status) {
        var statuses = {
            success: { icon: 'fa-check-circle', label: options.statusPassed || 'Passed', style: 'success' },
            warning: { icon: 'fa-exclamation-triangle', label: options.statusWarning || 'Warning', style: 'warning' },
            info: { icon: 'fa-info-circle', label: options.statusInformation || 'Information', style: 'info' },
            error: { icon: 'fa-times-circle', label: options.statusFailed || 'Failed', style: 'danger' }
        };
        return statuses[status] || statuses.info;
    }

    function statusIcon(status, colored) {
        var meta = resultStatus(status);
        return $('<i>').attr({
            class: 'fa ' + meta.icon + (colored === false ? '' : ' text-' + meta.style),
            'aria-hidden': 'true'
        });
    }

    function discoveryResult(answer) {
        var overall = answer.overall === 'warning' ? 'warning' : 'success';
        var meta = resultStatus(overall);
        var panel = $('<div class="oidc-discovery-result">');
        var headline = $('<div>').addClass('alert alert-' + meta.style)
            .append(statusIcon(overall), ' ')
            .append($('<strong>').text(answer.headline || options.discoveryAccepted || 'Discovery document accepted'));
        panel.append(headline);

        if (!Array.isArray(answer.checks)) {
            return panel.append($('<pre>').text(answer.summary || ''));
        }

        var table = $('<table class="table table-striped table-condensed oidc-discovery-results">');
        table.append($('<thead>').append($('<tr>')
            .append($('<th>').text(options.checkLabel || 'Check'))
            .append($('<th>').text(options.resultLabel || 'Result'))
            .append($('<th class="text-right">').text(options.statusLabel || 'Status'))));
        var body = $('<tbody>');
        answer.checks.forEach(function (check) {
            var checkMeta = resultStatus(check.status);
            var value = $('<td>').append($('<code>').text(check.value || ''));
            if (check.note) {
                value.append($('<div class="text-muted small">').text(check.note));
            }
            body.append($('<tr>').attr('data-status', check.status || 'info')
                .append($('<th scope="row">').text(check.label || ''))
                .append(value)
                .append($('<td class="text-right">').append(
                    $('<span>').addClass('label label-' + checkMeta.style)
                        .append(statusIcon(check.status, false), ' ')
                        .append($('<span>').text(checkMeta.label))
                )));
        });
        table.append(body);
        panel.append($('<div class="table-responsive">').append(table));
        return panel;
    }

    function discoveryError(message) {
        return $('<div class="alert alert-danger oidc-discovery-error" role="alert">')
            .append(statusIcon('error'), ' ')
            .append($('<strong>').text(options.discoveryRejected || 'Discovery was not accepted.'), ' ')
            .append($('<span>').text(message || ''));
    }

    function withDiscoveryTest() {
        var submit = $('#submit');
        if (submit.length === 0) {
            return;
        }
        var testButton = $('<button>')
            .attr({ type: 'button', class: 'btn btn-default auth_options auth_openidconnect oidc-discovery-test', style: 'margin-left: 10px' })
            .text(options.testLabel || 'Test')
            .on('click', function () {
                /* A network action by the firewall: POST lets core enforce its CSRF token. */
                var data = {
                    url: $(field('openidconnect_provider_url')).val(),
                    profile: $(field('openidconnect_provider_profile')).val(),
                    microsoft_audience: $(field('openidconnect_microsoft_audience')).val(),
                    response_mode: $(field('openidconnect_response_mode')).val(),
                    token_auth: $(field('openidconnect_token_auth')).val(),
                    claims_source: $(field('openidconnect_claims_source')).val()
                };
                testButton.prop('disabled', true).empty()
                    .append($('<i class="fa fa-spinner fa-spin" aria-hidden="true">'), ' ')
                    .append(document.createTextNode(options.testingLabel || 'Testing...'));
                $.ajax({ type: 'POST', url: '/api/openidconnect/discovery/probe', data: data })
                    .done(function (answer) {
                        if (answer && answer.status === 'ok') {
                            BootstrapDialog.show({
                                title: options.testLabel,
                                message: discoveryResult(answer),
                                type: answer.overall === 'warning'
                                    ? BootstrapDialog.TYPE_WARNING : BootstrapDialog.TYPE_SUCCESS,
                                size: BootstrapDialog.SIZE_WIDE
                            });
                        } else {
                            BootstrapDialog.show({
                                title: options.testLabel,
                                message: discoveryError((answer && answer.message) || 'unknown error'),
                                type: BootstrapDialog.TYPE_DANGER
                            });
                        }
                    })
                    .fail(function (xhr) {
                        BootstrapDialog.show({
                            title: options.testLabel,
                            message: discoveryError(xhr.responseText || 'request failed'),
                            type: BootstrapDialog.TYPE_DANGER
                        });
                    })
                    .always(function () {
                        testButton.prop('disabled', false).text(options.testLabel || 'Test');
                    });
            });
        testButton.insertAfter(submit);
        $('<span class="help-block auth_options auth_openidconnect oidc-discovery-help">')
            .text(options.testHelp || 'This optional test is independent of saving.')
            .insertAfter(testButton);
    }

    function withSignInTest() {
        var submit = $('#submit');
        if (submit.length === 0) {
            return;
        }
        var address = new URL(window.location.href);
        var nameInput = field('name');
        var savedName = nameInput ? nameInput.value.trim() : '';
        var saved = address.searchParams.get('act') === 'edit'
            && /^\d+$/.test(address.searchParams.get('id') || '') && savedName !== '';
        var requiredFields = [
            'openidconnect_provider_url', 'openidconnect_client_id', 'openidconnect_client_secret'
        ];
        var savedReady = saved && options.webGuiTransportReady !== false
            && requiredFields.every(function (name) {
            var input = field(name);
            return input && input.value.trim() !== '';
        });
        var running = false;
        var button = $('<button>')
            .attr({
                type: 'button',
                class: 'btn btn-default auth_options auth_openidconnect oidc-signin-test',
                style: 'margin-left: 10px'
            })
            .text(options.signInTestLabel || 'Test sign-in')
            .on('click', function () {
                if (button.prop('disabled')) {
                    return;
                }
                running = true;
                button.prop('disabled', true).empty()
                    .append($('<i class="fa fa-spinner fa-spin" aria-hidden="true">'), ' ')
                    .append(document.createTextNode(options.setupGeneratingLabel || 'Generating setup file...'));
                $.ajax({
                    type: 'POST',
                    url: '/api/openidconnect/test/start',
                    data: { provider: savedName }
                }).done(function (answer) {
                    if (answer && answer.status === 'ok' && answer.authorization_url_b64) {
                        try {
                            var authorizationUrl = new URL(window.atob(answer.authorization_url_b64));
                            if (authorizationUrl.protocol === 'https:') {
                                window.location.assign(authorizationUrl.href);
                                return;
                            }
                        } catch (_) {
                            /* The authenticated API must return one absolute HTTPS address. */
                        }
                    }
                    BootstrapDialog.show({
                        title: options.signInTestLabel || 'Test sign-in',
                        message: $('<div>').text((answer && answer.message) || 'unknown error').html(),
                        type: BootstrapDialog.TYPE_DANGER
                    });
                    running = false;
                    updateAvailability();
                }).fail(function (xhr) {
                    BootstrapDialog.show({
                        title: options.signInTestLabel || 'Test sign-in',
                        message: $('<div>').text(xhr.responseText || 'request failed').html(),
                        type: BootstrapDialog.TYPE_DANGER
                    });
                    running = false;
                    updateAvailability();
                });
            });
        var help = $('<span class="help-block auth_options auth_openidconnect oidc-signin-help">');

        function currentFieldsComplete() {
            return requiredFields.every(function (name) {
                var input = field(name);
                return input && input.value.trim() !== '';
            });
        }

        function updateAvailability() {
            var ready = saved && savedReady && currentFieldsComplete() && currentTransportReady();
            button.prop('disabled', running || !ready);
            if (!running) {
                button.text(options.signInTestLabel || 'Test sign-in');
            }
            if (!saved) {
                help.empty().append(inlineCode(
                    options.signInTestSaveHelp || 'Save this server before testing sign-in.'
                ));
            } else if (!currentTransportReady() || options.webGuiTransportReady === false) {
                help.empty().append(inlineCode(
                    options.signInTestTransportHelp
                        || 'Save a complete secure WebGUI transport configuration before testing sign-in.'
                ));
            } else if (!ready) {
                help.empty().append(inlineCode(
                    options.signInTestIncompleteHelp
                        || 'Complete and save `Exact issuer URL`, `Client ID` and `Client Secret` before testing sign-in.'
                ));
            } else {
                help.text(options.signInTestHelp || 'Runs a complete browser sign-in without changing OPNsense.');
            }
        }

        requiredFields.forEach(function (name) {
            $(field(name)).on('input change', updateAvailability);
        });
        ['openidconnect_tls_offloading', 'openidconnect_origin_policy', 'openidconnect_redirect_urls']
            .forEach(function (name) { $(field(name)).on('input change', updateAvailability); });
        var anchor = $('.oidc-discovery-help');
        button.insertAfter(anchor.length ? anchor : submit);
        help.insertAfter(button);
        updateAvailability();
    }

    function withApprovalManager() {
        var submit = $('#submit');
        var nameInput = field('name');
        if (submit.length === 0 || !nameInput) {
            return;
        }
        var address = new URL(window.location.href);
        var saved = address.searchParams.get('act') === 'edit'
            && /^\d+$/.test(address.searchParams.get('id') || '') && nameInput.value.trim() !== '';
        var button = $('<button class="btn btn-default auth_options auth_openidconnect oidc-approval-manager">')
            .attr({ type: 'button', style: 'margin-left: 10px' })
            .prop('disabled', !saved)
            .text(options.approvalLabel || 'Manage identities');
        var help = $('<span class="help-block auth_options auth_openidconnect oidc-approval-help">')
            .text(saved ? (options.approvalHelp || '') : (options.approvalSaveHelp || ''));

        function request(action, data) {
            return $.ajax({
                type: 'POST',
                url: '/api/openidconnect/approval/' + action,
                data: $.extend({ provider: nameInput.value.trim() }, data || {})
            });
        }

        var newAccountValue = '__openidconnect_new_local_account__';

        function accountPicker(accounts, selected, allowCreate) {
            var picker = $('<select class="form-control input-sm">')
                .append($('<option value="">').text(
                    accounts.length ? (options.approvalChooseAccount || 'Choose a local account')
                        : (options.approvalNoAccounts || 'No eligible local account is available.')
                ));
            accounts.forEach(function (candidate) {
                picker.append($('<option>').val(candidate.uid).text(candidate.name));
            });
            if (allowCreate) {
                picker.append($('<option>').val(newAccountValue)
                    .text(options.approvalCreateAccount || 'Create a new local account…'));
            }
            picker.val(selected || '');
            return picker;
        }

        function accountCreationEditor(picker) {
            var username = $('<input class="form-control input-sm" type="text" autocomplete="off" spellcheck="false">')
                .attr({ maxlength: 320, placeholder: options.approvalUsername || 'Username' })
                .css({ width: '100%', maxWidth: 'none' });
            var container = $('<div class="form-group oidc-account-creation">')
                .append($('<label>').text(options.approvalNewAccount || 'New local account'))
                .append(username)
                .append($('<p class="help-block">').text(
                    options.approvalAccountCreationHelp
                        || 'The account receives a scrambled password and no groups or privileges.'
                ));
            function creating() {
                return picker.val() === newAccountValue;
            }
            function valid() {
                var value = username.val().trim();
                return !creating() || (value !== '' && value.length <= 320
                    && !/[\u0000-\u001f\u007f]/.test(value));
            }
            function update() {
                container.toggle(creating());
                if (creating()) {
                    username.focus();
                }
            }
            picker.on('change', update);
            update();
            return { container: container, username: username, creating: creating, valid: valid };
        }

        function resolveAccount(picker, creation) {
            var deferred = $.Deferred();
            if (!creation.creating()) {
                deferred.resolve(picker.val(), false);
                return deferred.promise();
            }
            if (!creation.valid()) {
                deferred.reject(options.approvalAccountCreateFailed || 'Enter a valid new local username.');
                return deferred.promise();
            }
            request('create_account', { username: creation.username.val().trim() }).done(function (answer) {
                var created = answer && answer.account ? answer.account : {};
                if (answer && answer.status === 'ok' && /^\d+$/.test(created.uid || '') && created.name) {
                    picker.find('option[value="' + created.uid + '"]').remove();
                    picker.find('option[value="' + newAccountValue + '"]')
                        .before($('<option>').val(created.uid).text(created.name));
                    picker.val(created.uid).trigger('change');
                    deferred.resolve(created.uid, true);
                } else {
                    deferred.reject((answer && answer.message)
                        || options.approvalAccountCreateFailed || 'The local account could not be created.');
                }
            }).fail(function (xhr) {
                deferred.reject(xhr.responseText
                    || options.approvalAccountCreateFailed || 'The local account could not be created.');
            });
            return deferred.promise();
        }

        function editBinding(panel, answer, dialog, binding) {
            panel.find('.oidc-binding-editor').remove();
            var guidance = answer.subject_guidance || {};
            var editor = $('<div class="panel panel-info oidc-binding-editor">');
            var body = $('<div class="panel-body">');
            var issuer = $('<input class="form-control input-sm" type="url" autocomplete="off">')
                .css({ width: '100%', maxWidth: 'none' })
                .val(binding ? binding.issuer : (guidance.issuer_default || ''));
            if (!guidance.issuer_editable) {
                issuer.prop('readonly', true);
            }
            var subject = $('<input class="form-control input-sm" type="text" autocomplete="off" spellcheck="false">')
                .attr({ maxlength: 255, placeholder: guidance.placeholder || 'Paste the exact sub claim' })
                .css({ width: '100%', maxWidth: 'none' })
                .val(binding ? binding.subject : '');
            var account = accountPicker(
                answer.accounts || [],
                binding ? binding.uid : '',
                !binding && answer.account_creation_allowed
            );
            account.css({ width: '100%', maxWidth: 'none' });
            var creation = accountCreationEditor(account);
            var result = $('<div class="help-block oidc-binding-result">');
            var save = $('<button class="btn btn-primary btn-sm" type="button">')
                .text(options.bindingSave || 'Save binding');
            var cancel = $('<button class="btn btn-default btn-sm" type="button">')
                .text(options.bindingCancel || 'Cancel')
                .on('click', function () { editor.remove(); });

            var saving = false;
            function valid() {
                var value = subject.val().trim();
                var byteLength = window.TextEncoder
                    ? new window.TextEncoder().encode(value).length
                    : unescape(encodeURIComponent(value)).length;
                return issuer.val().trim() !== '' && byteLength > 0 && byteLength <= 255
                    && !/[\u0000-\u001f\u007f]/.test(value) && account.val() !== '' && creation.valid();
            }
            function update() {
                save.prop('disabled', saving || !answer.writable || !valid());
            }
            issuer.on('input change', update);
            subject.on('input change', update);
            account.on('change', update);
            creation.username.on('input change', update);
            save.on('click', function () {
                if (!valid()) {
                    (creation.creating() ? creation.username : subject).focus();
                    return;
                }
                saving = true;
                update();
                var action = binding ? 'update' : 'create';
                resolveAccount(account, creation).done(function (uid, created) {
                    request(action, {
                        binding_id: binding ? binding.id : '',
                        issuer: issuer.val().trim(),
                        subject: subject.val().trim(),
                        uid: uid
                    }).done(function (savedBinding) {
                        if (savedBinding && savedBinding.status === 'ok') {
                            load(dialog);
                        } else {
                            var message = (savedBinding && savedBinding.message)
                                || options.bindingSaveFailed || 'The identity binding could not be saved.';
                            if (created) {
                                message = (options.approvalAccountCreatedBindingFailed
                                    || 'The local account was created, but the identity was not bound.')
                                    + ' ' + message;
                            }
                            result.empty().addClass('text-danger').text(message);
                            saving = false;
                            update();
                        }
                    }).fail(function (xhr) {
                        var message = xhr.responseText
                            || options.bindingSaveFailed || 'The identity binding could not be saved.';
                        if (created) {
                            message = (options.approvalAccountCreatedBindingFailed
                                || 'The local account was created, but the identity was not bound.') + ' ' + message;
                        }
                        result.empty().addClass('text-danger').text(message);
                        saving = false;
                        update();
                    });
                }).fail(function (message) {
                    result.empty().addClass('text-danger').text(message);
                    saving = false;
                    update();
                });
            });

            body.append($('<div class="alert alert-warning">')
                .append(statusIcon('warning'), ' ')
                .append(inlineCode(options.bindingManualWarning || 'Manual binding requires verified values.')));
            body.append($('<div class="alert alert-info">')
                .append(statusIcon('info'), ' ')
                .append(inlineCode(guidance.text || options.bindingValidation || 'Use the exact sub claim.')));
            [
                [options.bindingIssuer || 'Exact issuer', issuer],
                [options.bindingSubject || 'Subject (sub)', subject],
                [options.bindingAccount || 'Local account', account]
            ].forEach(function (entry) {
                body.append($('<div class="form-group">')
                    .append($('<label>').text(entry[0]))
                    .append(entry[1]));
            });
            body.append(creation.container);
            body.append($('<p class="help-block">').append(inlineCode(options.bindingValidation || '')));
            body.append(result, $('<div>').append(save, ' ', cancel));
            editor.append($('<div class="panel-heading">').append($('<strong>').text(
                binding ? (options.bindingEditorEdit || 'Edit identity binding')
                    : (options.bindingEditorNew || 'Add an identity')
            )), body);
            panel.find('.oidc-manager-toolbar').after(editor);
            update();
            subject.focus();
        }

        function renderBindings(panel, answer, dialog) {
            var bindings = Array.isArray(answer.bindings) ? answer.bindings : [];
            var toolbar = $('<div class="clearfix oidc-manager-toolbar">')
                .append($('<h4 class="pull-left">').text(options.bindingHeading || 'Bound identities'));
            var add = $('<button class="btn btn-primary btn-sm pull-right" type="button">')
                .prop('disabled', !answer.writable)
                .append($('<i class="fa fa-plus" aria-hidden="true">'), ' ')
                .append($('<span>').text(options.bindingAdd || 'Add identity binding'))
                .on('click', function () { editBinding(panel, answer, dialog, null); });
            toolbar.append(add);
            panel.append(toolbar);
            if (bindings.length === 0) {
                panel.append($('<div class="alert alert-info">').append(
                    statusIcon('info'), ' ', $('<span>').text(options.bindingEmpty || 'No identities are bound.')
                ));
                return;
            }
            var table = $('<table class="table table-striped table-condensed">');
            table.append($('<thead>').append($('<tr>')
                .append($('<th>').text(options.bindingSubject || 'Subject (sub)'))
                .append($('<th>').text(options.bindingIssuer || 'Exact issuer'))
                .append($('<th>').text(options.bindingAccount || 'Local account'))
                .append($('<th class="text-right">'))));
            var tableBody = $('<tbody>');
            bindings.forEach(function (binding) {
                var subjectCell = $('<td>').append($('<code>').css('word-break', 'break-all').text(binding.subject || ''));
                if (!binding.canonical) {
                    subjectCell.append(' ', $('<span class="label label-warning">').text(
                        options.bindingLegacy || 'Legacy mapping'
                    ));
                }
                var accountCell = $('<td>').text(binding.account || '—');
                if (!binding.account_available) {
                    accountCell.append(' ', $('<span class="text-danger">').text(
                        options.bindingUnavailable || 'Stored account is unavailable'
                    ));
                }
                var edit = $('<button class="btn btn-default btn-xs" type="button">')
                    .prop('disabled', !answer.writable)
                    .text(options.bindingEdit || 'Edit')
                    .on('click', function () { editBinding(panel, answer, dialog, binding); });
                var remove = $('<button class="btn btn-danger btn-xs" type="button">')
                    .prop('disabled', !answer.writable)
                    .text(options.bindingDelete || 'Remove')
                    .on('click', function () {
                        BootstrapDialog.confirm({
                            title: options.bindingDeleteTitle || 'Remove identity binding',
                            message: options.bindingDeleteQuestion || 'Remove this binding?',
                            type: BootstrapDialog.TYPE_DANGER,
                            callback: function (confirmed) {
                                if (confirmed) {
                                    request('delete', { binding_id: binding.id }).done(function (removed) {
                                        if (removed && removed.status === 'ok') {
                                            load(dialog);
                                        } else {
                                            BootstrapDialog.alert((removed && removed.message) || 'Removal failed.');
                                        }
                                    });
                                }
                            }
                        });
                    });
                tableBody.append($('<tr>')
                    .append(subjectCell)
                    .append($('<td>').append($('<code>').css('word-break', 'break-all').text(binding.issuer || '')))
                    .append(accountCell)
                    .append($('<td class="text-right">').append(edit, ' ', remove)));
            });
            table.append(tableBody);
            panel.append($('<div class="table-responsive">').append(table));
        }

        function renderPending(panel, answer, dialog) {
            var requests = Array.isArray(answer.requests) ? answer.requests : [];
            var accounts = Array.isArray(answer.accounts) ? answer.accounts : [];
            panel.append($('<hr>'), $('<h4>').text(options.pendingHeading || 'Pending administrator approvals'));
            if (requests.length === 0) {
                panel.append($('<div class="alert alert-info">')
                    .append(statusIcon('info'), ' ')
                    .append($('<span>').text(answer.approval_enabled
                        ? (options.approvalEmpty || 'There are no pending identities.')
                        : (options.pendingPolicyOff || 'The current policy does not queue approvals.'))));
                return;
            }
            requests.forEach(function (pending) {
                var hints = pending.hints || {};
                var card = $('<div class="panel panel-default oidc-approval-card">');
                var heading = $('<div class="panel-heading">')
                    .append($('<strong>').text((options.approvalRequestLabel || 'Request') + ' ' + (pending.id || '')))
                    .append($('<span class="pull-right text-muted">').text(
                        (options.approvalAttemptsLabel || 'Attempts') + ': ' + (pending.attempts || 1)
                    ));
                var body = $('<div class="panel-body">');
                var reported = [hints.name, hints.username, hints.email]
                    .filter(function (value, index, values) { return value && values.indexOf(value) === index; })
                    .join(' · ');
                body.append($('<dl class="dl-horizontal">')
                    .append($('<dt>').text(options.approvalIdentity || 'Reported identity'))
                    .append($('<dd>').text(reported || '—'))
                    .append($('<dt>').text(options.approvalStableIdentity || 'Stable identity'))
                    .append($('<dd>').append($('<code>').css('word-break', 'break-all')
                        .text((pending.issuer || '') + ' · ' + (pending.subject || ''))))
                    .append($('<dt>').text(options.approvalSeen || 'First / last seen'))
                    .append($('<dd>').text(
                        new Date((pending.first_seen || 0) * 1000).toLocaleString() + ' / '
                        + new Date((pending.last_seen || 0) * 1000).toLocaleString()
                    )));
                var controls = $('<div class="form-inline">');
                var account = accountPicker(accounts, '', answer.account_creation_allowed);
                var creation = accountCreationEditor(account);
                var result = $('<div class="help-block oidc-approval-result-message">');
                var approving = false;
                var approve = $('<button class="btn btn-success btn-sm" type="button">')
                    .text(options.approvalApprove || 'Approve and bind')
                    .on('click', function () {
                        if (!account.val() || !creation.valid()) {
                            (creation.creating() ? creation.username : account).focus();
                            return;
                        }
                        approving = true;
                        updateApprove();
                        resolveAccount(account, creation).done(function (uid, created) {
                            request('approve', { request_id: pending.id, uid: uid }).done(function (answer) {
                                if (answer && answer.status === 'ok') {
                                    load(dialog);
                                } else {
                                    var message = (answer && answer.message) || 'Approval failed.';
                                    if (created) {
                                        message = (options.approvalAccountCreatedBindingFailed
                                            || 'The local account was created, but the identity was not bound.')
                                            + ' ' + message;
                                    }
                                    result.empty().addClass('text-danger').text(message);
                                    approving = false;
                                    updateApprove();
                                }
                            }).fail(function (xhr) {
                                var message = xhr.responseText || 'Approval failed.';
                                if (created) {
                                    message = (options.approvalAccountCreatedBindingFailed
                                        || 'The local account was created, but the identity was not bound.')
                                        + ' ' + message;
                                }
                                result.empty().addClass('text-danger').text(message);
                                approving = false;
                                updateApprove();
                            });
                        }).fail(function (message) {
                            result.empty().addClass('text-danger').text(message);
                            approving = false;
                            updateApprove();
                        });
                    });
                function updateApprove() {
                    approve.prop('disabled', approving || !answer.writable
                        || !account.val() || !creation.valid());
                }
                account.on('change', updateApprove);
                creation.username.on('input change', updateApprove);
                var deny = $('<button class="btn btn-danger btn-sm" type="button">')
                    .prop('disabled', !answer.writable)
                    .text(options.approvalDeny || 'Deny')
                    .on('click', function () {
                        BootstrapDialog.confirm({
                            title: options.approvalDeny || 'Deny',
                            message: (options.approvalRequestLabel || 'Request') + ' ' + pending.id,
                            type: BootstrapDialog.TYPE_DANGER,
                            callback: function (confirmed) {
                                if (confirmed) {
                                    request('deny', { request_id: pending.id }).done(function (result) {
                                        if (result && result.status === 'ok') {
                                            load(dialog);
                                        } else {
                                            BootstrapDialog.alert((result && result.message) || 'Denial failed.');
                                        }
                                    });
                                }
                            }
                        });
                    });
                controls.append(account, ' ', approve, ' ', deny);
                body.append(controls, creation.container, result);
                card.append(heading, body);
                panel.append(card);
                updateApprove();
            });
        }

        function render(answer, dialog) {
            var panel = $('<div class="oidc-approval-result">');
            if (!answer || answer.status !== 'ok') {
                return panel.append($('<div class="alert alert-danger">')
                    .append(statusIcon('error'), ' ')
                    .append($('<span>').text((answer && answer.message)
                        || options.bindingLoadFailed || 'The identity manager could not be loaded.')));
            }
            if (!answer.writable) {
                panel.append($('<div class="alert alert-warning">')
                    .append(statusIcon('warning'), ' ')
                    .append(inlineCode(options.bindingReadOnly || 'Identity changes are disabled.')));
            }
            renderBindings(panel, answer, dialog);
            renderPending(panel, answer, dialog);
            return panel;
        }

        function load(dialog) {
            dialog.setMessage($('<div class="text-center">').append(
                $('<i class="fa fa-spinner fa-spin fa-2x" aria-hidden="true">')
            ));
            request('list').done(function (answer) {
                dialog.setMessage(render(answer, dialog));
            }).fail(function (xhr) {
                dialog.setMessage(render({ status: 'error', message: xhr.responseText }, dialog));
            });
        }

        button.on('click', function () {
            var dialog = new BootstrapDialog({
                title: options.approvalLabel || 'Manage identities',
                type: BootstrapDialog.TYPE_PRIMARY,
                size: BootstrapDialog.SIZE_WIDE,
                message: $('<div>'),
                buttons: [{
                    label: options.approvalRefresh || 'Refresh',
                    icon: 'fa fa-refresh',
                    action: function (instance) { load(instance); }
                }, {
                    label: options.setupCompleteLabel || 'Done',
                    action: function (instance) { instance.close(); }
                }]
            });
            dialog.realize();
            dialog.open();
            load(dialog);
        });
        var anchor = $('.oidc-signin-help');
        button.insertAfter(anchor.length ? anchor : submit);
        help.insertAfter(button);
    }

    function withProviderSetup() {
        var submit = $('#submit');
        var profile = field('openidconnect_provider_profile');
        if (submit.length === 0 || !profile) {
            return;
        }
        var supported = options.setupProfiles || ['authentik', 'keycloak'];
        var panel = $('<span class="auth_options auth_openidconnect oidc-provider-setup">')
            .css({ display: 'inline-block', marginLeft: '10px', verticalAlign: 'top' });
        var channel = $('<select class="form-control input-sm">')
            .attr({ 'aria-label': options.setupChannelLabel || 'Logout channel' })
            .css({ display: 'inline-block', width: 'auto', marginRight: '6px' })
            .append($('<option value="backchannel">').text(
                options.setupBackchannelLabel || 'Back-channel'
            ))
            .append($('<option value="frontchannel">').text(
                options.setupFrontchannelLabel || 'Front-channel'
            ));
        var button = $('<button class="btn btn-default">')
            .attr({ type: 'button' })
            .text(options.setupLabel || 'Download provider setup');
        var guideButton = $('<button class="btn btn-default">')
            .attr({ type: 'button', style: 'margin-left: 6px' })
            .append($('<i class="fa fa-book" aria-hidden="true">'), ' ')
            .append($('<span>').text(options.setupGuideLabel || 'Open setup guide'));

        function setupData() {
            return {
                profile: profile.value,
                application_code: field('openidconnect_app_code').value,
                display_name: field('name') ? field('name').value : '',
                origins: effectiveOrigins().join(','),
                sector_origin: field('openidconnect_sector_origin').value,
                post_logout_redirect: $(field('openidconnect_logout_redirect')).is(':checked') ? '1' : '0',
                logout_channel: channel.val()
            };
        }

        function generate(download) {
            var appCode = field('openidconnect_app_code');
            if (appCode && applicationCodeConflict(appCode.value)) {
                $(appCode).trigger('input').trigger('focus');
                return;
            }
            var sectorOrigin = field('openidconnect_sector_origin').value;
            var enabled = $(field('openidconnect_enabled')).is(':checked');
            if (sectorOrigin && (currentServerId() === null || enabled || options.savedServerEnabled
                || sectorOrigin !== options.savedSectorOrigin
                || appCode.value !== options.savedApplicationCode)) {
                BootstrapDialog.show({
                    title: download
                        ? (options.setupLabel || 'Download provider setup')
                        : (options.setupGuideLabel || 'Open setup guide'),
                    message: $('<div>').text(options.setupPairwiseSaveHelp ||
                        'Save this server as a disabled draft before generating pairwise-subject setup.').html(),
                    type: BootstrapDialog.TYPE_WARNING
                });
                return;
            }
            button.prop('disabled', true);
            guideButton.prop('disabled', true);
            $.ajax({ type: 'POST', url: '/api/openidconnect/setup/generate', data: setupData() })
                .done(function (answer) {
                        if (!answer || answer.status !== 'ok') {
                            BootstrapDialog.show({
                                title: download
                                    ? (options.setupLabel || 'Download provider setup')
                                    : (options.setupGuideLabel || 'Open setup guide'),
                                message: $('<div>').text((answer && answer.message) || 'unknown error').html(),
                                type: BootstrapDialog.TYPE_DANGER
                            });
                            return;
                        }
                        if (download) {
                            var objectUrl = URL.createObjectURL(new Blob([answer.content], {
                                type: answer.media_type || 'application/octet-stream'
                            }));
                            var link = document.createElement('a');
                            link.href = objectUrl;
                            link.download = answer.filename || 'openid-connect-provider-setup.txt';
                            document.body.appendChild(link);
                            link.click();
                            link.remove();
                            URL.revokeObjectURL(objectUrl);
                        }
                        BootstrapDialog.show({
                            title: download
                                ? (options.setupDoneLabel || 'Provider setup downloaded')
                                : (options.setupGuideTitle || 'Provider setup guide'),
                            message: providerSetupResult(profile.value, answer, download),
                            type: download ? BootstrapDialog.TYPE_SUCCESS : BootstrapDialog.TYPE_PRIMARY,
                            size: BootstrapDialog.SIZE_WIDE
                        });
                })
                .fail(function (xhr) {
                        BootstrapDialog.show({
                            title: download
                                ? (options.setupLabel || 'Download provider setup')
                                : (options.setupGuideLabel || 'Open setup guide'),
                            message: $('<div>').text(xhr.responseText || 'request failed').html(),
                            type: BootstrapDialog.TYPE_DANGER
                        });
                })
                .always(function () {
                        button.prop('disabled', false).text(options.setupLabel || 'Download provider setup');
                        guideButton.prop('disabled', false);
                });
        }

        button.on('click', function () { generate(true); });
        guideButton.on('click', function () { generate(false); });
        panel.append(channel, button, guideButton)
            .append($('<span class="help-block">').text(options.setupHelp || ''));
        panel.insertAfter(submit.nextAll('.help-block').last().length
            ? submit.nextAll('.help-block').last() : submit);

        function update() {
            panel.toggle(supported.indexOf(profile.value) !== -1);
        }
        $(profile).on('change', update);
        update();
    }

    function withSharedSignalsSetup() {
        var secret = field('openidconnect_ssf_push_secret');
        var issuer = field('openidconnect_ssf_issuer');
        if (!secret || !issuer) {
            return;
        }
        $(secret).attr({
            type: 'password', autocomplete: 'new-password', autocapitalize: 'none', spellcheck: 'false'
        });
        var generate = $('<button class="btn btn-default btn-sm" type="button">')
            .css({ marginLeft: '6px' })
            .text(options.ssfGenerateSecretLabel || 'Generate secret')
            .on('click', function () {
                generate.prop('disabled', true);
                $.ajax({ type: 'POST', url: '/api/openidconnect/ssfsetup/secret' })
                    .done(function (answer) {
                        if (answer && answer.status === 'ok' && /^[A-Za-z0-9_-]{43}$/.test(answer.secret || '')) {
                            $(secret).val(answer.secret).trigger('input');
                        }
                    })
                    .always(function () { generate.prop('disabled', false); });
            });
        $(secret).after(generate);

        var probe = $('<button class="btn btn-default btn-sm" type="button">')
            .css({ marginLeft: '6px' })
            .text(options.ssfTestLabel || 'Test Shared Signals')
            .on('click', function () {
                probe.prop('disabled', true);
                $.ajax({
                    type: 'POST',
                    url: '/api/openidconnect/ssfsetup/probe',
                    data: { issuer: issuer.value }
                }).done(function (answer) {
                    BootstrapDialog.show({
                        title: options.ssfTestLabel || 'Test Shared Signals',
                        message: $('<div>').text(answer && answer.status === 'ok'
                            ? (options.ssfDiscoveryAccepted || 'Shared Signals discovery accepted.')
                            : ((answer && answer.message) || 'unknown error')).html(),
                        type: answer && answer.status === 'ok'
                            ? BootstrapDialog.TYPE_SUCCESS : BootstrapDialog.TYPE_DANGER
                    });
                }).fail(function (xhr) {
                    BootstrapDialog.show({
                        title: options.ssfTestLabel || 'Test Shared Signals',
                        message: $('<div>').text(xhr.responseText || 'request failed').html(),
                        type: BootstrapDialog.TYPE_DANGER
                    });
                }).always(function () { probe.prop('disabled', false); });
            });
        $(issuer).after(probe);

        var authorization = $('<div class="help-block oidc-ssf-authorization">');
        row('openidconnect_ssf_push_secret').find('td').last().append(authorization);
        function updateAuthorization() {
            authorization.empty();
            if (secret.value) {
                authorization.append($('<span>').text(
                    (options.ssfAuthorizationLabel || 'Authorization header') + ': '
                )).append($('<code>').text('Bearer ' + secret.value));
            }
        }
        $(secret).on('input change', updateAuthorization);
        updateAuthorization();
    }

    function providerSetupResult(provider, answer, includeDownload) {
        /* inlineCode keeps menu paths and literal values scannable without creating an
         * HTML input surface for provider responses or translated strings. */
        var guides = options.setupGuides || {};
        var guide = guides[provider] || {};
        var providerName = guide.name || provider;
        var panel = $('<div class="oidc-setup-result">').attr('data-provider', provider);
        var pages = $('<div class="oidc-setup-pages">');
        if (includeDownload) {
            var downloadPage = $('<section class="oidc-setup-page">').attr('data-step', 'download');
            downloadPage.append($('<h4>').text(options.setupDownloadHeading || 'Setup file ready'));
            downloadPage.append($('<div class="alert alert-success" role="status">')
                .append(statusIcon('success'), ' ')
                .append($('<strong>').text(
                    options.setupDownloadStartedLabel || 'The provider setup download has started.'
                )));

            var fileSummary = $('<div class="well well-sm oidc-setup-file">')
                .append($('<strong>').text((options.setupFileLabel || 'Downloaded file') + ': '),
                    $('<code>').text(answer.filename || 'openid-connect-provider-setup.txt'));
            if (guide.artifact) {
                fileSummary.append(' ', $('<span class="label label-info">').text(guide.artifact));
            }
            downloadPage.append(fileSummary);
            pages.append(downloadPage);
        }

        var importPage = $('<section class="oidc-setup-page">').attr('data-step', 'import');
        importPage.append($('<h4>').text(guide.heading || ('Import into ' + providerName)));
        var steps = $('<ol class="oidc-setup-steps">');
        (guide.steps || []).forEach(function (step) {
            steps.append($('<li>')
                .append($('<code>').text(step.place || ''))
                .append($('<div class="text-muted">').append(inlineCode(step.action || ''))));
        });
        importPage.append(steps);

        var warning = [options.setupReviewWarning || '', guide.warning || '']
            .filter(function (message) { return message.length > 0; }).join(' ');
        if (warning) {
            importPage.append($('<div class="alert alert-warning oidc-setup-warning" role="note">')
                .append(statusIcon('warning'), ' ')
                .append(inlineCode(warning)));
        }
        pages.append(importPage);

        var finishPage = $('<section class="oidc-setup-page">').attr('data-step', 'finish');
        finishPage.append($('<h4>').text(
            options.setupFinishHeading || 'Finish the connection in OPNsense'
        ));
        var finish = $('<ol class="oidc-setup-finish">');
        if (guide.providerFinish) {
            finish.append($('<li>').append(inlineCode(guide.providerFinish)));
        }
        if (answer.client_id_hint) {
            finish.append($('<li>').append(inlineCode(answer.client_id_hint)));
        }
        if (answer.issuer_hint) {
            finish.append($('<li>').append(inlineCode(answer.issuer_hint)));
        }
        finish.append($('<li>').append(inlineCode(options.setupFinishInstruction
            || 'Enter the exact issuer and client credentials in OPNsense, save, and run both tests.')));
        finishPage.append(finish);
        pages.append(finishPage);

        var progressLabel = $('<strong class="oidc-setup-progress-label">');
        var progressBar = $('<div class="progress-bar progress-bar-success" role="progressbar">');
        var progress = $('<div class="oidc-setup-progress">')
            .append(progressLabel)
            .append($('<div class="progress">').css('margin', '8px 0 18px').append(progressBar));
        var previous = $('<button type="button" class="btn btn-default oidc-setup-previous">')
            .append($('<i class="fa fa-chevron-left" aria-hidden="true">'), ' ')
            .append($('<span>').text(options.setupPreviousLabel || 'Previous'));
        var next = $('<button type="button" class="btn btn-primary oidc-setup-next">')
            .append($('<span>').text(options.setupNextLabel || 'Next'), ' ')
            .append($('<i class="fa fa-chevron-right" aria-hidden="true">'));
        var complete = $('<button type="button" class="btn btn-success oidc-setup-complete" data-dismiss="modal">')
            .append($('<i class="fa fa-check" aria-hidden="true">'), ' ')
            .append($('<span>').text(options.setupCompleteLabel || 'Done'));
        var navigation = $('<div class="oidc-setup-navigation clearfix">')
            .append(previous)
            .append($('<span class="pull-right">').append(next, complete));

        panel.append(progress, pages, navigation);
        var pageList = pages.children('.oidc-setup-page');
        var current = 0;

        function showPage(index) {
            current = Math.max(0, Math.min(index, pageList.length - 1));
            pageList.each(function (pageIndex) {
                $(this).toggle(pageIndex === current).attr('aria-hidden', pageIndex === current ? 'false' : 'true');
            });
            progressLabel.text((options.setupStepLabel || 'Step') + ' ' + (current + 1) + ' '
                + (options.setupOfLabel || 'of') + ' ' + pageList.length);
            progressBar.css('width', (((current + 1) / pageList.length) * 100) + '%')
                .attr({ 'aria-valuemin': '1', 'aria-valuemax': pageList.length, 'aria-valuenow': current + 1 });
            previous.prop('disabled', current === 0);
            next.toggle(current < pageList.length - 1);
            complete.toggle(current === pageList.length - 1);
        }

        previous.on('click', function () { showPage(current - 1); });
        next.on('click', function () { showPage(current + 1); });
        showPage(0);

        return panel;
    }

    function addSections() {
        $.each(options.sections || {}, function (firstField, title) {
            var target = row(firstField);
            if (target.length) {
                $('<tr class="auth_options auth_openidconnect oidc-section"><td colspan="2"><h4></h4></td></tr>')
                    .find('h4').text(title).end().insertBefore(target);
            }
        });
    }

    function applicationCodeAvailability() {
        var input = field('openidconnect_app_code');
        if (!input) {
            return;
        }
        var status = $('<span class="help-block text-danger oidc-app-code-conflict" role="status" aria-live="polite">')
            .hide();
        row('openidconnect_app_code').find('td').last().append(status);

        function update() {
            var conflict = applicationCodeConflict(input.value);
            status.empty().toggle(Boolean(conflict));
            $(input).attr('aria-invalid', conflict ? 'true' : 'false');
            if (conflict) {
                status.append(statusIcon('error'), ' ')
                    .append(document.createTextNode(
                        (options.applicationCodeConflictLabel || 'Already used by authentication server') + ': '
                    ))
                    .append($('<code>').text(conflict.name || conflict.code));
            }
        }
        $(input).on('input change', update);
        update();
    }

    function endpointPreview() {
        var target = row('openidconnect_app_code').find('td').last();
        if (!target.length) {
            return;
        }
        var preview = $('<div class="help-block oidc-endpoints"><strong></strong><div></div></div>');
        preview.find('strong').text(options.endpointLabel || 'Provider endpoints');
        target.append(preview);

        function update() {
            var code = (field('openidconnect_app_code').value || 'main').trim();
            var origins = effectiveOrigins();
            var supplied = origins[0];
            var output = preview.find('div').empty();
            if (!supplied) {
                $('<span>').text(options.noEndpointOrigin || 'No accepted HTTPS WebGUI origin is available.')
                    .appendTo(output);
                return;
            }
            var origin = supplied.replace(/\/$/, '');
            try {
                var parsed = new URL(supplied);
                if (parsed.protocol === 'https:') {
                    /* A mistakenly pasted callback must never produce a doubled preview. */
                    origin = parsed.origin;
                }
            } catch (_) {
                /* Keep the typed value visible while the normal form validator explains it. */
            }
            var base = origin + '/api/openidconnect/auth/';
            var destinations = [
                [options.authorizationEndpointLabel || 'Authorization redirect URI', base + 'callback/' + encodeURIComponent(code)],
                [options.postLogoutEndpointLabel || 'Post-logout redirect URI', origin + '/'],
                [options.backchannelEndpointLabel || 'Back-channel logout URI', base + 'backchannel/' + encodeURIComponent(code)],
                [options.frontchannelEndpointLabel || 'Front-channel logout URI', base + 'frontchannel/' + encodeURIComponent(code)]
            ];
            if ($(field('openidconnect_ssf_enabled')).is(':checked')) {
                destinations.push([
                    options.ssfEndpointLabel || 'Shared Signals push URI',
                    origin + '/api/openidconnect/ssf/push/' + encodeURIComponent(code)
                ]);
            }
            var sectorOrigin = field('openidconnect_sector_origin').value;
            if (sectorOrigin) {
                destinations.push([
                    options.sectorEndpointLabel || 'Pairwise sector identifier URI',
                    sectorOrigin + '/api/openidconnect/auth/sector/' + encodeURIComponent(code)
                ]);
            }
            destinations.forEach(function (destination) {
                $('<div>').append($('<span>').text(destination[0] + ': '))
                    .append($('<code>').text(destination[1])).appendTo(output);
            });
            $('<small>').text(options.endpointHelp || '').appendTo(output);
        }
        $(field('openidconnect_app_code')).on('input change', update);
        $(field('openidconnect_redirect_urls')).on('input change', update);
        $(field('openidconnect_origin_policy')).on('change', update);
        $(field('openidconnect_sector_origin')).on('change', update);
        $(field('openidconnect_ssf_enabled')).on('change', update);
        update();
    }

    function conditionalFields() {
        function update() {
            var creates = $(field('openidconnect_create_users')).is(':checked');
            var admission = field('openidconnect_bootstrap_mode').value || 'strict';
            var automatic = ['username', 'verified_email', 'either'].indexOf(admission) !== -1;
            var groupClaim = (field('openidconnect_group_claim').value || '').trim() !== '';
            var provider = field('openidconnect_provider_profile').value || 'general';
            var authentication = field('openidconnect_required_authentication').value || '';
            var authenticationRequired = authentication !== '';
            var buttonTextMode = field('openidconnect_button_text_mode').value || 'localized';
            var buttonTextCustomizable = (options.fixedButtonProfiles || []).indexOf(provider) === -1;
            row('openidconnect_tls_offloading').toggle(options.webGuiProtocol === 'http');
            row('openidconnect_microsoft_audience').toggle(provider === 'entra');
            row('openidconnect_acr_request').toggle(authenticationRequired && provider !== 'entra');
            row('openidconnect_acr_values').toggle(authenticationRequired && provider !== 'entra');
            row('openidconnect_amr_values').toggle(authenticationRequired);
            row('openidconnect_entra_auth_context').toggle(authenticationRequired && provider === 'entra');
            row('openidconnect_create_users').toggle(automatic);
            row('openidconnect_default_groups').toggle(automatic && creates);
            row('openidconnect_assignable_groups').toggle(groupClaim);
            row('openidconnect_allow_all_groups').toggle(groupClaim);
            row('openidconnect_logout_redirect').toggle($(field('openidconnect_logout_menu')).is(':checked'));
            var sharedSignals = $(field('openidconnect_ssf_enabled')).is(':checked');
            row('openidconnect_ssf_issuer').toggle(sharedSignals);
            row('openidconnect_ssf_audience').toggle(sharedSignals);
            row('openidconnect_ssf_push_secret').toggle(sharedSignals);
            row('openidconnect_button_text_mode').toggle(buttonTextCustomizable);
            row('openidconnect_button_provider_label').toggle(
                buttonTextCustomizable && buttonTextMode !== 'custom'
            );
            row('openidconnect_button_custom_text').toggle(
                buttonTextCustomizable && buttonTextMode === 'custom'
            );
        }
        $(field('openidconnect_create_users')).on('change', update);
        $(field('openidconnect_group_claim')).on('input change', update);
        $(field('openidconnect_logout_menu')).on('change', update);
        $(field('openidconnect_ssf_enabled')).on('change', update);
        $(field('openidconnect_origin_policy')).on('change', update);
        $(field('openidconnect_bootstrap_mode')).on('change', update);
        $(field('openidconnect_provider_profile')).on('change', update);
        $(field('openidconnect_required_authentication')).on('change', update);
        $(field('openidconnect_button_text_mode')).on('change', update);
        update();
    }

    function authenticationRequirementPresets() {
        var requirement = field('openidconnect_required_authentication');
        var profile = field('openidconnect_provider_profile');
        var requestMode = field('openidconnect_acr_request');
        var contexts = field('openidconnect_acr_values');
        var methods = field('openidconnect_amr_values');
        var presets = options.authenticationRequirementPresets || {};
        if (!requirement || !profile || !requestMode || !contexts || !methods) {
            return;
        }

        function selectedPreset() {
            var provider = ['okta', 'entra'].indexOf(profile.value) !== -1 ? profile.value : 'general';
            return ((presets[provider] || {})[requirement.value || '']) || null;
        }

        function apply(force) {
            var preset = selectedPreset();
            if (!preset) {
                return;
            }
            if (force || requestMode.value === '') {
                requestMode.value = preset.request === 'entra_context' ? '' : (preset.request || '');
            }
            if (force || contexts.value.trim() === '') {
                contexts.value = preset.acr || '';
            }
            if (force || methods.value.trim() === '') {
                methods.value = preset.amr || '';
            }
        }

        $(requirement).on('change', function () { apply(true); });
        $(profile).on('change', function () { apply(true); });
        apply(false);
    }

    function webGuiTransportNotice() {
        var transportRow = row('openidconnect_tls_offloading');
        if (transportRow.length === 0 || options.webGuiProtocol !== 'http') {
            transportRow.hide();
            return;
        }
        var notice = $('<div class="help-block oidc-transport-notice">');
        transportRow.find('td').last().append(notice);

        function update() {
            var selected = $(field('openidconnect_tls_offloading')).is(':checked');
            notice.removeClass('text-danger text-warning').empty();
            if (!selected) {
                notice.addClass('text-danger').append(inlineCode(options.tlsOffloadingBlocked || 'OpenID Connect is blocked while the WebGUI uses HTTP.'));
            } else if (!currentTransportReady()) {
                notice.addClass('text-danger').append(inlineCode(options.tlsOffloadingIncomplete || 'Complete the Custom public HTTPS origins.'));
            } else {
                notice.addClass('text-warning').append(inlineCode(options.tlsOffloadingActive || 'Advanced TLS-offloading exception active.'));
            }
        }
        ['openidconnect_tls_offloading', 'openidconnect_origin_policy', 'openidconnect_redirect_urls']
            .forEach(function (name) { $(field(name)).on('input change', update); });
        update();
    }

    function providerPresets() {
        var presets = options.profilePresets || {};
        var configured = options.configuredFields || [];
        var profile = field('openidconnect_provider_profile');
        var previousProfile;
        if (!profile) {
            return function () {};
        }
        previousProfile = profile.value || 'general';

        var summary = $('<div class="help-block oidc-profile-summary">');
        var summaryText = $('<span>');
        var restore = $('<button type="button" class="btn btn-default btn-xs oidc-profile-restore">')
            .text(options.profileRestoreLabel || 'Restore profile defaults');
        summary.append(summaryText, ' ', restore);
        row('openidconnect_provider_profile').find('td').last().append(summary);

        function preset() {
            return presets[profile.value] || presets.general || { values: {}, locked: [], placeholders: {} };
        }

        function setValue(name, value) {
            var input = field(name);
            if (!input) {
                return;
            }
            $(input).val(value).attr('value', value).trigger('change');

            /* A list field is upgraded after this function first runs. Keep that visible
             * picker in step when defaults are restored later. */
            if (input.type === 'hidden') {
                var picker = $(input).next('select.tokenize');
                if (picker.length) {
                    picker.empty();
                    listEntries(value).forEach(function (entry) {
                        picker.append($('<option selected="selected">').val(entry).text(entry));
                    });
                    picker.trigger('change');
                }
            }
        }

        function setLocked(name, locked) {
            var input = field(name);
            if (!input) {
                return;
            }
            var control = $(input);
            var picker = input.type === 'hidden' ? control.next('select.tokenize') : $();
            var shadow = control.siblings('input[type="hidden"][data-oidc-profile-shadow="' + name + '"]');

            if (input.tagName === 'SELECT') {
                if (locked) {
                    control.attr('data-oidc-profile-fixed', '1').prop('disabled', true);
                    if (!shadow.length) {
                        shadow = $('<input type="hidden">').attr({
                            name: name,
                            'data-oidc-profile-shadow': name
                        }).insertAfter(control);
                    }
                    shadow.val(input.value);
                } else if (control.attr('data-oidc-profile-fixed') === '1') {
                    control.removeAttr('data-oidc-profile-fixed').prop('disabled', false);
                    shadow.remove();
                }
            } else if (locked) {
                control.attr({ readonly: 'readonly', 'data-oidc-profile-fixed': '1' });
            } else if (control.attr('data-oidc-profile-fixed') === '1') {
                control.removeAttr('readonly data-oidc-profile-fixed');
            }
            if (picker.length) {
                picker.prop('disabled', locked).toggleClass('oidc-profile-fixed', locked);
            }
        }

        function decorate() {
            var selected = preset();
            var locked = selected.locked || [];
            var values = selected.values || {};
            var placeholders = selected.placeholders || {};
            Object.keys((presets.general || {}).values || values).forEach(function (name) {
                var input = field(name);
                if (!input) {
                    return;
                }
                var fixed = locked.indexOf(name) !== -1;
                setLocked(name, fixed);
                $(input).attr('placeholder', placeholders[name] || '');
                row(name).find('.oidc-profile-field-note').remove();
                if (profile.value === 'general') {
                    return;
                }
                var value = values[name] || '';
                var label = fixed
                    ? (options.profileFixedLabel || 'Fixed by the selected provider profile')
                    : (name === 'openidconnect_provider_url' && !value
                        ? (options.profileRequiredLabel || 'Enter the value issued by this provider')
                        : (options.profileRecommendedLabel || 'Recommended by the selected provider profile; editable'));
                $('<span class="help-block small oidc-profile-field-note">')
                    .append($('<i class="fa fa-lock" aria-hidden="true">').toggle(fixed), ' ')
                    .append($('<span>').text(label))
                    .appendTo(row(name).find('td').last());
            });

            if (profile.value === 'general') {
                summaryText.text(options.profileGenericHelp || 'Generic OpenID Connect makes no provider-specific assumptions.');
                restore.show();
            } else {
                summaryText.empty().append($('<strong>').text(
                    options.profileAppliedLabel || 'Provider defaults applied'
                ), ' — ' + (options.profileAppliedHelp || 'Recommended values remain editable.'));
                restore.show();
            }
        }

        function apply(force) {
            var selected = preset();
            Object.keys(selected.values || {}).forEach(function (name) {
                var input = field(name);
                if (force || (selected.locked || []).indexOf(name) !== -1
                    || (configured.indexOf(name) === -1 && input && input.value === '')) {
                    setValue(name, selected.values[name]);
                }
            });
            decorate();
        }

        $(profile).on('change', function () {
            /* Selecting a named profile is an explicit request for its complete starting
             * point. Generic instead unlocks the current values so custom providers do
             * not lose an issuer or claim mapping merely by changing classification. */
            var appCode = field('openidconnect_app_code');
            var previousCode = previousProfile.replace(/_/g, '-');
            if (profile.value !== 'general' && appCode
                && (appCode.value === '' || appCode.value === 'main' || appCode.value === previousCode)) {
                $(appCode).val(profile.value.replace(/_/g, '-')).trigger('change');
            }
            apply(profile.value !== 'general');
            previousProfile = profile.value;
        });
        restore.on('click', function () { apply(true); });
        apply(false);

        var microsoftAudience = field('openidconnect_microsoft_audience');
        var issuer = field('openidconnect_provider_url');
        if (microsoftAudience && issuer) {
            var discoverySuffix = '/.well-known/openid-configuration';
            function normalizeIssuerInput() {
                issuer.value = issuer.value.trim();
                if (issuer.value.endsWith(discoverySuffix)) {
                    issuer.value = issuer.value.slice(0, -discoverySuffix.length);
                    if (['auth0', 'authentik'].indexOf(profile.value) !== -1) {
                        issuer.value = issuer.value.replace(/\/+$/, '') + '/';
                    }
                }
            }
            $(issuer).on('change blur', normalizeIssuerInput);
            $(issuer.form).on('submit', normalizeIssuerInput);

            var managedMicrosoftIssuer = '';
            $(microsoftAudience).val(options.microsoftAudience || microsoftAudience.value || 'tenant');
            function updateMicrosoftIssuer() {
                var managed = profile.value === 'entra' && microsoftAudience.value !== 'tenant';
                if (managed) {
                    managedMicrosoftIssuer = 'https://login.microsoftonline.com/'
                        + microsoftAudience.value + '/v2.0';
                    issuer.value = managedMicrosoftIssuer;
                    $(issuer).attr({ readonly: 'readonly', 'data-oidc-microsoft-managed': '1' });
                } else if (managedMicrosoftIssuer && issuer.value === managedMicrosoftIssuer) {
                    issuer.value = '';
                    managedMicrosoftIssuer = '';
                } else {
                    managedMicrosoftIssuer = '';
                }
                if (!managed && $(issuer).attr('data-oidc-microsoft-managed') === '1') {
                    $(issuer).removeAttr('data-oidc-microsoft-managed');
                    if ($(issuer).attr('data-oidc-profile-fixed') !== '1') {
                        $(issuer).removeAttr('readonly');
                    }
                }
            }
            $(microsoftAudience).on('change', updateMicrosoftIssuer);
            $(profile).on('change', updateMicrosoftIssuer);
            updateMicrosoftIssuer();
        }

        return decorate;
    }

    /* --------------------------------------------------------------------- start */

    $(function () {
        $('[name=openidconnect_client_secret]').attr({
            type: 'password', autocomplete: 'new-password', autocapitalize: 'none', spellcheck: 'false'
        });
        var maximumAge = field('openidconnect_max_age');
        if (maximumAge && maximumAge.value.trim() === '') {
            /* Configurations written before the secure default may contain an explicit
             * empty element, which core does not replace with the field default. */
            maximumAge.value = String(options.maximumAuthenticationAgeDefault || '14400');
            maximumAge.setAttribute('value', maximumAge.value);
        }
        asTextarea('openidconnect_icon_svg', 6);
        asGroupPicker('openidconnect_default_groups');
        asGroupPicker('openidconnect_assignable_groups');

        /* PHP can distinguish an explicit Follow policy with additions from a legacy
         * origin list written before the policy switch. Core's bare form default cannot. */
        if (options.originPolicy === 'opnsense' || options.originPolicy === 'custom') {
            $(field('openidconnect_origin_policy')).val(options.originPolicy);
        }
        sectorOriginOptions();
        withDiscoveryTest();
        withSignInTest();
        withApprovalManager();
        withProviderSetup();
        withSharedSignalsSetup();
        addSections();
        applicationCodeAvailability();
        var updateProfileDecorations = providerPresets();
        authenticationRequirementPresets();
        conditionalFields();
        webGuiTransportNotice();
        endpointPreview();

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
                updateProfileDecorations();
            });
    });
}());
