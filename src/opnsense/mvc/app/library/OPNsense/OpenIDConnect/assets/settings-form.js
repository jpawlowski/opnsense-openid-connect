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

    /* Core upgrades ordinary selects to Bootstrap pickers. The native select remains
     * authoritative, but changing only that hidden element leaves a clickable picker
     * showing stale values and enabled options. Keep both halves of the control in step. */
    function refreshSelectPicker(input) {
        if (!input || input.tagName !== 'SELECT') {
            return;
        }
        var control = $(input);
        var picker = control.closest('.bootstrap-select');
        if (typeof control.selectpicker === 'function'
            && (control.data('selectpicker') || picker.length)) {
            control.selectpicker('refresh');
            picker = control.closest('.bootstrap-select');
        }
        if (picker.length) {
            picker.toggleClass('disabled', input.disabled).removeClass(input.disabled ? 'open' : '');
            picker.children('button').prop('disabled', input.disabled)
                .attr('aria-disabled', input.disabled ? 'true' : 'false');
        }
    }

    function setConditionalSelectLock(input, locked) {
        if (!input || input.tagName !== 'SELECT') {
            return;
        }
        var control = $(input);
        if (locked) {
            control.attr('data-oidc-conditional-fixed', '1').prop('disabled', true);
        } else if (control.attr('data-oidc-conditional-fixed') === '1') {
            control.removeAttr('data-oidc-conditional-fixed');
            if (control.attr('data-oidc-profile-fixed') !== '1') {
                control.prop('disabled', false);
            }
        }
        refreshSelectPicker(input);
    }

    function toggleFieldRow(name, visible) {
        var input = field(name);
        if (!visible && input && input.tagName === 'SELECT') {
            $(input).closest('.bootstrap-select').removeClass('open');
        }
        row(name).toggle(visible);
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
        var standardPort = field('openidconnect_standard_https_port');
        var entered = listEntries(field('openidconnect_redirect_urls').value);
        var inherited = (options.opnsenseOrigins || []).slice();
        if (standardPort && $(standardPort).is(':checked')) {
            inherited = inherited.concat(options.opnsenseStandardHttpsOrigins || []);
        }
        var origins = !policy || policy.value !== 'custom'
            ? uniqueOrigins(inherited.concat(entered))
            : uniqueOrigins(entered);
        var current = normalizedOrigin(window.location.origin);
        var currentIndex = current ? origins.indexOf(current) : -1;
        if (currentIndex > 0) {
            origins.splice(currentIndex, 1);
            origins.unshift(current);
        }
        return origins;
    }

    function currentSetupOrigin() {
        var current = normalizedOrigin(window.location.origin);
        if (!current || effectiveOrigins().indexOf(current) === -1) {
            return null;
        }
        var hostname = new URL(current).hostname.replace(/\.$/, '');
        if (hostname.indexOf('.') === -1 || hostname.indexOf(':') !== -1
            || /^\d+(?:\.\d+){3}$/.test(hostname)) {
            return null;
        }
        return current;
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
        refreshSelectPicker(select);

        function update() {
            selected = select.value;
            $(select).empty().append($('<option>').attr('value', '').text(options.sectorOffLabel || 'Off'));
            effectiveOrigins().forEach(function (origin) {
                $(select).append($('<option>').attr('value', origin).text(origin));
            });
            select.value = effectiveOrigins().indexOf(selected) === -1 ? '' : selected;
            refreshSelectPicker(select);
        }
        $(field('openidconnect_redirect_urls')).on('input change', update);
        $(field('openidconnect_origin_policy')).on('change', update);
        $(field('openidconnect_standard_https_port')).on('change', update);
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
            $(input).val((picker.val() || []).join(',')).trigger('change');
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

    function formActionSection(name, label) {
        var submit = $('#submit');
        var sections = $('.oidc-action-sections');
        if (sections.length === 0 && submit.length) {
            sections = $('<div class="oidc-action-sections auth_options auth_openidconnect">')
                .insertBefore(submit);
        }
        var section = sections.children('[data-oidc-action-section="' + name + '"]');
        if (section.length === 0) {
            section = $('<section class="oidc-action-section">')
                .attr('data-oidc-action-section', name)
                .append($('<h4>').text(label))
                .append($('<div class="oidc-form-actions" role="group">').attr(
                    'aria-label', label
                ))
                .appendTo(sections);
        }
        return section;
    }

    /* A disabled button does not reliably receive pointer or keyboard events, so its
     * title cannot explain why the action is unavailable. Let a focusable wrapper own
     * the tooltip while leaving the real button disabled for form semantics. */
    function withActionHelp(button, className) {
        var wrapper = $('<span class="oidc-action-help">').addClass(className || '').append(button);
        var tooltipReady = false;

        function update(message, disabled) {
            var explanation = String(message || '').replace(/`/g, '');
            wrapper.toggleClass('oidc-action-help-disabled', disabled).attr({
                'aria-label': explanation,
                title: explanation
            });
            if (disabled) {
                wrapper.attr('tabindex', '0');
            } else {
                wrapper.removeAttr('tabindex');
            }
            button.attr('title', explanation);
            if (typeof wrapper.tooltip === 'function') {
                if (!tooltipReady) {
                    wrapper.tooltip({ container: 'body', placement: 'top', trigger: 'hover focus' });
                    tooltipReady = true;
                }
                wrapper.attr({ 'data-original-title': explanation, title: '' });
            }
        }

        return { element: wrapper, update: update };
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

    function checkFlow(check) {
        var actors = options.actors || {};
        var actorIcons = { opnsense: 'fa-shield', browser: 'fa-desktop', idp: 'fa-cloud' };
        var path = Array.isArray(check.actors) ? check.actors.filter(function (actor) {
            return Object.prototype.hasOwnProperty.call(actorIcons, actor);
        }) : [];
        var flow = $('<div class="oidc-check-flow text-muted small">');
        path.forEach(function (actor, index) {
            if (index > 0) {
                flow.append($('<span class="oidc-check-connector" aria-hidden="true">'));
            }
            flow.append($('<span class="oidc-check-actor">')
                .append($('<i aria-hidden="true">').addClass('fa ' + actorIcons[actor]), ' ')
                .append($('<span>').text(actors[actor] || actor)));
        });
        var separator = options.actorFlowSeparator || 'to';
        var actorText = path.map(function (actor) { return actors[actor] || actor; })
            .join(' ' + separator + ' ');
        flow.attr({
            'aria-label': actorText,
            'data-actors': path.join(',')
        });
        return flow;
    }

    function checkDetails(check) {
        var sources = options.verificationSources || {};
        var execution = options.verificationExecution || {};
        var verificationIcons = {
            live: 'fa-bolt', metadata: 'fa-file-text-o', configuration: 'fa-sliders',
            'not-tested': 'fa-clock-o', skipped: 'fa-minus-circle'
        };
        var verification = Object.prototype.hasOwnProperty.call(verificationIcons, check.verification)
            ? check.verification : 'not-tested';
        var details = $('<div class="oidc-probe-check-details">');
        if (check.purpose) {
            details.append($('<p class="oidc-probe-purpose">')
                .append($('<strong>').text((options.purposeLabel || 'Why this matters') + ': '))
                .append($('<span>').text(check.purpose)));
        }
        if (check.note) {
            details.append($('<p>').text(check.note));
        }
        var facts = $('<div class="oidc-probe-facts text-muted">')
            .append($('<p>')
                .append($('<strong>').text((options.sourceLabel || 'Source') + ': '))
                .append($('<span>').text(sources[verification] || verification)))
            .append($('<p>')
                .append($('<i aria-hidden="true">').addClass('fa ' + verificationIcons[verification]), ' ')
                .append($('<strong>').text((options.executionLabel || 'Execution') + ': '))
                .append($('<span>').text(execution[verification] || verification)));
        var references = Array.isArray(check.standards) ? check.standards.filter(function (reference) {
            return reference && typeof reference.title === 'string' && typeof reference.url === 'string'
                && /^https:\/\/(?:www\.rfc-editor\.org|openid\.net)\//.test(reference.url);
        }) : [];
        if (references.length) {
            var standard = $('<p>').append($('<i class="fa fa-book" aria-hidden="true">'), ' ')
                .append($('<strong>').text((options.standardLabel || 'Related standard') + ': '));
            references.forEach(function (reference, index) {
                if (index > 0) {
                    standard.append(document.createTextNode(', '));
                }
                standard.append($('<a>').attr({
                    href: reference.url,
                    target: '_blank',
                    rel: 'noopener noreferrer'
                }).text(reference.title));
            });
            facts.append(standard);
        }
        details.append(facts);
        return details;
    }

    function discoveryResult(answer) {
        var overall = ['success', 'warning', 'error'].indexOf(answer.overall) !== -1
            ? answer.overall : 'success';
        var meta = resultStatus(overall);
        var panel = $('<div class="oidc-probe-result oidc-discovery-result">');
        var headline = $('<div class="oidc-probe-summary" role="status">')
            .append($('<span>').addClass('label label-' + meta.style)
                .append(statusIcon(overall, false), ' ', $('<span>').text(meta.label)))
            .append($('<strong>').text(answer.headline || options.discoveryAccepted || 'Discovery document accepted'));
        panel.append(headline);

        if (!Array.isArray(answer.checks)) {
            return panel.append($('<pre>').text(answer.summary || ''));
        }

        var checks = $('<div class="oidc-probe-results oidc-discovery-results">');
        var readiness = $('<div class="oidc-probe-section" role="list">');
        var unsupported = $('<div class="oidc-probe-section oidc-probe-unsupported" role="list">');
        answer.checks.forEach(function (check, index) {
            var unavailable = check.section === 'unsupported';
            var checkMeta = resultStatus(check.status);
            var detailsId = 'oidc-probe-details-' + index + '-' + Math.random().toString(36).slice(2, 9);
            var details = checkDetails(check).attr({ id: detailsId, role: 'region' }).hide();
            var info = $('<button class="btn btn-link btn-sm oidc-probe-info" type="button">').attr({
                'aria-expanded': 'false',
                'aria-controls': detailsId,
                title: options.detailsLabel || 'Show details'
            }).append($('<i class="fa fa-info-circle" aria-hidden="true">'),
                $('<span class="sr-only">').text(options.detailsLabel || 'Show details'))
                .on('click', function () {
                    var expanded = $(this).attr('aria-expanded') === 'true';
                    var label = expanded
                        ? (options.detailsLabel || 'Show details')
                        : (options.hideDetailsLabel || 'Hide details');
                    $(this).attr('aria-expanded', expanded ? 'false' : 'true')
                        .attr('title', label)
                        .find('.sr-only').text(label);
                    details.toggle(!expanded);
                });
            var status = unavailable ? $() : $('<span>').addClass('label label-' + checkMeta.style)
                .append(statusIcon(check.status, false), ' ')
                .append($('<span>').text(checkMeta.label));
            var item = $('<section class="oidc-probe-check" role="listitem">').attr({
                'data-status': check.status || 'info',
                'data-verification': check.verification || 'not-tested',
                'data-section': unavailable ? 'unsupported' : 'readiness'
            }).append($('<div class="oidc-probe-check-grid">')
                .append($('<div class="oidc-probe-check-identity">')
                    .append($('<h4>').text(check.label || ''), checkFlow(check)))
                .append($('<div class="oidc-probe-check-value">')
                    .append($('<code>').text(check.value || '')))
                .append($('<div class="oidc-probe-check-actions">').append(status, info)), details);
            (unavailable ? unsupported : readiness).append(item);
        });
        checks.append($('<h3 class="oidc-probe-section-title">').text(
            options.readinessHeading || 'Readiness'
        ), readiness);
        if (unsupported.children().length) {
            checks.append($('<div class="oidc-probe-section-heading">')
                .append($('<h3 class="oidc-probe-section-title">').text(
                    options.notOfferedHeading || 'Not offered by the provider'
                ))
                .append($('<p class="text-muted">').text(options.notOfferedHelp
                    || 'Optional capabilities absent from the live Discovery document.')),
            unsupported);
        }
        panel.append(checks);
        return panel;
    }

    function discoveryError(message) {
        return $('<div class="alert alert-danger oidc-discovery-error" role="alert">')
            .append(statusIcon('error'), ' ')
            .append($('<strong>').text(options.discoveryRejected || 'Discovery was not accepted.'), ' ')
            .append($('<span>').text(message || ''));
    }

    function currentProbeData() {
        var names = [
            'openidconnect_provider_url', 'openidconnect_app_code', 'openidconnect_provider_profile',
            'openidconnect_microsoft_audience', 'openidconnect_client_id', 'openidconnect_client_secret',
            'openidconnect_signing_certificate', 'openidconnect_token_auth', 'openidconnect_client_certificate',
            'openidconnect_retiring_client_certificate', 'openidconnect_certificate_bound_access_tokens',
            'openidconnect_par_mode', 'openidconnect_request_object_key',
            'openidconnect_scopes',
            'openidconnect_response_mode', 'openidconnect_claims_source', 'openidconnect_max_age',
            'openidconnect_select_account', 'openidconnect_required_authentication', 'openidconnect_acr_request',
            'openidconnect_acr_values', 'openidconnect_amr_values', 'openidconnect_entra_auth_context',
            'openidconnect_origin_policy', 'openidconnect_standard_https_port',
            'openidconnect_redirect_urls', 'openidconnect_tls_offloading'
        ];
        var data = {};
        names.forEach(function (name) {
            var input = field(name);
            if (input) {
                data[name] = input.type === 'checkbox' ? ($(input).is(':checked') ? '1' : '0') : $(input).val();
            }
        });
        data.url = data.openidconnect_provider_url || '';
        return data;
    }

    function currentClientFieldsComplete() {
        var issuer = (field('openidconnect_provider_url') || {}).value || '';
        var clientId = (field('openidconnect_client_id') || {}).value || '';
        var method = (field('openidconnect_token_auth') || {}).value || '';
        var secret = (field('openidconnect_client_secret') || {}).value || '';
        var certificate = (field('openidconnect_client_certificate') || {}).value || '';
        var signingCertificate = (field('openidconnect_signing_certificate') || {}).value || '';
        var boundInput = field('openidconnect_certificate_bound_access_tokens');
        var bound = boundInput ? $(boundInput).is(':checked') : false;
        var tlsMethod = method === 'tls_client_auth' || method === 'self_signed_tls_client_auth';
        var needsCertificate = bound || tlsMethod || (method === '' && certificate.trim() !== '');
        var needsSigningCertificate = method === 'private_key_jwt'
            || (method === '' && certificate.trim() === '' && signingCertificate.trim() !== '');
        var needsSecret = method === 'client_secret_basic' || method === 'client_secret_post'
            || (method === '' && certificate.trim() === '' && signingCertificate.trim() === '');
        return issuer.trim() !== '' && clientId.trim() !== ''
            && (!needsCertificate || certificate.trim() !== '')
            && (!needsSigningCertificate || signingCertificate.trim() !== '')
            && (!needsSecret || secret.trim() !== '');
    }

    function withDiscoveryTest() {
        var submit = $('#submit');
        if (submit.length === 0) {
            return;
        }
        var testButton = $('<button>')
            .attr({ type: 'button', class: 'btn btn-default oidc-discovery-test' })
            .text(options.testLabel || 'Test')
            .on('click', function () {
                /* A network action by the firewall: POST lets core enforce its CSRF token. */
                var data = currentProbeData();
                testButton.prop('disabled', true).empty()
                    .append($('<i class="fa fa-spinner fa-spin" aria-hidden="true">'), ' ')
                    .append(document.createTextNode(options.testingLabel || 'Testing...'));
                $.ajax({ type: 'POST', url: '/api/openidconnect/discovery/probe', data: data })
                    .done(function (answer) {
                        if (answer && answer.status === 'ok') {
                            BootstrapDialog.show({
                                title: options.testLabel,
                                message: discoveryResult(answer),
                                type: BootstrapDialog.TYPE_PRIMARY,
                                size: BootstrapDialog.SIZE_WIDE,
                                cssClass: 'oidc-dialog-large oidc-dialog-resizable'
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
        formActionSection('diagnostics', options.diagnosticsActionsHeading || 'Test and diagnostics')
            .find('.oidc-form-actions').append(testButton);
    }

    function withHealthTest() {
        var submit = $('#submit');
        if (submit.length === 0) {
            return;
        }
        var readinessFields = [
            'openidconnect_provider_url', 'openidconnect_client_id', 'openidconnect_client_secret',
            'openidconnect_client_certificate', 'openidconnect_signing_certificate', 'openidconnect_token_auth',
            'openidconnect_certificate_bound_access_tokens'
        ];
        var running = false;
        var button = $('<button>')
            .attr({
                type: 'button',
                class: 'btn btn-default oidc-health-test'
            })
            .text(options.healthTestLabel || 'Connection health')
            .on('click', function () {
                if (button.prop('disabled')) {
                    return;
                }
                running = true;
                updateAvailability();
                button.empty()
                    .append($('<i class="fa fa-spinner fa-spin" aria-hidden="true">'), ' ')
                    .append(document.createTextNode(options.healthTestingLabel || 'Checking...'));
                $.ajax({ type: 'POST', url: '/api/openidconnect/health/probe', data: currentProbeData() })
                    .done(function (answer) {
                        if (answer && answer.status === 'ok') {
                            BootstrapDialog.show({
                                title: options.healthTestLabel || 'Connection health',
                                message: discoveryResult(answer),
                                type: BootstrapDialog.TYPE_PRIMARY,
                                size: BootstrapDialog.SIZE_WIDE,
                                cssClass: 'oidc-dialog-large oidc-dialog-resizable'
                            });
                        } else {
                            BootstrapDialog.show({
                                title: options.healthTestLabel || 'Connection health',
                                message: discoveryError((answer && answer.message) || 'unknown error'),
                                type: BootstrapDialog.TYPE_DANGER
                            });
                        }
                    })
                    .fail(function (xhr) {
                        BootstrapDialog.show({
                            title: options.healthTestLabel || 'Connection health',
                            message: discoveryError(xhr.responseText || 'request failed'),
                            type: BootstrapDialog.TYPE_DANGER
                        });
                    })
                    .always(function () {
                        running = false;
                        updateAvailability();
                    });
            });
        function complete() {
            return currentClientFieldsComplete();
        }

        function updateAvailability() {
            button.prop('disabled', running || !complete());
            if (!running) {
                button.text(options.healthTestLabel || 'Connection health');
            }
            button.attr('title', complete()
                ? (options.healthTestHelp || 'Uses the current form values; saving is not required.')
                : (options.healthTestIncompleteHelp
                    || 'Enter Exact issuer URL, Client ID and the selected client credential.'));
        }

        readinessFields.forEach(function (name) {
            $(field(name)).on('input change', updateAvailability);
        });
        formActionSection('diagnostics', options.diagnosticsActionsHeading || 'Test and diagnostics')
            .find('.oidc-form-actions').append(button);
        updateAvailability();
    }

    function withSignInTest() {
        var submit = $('#submit');
        if (submit.length === 0) {
            return { establishBaseline: function () {} };
        }
        var form = submit.closest('form');
        var nameInput = field('name');
        var savedName = nameInput ? nameInput.value.trim() : '';
        var serverId = currentServerId();
        var saved = serverId !== null;
        var savedReady = false;
        var initialized = false;
        var baseline = null;
        var running = false;
        var revert = $('<button>')
            .attr({
                type: 'button',
                class: 'btn btn-default auth_options auth_openidconnect oidc-revert-changes'
            })
            .text(options.revertChangesLabel || 'Revert changes')
            .hide()
            .on('click', function () {
                var target = new URL('/system_authservers.php', window.location.origin);
                target.searchParams.set('act', saved ? 'edit' : 'new');
                if (saved) {
                    target.searchParams.set('id', String(serverId));
                }
                window.location.assign(target.href);
            });
        var button = $('<button>')
            .attr({
                type: 'button',
                class: 'btn btn-primary oidc-signin-test'
            })
            .text(options.signInTestLabel || 'Test sign-in')
            .on('click', function () {
                if (button.prop('disabled')) {
                    return;
                }
                running = true;
                button.prop('disabled', true).empty()
                    .append($('<i class="fa fa-spinner fa-spin" aria-hidden="true">'), ' ')
                    .append(document.createTextNode(options.testingLabel || 'Testing...'));
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
        var buttonHelp = withActionHelp(button, 'oidc-signin-test-help');
        function currentFieldsComplete() {
            return currentClientFieldsComplete();
        }

        function formState() {
            var form = submit.closest('form').get(0);
            var values = [];
            if (!form) {
                return '';
            }
            new FormData(form).forEach(function (value, name) {
                if (name === 'name' || name === 'type' || name.indexOf('openidconnect_') === 0) {
                    values.push([name, String(value)]);
                }
            });
            values.sort(function (left, right) {
                var leftValue = left[0] + '\u0000' + left[1];
                var rightValue = right[0] + '\u0000' + right[1];
                return leftValue < rightValue ? -1 : (leftValue > rightValue ? 1 : 0);
            });
            return JSON.stringify(values);
        }

        function formChanged() {
            return initialized && (baseline === null || formState() !== baseline);
        }
        function updateAvailability() {
            var changed = formChanged();
            var ready = saved && initialized && !changed && savedReady;
            var disabled = running || !ready;
            var typeInput = field('type');
            button.prop('disabled', disabled);
            revert.toggle(!!typeInput && typeInput.value === 'openidconnect' && changed && !running);
            if (!running) {
                button.text(options.signInTestLabel || 'Test sign-in');
            }
            var explanation;
            if (!initialized) {
                explanation = options.formPreparing || 'Preparing form state...';
            } else if (!currentFieldsComplete()) {
                explanation = options.signInTestIncompleteHelp
                    || 'Complete and save the issuer, client ID and selected client credential before testing sign-in.';
            } else if (changed) {
                explanation = options.signInTestChangedHelp
                    || 'Save or revert your changes before testing sign-in.';
            } else if (!saved) {
                explanation = options.signInTestSaveHelp || 'Save this server before testing sign-in.';
            } else if (!currentTransportReady()) {
                explanation = options.signInTestTransportHelp
                    || 'Save a complete secure WebGUI transport configuration before testing sign-in.';
            } else if (!savedReady) {
                explanation = options.signInTestIncompleteHelp
                    || 'Complete and save the issuer, client ID and selected client credential before testing sign-in.';
            } else {
                explanation = options.signInTestHelp
                    || 'Runs a complete browser sign-in without changing OPNsense.';
            }
            buttonHelp.update(explanation, disabled);
        }

        function establishBaseline() {
            initialized = true;
            if (options.formLoadedState === true) {
                baseline = formState();
            }
            if (saved && options.formLoadedFromSavedState === true) {
                savedReady = currentFieldsComplete() && currentTransportReady();
            }
            updateAvailability();
        }

        submit.closest('form').on('input change tokenize:tokens:change', updateAvailability);
        formActionSection('diagnostics', options.diagnosticsActionsHeading || 'Test and diagnostics')
            .find('.oidc-form-actions').append(buttonHelp.element);
        submit.after(revert);
        updateAvailability();
        return { establishBaseline: establishBaseline };
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
        button.attr('title', saved ? (options.approvalHelp || '') : (options.approvalSaveHelp || ''));

        function request(action, data) {
            return $.ajax({
                type: 'POST',
                url: '/api/openidconnect/approval/' + action,
                data: $.extend({ provider: nameInput.value.trim() }, data || {})
            });
        }

        var newAccountValue = '__openidconnect_new_local_account__';

        function accountPicker(accounts, selected, allowCreate, selectedLabel) {
            var picker = $('<select class="form-control">')
                .append($('<option value="">').text(
                    accounts.length ? (options.approvalChooseAccount || 'Choose a local account')
                        : (options.approvalNoAccounts || 'No eligible local account is available.')
                ));
            accounts.forEach(function (candidate) {
                picker.append($('<option>').val(candidate.uid).text(candidate.name));
            });
            if (selected && picker.find('option[value="' + selected + '"]').length === 0) {
                picker.append($('<option>').val(selected).text(selectedLabel || selected));
            }
            if (allowCreate) {
                picker.append($('<option>').val(newAccountValue)
                    .text(options.approvalCreateAccount || 'Create a new local account…'));
            }
            picker.val(selected || '');
            return picker;
        }

        function accountGroups(accounts, binding, uid) {
            if (binding && uid === binding.uid) {
                return Array.isArray(binding.groups) ? binding.groups : [];
            }
            var selected = accounts.find(function (candidate) { return candidate.uid === uid; });
            return selected && Array.isArray(selected.groups) ? selected.groups : [];
        }

        function groupPicker(groups, selected, writable) {
            var picker = $('<select multiple="multiple" class="selectpicker">');
            groups.forEach(function (group) {
                picker.append($('<option>').val(group).text(group));
            });
            picker.val(selected || []).prop('disabled', !writable);
            return picker;
        }

        function selectGroups(picker, selected) {
            picker.val(selected || []).selectpicker('refresh');
        }

        function accountCreationEditor(picker, groupSelectionOffered) {
            var username = $('<input class="form-control" type="text" autocomplete="off" spellcheck="false">')
                .attr({ maxlength: 320, placeholder: options.approvalUsername || 'Username' })
                .css({ width: '100%', maxWidth: 'none' });
            var container = $('<div class="form-group oidc-account-creation">')
                .append($('<label>').text(options.approvalNewAccount || 'New local account'))
                .append(username)
                .append($('<p class="help-block">').text(
                    groupSelectionOffered
                        ? (options.approvalAccountCreationWithGroupsHelp
                            || 'The account receives a scrambled password. Selected existing groups are applied '
                                + 'when the binding is saved.')
                        : (options.approvalAccountCreationHelp
                            || 'The account receives a scrambled password and no groups or privileges.')
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
                    picker.val(created.uid).trigger('change', [true]);
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

        function editBinding(answer, dialog, binding) {
            var guidance = answer.subject_guidance || {};
            var editor = $('<div class="oidc-binding-editor">');
            var issuer = $('<input class="form-control" type="url" autocomplete="off">')
                .css({ width: '100%', maxWidth: 'none' })
                .val(binding ? binding.issuer : (guidance.issuer_default || ''));
            if (!guidance.issuer_editable) {
                issuer.prop('readonly', true);
            }
            var subject = $('<input class="form-control" type="text" autocomplete="off" spellcheck="false">')
                .attr({ maxlength: 255, placeholder: guidance.placeholder || 'Paste the exact sub claim' })
                .css({ width: '100%', maxWidth: 'none' })
                .val(binding ? binding.subject : '');
            var account = accountPicker(
                answer.accounts || [],
                binding ? binding.uid : '',
                !binding && answer.account_creation_allowed,
                binding ? binding.account : ''
            );
            account.css({ width: '100%', maxWidth: 'none' });
            var creation = accountCreationEditor(account, true);
            var availableGroups = Array.isArray(answer.groups) ? answer.groups : [];
            var memberships = groupPicker(
                availableGroups,
                binding && Array.isArray(binding.groups) ? binding.groups : [],
                answer.account_groups_writable === true
            );
            var result = $('<div class="help-block oidc-binding-result">');
            var save = $('<button class="btn btn-primary" type="button">')
                .text(options.bindingSave || 'Save binding');
            var cancel = $('<button class="btn btn-default" type="button">')
                .text(options.bindingCancel || 'Cancel')
                .on('click', function () { load(dialog, 'bindings'); });

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
            account.on('change', function (_, preserveGroups) {
                if (!preserveGroups) {
                    selectGroups(memberships, accountGroups(answer.accounts || [], binding, account.val()));
                }
                update();
            });
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
                    var data = {
                        binding_id: binding ? binding.id : '',
                        issuer: issuer.val().trim(),
                        subject: subject.val().trim(),
                        uid: uid
                    };
                    if (answer.account_groups_writable === true) {
                        data.groups_json = JSON.stringify(memberships.val() || []);
                        data.groups_expected_json = JSON.stringify(
                            created ? [] : accountGroups(answer.accounts || [], binding, uid)
                        );
                    }
                    request(action, data).done(function (savedBinding) {
                        if (savedBinding && savedBinding.status === 'ok') {
                            load(dialog, 'bindings');
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

            editor.append($('<p class="oidc-binding-caution text-warning">')
                .append(statusIcon('warning'), ' ')
                .append(inlineCode(options.bindingManualWarning || 'Manual binding requires verified values.')));
            editor.append($('<div class="form-group">')
                .append($('<label>').text(options.bindingIssuer || 'Exact issuer'))
                .append(issuer));
            editor.append($('<div class="form-group">')
                .append($('<label>').text(options.bindingSubject || 'Subject (sub)'))
                .append(subject)
                .append($('<p class="help-block">').append(inlineCode(
                    guidance.text || options.bindingValidation || 'Use the exact sub claim.'
                ))));
            editor.append($('<div class="form-group">')
                .append($('<label>').text(options.bindingAccount || 'Local account'))
                .append(account));
            editor.append(creation.container);
            editor.append($('<div class="form-group">')
                .append($('<label>').text(options.bindingGroups || 'Local groups'))
                .append(memberships)
                .append($('<p class="help-block">').text(
                    availableGroups.length === 0
                        ? (options.bindingNoGroups || 'No local groups are available.')
                        : (answer.account_groups_writable === true
                            ? (options.bindingGroupsHelp
                                || 'Optional. Existing memberships are preselected; saving replaces the selection.')
                            : (options.bindingGroupsReadOnly
                                || 'Memberships are shown read-only because account management is not permitted.'))
                )));
            memberships.selectpicker({ width: '100%' });
            editor.append(result,
                $('<div class="oidc-binding-editor-actions">').append(save, cancel));
            dialog.setTitle(
                binding ? (options.bindingEditorEdit || 'Edit identity binding')
                    : (options.bindingEditorNew || 'Add an identity')
            );
            dialog._oidcView = 'editor';
            dialog.setMessage(editor);
            update();
            subject.focus();
        }

        function renderBindings(panel, answer, dialog) {
            var bindings = Array.isArray(answer.bindings) ? answer.bindings : [];
            var requests = Array.isArray(answer.requests) ? answer.requests : [];
            var toolbar = $('<div class="oidc-manager-toolbar">')
                .append($('<h4>').text(options.bindingHeading || 'Bound identities'));
            var actions = $('<div class="btn-group oidc-manager-actions" role="group">');
            var pending = $('<button class="btn btn-default" type="button">')
                .append($('<i class="fa fa-clock-o" aria-hidden="true">'), ' ')
                .append($('<span>').text(options.pendingHeading || 'Pending approvals'), ' ')
                .append($('<span class="badge">').text(requests.length))
                .on('click', function () { load(dialog, 'pending'); });
            var add = $('<button class="btn btn-primary" type="button">')
                .prop('disabled', !answer.writable)
                .append($('<i class="fa fa-plus" aria-hidden="true">'), ' ')
                .append($('<span>').text(options.bindingAdd || 'Add identity binding'))
                .on('click', function () { editBinding(answer, dialog, null); });
            actions.append(pending, add);
            toolbar.append(actions);
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
                var edit = $('<button class="btn btn-default btn-sm" type="button">')
                    .prop('disabled', !answer.writable)
                    .append($('<i class="fa fa-pencil" aria-hidden="true">'), ' ')
                    .append($('<span>').text(options.bindingEdit || 'Edit'))
                    .on('click', function () { editBinding(answer, dialog, binding); });
                var remove = $('<button class="btn btn-danger btn-sm" type="button">')
                    .prop('disabled', !answer.writable)
                    .append($('<i class="fa fa-trash" aria-hidden="true">'), ' ')
                    .append($('<span>').text(options.bindingDelete || 'Remove'))
                    .on('click', function () {
                        BootstrapDialog.confirm({
                            title: options.bindingDeleteTitle || 'Remove identity binding',
                            message: options.bindingDeleteQuestion || 'Remove this binding?',
                            type: BootstrapDialog.TYPE_DANGER,
                            callback: function (confirmed) {
                                if (confirmed) {
                                    request('delete', { binding_id: binding.id }).done(function (removed) {
                                        if (removed && removed.status === 'ok') {
                                            load(dialog, 'bindings');
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
                    .append($('<td class="text-right oidc-binding-actions">')
                        .append($('<div class="btn-group btn-group-sm" role="group">').append(edit, remove))));
            });
            table.append(tableBody);
            panel.append($('<div class="table-responsive">').append(table));
        }

        function renderPending(panel, answer, dialog) {
            var requests = Array.isArray(answer.requests) ? answer.requests : [];
            var accounts = Array.isArray(answer.accounts) ? answer.accounts : [];
            panel.append($('<div class="oidc-manager-toolbar">')
                .append($('<h4>').text(options.pendingHeading || 'Pending administrator approvals'))
                .append($('<button class="btn btn-default" type="button">')
                    .append($('<i class="fa fa-chevron-left" aria-hidden="true">'), ' ')
                    .append($('<span>').text(options.bindingBack || 'Back to bound identities'))
                    .on('click', function () { load(dialog, 'bindings'); })));
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
                var approve = $('<button class="btn btn-primary" type="button">')
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
                                    load(dialog, 'pending');
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
                var deny = $('<button class="btn btn-danger" type="button">')
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
                                            load(dialog, 'pending');
                                        } else {
                                            BootstrapDialog.alert((result && result.message) || 'Denial failed.');
                                        }
                                    });
                                }
                            }
                        });
                    });
                controls.append(account,
                    $('<span class="oidc-approval-actions">').append(approve, deny));
                body.append(controls, creation.container, result);
                card.append(heading, body);
                panel.append(card);
                updateApprove();
            });
        }

        function render(answer, dialog, view) {
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
            if (view === 'pending') {
                dialog.setTitle(options.pendingHeading || 'Pending administrator approvals');
                renderPending(panel, answer, dialog);
            } else {
                dialog.setTitle(options.approvalLabel || 'Manage identities');
                renderBindings(panel, answer, dialog);
            }
            return panel;
        }

        function load(dialog, view) {
            view = view || (dialog._oidcView === 'pending' ? 'pending' : 'bindings');
            dialog._oidcView = view;
            dialog.setMessage($('<div class="text-center">').append(
                $('<i class="fa fa-spinner fa-spin fa-2x" aria-hidden="true">')
            ));
            request('list').done(function (answer) {
                dialog.setMessage(render(answer, dialog, view));
            }).fail(function (xhr) {
                dialog.setMessage(render({ status: 'error', message: xhr.responseText }, dialog, view));
            });
        }

        button.on('click', function () {
            var dialog = new BootstrapDialog({
                title: options.approvalLabel || 'Manage identities',
                type: BootstrapDialog.TYPE_PRIMARY,
                size: BootstrapDialog.SIZE_WIDE,
                cssClass: 'oidc-dialog-large oidc-dialog-resizable oidc-identity-dialog',
                message: $('<div>'),
                buttons: [{
                    label: options.approvalRefresh || 'Refresh',
                    icon: 'fa fa-refresh',
                    action: function (instance) { load(instance, instance._oidcView); }
                }, {
                    label: options.setupCompleteLabel || 'Done',
                    action: function (instance) { instance.close(); }
                }]
            });
            dialog.realize();
            dialog.open();
            load(dialog, 'bindings');
        });
        formActionSection('identities', options.identityActionsHeading || 'Identity management')
            .find('.oidc-form-actions').append(button);
    }

    function withProviderSetup() {
        var submit = $('#submit');
        var profile = field('openidconnect_provider_profile');
        if (submit.length === 0 || !profile) {
            return;
        }
        var supported = options.setupProfiles || ['authentik', 'keycloak'];
        var panel = $('<span class="oidc-provider-setup">');
        var channel = $('<select class="form-control">')
            .attr({ 'aria-label': options.setupChannelLabel || 'Logout channel' })
            .append($('<option value="backchannel">').text(
                options.setupBackchannelLabel || 'Back-channel'
            ))
            .append($('<option value="frontchannel">').text(
                options.setupFrontchannelLabel || 'Front-channel'
            ));
        var receiver = field('openidconnect_logout_notifications');
        var button = $('<button class="btn btn-default">')
            .attr({ type: 'button' })
            .text(options.setupLabel || 'Download provider setup');
        var guideButton = $('<button class="btn btn-default">')
            .attr({ type: 'button' })
            .append($('<i class="fa fa-book" aria-hidden="true">'), ' ')
            .append($('<span>').text(options.setupGuideLabel || 'Open setup guide'));

        function setupData() {
            var origins = effectiveOrigins();
            return {
                profile: profile.value,
                application_code: field('openidconnect_app_code').value,
                display_name: field('name') ? field('name').value : '',
                origins: origins.join(','),
                preferred_origin: currentSetupOrigin() || '',
                sector_origin: field('openidconnect_sector_origin').value,
                post_logout_redirect: $(field('openidconnect_logout_redirect')).is(':checked') ? '1' : '0',
                logout_channel: channel.val(),
                openidconnect_scopes: field('openidconnect_scopes').value,
                openidconnect_username_claim: field('openidconnect_username_claim').value,
                openidconnect_group_claim: field('openidconnect_group_claim').value,
                openidconnect_required_authentication: field('openidconnect_required_authentication').value,
                openidconnect_acr_request: field('openidconnect_acr_request').value,
                openidconnect_acr_values: field('openidconnect_acr_values').value,
                openidconnect_amr_values: field('openidconnect_amr_values').value
            };
        }

        function synchronizeLogoutChannel() {
            if (!receiver) {
                return;
            }
            var selected = channel.val();
            if (receiver.value !== 'both' && receiver.value !== selected) {
                $(receiver).val(selected).trigger('change');
                refreshSelectPicker(receiver);
            }
        }

        function generate(download) {
            synchronizeLogoutChannel();
            if (!currentSetupOrigin()) {
                BootstrapDialog.show({
                    title: download
                        ? (options.setupLabel || 'Download provider setup')
                        : (options.setupGuideLabel || 'Open setup guide'),
                    message: $('<div>').text(options.setupOriginMismatchHelp ||
                        'Open this form through an accepted HTTPS WebGUI FQDN.').html(),
                    type: BootstrapDialog.TYPE_WARNING
                });
                return;
            }
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
                            type: BootstrapDialog.TYPE_PRIMARY,
                            size: BootstrapDialog.SIZE_WIDE,
                            cssClass: 'oidc-dialog-large oidc-dialog-resizable'
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
        if (receiver && ['backchannel', 'frontchannel'].indexOf(receiver.value) !== -1) {
            channel.val(receiver.value);
        }
        channel.on('change', synchronizeLogoutChannel);
        $(receiver).on('change', function () {
            if (['backchannel', 'frontchannel'].indexOf(receiver.value) !== -1) {
                channel.val(receiver.value);
            }
        });
        panel.append(channel, button, guideButton);
        var setupSection = formActionSection(
            'provider-setup', options.providerSetupActionsHeading || 'Provider setup'
        );
        setupSection.find('.oidc-form-actions').append(panel);

        function update() {
            setupSection.toggle(supported.indexOf(profile.value) !== -1);
        }
        $(profile).on('change', update);
        update();
    }

    function withSharedSignalsSetup() {
        var secret = field('openidconnect_ssf_push_secret');
        var previousSecret = field('openidconnect_ssf_previous_push_secret');
        var issuer = field('openidconnect_ssf_issuer');
        var authorizationField = field('openidconnect_ssf_management_authorization');
        var methodField = field('openidconnect_ssf_delivery_method');
        var streamField = field('openidconnect_ssf_stream_id');
        var audienceField = field('openidconnect_ssf_audience');
        var pollEndpointField = field('openidconnect_ssf_poll_endpoint');
        if (!secret || !previousSecret || !issuer || !authorizationField || !methodField
            || !streamField || !audienceField || !pollEndpointField) {
            return;
        }
        $(secret).add(previousSecret).add(authorizationField).attr({
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

        var rotate = $('<button class="btn btn-default btn-sm" type="button">')
            .css({ marginLeft: '6px' })
            .text(options.ssfRotateSecretLabel || 'Prepare rotation')
            .on('click', function () {
                if (!/^[A-Za-z0-9_-]{43}$/.test(secret.value || '')) {
                    $(secret).focus();
                    return;
                }
                rotate.prop('disabled', true);
                $.ajax({ type: 'POST', url: '/api/openidconnect/ssfsetup/secret' })
                    .done(function (answer) {
                        if (answer && answer.status === 'ok' && /^[A-Za-z0-9_-]{43}$/.test(answer.secret || '')) {
                            $(previousSecret).val(secret.value).trigger('input');
                            $(secret).val(answer.secret).trigger('input');
                            BootstrapDialog.alert(options.ssfRotationPrepared ||
                                'Save both credentials before updating the transmitter stream.');
                        }
                    })
                    .always(function () { rotate.prop('disabled', false); });
            });
        $(secret).after(rotate);

        var probe = $('<button class="btn btn-default btn-sm" type="button">')
            .css({ marginLeft: '6px' })
            .text(options.ssfTestLabel || 'Test Shared Signals')
            .on('click', function () {
                probe.prop('disabled', true);
                $.ajax({
                    type: 'POST',
                    url: '/api/openidconnect/ssfsetup/probe',
                    data: { issuer: issuer.value, delivery_method: methodField.value }
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

        function managementData() {
            var origins = effectiveOrigins();
            return {
                issuer: issuer.value,
                authorization: authorizationField.value,
                delivery_method: methodField.value,
                stream_id: streamField.value,
                audience: audienceField.value,
                poll_endpoint: pollEndpointField.value,
                push_secret: secret.value,
                receiver_origin: origins.length ? origins[0] : '',
                application_code: field('openidconnect_app_code').value || 'main',
                description: field('name') ? field('name').value : 'OPNsense OpenID Connect'
            };
        }

        var managementResult = $('<span class="help-block oidc-ssf-management-result">');
        function showManagement(answer) {
            if (!answer || answer.status !== 'ok') {
                managementResult.removeClass('text-success').addClass('text-danger')
                    .text((answer && answer.message) || 'Shared Signals operation failed.');
                return false;
            }
            if (answer.stream_id) {
                $(streamField).val(answer.stream_id).trigger('input');
            }
            if (answer.audience) {
                $(audienceField).val(answer.audience).trigger('input');
            }
            if (typeof answer.poll_endpoint === 'string') {
                $(pollEndpointField).val(answer.poll_endpoint).trigger('input');
            }
            var streamStatus = answer.stream_status || {};
            var message = streamStatus.status
                ? (options.ssfStreamStatusLabel || 'Stream status') + ': ' + streamStatus.status
                : (answer.deleted
                    ? (options.ssfStreamDeleted || 'Stream deleted; save this server to clear its local values.')
                    : (options.ssfStreamApplied || 'Stream response accepted; save this server to retain its values.'));
            managementResult.removeClass('text-danger').addClass('text-success').text(message);
            return true;
        }

        function managementButton(label, action, extra) {
            return $('<button class="btn btn-default btn-sm" type="button">').text(label).on('click', function () {
                var button = $(this);
                function execute() {
                    button.prop('disabled', true);
                    $.ajax({
                        type: 'POST',
                        url: '/api/openidconnect/ssfsetup/' + action,
                        data: $.extend(managementData(), extra || {})
                    }).done(function (answer) {
                        if (showManagement(answer) && action === 'delete') {
                            $(streamField).val('').trigger('input');
                            $(audienceField).val('').trigger('input');
                            $(pollEndpointField).val('').trigger('input');
                        }
                    }).fail(function (xhr) {
                        showManagement({ status: 'error', message: xhr.responseText || 'request failed' });
                    }).always(function () { button.prop('disabled', false); });
                }
                if (action === 'delete') {
                    BootstrapDialog.confirm({
                        title: options.ssfDeleteStreamLabel || 'Delete stream',
                        message: options.ssfDeleteStreamConfirm ||
                            'Delete this stream at the transmitter? This cannot be undone.',
                        type: BootstrapDialog.TYPE_DANGER,
                        callback: function (confirmed) { if (confirmed) { execute(); } }
                    });
                } else {
                    execute();
                }
            });
        }

        var management = $('<div class="oidc-ssf-management">').css({ marginTop: '8px' })
            .append(managementButton(options.ssfCreateStreamLabel || 'Create stream', 'create'), ' ')
            .append(managementButton(options.ssfReadStreamLabel || 'Read stream', 'read'), ' ')
            .append(managementButton(options.ssfUpdateStreamLabel || 'Update stream', 'update'), ' ')
            .append(managementButton(options.ssfReadStatusLabel || 'Read status', 'status'), ' ')
            .append(managementButton(options.ssfEnableStreamLabel || 'Enable', 'setstatus', {
                status_value: 'enabled'
            }), ' ')
            .append(managementButton(options.ssfPauseStreamLabel || 'Pause', 'setstatus', {
                status_value: 'paused', reason: 'Paused by OPNsense administrator'
            }), ' ');
        var remove = managementButton(options.ssfDeleteStreamLabel || 'Delete stream', 'delete')
            .removeClass('btn-default').addClass('btn-danger');
        management.append(remove, managementResult);
        row('openidconnect_ssf_stream_id').find('td').last().append(management);
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
        var titleId = 'openidconnect-provider-endpoints';
        var preview = $('<div class="oidc-endpoints" role="region">').attr('aria-labelledby', titleId);
        var output = $('<div class="oidc-endpoint-list">');
        var help = $('<p class="oidc-endpoint-help">');
        preview.append(
            $('<div class="oidc-support-panel-heading">').append(
                $('<strong>').attr('id', titleId).text(options.endpointLabel || 'Provider endpoints')
            ),
            output,
            help
        );
        target.append(preview);

        function writeClipboard(value) {
            if (navigator.clipboard && typeof navigator.clipboard.writeText === 'function') {
                return navigator.clipboard.writeText(value);
            }
            return new Promise(function (resolve, reject) {
                var textarea = $('<textarea readonly>').css({
                    left: '-9999px',
                    opacity: 0,
                    position: 'fixed',
                    top: 0
                }).val(value).appendTo(document.body);
                textarea[0].select();
                textarea[0].setSelectionRange(0, value.length);
                try {
                    if (!document.execCommand('copy')) {
                        throw new Error('copy command was rejected');
                    }
                    resolve();
                } catch (error) {
                    reject(error);
                } finally {
                    textarea.remove();
                }
            });
        }

        function endpointRow(destination, index) {
            var copyLabel = options.endpointCopyLabel || 'Copy';
            var copiedLabel = options.endpointCopiedLabel || 'Copied';
            var button = $('<button type="button" class="btn btn-default btn-xs oidc-endpoint-copy">')
                .attr('aria-label', copyLabel + ' ' + destination[0])
                .append($('<i class="fa fa-copy" aria-hidden="true">'), ' ', $('<span>').text(copyLabel));
            button.on('click', function () {
                button.prop('disabled', true);
                writeClipboard(destination[1]).then(function () {
                    button.addClass('btn-success').removeClass('btn-default')
                        .attr('aria-label', copiedLabel + ': ' + destination[0])
                        .find('span').text(copiedLabel);
                    window.setTimeout(function () {
                        button.addClass('btn-default').removeClass('btn-success').prop('disabled', false)
                            .attr('aria-label', copyLabel + ' ' + destination[0])
                            .find('span').text(copyLabel);
                    }, 1600);
                }).catch(function () {
                    button.prop('disabled', false);
                    BootstrapDialog.alert(options.endpointCopyFailed
                        || 'This URI could not be copied. Select it and copy it manually.');
                });
            });
            return $('<div class="oidc-endpoint-row">')
                .append($('<div class="oidc-endpoint-name">').text(destination[0]))
                .append($('<div class="oidc-endpoint-value">').append(
                    $('<code>').attr('data-oidc-endpoint', index).text(destination[1])
                ))
                .append(button);
        }

        function update() {
            var code = (field('openidconnect_app_code').value || 'main').trim();
            var origins = effectiveOrigins();
            var supplied = origins[0];
            output.empty();
            help.empty();
            if (!supplied) {
                $('<div class="oidc-endpoint-empty" role="status">')
                    .text(options.noEndpointOrigin || 'No accepted HTTPS WebGUI origin is available.')
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
                [options.lifecycleEndpointLabel || 'Lifecycle-test post-logout redirect URI',
                    base + 'logouttestcallback/' + encodeURIComponent(code)],
                [options.postLogoutEndpointLabel || 'Post-logout redirect URI', origin + '/'],
                [options.backchannelEndpointLabel || 'Back-channel logout URI', base + 'backchannel/' + encodeURIComponent(code)],
                [options.frontchannelEndpointLabel || 'Front-channel logout URI', base + 'frontchannel/' + encodeURIComponent(code)]
            ];
            if ($(field('openidconnect_ssf_enabled')).is(':checked')
                && field('openidconnect_ssf_delivery_method').value !== 'poll') {
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
            destinations.forEach(function (destination, index) {
                endpointRow(destination, index).appendTo(output);
            });
            help.text(options.endpointHelp || '');
        }
        $(field('openidconnect_app_code')).on('input change', update);
        $(field('openidconnect_redirect_urls')).on('input change', update);
        $(field('openidconnect_origin_policy')).on('change', update);
        $(field('openidconnect_standard_https_port')).on('change', update);
        $(field('openidconnect_sector_origin')).on('change', update);
        $(field('openidconnect_ssf_enabled')).on('change', update);
        $(field('openidconnect_ssf_delivery_method')).on('change', update);
        update();
    }

    function conditionalFields() {
        var admissionInput = field('openidconnect_bootstrap_mode');
        var creationInput = field('openidconnect_create_users');
        var authenticationInput = field('openidconnect_required_authentication');
        var admissionNotice = $('<div class="help-block text-warning oidc-public-admission-boundary">').hide();
        var creationNotice = $('<div class="help-block text-warning oidc-public-creation-boundary">').hide();
        var authenticationNotice = $('<div class="help-block text-warning oidc-authentication-requirement-boundary">')
            .hide();
        row('openidconnect_bootstrap_mode').find('td').last().append(admissionNotice, creationNotice);
        row('openidconnect_required_authentication').find('td').last().append(authenticationNotice);

        function populationBoundary(provider) {
            var audience = field('openidconnect_microsoft_audience').value || 'tenant';
            var issuer = (field('openidconnect_provider_url').value || '').trim()
                .replace(/\/\.well-known\/openid-configuration$/, '').replace(/\/+$/, '');
            var publicGitLab = provider === 'gitlab' && issuer === 'https://gitlab.com';
            return {
                creation: (options.accountCreationBlockedProfiles || []).indexOf(provider) !== -1
                    || publicGitLab || (provider === 'entra' && audience !== 'tenant'),
                admission: (options.automaticAdmissionBlockedProfiles || []).indexOf(provider) !== -1
                    || publicGitLab || (provider === 'entra' && audience !== 'tenant')
            };
        }

        function update() {
            var groupClaim = (field('openidconnect_group_claim').value || '').trim() !== '';
            var provider = field('openidconnect_provider_profile').value || 'general';
            var boundary = populationBoundary(provider);
            var authenticationCapabilities = (options.authenticationRequirementCapabilities || {})[provider] || [];
            var broadMicrosoftAudience = provider === 'entra'
                && (field('openidconnect_microsoft_audience').value || 'tenant') !== 'tenant';
            if (broadMicrosoftAudience) {
                authenticationCapabilities = [];
            }
            $(authenticationInput).find('option').each(function () {
                $(this).prop('disabled', this.value !== ''
                    && authenticationCapabilities.indexOf(this.value) === -1);
            });
            var authentication = authenticationInput.value || '';
            if (authentication !== '' && authenticationCapabilities.indexOf(authentication) === -1) {
                $(authenticationInput).val('');
                authentication = '';
            }
            var authenticationUnsupported = authenticationCapabilities.length === 0;
            var authenticationManual = provider === 'keycloak';
            setConditionalSelectLock(authenticationInput, authenticationUnsupported);
            authenticationNotice.toggle(authenticationUnsupported || authenticationManual).empty();
            if (authenticationUnsupported || authenticationManual) {
                authenticationNotice
                    .append($('<i aria-hidden="true">').addClass(
                        authenticationUnsupported ? 'fa fa-lock' : 'fa fa-info-circle'
                    ), ' ')
                    .append($('<span>').text(broadMicrosoftAudience
                        ? (options.authenticationRequirementMicrosoftTenantHelp || '')
                        : (authenticationUnsupported
                            ? (options.authenticationRequirementUnsupportedHelp || '')
                            : (options.authenticationRequirementManualHelp || ''))));
            }
            $(admissionInput).find('option').each(function () {
                $(this).prop('disabled', boundary.admission
                    && ['username', 'verified_email', 'either'].indexOf(this.value) !== -1);
            });
            var populationCoercions = $();
            var admission = admissionInput.value || 'strict';
            var automatic = ['username', 'verified_email', 'either'].indexOf(admission) !== -1;
            if (boundary.admission && automatic) {
                $(admissionInput).val('approval');
                populationCoercions = populationCoercions.add(admissionInput);
                admission = 'approval';
                automatic = false;
            }
            refreshSelectPicker(admissionInput);
            if (boundary.creation && $(creationInput).is(':checked')) {
                $(creationInput).prop('checked', false);
                populationCoercions = populationCoercions.add(creationInput);
            }
            $(creationInput).prop('disabled', boundary.creation);
            var creates = $(creationInput).is(':checked');
            admissionNotice.toggle(boundary.admission).text(
                boundary.admission ? (options.publicPopulationAdmissionHelp || '') : ''
            );
            creationNotice.toggle(boundary.creation).text(
                boundary.creation ? (options.publicPopulationAccountCreationHelp || '') : ''
            );
            var authenticationRequired = authentication !== '';
            var buttonTextMode = field('openidconnect_button_text_mode').value || 'localized';
            var buttonTextCustomizable = (options.fixedButtonProfiles || []).indexOf(provider) === -1;
            toggleFieldRow('openidconnect_tls_offloading', options.webGuiProtocol === 'http');
            toggleFieldRow(
                'openidconnect_standard_https_port',
                options.webGuiProtocol === 'https'
                    && Number(options.webGuiPort || 443) !== 443
                    && field('openidconnect_origin_policy').value !== 'custom'
            );
            toggleFieldRow('openidconnect_microsoft_audience', provider === 'entra');
            toggleFieldRow('openidconnect_acr_request', authenticationRequired && provider !== 'entra');
            toggleFieldRow('openidconnect_acr_values', authenticationRequired && provider !== 'entra');
            toggleFieldRow('openidconnect_amr_values', authenticationRequired);
            toggleFieldRow('openidconnect_entra_auth_context', authenticationRequired && provider === 'entra');
            toggleFieldRow('openidconnect_create_users', automatic && !boundary.creation);
            toggleFieldRow('openidconnect_default_groups', automatic && creates && !boundary.creation);
            toggleFieldRow('openidconnect_assignable_groups', groupClaim);
            toggleFieldRow('openidconnect_allow_all_groups', groupClaim);
            toggleFieldRow('openidconnect_logout_redirect', $(field('openidconnect_logout_menu')).is(':checked'));
            var sharedSignals = $(field('openidconnect_ssf_enabled')).is(':checked');
            var sharedSignalsPoll = field('openidconnect_ssf_delivery_method').value === 'poll';
            toggleFieldRow('openidconnect_ssf_issuer', sharedSignals);
            toggleFieldRow('openidconnect_ssf_audience', sharedSignals);
            toggleFieldRow('openidconnect_ssf_delivery_method', sharedSignals);
            toggleFieldRow('openidconnect_ssf_management_authorization', sharedSignals);
            toggleFieldRow('openidconnect_ssf_stream_id', sharedSignals);
            toggleFieldRow('openidconnect_ssf_poll_endpoint', sharedSignals && sharedSignalsPoll);
            toggleFieldRow('openidconnect_ssf_push_secret', sharedSignals && !sharedSignalsPoll);
            toggleFieldRow('openidconnect_ssf_previous_push_secret', sharedSignals && !sharedSignalsPoll);
            toggleFieldRow('openidconnect_button_text_mode', buttonTextCustomizable);
            toggleFieldRow('openidconnect_button_provider_label',
                buttonTextCustomizable && buttonTextMode !== 'custom'
            );
            toggleFieldRow('openidconnect_button_custom_text',
                buttonTextCustomizable && buttonTextMode === 'custom'
            );
            refreshSelectPicker(authenticationInput);
            /* These security-boundary coercions are direct assignments. Notify the
             * profile controls after the complete population state is consistent. */
            populationCoercions.trigger('input');
        }
        $(field('openidconnect_create_users')).on('change', update);
        $(field('openidconnect_group_claim')).on('input change', update);
        $(field('openidconnect_logout_menu')).on('change', update);
        $(field('openidconnect_ssf_enabled')).on('change', update);
        $(field('openidconnect_ssf_delivery_method')).on('change', update);
        $(field('openidconnect_origin_policy')).on('change', update);
        $(field('openidconnect_bootstrap_mode')).on('change', update);
        $(field('openidconnect_provider_profile')).on('change', update);
        $(field('openidconnect_microsoft_audience')).on('change', update);
        $(field('openidconnect_provider_url')).on('input change', update);
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
            var provider = profile.value || 'general';
            return ((presets[provider] || {})[requirement.value || '']) || null;
        }

        function apply(force) {
            var preset = selectedPreset();
            if (!preset) {
                return;
            }
            if (force || requestMode.value === '') {
                requestMode.value = preset.request === 'entra_context' ? '' : (preset.request || '');
                refreshSelectPicker(requestMode);
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

        var summary = $('<div class="oidc-profile-summary">');
        var summaryText = $('<div class="oidc-profile-summary-text">');
        var restore = $('<button type="button" class="btn btn-default btn-sm oidc-profile-restore">')
            .append($('<i class="fa fa-undo" aria-hidden="true">'), ' ')
            .append($('<span>').text(options.profileRestoreLabel || 'Restore profile defaults'));
        summary.append(summaryText, $('<div class="oidc-profile-actions">').append(restore));
        row('openidconnect_provider_profile').find('td').last().append(summary);

        function preset() {
            return presets[profile.value] || presets.general || { values: {}, locked: [], placeholders: {} };
        }

        function setValue(name, value) {
            var input = field(name);
            if (!input) {
                return;
            }
            if (input.type === 'checkbox') {
                $(input).prop('checked', value === '1').trigger('change');
                return;
            }
            $(input).val(value).attr('value', value).trigger('change');
            refreshSelectPicker(input);

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

        function currentValue(name) {
            var input = field(name);
            if (!input) {
                return null;
            }
            return input.type === 'checkbox' ? ($(input).is(':checked') ? '1' : '0') : input.value;
        }

        function restoreNeeded() {
            var values = preset().values || {};
            return Object.keys(values).some(function (name) {
                var value = currentValue(name);
                return value !== null && value !== String(values[name]);
            });
        }

        function updateRestoreState() {
            restore.prop('disabled', !restoreNeeded());
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
            refreshSelectPicker(input);
        }

        function decorate() {
            var selected = preset();
            var locked = selected.locked || [];
            var values = selected.values || {};
            var classifications = selected.classifications || {};
            var placeholders = selected.placeholders || {};
            Object.keys((presets.general || {}).values || values).forEach(function (name) {
                var input = field(name);
                if (!input) {
                    return;
                }
                var classification = classifications[name]
                    || (locked.indexOf(name) !== -1 ? 'fixed' : 'editable');
                var fixed = classification === 'fixed';
                setLocked(name, fixed);
                $(input).attr({
                    placeholder: placeholders[name] || '',
                    'data-oidc-profile-classification': classification
                });
                row(name).find('.oidc-profile-field-note').remove();
                if (profile.value === 'general') {
                    return;
                }
                var value = values[name] || '';
                var labels = {
                    fixed: options.profileFixedLabel || 'Fixed by the selected provider profile',
                    recommended: options.profileRecommendedLabel
                        || 'Recommended by the selected provider profile; editable',
                    editable: options.profileEditableLabel
                        || 'Available for this provider; no provider-specific default',
                    hidden: options.profileHiddenLabel || 'Used only by another provider profile',
                    unsupported: options.profileUnsupportedLabel
                        || 'Not supported by the selected provider profile'
                };
                var label = name === 'openidconnect_provider_url' && !value
                    ? (options.profileRequiredLabel || 'Enter the value issued by this provider')
                    : (labels[classification] || labels.editable);
                $('<span class="help-block small oidc-profile-field-note">')
                    .append($('<i class="fa fa-lock" aria-hidden="true">').toggle(
                        fixed || classification === 'unsupported'
                    ), ' ')
                    .append($('<span>').text(label))
                    .appendTo(row(name).find('td').last());
            });

            if (profile.value === 'general') {
                summaryText.empty()
                    .append($('<strong>').text(options.profileGenericLabel || 'Generic provider profile'))
                    .append($('<div>').text(options.profileGenericHelp
                        || 'Generic OpenID Connect makes no provider-specific assumptions.'));
            } else {
                summaryText.empty()
                    .append($('<strong>').text(options.profileAppliedLabel || 'Provider defaults applied'))
                    .append($('<div>').text(options.profileAppliedHelp || 'Recommended values remain editable.'));
            }
            updateRestoreState();
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
        Object.keys((presets.general || {}).values || {}).forEach(function (name) {
            $(field(name)).on('input change', updateRestoreState);
        });
        restore.on('click', function () {
            if (!restoreNeeded()) {
                return;
            }
            BootstrapDialog.confirm({
                title: options.profileRestoreLabel || 'Restore profile defaults',
                message: options.profileRestoreConfirm
                    || 'Replace edited values with the defaults for the selected provider profile?',
                type: BootstrapDialog.TYPE_WARNING,
                callback: function (confirmed) { if (confirmed) { apply(true); } }
            });
        });
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
                updateRestoreState();
            }
            $(issuer).on('change blur', normalizeIssuerInput);
            $(issuer.form).on('submit', normalizeIssuerInput);

            var managedMicrosoftIssuer = '';
            $(microsoftAudience).val(options.microsoftAudience || microsoftAudience.value || 'tenant');
            refreshSelectPicker(microsoftAudience);
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
                updateRestoreState();
            }
            $(microsoftAudience).on('change', updateMicrosoftIssuer);
            $(profile).on('change', updateMicrosoftIssuer);
            updateMicrosoftIssuer();
        }

        return decorate;
    }

    /* ---------------------------------------------------------- lifecycle result */

    function lifecycleTestFromAddress() {
        var address = new URL(window.location.href);
        var startId = address.searchParams.get('openidconnect_lifecycle') || '';
        var resultId = address.searchParams.get('openidconnect_lifecycle_result') || '';
        if (!/^[A-Za-z0-9_-]{43}$/.test(startId) && !/^[A-Za-z0-9_-]{43}$/.test(resultId)) {
            return;
        }
        address.searchParams.delete('openidconnect_lifecycle');
        address.searchParams.delete('openidconnect_lifecycle_result');
        window.history.replaceState({}, document.title, address.pathname + address.search + address.hash);

        if (/^[A-Za-z0-9_-]{43}$/.test(startId)) {
            $.ajax({
                type: 'POST',
                url: '/api/openidconnect/test/logout',
                data: { test_id: startId }
            }).done(function (answer) {
                if (answer && answer.status === 'ok' && answer.logout_url_b64) {
                    try {
                        var logoutUrl = new URL(window.atob(answer.logout_url_b64));
                        if (logoutUrl.protocol === 'https:') {
                            window.location.assign(logoutUrl.href);
                            return;
                        }
                    } catch (_) {
                        /* The authenticated API must return one absolute HTTPS address. */
                    }
                }
                BootstrapDialog.show({
                    title: options.lifecycleTestLabel || 'Validate sign-out',
                    message: $('<div>').text((answer && answer.message) || 'unknown error').html(),
                    type: BootstrapDialog.TYPE_DANGER
                });
            }).fail(function (xhr) {
                BootstrapDialog.show({
                    title: options.lifecycleTestLabel || 'Validate sign-out',
                    message: $('<div>').text(xhr.responseText || 'request failed').html(),
                    type: BootstrapDialog.TYPE_DANGER
                });
            });
            return;
        }

        var attempts = 0;
        function showResult(result, final) {
            var expected = Array.isArray(result.expected) ? result.expected : [];
            var observed = result.observed && typeof result.observed === 'object' ? result.observed : {};
            var testable = result.testable && typeof result.testable === 'object' ? result.testable : {};
            var rows = $('<tbody>');
            function row(label, value, kind) {
                rows.append($('<tr>')
                    .append($('<th>').css('width', '65%').text(label),
                        $('<td class="text-right">').css('width', '12rem').append($('<span class="label">')
                            .css({ display: 'block', width: '100%', textAlign: 'center' })
                            .addClass('label-' + kind).text(value))));
            }
            row(options.lifecycleReturnLabel || 'RP-initiated logout return',
                result.returned ? (options.passedLabel || 'Passed') : (options.notObservedLabel || 'Not observed'),
                result.returned ? 'success' : (final ? 'danger' : 'warning'));
            ['frontchannel', 'backchannel'].forEach(function (channel) {
                var label = channel === 'frontchannel'
                    ? (options.frontchannelLabel || 'Front-channel logout')
                    : (options.backchannelLabel || 'Back-channel logout');
                if (expected.indexOf(channel) === -1) {
                    row(label, options.notConfiguredLabel || 'Not configured', 'info');
                } else if (testable[channel] === false) {
                    row(label, options.notTestableLabel || 'Not testable (no sid)', 'warning');
                } else if (observed[channel]) {
                    row(label, options.passedLabel || 'Passed', 'success');
                } else {
                    row(label, final ? (options.notObservedLabel || 'Not observed')
                        : (options.waitingLabel || 'Waiting...'), final ? 'danger' : 'warning');
                }
            });
            var table = $('<table class="table table-striped">').css('table-layout', 'fixed').append(rows);
            var failed = !result.returned || expected.some(function (channel) {
                return testable[channel] !== false && !observed[channel];
            });
            BootstrapDialog.show({
                title: options.lifecycleResultLabel || 'OpenID Connect lifecycle test',
                message: $('<div>').append(
                    $('<p>').text(options.lifecycleResultHelp
                        || 'Validated provider logout notifications can end the administrator WebGUI session.'),
                    table
                ),
                type: final
                    ? (failed ? BootstrapDialog.TYPE_DANGER : BootstrapDialog.TYPE_SUCCESS)
                    : BootstrapDialog.TYPE_WARNING
            });
        }
        function poll() {
            attempts++;
            $.ajax({
                type: 'POST',
                url: '/api/openidconnect/test/result',
                data: { test_id: resultId }
            }).done(function (answer) {
                if (!answer || answer.status !== 'ok' || !answer.result) {
                    showResult({ expected: [], observed: {}, testable: {}, returned: null }, true);
                    return;
                }
                var result = answer.result;
                var expected = Array.isArray(result.expected) ? result.expected : [];
                var observed = result.observed && typeof result.observed === 'object' ? result.observed : {};
                var testable = result.testable && typeof result.testable === 'object' ? result.testable : {};
                var pending = expected.some(function (channel) {
                    return testable[channel] !== false && !observed[channel];
                });
                if (result.returned && (!pending || attempts >= 10)) {
                    showResult(result, true);
                } else if (attempts >= 10) {
                    showResult(result, true);
                } else {
                    window.setTimeout(poll, 1000);
                }
            }).fail(function () {
                showResult({ expected: [], observed: {}, testable: {}, returned: null }, true);
            });
        }
        poll();
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
            refreshSelectPicker(field('openidconnect_origin_policy'));
        }
        sectorOriginOptions();
        withDiscoveryTest();
        withHealthTest();
        var signInTest = withSignInTest();
        withProviderSetup();
        withApprovalManager();
        withSharedSignalsSetup();
        addSections();
        applicationCodeAvailability();
        var updateProfileDecorations = providerPresets();
        authenticationRequirementPresets();
        conditionalFields();
        webGuiTransportNotice();
        endpointPreview();
        lifecycleTestFromAddress();

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
        if (signInTest) {
            /* Everything that can alter submitted values during synchronous setup has
             * run. Freeze that state before optional UI scripts yield to user input. */
            signInTest.establishBaseline();
        }

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
