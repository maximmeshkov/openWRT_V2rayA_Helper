'use strict';
'require view';
'require rpc';
'require v2raya-helper.menu as helperMenu';

var ruleParams = ['kind', 'value', 'outbound', 'before_line', 'revision'];
var readContext = rpc.declare({
	object: 'v2raya-helper',
	method: 'routing_context',
	expect: { '': {} },
	reject: true
});
var previewRule = rpc.declare({
	object: 'v2raya-helper',
	method: 'routing_preview',
	params: ruleParams,
	expect: { '': {} },
	reject: true
});
var saveRule = rpc.declare({
	object: 'v2raya-helper',
	method: 'routing_save',
	params: ruleParams,
	expect: { '': {} },
	reject: true
});

function formRow(label, control, help) {
	return E('div', { 'class': 'cbi-value' }, [
		E('label', { 'class': 'cbi-value-title', 'for': control.id }, [label]),
		E('div', { 'class': 'cbi-value-field' }, help ? [control, help] : [control])
	]);
}

function option(value, label, disabled) {
	return E('option', { 'value': value, 'disabled': disabled ? '' : null }, [label]);
}

function advanced(kind) {
	return kind === 'regexp' || kind === 'geosite' || kind === 'geoip';
}

function addressValue(kind, input) {
	var value = input.trim();
	if (kind !== 'ip' && !advanced(kind) && /^https?:\/\//i.test(value)) {
		var url = new URL(value);
		if (url.username || url.password || !url.hostname)
			throw new Error();
		return url.hostname;
	}
	return value;
}

function responseError(reply, fallback) {
	return reply && typeof reply.error === 'string' ? reply.error : fallback;
}

return view.extend({
	handleSave: null,
	handleSaveApply: null,
	handleReset: null,

	load: function() {
		helperMenu.refresh();
		return readContext().catch(function() { return {}; });
	},

	render: function(initialContext) {
		var context = null;
		var busy = false;
		var canWrite = L.hasViewPermission() === true;
		var matchTypes = {
			domain: {
				label: _('Domain and subdomains'),
				example: 'example.org',
				help: _('Matches the host you enter and its subdomains. If you paste a URL, the form uses its host name.')
			},
			contains: {
				label: _('Domain contains'),
				example: 'example',
				help: _('Matches the text anywhere in a host name.')
			},
			full: {
				label: _('Exact domain'),
				example: 'www.example.org',
				help: _('Matches exactly one host name. Use the complete name, including any subdomain.')
			},
			ip: {
				label: _('IP address or CIDR'),
				example: '203.0.113.0/24',
				help: _('Enter one IPv4 or IPv6 address, or a network in CIDR notation.')
			},
			regexp: {
				label: _('Domain regular expression'),
				example: '(^|\\.)example\\.org$',
				help: _('Use a pattern for the host name. This example matches example.org and its subdomains.')
			},
			geosite: {
				label: _('Geosite domain list'),
				example: 'google',
				help: _('Enter only the name of a domain list from the installed geosite.dat file.')
			},
			geoip: {
				label: _('GeoIP address list'),
				example: 'private',
				help: _('Enter only the name of an address list from the installed geoip.dat file.')
			}
		};
		var kind = E('select', { 'id': 'routinga-kind', 'class': 'cbi-input-select' },
			Object.keys(matchTypes).map(function(value) { return option(value, matchTypes[value].label); }));
		var address = E('input', {
			'id': 'routinga-address', 'class': 'cbi-input-text', 'type': 'text',
			'aria-describedby': 'routinga-address-help',
			'required': '', 'autocomplete': 'off', 'spellcheck': 'false', 'maxlength': 2048
		});
		var addressHelp = E('p', {
			'id': 'routinga-address-help', 'class': 'cbi-section-descr', 'aria-live': 'polite'
		});
		var outbound = E('select', { 'id': 'routinga-outbound', 'class': 'cbi-input-select', 'required': '' });
		var positionButton = E('button', {
			'id': 'routinga-position', 'type': 'button', 'class': 'btn cbi-button cbi-button-neutral',
			'aria-expanded': 'false', 'aria-controls': 'routinga-position-picker'
		}, [_('Insert before a rule…')]);
		var endButton = E('button', {
			'type': 'button', 'class': 'btn cbi-button cbi-button-neutral', 'hidden': ''
		}, [_('Use end of rule list')]);
		var placement = E('div', { 'aria-live': 'polite', 'style': 'overflow-wrap:anywhere' });
		var search = E('input', {
			'id': 'routinga-position-search', 'type': 'search', 'class': 'cbi-input-text',
			'aria-label': _('Search existing rules'), 'placeholder': _('Search domain, outbound or line number'),
			'autocomplete': 'off', 'spellcheck': 'false', 'style': 'width:100%;box-sizing:border-box'
		});
		var results = E('ul', { 'id': 'routinga-position-results',
			'style': 'max-height:14rem;overflow:auto;list-style:none;padding:0;margin:.4em 0' });
		var count = E('div', { 'role': 'status', 'class': 'cbi-section-descr' });
		var picker = E('div', {
			'id': 'routinga-position-picker', 'hidden': '', 'style': 'margin-top:.5em'
		}, [search, results, count]);
		var positionControls = E('div', {
			'style': 'width:100%;max-width:44rem;min-width:0'
		}, [placement, E('div', { 'style': 'display:flex;flex-wrap:wrap;gap:.4em;margin-top:.4em' }, [
			positionButton, endButton
		]), picker]);
		var positions = [], positionsTotal = 0, selectedPosition = null;
		var versionHint = E('p', { 'class': 'cbi-section-descr' });
		var status = E('p', { 'role': 'status', 'aria-live': 'polite' });
		var formHint = E('p', { 'class': 'cbi-section-descr', 'aria-live': 'polite' });
		var code = E('pre', { 'hidden': '', 'tabindex': '0', 'aria-label': _('Rule preview') });
		var previewButton = E('button', { 'type': 'submit', 'class': 'btn cbi-button cbi-button-action' }, [_('Preview rule')]);
		var saveButton = E('button', { 'type': 'button', 'class': 'btn cbi-button cbi-button-save' }, [_('Add rule')]);
		var reloadButton = E('button', { 'type': 'button', 'class': 'btn cbi-button cbi-button-neutral' }, [_('Refresh')]);
		var fields = E('fieldset', { 'class': 'cbi-section' }, [
			formRow(_('Match type'), kind),
			formRow(_('Address'), address, addressHelp),
			formRow(_('Outbound'), outbound),
			E('div', { 'class': 'cbi-value' }, [
				E('span', { 'class': 'cbi-value-title' }, [_('Rule position')]),
				E('div', { 'class': 'cbi-value-field' }, [positionControls])
			])
		]);

		function updateControls() {
			var canSave = !!(context && context.can_save && canWrite);
			var ready = !!(address.value.trim() && outbound.value);
			var needsValidator = canSave && advanced(kind.value) && !context.validate_advanced;
			fields.disabled = busy || !context;
			previewButton.disabled = busy || !context || !ready;
			saveButton.style.display = canSave ? '' : 'none';
			saveButton.disabled = busy || !canSave || !ready || needsValidator;
			saveButton.textContent = canSave && context.save_verified === false ? _('Add rule (may restart core)') : _('Add rule');
			reloadButton.disabled = busy;
			formHint.textContent = context && !busy ? (
				!address.value.trim() ? _('Enter an address.') : !outbound.value ? _('Choose an outbound.') :
				needsValidator ? _('Saving this rule requires validation with the local core.') : ''
			) : '';
			formHint.style.display = formHint.textContent ? '' : 'none';
		}

		function showStatus(message, tone) {
			status.textContent = message;
			status.className = tone ? 'alert-message ' + tone : '';
			status.style.display = message ? '' : 'none';
		}

		function clearPreview() {
			code.textContent = '';
			code.style.display = 'none';
		}

		function showRule(rule, label) {
			code.textContent = rule;
			code.setAttribute('aria-label', label);
			code.hidden = false;
			code.style.display = '';
		}

		function showPlacement() {
			placement.textContent = '';
			if (selectedPosition) {
				placement.appendChild(E('span', {}, [
					_('Before rule'), ' ', E('code', { 'style': 'white-space:pre-wrap' }, [selectedPosition.label]),
					' ', E('small', {}, [_('Line %d').format(selectedPosition.line)])
				]));
			} else {
				placement.textContent = _('After existing rules');
			}
			positionButton.style.display = positions.length ? '' : 'none';
			endButton.hidden = !selectedPosition;
			endButton.style.display = selectedPosition ? '' : 'none';
		}

		function closePicker() {
			picker.hidden = true;
			positionButton.setAttribute('aria-expanded', 'false');
			search.value = '';
			results.textContent = '';
		}

		function choosePosition(item) {
			selectedPosition = item;
			closePicker();
			showPlacement();
			positionButton.focus();
			edited();
		}

		function showMatches() {
			var query = search.value.trim().toLowerCase();
			var matches = positions.filter(function(item) {
				return String(item.line) === query || item.label.toLowerCase().includes(query);
			});
			var rows = document.createDocumentFragment();
			matches.forEach(function(item) {
				var button = E('button', {
					'type': 'button', 'class': 'btn cbi-button cbi-button-neutral',
					'style': 'display:flex;align-items:baseline;gap:.6em;width:100%;box-sizing:border-box;text-align:left;white-space:normal'
				}, [E('code', { 'style': 'flex:1;min-width:0;white-space:pre-wrap;overflow-wrap:anywhere' }, [item.label]),
					E('small', { 'style': 'white-space:nowrap' }, [_('Line %d').format(item.line)])]);
				button.addEventListener('click', function() { choosePosition(item); });
				rows.appendChild(E('li', { 'style': 'margin:.2em 0' }, [button]));
			});
			results.replaceChildren(rows);
			results.scrollTop = 0;
			var message = matches.length ? _('Matching rules: %d').format(matches.length) : _('No matching rules.');
			if (positionsTotal > positions.length)
				message += ' ' + _('Search covers the first %d of %d rules.').format(positions.length, positionsTotal);
			count.textContent = message;
		}

		function populate(reply) {
			var selected = outbound.value;
			clearPreview();
			closePicker();
			selectedPosition = null;
			positions = [];
			positionsTotal = 0;
			if (!reply || reply.ok !== true || typeof reply.revision !== 'string') {
				context = null;
				versionHint.textContent = '';
				showPlacement();
				showStatus(responseError(reply, _('Could not load RoutingA from v2rayA.')), 'warning');
				updateControls();
				return;
			}
			context = reply;
			outbound.textContent = '';
			outbound.appendChild(option('', _('Choose an outbound')));
			(Array.isArray(reply.outbounds) ? reply.outbounds : []).forEach(function(item) {
				outbound.appendChild(option(item.name,
					item.available ? item.name : item.name + ' — ' + _('No server assigned'), !item.available));
				if (item.available && selected === item.name)
					outbound.value = selected;
			});

			positions = (Array.isArray(reply.positions) ? reply.positions : []).filter(function(item) {
				return item && Number.isInteger(item.line) && item.line > 0 && typeof item.label === 'string' && item.label;
			});
			positionsTotal = Number.isInteger(reply.positions_total) ? reply.positions_total : positions.length;
			showPlacement();
			if (!reply.can_save)
				versionHint.textContent = _('Preview only. Saving is not verified for v2rayA %s; the Compatibility page can allow it.').format(reply.version || _('unknown'));
			else if (!canWrite)
				versionHint.textContent = _('Your LuCI account can preview rules. Saving requires write permission.');
			else if (reply.save_verified === false)
				versionHint.textContent = _('v2rayA %s is not verified: saving may make v2rayA restart its core.').format(reply.version || _('unknown'));
			else
				versionHint.textContent = _('Saved rules take effect the next time v2rayA rebuilds the core configuration.');
			updateControls();
		}

		async function run(task, errorMessage) {
			if (busy)
				return;
			busy = true;
			updateControls();
			try {
				await task();
			} catch (error) {
				showStatus(errorMessage, 'warning');
			} finally {
				busy = false;
				updateControls();
			}
		}

		function edited() {
			clearPreview();
			showStatus('');
			updateControls();
		}

		function updateAddressHelp() {
			var type = matchTypes[kind.value];
			address.placeholder = type.example;
			addressHelp.textContent = type.help;
		}

		function draftArgs() {
			try {
				return [kind.value, addressValue(kind.value, address.value), outbound.value,
					selectedPosition ? selectedPosition.line : 0, context.revision];
			} catch (error) {
				showStatus(_('Enter a valid HTTP or HTTPS URL without login credentials.'), 'warning');
				return null;
			}
		}

		function handlePreview(event) {
			event.preventDefault();
			if (previewButton.disabled)
				return;
			return run(async function() {
				clearPreview();
				var args = draftArgs();
				if (!args) return;
				showStatus(_('Preparing preview…'));
				var reply = await previewRule.apply(null, args);
				if (!reply || reply.ok !== true || typeof reply.rule !== 'string' ||
				    reply.revision !== args[4] || reply.before_line !== args[3]) {
					showStatus(responseError(reply, _('Could not preview the rule.')), 'warning');
					return;
				}
				showRule(reply.rule, _('Rule preview'));
				showStatus(_('Preview only. The rule has not been saved. The first matching rule wins.'));
			}, _('Could not preview the rule.'));
		}

		function handleSaveRule() {
			if (saveButton.disabled)
				return;
			return run(async function() {
				var args = draftArgs();
				if (!args) return;
				var saveMayRestart = context.save_verified === false;
				clearPreview();
				showStatus(_('Saving rule…'));
				var reply = await saveRule.apply(null, args);
				if (!reply || reply.ok !== true) {
					showStatus(responseError(reply, _('Could not confirm the rule was saved. Refresh before retrying.')), 'warning');
					return;
				}
				address.value = '';
				context = null;
				var saved = saveMayRestart ? _('Rule saved in RoutingA.') :
					_('Rule saved in RoutingA. It will take effect on the next core configuration rebuild.');
			if (!saveMayRestart)
				saved += ' ' + _('To apply now, click the Running status in v2rayA to stop the core, then click Ready to start it again. This interrupts active proxy connections.');
				showStatus(saved, 'success');
				var refreshed = await readContext().catch(function() { return {}; });
				populate(refreshed);
				if (!context)
					showStatus(saved + ' ' + _('Could not refresh the rule list.'), 'warning');
				if (typeof reply.rule === 'string')
					showRule(reply.rule, _('Saved rule'));
			}, _('Could not confirm the rule was saved. Refresh before retrying.'));
		}

		address.addEventListener('input', edited);
		kind.addEventListener('change', function() {
			updateAddressHelp();
			edited();
		});
		outbound.addEventListener('change', edited);
		positionButton.addEventListener('click', function() {
			if (!picker.hidden) {
				closePicker();
				return;
			}
			picker.hidden = false;
			positionButton.setAttribute('aria-expanded', 'true');
			showMatches();
			search.focus();
		});
		endButton.addEventListener('click', function() { choosePosition(null); });
		search.addEventListener('input', showMatches);
		search.addEventListener('keydown', function(event) {
			if (event.key !== 'Enter' && event.key !== 'ArrowDown') return;
			event.preventDefault();
			var match = results.querySelector('button');
			if (match) match.focus();
		});
		picker.addEventListener('keydown', function(event) {
			if (event.key !== 'Escape') return;
			event.preventDefault();
			closePicker();
			positionButton.focus();
		});
		saveButton.addEventListener('click', handleSaveRule);
		reloadButton.addEventListener('click', function() {
			return run(async function() {
				clearPreview();
				context = null;
				showStatus(_('Loading RoutingA…'));
				populate(await readContext());
				if (context)
					showStatus('');
			}, _('Could not load RoutingA from v2rayA.'));
		});

		updateAddressHelp();
		populate(initialContext);
		return E('div', { 'class': 'cbi-map' }, [
			E('h2', {}, [_('RoutingA')]),
			versionHint,
			E('form', { 'submit': handlePreview }, [
				fields, formHint, status, code,
				E('div', { 'class': 'cbi-page-actions', 'style': 'display:flex;flex-wrap:wrap;gap:.5em;justify-content:flex-start' },
					[saveButton, previewButton, reloadButton])
			])
		]);
	}
});
