'use strict';
'require view';
'require rpc';

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

function formRow(label, control) {
	return E('div', { 'class': 'cbi-value' }, [
		E('label', { 'class': 'cbi-value-title', 'for': control.id }, [label]),
		E('div', { 'class': 'cbi-value-field' }, [control])
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
		return readContext().catch(function() { return {}; });
	},

	render: function(initialContext) {
		var context = null;
		var preview = null;
		var busy = false;
		var canWrite = L.hasViewPermission() === true;
		var kind = E('select', { 'id': 'routinga-kind', 'class': 'cbi-input-select' }, [
			option('domain', _('Domain and subdomains')),
			option('contains', _('Domain contains')),
			option('full', _('Exact domain')),
			option('ip', _('IP address or CIDR')),
			option('regexp', _('Domain regular expression')),
			option('geosite', _('Geosite domain list')),
			option('geoip', _('GeoIP address list'))
		]);
		var address = E('input', {
			'id': 'routinga-address', 'class': 'cbi-input-text', 'type': 'text',
			'required': '', 'autocomplete': 'off', 'spellcheck': 'false', 'maxlength': 2048
		});
		var outbound = E('select', { 'id': 'routinga-outbound', 'class': 'cbi-input-select', 'required': '' });
		var position = E('select', { 'id': 'routinga-position', 'class': 'cbi-input-select' });
		var versionHint = E('p', { 'class': 'cbi-section-descr' });
		var status = E('p', { 'role': 'status', 'aria-live': 'polite' });
		var code = E('pre', { 'hidden': '', 'tabindex': '0', 'aria-label': _('Rule preview') });
		var previewButton = E('button', { 'type': 'submit', 'class': 'btn cbi-button cbi-button-action' }, [_('Preview rule')]);
		var saveButton = E('button', { 'type': 'button', 'class': 'btn cbi-button cbi-button-save' }, [_('Save for next Xray configuration rebuild')]);
		var reloadButton = E('button', { 'type': 'button', 'class': 'btn cbi-button cbi-button-neutral' }, [_('Refresh')]);
		var fields = E('fieldset', { 'class': 'cbi-section' }, [
			formRow(_('Match type'), kind),
			formRow(_('Address'), address),
			formRow(_('Outbound'), outbound),
			formRow(_('Insert rule'), position)
		]);

		function updateControls() {
			fields.disabled = busy || !context;
			previewButton.disabled = busy || !context || !address.value.trim() || !outbound.value;
			saveButton.hidden = !context || !context.can_save || !canWrite;
			saveButton.disabled = busy || !preview || (advanced(kind.value) && !context.validate_advanced);
			reloadButton.disabled = busy;
		}

		function showStatus(message, error) {
			status.textContent = message;
			status.className = error ? 'alert-message warning' : '';
		}

		function clearPreview() {
			preview = null;
			code.textContent = '';
			code.hidden = true;
		}

		function populate(reply) {
			var selected = outbound.value;
			clearPreview();
			if (!reply || reply.ok !== true || typeof reply.revision !== 'string') {
				context = null;
				versionHint.textContent = '';
				showStatus(responseError(reply, _('Could not load RoutingA from v2rayA.')), true);
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

			position.textContent = '';
			position.appendChild(option('0', _('After existing rules')));
			(Array.isArray(reply.positions) ? reply.positions : []).forEach(function(item) {
				if (Number.isInteger(item.line) && item.line > 0) {
					var label = _('Before line %d').format(item.line);
					position.appendChild(option(item.line, item.label ? label + ' — ' + item.label : label));
				}
			});
			if (!reply.can_save)
				versionHint.textContent = _('Preview only. Saving without reconfiguring Xray is unverified for v2rayA %s.').format(reply.version || _('unknown'));
			else if (!canWrite)
				versionHint.textContent = _('Your LuCI account can preview rules. Saving requires write permission.');
			else
				versionHint.textContent = _('Saved rules take effect the next time v2rayA rebuilds the Xray configuration.');
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
				showStatus(errorMessage, true);
			} finally {
				busy = false;
				updateControls();
			}
		}

		function edited() {
			clearPreview();
			showStatus('', false);
			address.placeholder = kind.value === 'ip' ? '203.0.113.0/24' : 'example.org';
			updateControls();
		}

		function handlePreview(event) {
			event.preventDefault();
			if (previewButton.disabled)
				return;
			return run(async function() {
				clearPreview();
				var value;
				try {
					value = addressValue(kind.value, address.value);
				} catch (error) {
					showStatus(_('Enter a valid HTTP or HTTPS URL without login credentials.'), true);
					return;
				}
				showStatus(_('Preparing preview…'), false);
				var args = [kind.value, value, outbound.value, Number(position.value), context.revision];
				var reply = await previewRule.apply(null, args);
				if (!reply || reply.ok !== true || typeof reply.rule !== 'string' ||
				    reply.revision !== args[4] || reply.before_line !== args[3]) {
					showStatus(responseError(reply, _('Could not preview the rule.')), true);
					return;
				}
				preview = args;
				code.textContent = reply.rule;
				code.hidden = false;
				showStatus(_('The first matching rule wins.'), false);
			}, _('Could not preview the rule.'));
		}

		function handleSaveRule() {
			if (!preview || !context || !context.can_save || !canWrite)
				return;
			return run(async function() {
				var args = preview;
				clearPreview();
				showStatus(_('Saving rule…'), false);
				var reply = await saveRule.apply(null, args);
				if (!reply || reply.ok !== true) {
					showStatus(responseError(reply, _('Could not confirm the rule was saved. Refresh before retrying.')), true);
					return;
				}
				address.value = '';
				context = null;
				showStatus(_('Rule saved in RoutingA. It will take effect on the next Xray configuration rebuild.'), false);
				var refreshed = await readContext().catch(function() { return {}; });
				populate(refreshed);
				if (!context)
					showStatus(_('Rule saved in RoutingA. Could not refresh the list.'), true);
			}, _('Could not confirm the rule was saved. Refresh before retrying.'));
		}

		address.addEventListener('input', edited);
		[kind, outbound, position].forEach(function(control) { control.addEventListener('change', edited); });
		saveButton.addEventListener('click', handleSaveRule);
		reloadButton.addEventListener('click', function() {
			return run(async function() {
				clearPreview();
				context = null;
				showStatus(_('Loading RoutingA…'), false);
				populate(await readContext());
				if (context)
					showStatus('', false);
			}, _('Could not load RoutingA from v2rayA.'));
		});

		address.placeholder = 'example.org';
		populate(initialContext);
		return E('div', { 'class': 'cbi-map' }, [
			E('h2', {}, [_('RoutingA')]),
			versionHint,
			E('form', { 'submit': handlePreview }, [
				fields, code,
				E('div', { 'class': 'cbi-page-actions' }, [reloadButton, ' ', previewButton, ' ', saveButton]),
				status
			])
		]);
	}
});
