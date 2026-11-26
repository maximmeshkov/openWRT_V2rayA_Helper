'use strict';
'require view';
'require rpc';

var readContext = rpc.declare({
	object: 'v2raya-helper',
	method: 'failover_context',
	expect: { '': {} },
	reject: true
});
var savePolicy = rpc.declare({
	object: 'v2raya-helper',
	method: 'failover_save',
	params: ['policy'],
	expect: { '': {} },
	reject: true
});

var candidateLimit = 64;

function row(title, control) {
	return E('div', { 'class': 'cbi-value' }, [
		E('label', { 'class': 'cbi-value-title', 'for': control.id }, [title]),
		E('div', { 'class': 'cbi-value-field' }, [control])
	]);
}

function option(value, label) {
	return E('option', { 'value': value }, [label]);
}

function rangeInput(id, min, max) {
	return E('input', {
		'id': id, 'class': 'cbi-input-text', 'type': 'number',
		'min': min, 'max': max, 'step': 1
	});
}

function newPolicy(outbound, saved) {
	return Object.assign({
		outbound: outbound, mode: 'off', candidates: [], failures: 3,
		failure_method: 'consecutive', failure_window_minutes: 10,
		max_ms: 0, cooldown_seconds: 900, start: '', end: ''
	}, saved || {});
}

function validTime(value) {
	return /^([01]\d|2[0-3]):[0-5]\d$/.test(value);
}

function validInteger(value, min, max) {
	return value !== '' && Number.isInteger(Number(value)) && Number(value) >= min && Number(value) <= max;
}

function errorText(reply, fallback) {
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
		var canWrite = L.hasViewPermission() === true;
		var context, selected = '', busy = false;
		var drafts = new Map(), saved = new Map(), catalogue = new Map(), dirty = new Set();
		var outbound = E('select', { 'id': 'failover-outbound', 'class': 'cbi-input-select' });
		var mode = E('select', { 'id': 'failover-mode', 'class': 'cbi-input-select' }, [
			option('off', _('Off')),
			option('outage', _('On repeated outages')),
			option('scheduled', _('Inside a time window'))
		]);
		var failures = rangeInput('failover-failures', 3, 30);
		var failureMethod = E('select', { 'id': 'failover-failure-method', 'class': 'cbi-input-select' }, [
			option('consecutive', _('Consecutive failures')),
			option('window', _('Failures in a time window'))
		]);
		var failureWindow = rangeInput('failover-failure-window', 1, 180);
		var windowRow = E('div', {}, [
			row(_('Failure window (minutes)'), failureWindow),
			E('p', { 'class': 'cbi-section-descr' }, [
				_('Choose a window long enough to contain the requested number of checks.')
			])
		]);
		var cooldown = rangeInput('failover-cooldown', 60, 86400);
		var latency = rangeInput('failover-latency', 0, 60000);
		var start = E('input', { 'id': 'failover-start', 'class': 'cbi-input-text', 'type': 'time' });
		var end = E('input', { 'id': 'failover-end', 'class': 'cbi-input-text', 'type': 'time' });
		var current = E('span', { 'id': 'failover-current' });
		var search = E('input', {
			'id': 'failover-search', 'class': 'cbi-input-text', 'type': 'search',
			'placeholder': _('Filter servers')
		});
		var list = E('div', { 'class': 'cbi-value-field' });
		var count = E('p');
		var options = E('div', {}, [
			row(_('How to count failures'), failureMethod),
			row(_('Failed checks required'), failures),
			windowRow,
			row(_('Minimum time between switches (seconds)'), cooldown)
		]);
		var schedule = E('div', {}, [
			row(_('From (router time)'), start),
			row(_('Until (router time)'), end),
			row(_('Latency limit (ms, 0 disables)'), latency),
			E('p', { 'class': 'cbi-section-descr' }, [
				_('Inside these hours, repeated failures or consecutive checks over the latency limit can trigger a switch.')
			])
		]);
		var confirm = E('input', { 'id': 'failover-confirm', 'type': 'checkbox' });
		var confirmation = E('p', { 'class': 'alert-message warning' }, [
			E('label', { 'for': confirm.id }, [
				confirm, ' ', _('I allow automatic switches to restart Xray and interrupt its connections.')
			])
		]);
		var fields = E('fieldset', { 'class': 'cbi-section' }, [
			row(_('Current server'), current),
			row(_('Mode'), mode),
			options, schedule,
			row(_('Replacement servers'), search), list, count, confirmation
		]);
		var availability = E('p', { 'class': 'cbi-section-descr' });
		var status = E('p', { 'role': 'status', 'aria-live': 'polite' });
		var refresh = E('button', { 'type': 'button', 'class': 'btn cbi-button cbi-button-neutral' }, [_('Refresh')]);
		var save = E('button', { 'type': 'submit', 'class': 'btn cbi-button cbi-button-save' }, [_('Save switching settings')]);

		function message(text, error) {
			status.textContent = text;
			status.className = error ? 'alert-message warning' : '';
		}

		function draft() {
			return drafts.get(selected);
		}

		function updateControls() {
			var enabled = mode.value !== 'off';
			fields.hidden = !selected;
			fields.disabled = busy || !context || !canWrite;
			outbound.disabled = busy || !context || context.outbounds.length === 0;
			options.hidden = !enabled;
			windowRow.hidden = failureMethod.value !== 'window';
			schedule.hidden = mode.value !== 'scheduled';
			confirmation.hidden = !enabled || !canWrite;
			save.hidden = !canWrite;
			save.disabled = busy || !context || !selected || (enabled && !context.can_switch);
			refresh.disabled = busy;
		}

		function rememberInputs() {
			if (!draft())
				return;
			Object.assign(draft(), {
				mode: mode.value, failures: failures.value, cooldown_seconds: cooldown.value,
				failure_method: failureMethod.value, failure_window_minutes: failureWindow.value,
				max_ms: latency.value, start: start.value, end: end.value
			});
		}

		function showCandidates() {
			list.textContent = '';
			if (!draft())
				return;
			var chosen = new Set(draft().candidates);
			var filter = search.value.trim().toLowerCase();
			var visible = 0;

			function candidate(key, label, missing) {
				var checkbox = E('input', { 'type': 'checkbox' });
				checkbox.checked = chosen.has(key);
				checkbox.addEventListener('change', function() {
					if (checkbox.checked) {
						if (chosen.size >= candidateLimit) {
							checkbox.checked = false;
							message(_('Select at most 64 replacement servers.'), true);
							return;
						}
						chosen.add(key);
					} else {
						chosen.delete(key);
					}
					draft().candidates = Array.from(chosen);
					dirty.add(selected);
					count.textContent = _('Selected servers: %d').format(chosen.size);
					message('', false);
					if (missing)
						showCandidates();
				});
				list.appendChild(E('div', { 'class': 'cbi-value' }, [
					E('label', {}, [checkbox, ' ', label])
				]));
				visible++;
			}

			catalogue.forEach(function(node, key) {
				var label = [node.name || node.address, node.address, node.net].filter(Boolean).join(' · ');
				if (chosen.has(key) || !filter || label.toLowerCase().includes(filter))
					candidate(key, label, false);
			});
			chosen.forEach(function(key) {
				if (!catalogue.has(key))
					candidate(key, _('Selected server unavailable. Deselect to remove it.'), true);
			});
			if (!visible)
				list.appendChild(E('p', {}, [_('No matching servers.')]));
			count.textContent = _('Selected servers: %d').format(chosen.size);
		}

		function showOutbound() {
			selected = outbound.value;
			confirm.checked = false;
			search.value = '';
			if (selected) {
				if (!draft())
					drafts.set(selected, newPolicy(selected, saved.get(selected)));
				var policy = draft();
				mode.value = policy.mode;
				failures.value = policy.failures;
				failureMethod.value = policy.failure_method;
				failureWindow.value = policy.failure_window_minutes;
				cooldown.value = policy.cooldown_seconds;
				latency.value = policy.max_ms;
				start.value = policy.start;
				end.value = policy.end;
				var target = context.outbounds.find(function(item) { return item.name === selected; });
				current.textContent = target && target.current || _('No single current server');
			}
			showCandidates();
			updateControls();
		}

		function populate(reply) {
			outbound.textContent = '';
			if (!reply || reply.ok !== true || !Array.isArray(reply.outbounds) ||
			    !Array.isArray(reply.nodes) || !Array.isArray(reply.policies)) {
				context = null;
				availability.textContent = '';
				showOutbound();
				message(errorText(reply, _('Could not load switching settings.')), true);
				return;
			}
			context = reply;
			catalogue = new Map(reply.nodes.map(function(node) { return [node.key, node]; }));
			saved = new Map(reply.policies.map(function(policy) { return [policy.outbound, policy]; }));
			drafts.forEach(function(policy, name) {
				if (!dirty.has(name))
					drafts.delete(name);
			});
			reply.outbounds.forEach(function(item) {
				outbound.appendChild(option(item.name, item.name));
			});
			if (reply.outbounds.some(function(item) { return item.name === selected; }))
				outbound.value = selected;
			if (context.catalog_unavailable)
				availability.textContent = _('The v2rayA server list is unavailable. You can disable saved automatic switching here.');
			else if (!context.can_switch)
				availability.textContent = _('Automatic switching is unavailable for this v2rayA version or core.');
			else if (!canWrite)
				availability.textContent = _('Your LuCI account has read access to these settings.');
			else
				availability.textContent = '';
			showOutbound();
			message(selected ? '' : _('No outbounds are available.'), false);
		}

		async function perform(task, fallback) {
			if (busy)
				return;
			busy = true;
			updateControls();
			try {
				await task();
			} catch (error) {
				message(fallback, true);
			} finally {
				busy = false;
				updateControls();
			}
		}

		function submit(event) {
			event.preventDefault();
			if (save.disabled || !canWrite)
				return;
			rememberInputs();
			var input = draft();
			var policy = {
				outbound: selected, mode: input.mode,
				candidates: input.candidates,
				allow_restart: false
			};
			if (input.mode !== 'off') {
				if (!policy.candidates.length ||
				    policy.candidates.some(function(key) { return !catalogue.has(key); })) {
					message(_('Choose at least one available replacement server and remove unavailable selections.'), true);
					return;
				}
				if (!validInteger(input.failures, 3, 30) || !validInteger(input.cooldown_seconds, 60, 86400)) {
					message(_('Enter 3 to 30 checks and a switch interval of 60 to 86400 seconds.'), true);
					return;
				}
				if (input.failure_method === 'window' && !validInteger(input.failure_window_minutes, 1, 180)) {
					message(_('Enter a failure window between 1 and 180 minutes.'), true);
					return;
				}
				if (!confirm.checked) {
					message(_('Confirm that automatic switching may interrupt Xray connections.'), true);
					return;
				}
				policy.allow_restart = true;
			}
			if (validInteger(input.failures, 3, 30))
				policy.failures = Number(input.failures);
			policy.failure_method = input.failure_method;
			if (validInteger(input.failure_window_minutes, 1, 180))
				policy.failure_window_minutes = Number(input.failure_window_minutes);
			if (validInteger(input.cooldown_seconds, 60, 86400))
				policy.cooldown_seconds = Number(input.cooldown_seconds);
			if (input.mode === 'scheduled') {
				if (!validTime(input.start) || !validTime(input.end) || input.start === input.end ||
				    !validInteger(input.max_ms, 0, 60000)) {
					message(_('Choose two different times and a latency limit between 0 and 60000 ms.'), true);
					return;
				}
			}
			if (validTime(input.start) && validTime(input.end) && input.start !== input.end) {
				policy.start = input.start;
				policy.end = input.end;
			}
			if (validInteger(input.max_ms, 0, 60000))
				policy.max_ms = Number(input.max_ms);
			return perform(async function() {
				var reply = await savePolicy(policy);
				if (!reply || reply.ok !== true) {
					message(errorText(reply, _('Could not save switching settings.')), true);
					return;
				}
				var updated = newPolicy(selected, policy);
				delete updated.allow_restart;
				saved.set(selected, updated);
				drafts.set(selected, updated);
				dirty.delete(selected);
				showOutbound();
				message(_('Switching settings saved.'), false);
			}, _('Could not confirm that the switching settings were saved.'));
		}

		outbound.addEventListener('change', function() {
			rememberInputs();
			showOutbound();
			message('', false);
		});
		mode.addEventListener('change', function() {
			confirm.checked = false;
			dirty.add(selected);
			rememberInputs();
			updateControls();
			message('', false);
		});
		failureMethod.addEventListener('change', function() {
			confirm.checked = false;
			dirty.add(selected);
			rememberInputs();
			updateControls();
		});
		[failures, failureWindow, cooldown, latency, start, end].forEach(function(input) {
			input.addEventListener('input', function() {
				dirty.add(selected);
				rememberInputs();
			});
		});
		search.addEventListener('input', showCandidates);
		refresh.addEventListener('click', function() {
			rememberInputs();
			return perform(async function() {
				populate(await readContext());
			}, _('Could not refresh switching settings.'));
		});
		populate(initialContext);
		return E('div', { 'class': 'cbi-map' }, [
			E('h2', {}, [_('Server failover')]),
			availability,
			E('form', { 'submit': submit, 'novalidate': '' }, [
				row(_('Outbound'), outbound), fields,
				E('div', { 'class': 'cbi-page-actions' }, [refresh, ' ', save]),
				status
			])
		]);
	}
});
