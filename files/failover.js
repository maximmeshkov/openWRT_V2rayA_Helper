'use strict';
'require view';
'require rpc';
'require session';
'require poll';

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
var readStatus = rpc.declare({
	object: 'v2raya-helper', method: 'status', expect: { '': {} }, reject: true
});
var readHistory = rpc.declare({
	object: 'v2raya-helper', method: 'latency', params: ['outbound'], expect: { '': {} }, reject: true
});

var candidateLimit = 64;
var outboundKey = 'v2raya-helper-failover-outbound';

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

function validContext(reply) {
	return reply && reply.ok === true && Array.isArray(reply.outbounds) &&
		Array.isArray(reply.nodes) && Array.isArray(reply.policies);
}

function matchesSaved(requested, stored) {
	return stored && Object.keys(requested).every(function(field) {
		if (field === 'allow_restart') return true;
		if (field === 'candidates')
			return Array.isArray(stored.candidates) && requested.candidates.length === stored.candidates.length &&
				requested.candidates.every(function(key, index) { return key === stored.candidates[index]; });
		return requested[field] === stored[field];
	});
}

function activeReadings(reply, server) {
	if (!reply || !Array.isArray(reply.samples) || !Number.isSafeInteger(reply.router_unix)) return null;
	var samples = reply.samples.filter(function(sample) {
		return sample && sample.role === 'active' && sample.server === server && typeof sample.series === 'string' &&
			Number.isSafeInteger(sample.at) && sample.at > 0 && sample.at <= reply.router_unix;
	}).sort(function(a, b) { return b.at - a.at; });
	return { now: reply.router_unix, times: samples.length ? samples.filter(function(sample) {
		return sample.series === samples[0].series;
	}).map(function(sample) { return sample.at; }) : [] };
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
		var context, selected = session.getLocalData(outboundKey) || '', busy = false;
		var drafts = new Map(), saved = new Map(), catalogue = new Map(), dirty = new Set(), unverified = new Map();
		var timing = null, timingTarget = null, timingRequests = 0, timingBusy = false;
		var outbound = E('select', { 'id': 'failover-outbound', 'class': 'cbi-input-select' });
		var modeLabels = { off: _('Off'), outage: _('On repeated outages'), scheduled: _('During scheduled hours') };
		var mode = E('select', { 'id': 'failover-mode', 'class': 'cbi-input-select' }, [
			option('off', modeLabels.off), option('outage', modeLabels.outage), option('scheduled', modeLabels.scheduled)
		]);
		var savedMode = E('p', { 'id': 'failover-saved-mode', 'class': 'cbi-section-descr', 'aria-live': 'polite' });
		var cadence = E('p', { 'id': 'failover-check-cadence', 'class': 'cbi-section-descr' });
		var recent = E('p', { 'id': 'failover-check-history', 'class': 'cbi-section-descr' });
		var capacity = E('p', { 'id': 'failover-cadence-capacity', 'class': 'cbi-section-descr' });
		var failures = rangeInput('failover-failures', 3, 30);
		var failureMethod = E('select', { 'id': 'failover-failure-method', 'class': 'cbi-input-select' }, [
			option('consecutive', _('Consecutive failures')),
			option('window', _('Failures over the last N minutes'))
		]);
		var failureWindow = rangeInput('failover-failure-window', 1, 180);
		var windowRow = row(_('Count failures over (minutes)'), failureWindow);
		var cooldown = rangeInput('failover-cooldown', 60, 86400);
		var latency = rangeInput('failover-latency', 0, 60000);
		var start = E('input', { 'id': 'failover-start', 'class': 'cbi-input-text', 'type': 'time' });
		var end = E('input', { 'id': 'failover-end', 'class': 'cbi-input-text', 'type': 'time' });
		var current = E('span', { 'id': 'failover-current' });
		var search = E('input', {
			'id': 'failover-search', 'class': 'cbi-input-text', 'type': 'search',
			'placeholder': _('Filter servers')
		});
		var list = E('div', { 'class': 'cbi-value-field', 'style': 'max-height:22rem;overflow:auto' });
		var count = E('p');
		var removeUnavailable = E('button', {
			'id': 'failover-remove-unavailable', 'type': 'button', 'class': 'btn cbi-button cbi-button-neutral'
		}, [_('Remove unavailable selections')]);
		var options = E('div', {}, [
			row(_('How to count failures'), failureMethod),
			row(_('Failed checks required (3–30)'), failures),
			windowRow, capacity,
			row(_('Minimum pause between switches across all outbounds (seconds)'), cooldown)
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
			row(_('Mode'), mode), savedMode, cadence, recent, options, schedule, confirmation
		]);
		var candidateFields = E('fieldset', { 'class': 'cbi-section' }, [
			row(_('Replacement servers'), search),
			E('div', { 'style': 'display:flex;flex-wrap:wrap;align-items:baseline;gap:.5em' }, [count, removeUnavailable]),
			list
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

		function showSavedMode() {
			var stored = saved.get(selected);
			savedMode.textContent = '';
			if (context && selected)
				savedMode.textContent = stored ? _('Saved mode: %s').format(modeLabels[stored.mode]) : _('Default mode: Off');
			if (context && dirty.has(selected))
				savedMode.textContent += ' · ' + _('Unsaved changes');
		}

		function markEdited() {
			dirty.add(selected);
			unverified.delete(selected);
			showSavedMode();
		}

		function showTiming() {
			if (!context || !selected) return;
			if (!timingTarget || timingTarget.outbound !== selected) {
				cadence.textContent = recent.textContent = capacity.textContent = '';
				return;
			}
			var minutes = validInteger(failureWindow.value, 1, 180) ? Number(failureWindow.value) : 10;
			var windowed = failureMethod.value === 'window';
			var interval = timing && timing.interval;
			var server = timing ? timing.server : timingTarget.server;
			if (timing)
				current.textContent = server || _('No single current server');
			cadence.textContent = interval ? _('HTTPS checks wait at least %d seconds after each completed check. Queueing and request time can add to the gap.').format(interval) :
				(timingBusy ? _('Loading HTTPS check timing…') : _('The configured HTTPS check interval is unavailable.'));
			var history = timing && timing.readings;
			if (history) {
				var observed = history.times.filter(function(at) { return history.now - at <= minutes * 60; }).length;
				recent.textContent = _('This server had %d HTTPS checks in the last %d minutes.').format(observed, minutes);
				if (history.times.length > 1)
					recent.textContent += ' ' + _('The latest two were %d seconds apart.').format(history.times[0] - history.times[1]);
			} else {
				recent.textContent = !server ? _('Switching requires one current server per outbound.') :
					(timingBusy ? '' : _('Recent HTTPS checks for this server are unavailable.'));
			}
			capacity.className = 'cbi-section-descr';
			capacity.textContent = '';
			if (!interval || !server || !validInteger(failures.value, 3, 30)) return;
			var required = Number(failures.value);
			if (windowed && validInteger(failureWindow.value, 1, 180)) {
				var maximum = Math.floor(minutes * 60 / interval) + 1;
				capacity.textContent = _('At most %d checks fit in %d minutes at ideal spacing. The latest check must also fail.').format(maximum, minutes);
				if (required > maximum) {
					capacity.className = 'alert-message warning';
					capacity.textContent += ' ' + _('A threshold of %d cannot be reached in this window.').format(required);
				}
			} else if (!windowed) {
				capacity.textContent = _('The first and last of %d consecutive failures are at least %d seconds apart.').format(required, (required - 1) * interval);
			}
		}

		function refreshTiming() {
			if (!context || !selected) return Promise.resolve();
			var item = context.outbounds.find(function(item) { return item.name === selected; });
			var target = { outbound: selected, server: item && item.current || '' };
			var changed = !timingTarget || target.outbound !== timingTarget.outbound || target.server !== timingTarget.server;
			if (timingBusy && !changed) return Promise.resolve();
			if (changed) timing = null;
			timingTarget = target;
			var id = ++timingRequests;
			timingBusy = true;
			showTiming();
			return Promise.all([
				readStatus().catch(function() { return null; }),
				readHistory(target.outbound).catch(function() { return null; })
			]).then(function(replies) {
				if (id !== timingRequests) return;
				timingBusy = false;
				var info = replies[0], snapshot = info && info.snapshot;
				var interval = snapshot && snapshot.node_check_interval;
				var fresh = snapshot && Number.isSafeInteger(info.router_unix) &&
					Date.parse(snapshot.fresh_until) > info.router_unix * 1000;
				var server = target.server;
				if (fresh && snapshot.state === 'ok' && Array.isArray(snapshot.outbounds)) {
					var outbound = snapshot.outbounds.find(function(item) { return item.name === target.outbound; });
					var members = outbound && outbound.members;
					server = Array.isArray(members) && members.length === 1 ? members[0].name : '';
				}
				timing = { interval: fresh && Number.isSafeInteger(interval) && interval > 0 ? interval : null,
					server: server, readings: server ? activeReadings(replies[1], server) : null };
				showTiming();
			});
		}

		function updateControls() {
			var enabled = mode.value !== 'off';
			fields.hidden = candidateFields.hidden = !selected;
			fields.disabled = candidateFields.disabled = busy || !context || !canWrite;
			outbound.disabled = busy || !context || context.outbounds.length === 0;
			options.hidden = !enabled;
			windowRow.hidden = failureMethod.value !== 'window';
			schedule.hidden = mode.value !== 'scheduled';
			confirmation.hidden = !enabled || !canWrite;
			save.hidden = !canWrite;
			save.disabled = busy || !context || !selected || (enabled && !context.can_switch);
			refresh.disabled = busy;
			showSavedMode();
			showTiming();
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
					markEdited();
					showCandidateCount();
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
			showCandidateCount();
		}

		function showCandidateCount() {
			var chosen = draft().candidates;
			var missing = chosen.filter(function(key) { return !catalogue.has(key); }).length;
			count.textContent = _('Selected servers: %d').format(chosen.length);
			removeUnavailable.hidden = !missing || context.catalog_unavailable || !canWrite;
			if (missing && !context.catalog_unavailable)
				count.textContent += ' · ' + _('Unavailable: %d').format(missing);
		}

		function showOutbound() {
			selected = outbound.value;
			confirm.checked = false;
			search.value = '';
			if (selected) {
				session.setLocalData(outboundKey, selected);
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
			refreshTiming();
		}

		function populate(reply) {
			var requestedOutbound = selected || session.getLocalData(outboundKey);
			outbound.textContent = '';
			if (!validContext(reply)) {
				context = null;
				availability.textContent = '';
				showOutbound();
				message(errorText(reply, _('Could not load switching settings.')), true);
				return;
			}
			context = reply;
			catalogue = new Map();
			var ambiguous = new Set();
			reply.nodes.forEach(function(node) {
				if (catalogue.has(node.key)) {
					catalogue.delete(node.key);
					ambiguous.add(node.key);
				} else if (!ambiguous.has(node.key)) {
					catalogue.set(node.key, node);
				}
			});
			saved = new Map(reply.policies.map(function(policy) { return [policy.outbound, policy]; }));
			unverified.forEach(function(policy, name) {
				if (matchesSaved(policy, saved.get(name))) {
					dirty.delete(name);
					unverified.delete(name);
				}
			});
			drafts.forEach(function(policy, name) {
				if (!dirty.has(name))
					drafts.delete(name);
			});
			reply.outbounds.forEach(function(item) {
				outbound.appendChild(option(item.name, item.name));
			});
			if (reply.outbounds.some(function(item) { return item.name === requestedOutbound; }))
				outbound.value = requestedOutbound;
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
			dirty.add(selected);
			unverified.delete(selected);
			return perform(async function() {
				var reply = await savePolicy(policy);
				if (!reply || reply.ok !== true) {
					message(errorText(reply, _('Could not save switching settings.')), true);
					return;
				}
				unverified.set(policy.outbound, policy);
				var verified = await readContext().catch(function() { return null; });
				if (!validContext(verified)) {
					message(_('The router accepted the save. Refresh to verify the stored settings.'), true);
					return;
				}
				var stored = verified.policies.find(function(item) { return item.outbound === policy.outbound; });
				var confirmed = matchesSaved(policy, stored);
				populate(verified);
				if (confirmed)
					message(_('Saved %s: %s').format(policy.outbound, modeLabels[stored.mode]), false);
				else
					message(_('The settings read from the router differ from this draft.'), true);
			}, _('Could not confirm that the switching settings were saved.'));
		}

		outbound.addEventListener('change', function() {
			rememberInputs();
			showOutbound();
			message('', false);
		});
		mode.addEventListener('change', function() {
			confirm.checked = false;
			markEdited();
			rememberInputs();
			updateControls();
			message('', false);
		});
		failureMethod.addEventListener('change', function() {
			markEdited();
			rememberInputs();
			updateControls();
		});
		[failures, failureWindow, cooldown, latency, start, end].forEach(function(input) {
			input.addEventListener('input', function() {
				markEdited();
				rememberInputs();
				if (input === failures || input === failureWindow) showTiming();
			});
		});
		search.addEventListener('input', showCandidates);
		removeUnavailable.addEventListener('click', function() {
			if (!draft() || !canWrite || busy || !context || context.catalog_unavailable) return;
			draft().candidates = draft().candidates.filter(function(key) { return catalogue.has(key); });
			markEdited();
			showCandidates();
			message(_('Unavailable servers removed from this draft. Save to apply.'), false);
		});
		refresh.addEventListener('click', function() {
			rememberInputs();
			return perform(async function() {
				populate(await readContext());
			}, _('Could not refresh switching settings.'));
		});
		var root = E('div', { 'class': 'cbi-map' }, [
			E('h2', {}, [_('Server failover')]),
			availability,
			E('form', { 'submit': submit, 'novalidate': '' }, [
				row(_('Outbound'), outbound), fields,
				E('div', { 'class': 'cbi-page-actions' }, [refresh, ' ', save]),
				status, candidateFields
			])
		]);
		populate(initialContext);
		function pollTiming() {
			if (root.isConnected === false) {
				poll.remove(pollTiming);
				return Promise.resolve();
			}
			return refreshTiming();
		}
		poll.add(pollTiming, 30);
		return root;
	}
});
