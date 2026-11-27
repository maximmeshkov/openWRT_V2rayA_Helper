'use strict';
'require view';
'require rpc';
'require uci';
'require ui';
'require v2raya-helper.menu as helperMenu';

var readEnvironment = rpc.declare({
	object: 'v2raya-helper',
	method: 'environment',
	expect: { '': {} }
});

/* Changes the helper may ask v2rayA to make; reading and HTTPS checks need no permission. */
var features = [
	['switch', _('Automatic server switching')],
	['routing_save', _('Saving RoutingA rules')],
	['core_start', _('Starting a crashed core')],
	['redirect_restore', _('Restoring the LAN REDIRECT rule')]
];

function duration(seconds) {
	if (!Number.isSafeInteger(seconds) || seconds < 0)
		return null;
	var days = Math.floor(seconds / 86400), hours = Math.floor(seconds % 86400 / 3600);
	var minutes = Math.floor(seconds % 3600 / 60);
	if (days) return _('%d d %d h').format(days, hours);
	if (hours) return _('%d h %d min').format(hours, minutes);
	return _('%d min').format(minutes);
}

function row(label, value) {
	return E('tr', { 'class': 'tr' }, [
		E('td', { 'class': 'td left', 'width': '33%' }, [label]),
		E('td', { 'class': 'td left' }, [value])
	]);
}

function badge(state) {
	var text = { verified: _('Verified'), opted_in: _('Allowed by you'), denied: _('Off') }[state] || _('Unknown');
	var color = { verified: 'success', opted_in: 'warning', denied: 'neutral' }[state] || 'neutral';
	return E('span', { 'class': 'label ' + color }, [text]);
}

return view.extend({
	handleSave: null,
	handleSaveApply: null,
	handleReset: null,

	load: function() {
		return Promise.all([readEnvironment().catch(function() { return null; }), uci.load('v2raya_helper')]);
	},

	setOptIn: function(version) {
		if (version)
			uci.set('v2raya_helper', 'main', 'allow_unverified', version);
		else
			uci.unset('v2raya_helper', 'main', 'allow_unverified');
		document.addEventListener('uci-applied', function() { window.location.reload(); }, { once: true });
		return uci.save().then(function() { return ui.changes.apply(true); });
	},

	render: function(data) {
		helperMenu.refresh();
		var env = data[0] || {}, canWrite = L.hasViewPermission() === true;
		var version = typeof env.version === 'string' ? env.version : null;
		var optedIn = uci.get('v2raya_helper', 'main', 'allow_unverified');
		var core = env.core && typeof env.core.binary === 'string' ? env.core : null;
		var age = core ? duration(core.age) : null;

		var facts = E('table', { 'class': 'table' }, [
			row(_('v2rayA'), version ? '%s · %s'.format(version, env.variant || _('unknown core')) :
				_('Not reachable. Check that v2rayA runs and the API address in the helper settings.')),
			row(_('Core'), core ? [E('code', {}, [core.binary]), ' · PID ' + core.pid,
				age ? ' · ' + _('running for %s').format(age) : ''] : _('No running core found')),
			row(_('Geo files'), core && core.assets ? E('code', {}, [core.assets]) : '—'),
			row(_('HTTPS through servers'), core ?
				_('SOCKS5 and HTTP proxies directly; every other protocol through a separate, short-lived copy of this core.') :
				_('SOCKS5 and HTTP proxies only, until the helper finds the core.')),
			row(_('Process check'), env.peer_check === true ? _('Available') : env.peer_check === false ?
				_('Needs libcurl 7.80 or newer: core start, LAN REDIRECT restore and login renewal stay off.') : '—')
		]);

		var denied = false;
		var list = E('table', { 'class': 'table' }, features.map(function(feature) {
			var decision = env.features && env.features[feature[0]] || {};
			if (decision.state === 'denied' && feature[0] !== 'redirect_restore')
				denied = true;
			var note = decision.state === 'verified' ? _('Verified for this v2rayA version.') :
				decision.state === 'opted_in' ? _('Allowed by you for v2rayA %s; not verified.').format(version) :
				decision.reason || _('v2rayA did not report its version.');
			return E('tr', { 'class': 'tr' }, [
				E('td', { 'class': 'td left', 'width': '33%' }, [feature[1]]),
				E('td', { 'class': 'td left', 'width': '15%' }, [badge(decision.state)]),
				E('td', { 'class': 'td left' }, [note])
			]);
		}));

		var actions = [];
		if (canWrite && version && optedIn === version)
			actions.push(E('button', { 'class': 'btn cbi-button cbi-button-neutral',
				'click': ui.createHandlerFn(this, 'setOptIn', null) }, [_('Withdraw permission')]));
		else if (canWrite && version && denied)
			actions.push(E('p', {}, [_('Allowing changes for an unverified version may fail or behave differently than in the verified builds. The permission names v2rayA %s only; an upgrade turns it off again.').format(version)]),
				E('button', { 'class': 'btn cbi-button cbi-button-negative',
					'click': ui.createHandlerFn(this, 'setOptIn', version) },
					[_('Allow changes for v2rayA %s at my own risk').format(version)]));

		return E('div', { 'class': 'cbi-map' }, [
			E('h2', {}, [_('Compatibility')]),
			E('p', { 'class': 'cbi-section-descr' }, [
				_('What this router runs and which changes the helper may make here. Monitoring and HTTPS checks never restart the core v2rayA runs.')
			]),
			E('div', { 'class': 'cbi-section' }, [E('h3', {}, [_('This router')]), facts]),
			E('div', { 'class': 'cbi-section' }, [E('h3', {}, [_('Changes the helper may make')]), list].concat(actions))
		]);
	}
});
