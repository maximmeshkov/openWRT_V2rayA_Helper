'use strict';
'require baseclass';
'require rpc';

var readStatus = rpc.declare({
	object: 'v2raya-helper',
	method: 'status',
	expect: { '': {} },
	reject: true
});

function textCell(label, value, span) {
	return E('td', { 'class': 'td', 'data-title': label, 'rowspan': span || 1 }, [value]);
}

function reading(result, route) {
	result = result || {};
	var label;
	var style;
	var active = route && result.source === 'node_https';
	var http = active && Number.isInteger(result.http_code) &&
		result.http_code >= 100 && result.http_code <= 599;
	var title = result.detail || '';
	if (active)
		title = [_('HTTPS check'), result.target, result.detail,
			result.tls_client === 'libcurl' ? _('Helper uses its own TLS client') : null].filter(Boolean).join(' · ');
	else if (route && result.detail === 'observatory_http')
		title = _('Xray Observatory');
	switch (result.state) {
	case 'ok':
		if (route) label = http ? 'HTTP ' + result.http_code : _('HTTP response');
		else if (result.detail === 'local_tcp') label = _('Local port open');
		else if (result.detail === 'local_quic') label = _('Local QUIC response');
		else if (result.detail === 'quic') label = _('QUIC response');
		else label = _('TCP connected');
		style = 'success';
		break;
	case 'failed':      label = _('Request failed'); style = 'danger'; break;
	case 'timeout':     label = _('Timed out'); style = 'warning'; break;
	case 'refused':     label = _('Connection refused'); style = 'danger'; break;
	case 'error':
		if (http) label = 'HTTP ' + result.http_code;
		else if (active && result.detail === 'https_tls_error') label = _('TLS error');
		else if (active && result.detail === 'https_timeout') label = _('Timed out');
		else if (active && result.detail === 'https_proxy_error') label = _('Proxy connection failed');
		else if (active && result.detail === 'https_connect_error') label = _('Connection failed');
		else label = _('Probe error');
		style = 'warning';
		break;
	case 'unsupported': label = _('Unsupported probe'); break;
	case 'pending':     label = _('Checking…'); break;
	default:            label = _('No measurement'); break;
	}
	if ((result.state === 'ok' || (http && result.state === 'error')) && Number.isFinite(result.ms))
		label += ' · ' + result.ms + ' ' + _('ms');
	return E('span', { 'class': style ? 'label ' + style : '', 'title': title }, [label]);
}

return baseclass.extend({
	title: _('v2rayA outbounds'),

	load: function() {
		// A transient rpcd error must not make LuCI drop the include from later polls.
		return readStatus().catch(function() { return {}; });
	},

	render: function(reply) {
		var snapshot = reply && reply.snapshot;
		if (!snapshot)
			return E('p', {}, [_('Monitor status unavailable')]);

		var deadline = Date.parse(snapshot.fresh_until);
		var inTime = Number.isFinite(deadline) && Number.isFinite(reply.router_unix) &&
			reply.router_unix * 1000 < deadline;
		var fresh = snapshot.state === 'ok' && inTime;
		var items = Array.isArray(snapshot.outbounds) ? snapshot.outbounds : [];
		var content = E('div');
		if (!fresh) {
			var notices = {
				starting: _('Waiting for the first reading'),
				stopped: _('v2rayA stopped or paused')
			};
			var waiting = snapshot.state === 'starting' && !snapshot.fresh_until;
			var notice = (inTime || waiting) && notices[snapshot.state] || _('Monitoring data is stale');
			content.appendChild(E('p', {}, [snapshot.message ? notice + ' · ' + snapshot.message : notice]));
		}
		if (!items.length) {
			if (fresh)
				content.appendChild(E('p', {}, [_('No outbounds')]));
			return content;
		}

		var nodes = items.some(function(row) {
			return (row.members || []).some(function(member) { return !!member.https; });
		});
		var headings = [_('Outbound'), _('Server'), _('To server'), nodes ? _('HTTPS via server') : _('Through outbound')];
		var table = E('table', { 'class': 'table' }, [
			E('thead', {}, [E('tr', { 'class': 'tr table-titles' }, headings.map(function(label) {
				return E('th', { 'class': 'th', 'scope': 'col' }, [label]);
			}))])
		]);
		var rows = E('tbody');
		items.forEach(function(outbound) {
			var members = Array.isArray(outbound.members) && outbound.members.length ? outbound.members : [null];
			members.forEach(function(member, index) {
				var cells = [];
				if (index === 0)
					cells.push(textCell(headings[0], outbound.name, members.length));
				var name = member ? member.name || member.address : _('No server selected');
				if (member && member.selected && members.length > 1)
					name += ' · ' + _('Selected');
				cells.push(textCell(headings[1], name));
				cells.push(textCell(headings[2], fresh && member ?
					reading(member.server, false) : '—'));
				if (nodes)
					cells.push(textCell(headings[3], fresh && member ? reading(member.https, true) : '—'));
				else if (index === 0)
					cells.push(textCell(headings[3], fresh && member ?
						reading(outbound.route, true) : '—', members.length));
				rows.appendChild(E('tr', { 'class': 'tr' }, cells));
			});
		});
		table.appendChild(rows);
		content.appendChild(table);
		return content;
	}
});
