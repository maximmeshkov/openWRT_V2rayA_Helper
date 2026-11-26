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
	switch (result.state) {
	case 'ok':
		if (route) label = _('HTTP response');
		else if (result.detail === 'local_tcp') label = _('Local port open');
		else if (result.detail === 'local_quic') label = _('Local QUIC response');
		else if (result.detail === 'quic') label = _('QUIC response');
		else label = _('TCP connected');
		if (Number.isFinite(result.ms))
			label += ' · ' + result.ms + ' ' + _('ms');
		style = 'success';
		break;
	case 'failed':      label = _('Request failed'); style = 'danger'; break;
	case 'timeout':     label = _('Timed out'); style = 'warning'; break;
	case 'refused':     label = _('Connection refused'); style = 'danger'; break;
	case 'error':       label = _('Probe error'); style = 'warning'; break;
	case 'unsupported': label = _('Unsupported probe'); break;
	case 'pending':     label = _('Checking…'); break;
	default:            label = _('No measurement'); break;
	}
	return E('span', { 'class': style ? 'label ' + style : '', 'title': result.detail || '' }, [label]);
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

		var headings = [_('Outbound'), _('Server'), _('To server'), _('Through outbound')];
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
				if (index === 0)
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
