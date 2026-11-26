'use strict';
'require view';
'require rpc';
'require poll';
'require dom';

var readHistory = rpc.declare({
	object: 'v2raya-helper',
	method: 'latency',
	params: ['outbound'],
	expect: { '': {} },
	reject: true
});

var palette = ['#3388d7', '#238b6c', '#ac620f', '#a958a5', '#698018', '#7964cf', '#bd5670', '#008497'];
var dashStyles = [[], [7, 3], [2, 3], [8, 2, 2, 2], [12, 4], [4, 4], [10, 2, 4, 2], [3, 2, 3, 5]];
var colors = { timeout: '#f05260', error: '#d84d5b' };
var states = ['ok', 'timeout', 'error'];

function option(value, label) {
	return E('option', { 'value': value }, [label]);
}

function sampleText(sample) {
	var role = sample.role === 'reserve' ? _('Reserve') : _('Assigned');
	var result = sample.state === 'ok' ? sample.ms + ' ' + _('ms') :
		(sample.state === 'timeout' ? _('Timeout') : _('Error'));
	return [sample.outbound, sample.server, role, result, new Date(sample.at * 1000).toLocaleString()].join(' · ');
}

function expandHistory(groups) {
	var samples = [];
	groups.forEach(function(group) {
		if (!group || typeof group.name !== 'string' || !Array.isArray(group.tracks) || !Array.isArray(group.points))
			return;
		group.points.forEach(function(point) {
			if (!Array.isArray(point) || !Number.isSafeInteger(point[0]) || point[0] <= 0 ||
				!Number.isInteger(point[1]) || !Number.isInteger(point[2]))
				return;
			var track = group.tracks[point[1]], state = states[point[2]];
			if (!Array.isArray(track) || typeof track[0] !== 'string' || typeof track[1] !== 'string' ||
				(track[2] !== 0 && track[2] !== 1) || !state ||
				(state === 'ok' && (!Number.isFinite(point[3]) || point[3] < 0)))
				return;
			samples.push({ outbound: group.name, at: point[0], server: track[0], series: track[1],
				role: track[2] === 1 ? 'reserve' : 'active', state: state, ms: point[3] });
		});
	});
	return samples.sort(function(a, b) { return a.at - b.at; });
}

function scaleStep(maximum) {
	var base = Math.pow(10, Math.floor(Math.log10(maximum / 4)));
	var ratio = maximum / (4 * base);
	return base * (ratio <= 1 ? 1 : ratio <= 2 ? 2 : ratio <= 5 ? 5 : 10);
}

function timeLabel(value, hours) {
	var date = new Date(value * 1000);
	return hours === 24 ? date.toLocaleString([], { day: 'numeric', hour: 'numeric', minute: '2-digit' }) :
		date.toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' });
}

function draw(canvas, samples, now, hours, pens) {
	var context = canvas.getContext('2d');
	if (!context)
		return [];

	var failures = new Map();
	samples.forEach(function(sample) {
		if (sample.state === 'ok')
			return;
		if (!failures.has(sample.outbound))
			failures.set(sample.outbound, { index: failures.size, timeout: false, error: false });
		failures.get(sample.outbound)[sample.state] = true;
	});
	var failureHeight = 30;
	var height = 270 + failures.size * failureHeight;
	canvas.style.height = height + 'px';
	var box = canvas.getBoundingClientRect();
	var width = Math.max(280, box.width || 720);
	var pixelRatio = Math.min(window.devicePixelRatio || 1, 3);
	canvas.width = Math.round(width * pixelRatio);
	canvas.height = Math.round(height * pixelRatio);
	context.setTransform(pixelRatio, 0, 0, pixelRatio, 0, 0);
	context.font = '12px sans-serif';
	var left = width < 520 ? 72 : 112, right = width - 12, top = 16, bottom = 230;
	var gridColor = window.getComputedStyle(canvas).color;
	var begin = now - hours * 3600, maximum = 20;
	samples.forEach(function(sample) {
		if (sample.state === 'ok')
			maximum = Math.max(maximum, sample.ms);
	});
	var step = scaleStep(maximum), ceiling = Math.ceil(maximum / step) * step;
	var stepX = (now - begin) / (width < 520 ? 2 : 4);
	var plotted = [];

	function x(at) {
		return left + (right - left) * (at - begin) / (now - begin);
	}
	function y(ms) {
		return bottom - (bottom - top) * ms / ceiling;
	}
	function line(x1, y1, x2, y2, color, opacity) {
		context.strokeStyle = color;
		context.globalAlpha = opacity;
		context.beginPath();
		context.moveTo(x1, y1);
		context.lineTo(x2, y2);
		context.stroke();
		context.globalAlpha = 1;
	}

	context.fillStyle = gridColor;
	context.textAlign = 'right';
	context.textBaseline = 'middle';
	for (var tick = 0; tick <= ceiling; tick += step) {
		line(left, y(tick), right, y(tick), gridColor, .16);
		context.fillText(tick + ' ' + _('ms'), left - 6, y(tick));
	}
	var firstFailure = bottom + 22;
	function failureY(sample) {
		var row = failures.get(sample.outbound);
		var center = firstFailure + row.index * failureHeight;
		return row.timeout && row.error ? center + (sample.state === 'timeout' ? -6 : 8) : center;
	}
	failures.forEach(function(row, name) {
		var at = firstFailure + row.index * failureHeight;
		context.fillStyle = row.timeout ? colors.timeout : gridColor;
		context.globalAlpha = .11;
		context.fillRect(left, at - 14, right - left, 28);
		context.globalAlpha = 1;
		context.fillStyle = gridColor;
		context.fillText(name, left - 6, at, left - 9);
	});
	context.fillStyle = gridColor;
	context.textBaseline = 'top';
	for (var at = begin; at <= now; at += stepX) {
		line(x(at), top, x(at), bottom + failures.size * failureHeight + 6, gridColor, .13);
		context.textAlign = at === begin ? 'left' : (at === now ? 'right' : 'center');
		context.fillText(timeLabel(at, hours), x(at), height - 21);
	}

	var previous = new Map();
	samples.forEach(function(sample) {
		var point = { sample: sample, x: x(sample.at), y: sample.state === 'ok' ? y(sample.ms) : failureY(sample) };
		plotted.push(point);
		if (sample.role !== 'active')
			return;
		if (!previous.has(sample.outbound))
			previous.set(sample.outbound, new Map());
		var series = previous.get(sample.outbound), last = series.get(sample.series);
		if (sample.state !== 'ok') {
			series.delete(sample.series);
			return;
		}
		if (last && sample.at - last.sample.at <= 300) {
			var pen = pens.get(sample.outbound);
			context.lineWidth = 1.6;
			context.setLineDash(pen.dash);
			line(last.x, last.y, point.x, point.y, pen.color, 1);
		}
		series.set(sample.series, point);
	});
	context.setLineDash([]);

	plotted.forEach(function(point) {
		var state = point.sample.state;
		var radius = point.sample.role === 'reserve' ? 4 : 2.5;
		context.lineWidth = 1.5;
		context.fillStyle = state === 'ok' ? pens.get(point.sample.outbound).color : colors[state];
		context.strokeStyle = context.fillStyle;
		context.beginPath();
		if (state === 'timeout') {
			context.moveTo(point.x, point.y - 8);
			context.lineTo(point.x + 8, point.y);
			context.lineTo(point.x, point.y + 8);
			context.lineTo(point.x - 8, point.y);
			context.closePath();
			context.fill();
		} else if (state === 'error') {
			context.moveTo(point.x - 4, point.y - 4);
			context.lineTo(point.x + 4, point.y + 4);
			context.moveTo(point.x + 4, point.y - 4);
			context.lineTo(point.x - 4, point.y + 4);
			context.stroke();
		} else {
			context.arc(point.x, point.y, radius, 0, 2 * Math.PI);
			if (point.sample.role === 'reserve')
				context.stroke();
			else
				context.fill();
		}
	});
	return plotted;
}

function legendItem(symbol, color, label) {
	return E('span', { 'style': 'display:inline-block;margin:0 1em .3em 0;white-space:nowrap' }, [
		E('span', { 'aria-hidden': 'true', 'style': 'color:' + color }, [symbol]), ' ', label
	]);
}

return view.extend({
	handleSave: null,
	handleSaveApply: null,
	handleReset: null,

	load: function() {
		return readHistory('').catch(function() { return null; });
	},

	render: function(initial) {
		var all = E('input', { 'type': 'checkbox' });
		var choices = E('div', { 'style': 'display:flex;gap:.4em 1em;flex-wrap:wrap' });
		var outboundsField = E('fieldset', { 'style': 'border:0;padding:0;margin:.75em 0 0;min-width:0' }, [
			E('legend', {}, [_('Outbounds')]), E('label', {}, [all, ' ', _('All outbounds')]), choices
		]);
		var range = E('select', { 'id': 'v2raya-latency-range', 'class': 'cbi-input-select' }, [
			option('1', _('Last hour')), option('6', _('Last 6 hours')), option('24', _('Last 24 hours'))
		]);
		var canvas = E('canvas', {
			'style': 'display:block;width:100%;height:300px', 'tabindex': '0', 'role': 'img',
			'aria-label': _('HTTPS latency chart. Use the arrow keys to review individual checks.')
		});
		var status = E('p', { 'role': 'status' });
		var detail = E('p', { 'style': 'min-height:1.5em;overflow-wrap:anywhere', 'aria-live': 'polite' });
		var timeoutCount = E('strong');
		var heading = E('div', { 'style': 'display:flex;gap:1em;flex-wrap:wrap;align-items:center' }, [
			E('label', { 'for': range.id }, [_('Time range')]), range
		]);
		var graph = E('figure', { 'style': 'margin:1em 0 0' }, [canvas, E('figcaption', {}, [
			legendItem('━', 'currentColor', _('Assigned server')),
			legendItem('○', 'currentColor', _('Reserve check')),
			legendItem('◆', colors.timeout, timeoutCount),
			legendItem('×', colors.error, _('Error'))
		]), detail]);
		var root = E('div', {}, [E('h2', {}, [_('HTTPS latency')]), heading, outboundsField, status, graph]);
		var outbounds = [], history = [], points = [], now = 0;
		var busy = false, loadProblem = false, selectedPoint = -1;
		var hidden = new Set(), pens = new Map(), boxes = new Map();

		function updateSelection() {
			var selected = 0;
			boxes.forEach(function(box, name) {
				box.checked = !hidden.has(name);
				if (box.checked) selected++;
			});
			all.disabled = !outbounds.length;
			all.checked = !!selected && selected === outbounds.length;
			all.indeterminate = !!selected && selected < outbounds.length;
		}

		function updateList(list) {
			var names = Array.from(new Set(list.filter(function(name) { return typeof name === 'string' && name; })));
			if (names.length === outbounds.length && names.every(function(name, index) { return name === outbounds[index]; }))
				return;
			outbounds = names;
			boxes.clear();
			dom.content(choices, names.map(function(name) {
				if (!pens.has(name)) {
					var index = pens.size;
					pens.set(name, { color: palette[index % palette.length],
						dash: dashStyles[Math.floor(index / palette.length) % dashStyles.length] });
				}
				var pen = pens.get(name);
				var box = E('input', { 'type': 'checkbox' });
				boxes.set(name, box);
				box.addEventListener('change', function() {
					if (box.checked) hidden.delete(name);
					else hidden.add(name);
					updateSelection();
					redraw();
				});
				return E('label', { 'style': 'display:inline-flex;gap:.35em;align-items:center;overflow-wrap:anywhere' }, [
					box, E('span', { 'aria-hidden': 'true', 'style': 'color:' + pen.color }, [pen.dash.length ? '┄' : '━']), name
				]);
			}));
			updateSelection();
		}

		function review(index) {
			selectedPoint = index;
			var sample = points[index] && points[index].sample;
			detail.textContent = sample ? sampleText(sample) :
				(points.length ? _('Latest check') + ' · ' + sampleText(points[points.length - 1].sample) : '');
		}

		function redraw() {
			var hours = Number(range.value), from = now - hours * 3600;
			var visible = history.filter(function(sample) {
				return boxes.has(sample.outbound) && !hidden.has(sample.outbound) && sample.at >= from && sample.at <= now;
			});
			timeoutCount.textContent = _('Timeout (%d)').format(visible.filter(function(sample) {
				return sample.state === 'timeout';
			}).length);
			graph.hidden = !visible.length;
			points = visible.length ? draw(canvas, visible, now, hours, pens) : [];
			review(-1);
			if (loadProblem)
				status.textContent = visible.length ? _('Unable to refresh the chart. Showing earlier checks.') :
					_('Unable to load latency history.');
			else if (!outbounds.length)
				status.textContent = _('No outbounds with recorded checks.');
			else if (!outbounds.some(function(name) { return !hidden.has(name); }))
				status.textContent = _('Select an outbound to show its checks.');
			else
				status.textContent = visible.length ? '' : _('No HTTPS checks in this time range.');
		}

		function receive(reply) {
			if (!reply || !Array.isArray(reply.outbounds) || !Number.isSafeInteger(reply.router_unix) || reply.router_unix <= 0)
				throw new Error();
			var groups = typeof reply.histories === 'string' ? JSON.parse(reply.histories) : reply.histories;
			if (!Array.isArray(groups)) throw new Error();
			history = expandHistory(groups);
			updateList(reply.outbounds);
			now = reply.router_unix;
			loadProblem = false;
			redraw();
		}

		function showLoadProblem() {
			loadProblem = true;
			redraw();
		}

		function refresh() {
			if (busy) return Promise.resolve();
			busy = true;
			return readHistory('').then(receive).catch(showLoadProblem).finally(function() {
				busy = false;
			});
		}

		all.addEventListener('change', function() {
			outbounds.forEach(function(name) {
				if (all.checked) hidden.delete(name);
				else hidden.add(name);
			});
			updateSelection();
			redraw();
		});
		range.addEventListener('change', redraw);
		canvas.addEventListener('pointermove', function(event) {
			var box = canvas.getBoundingClientRect(), closest = -1, distance = 16 * 16;
			points.forEach(function(point, index) {
				var dx = event.clientX - box.left - point.x, dy = event.clientY - box.top - point.y;
				var candidate = dx * dx + dy * dy;
				if (candidate < distance) { closest = index; distance = candidate; }
			});
			if (closest !== selectedPoint) review(closest);
		});
		canvas.addEventListener('pointerleave', function() { review(-1); });
		canvas.addEventListener('keydown', function(event) {
			if (!points.length || (event.key !== 'ArrowLeft' && event.key !== 'ArrowRight')) return;
			event.preventDefault();
			var index = selectedPoint < 0 ? points.length - 1 : selectedPoint + (event.key === 'ArrowLeft' ? -1 : 1);
			review(Math.max(0, Math.min(index, points.length - 1)));
		});

		updateSelection();
		try {
			receive(initial);
		} catch (error) {
			showLoadProblem();
		}
		var resize = typeof ResizeObserver === 'function' ? new ResizeObserver(redraw) : null;
		if (resize) resize.observe(canvas);
		function pollHistory() {
			if (root.isConnected === false) {
				if (resize) resize.disconnect();
				poll.remove(pollHistory);
				return Promise.resolve();
			}
			return refresh();
		}
		poll.add(pollHistory, 15);
		return root;
	}
});
