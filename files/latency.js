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

var colors = { active: '#3989d7', reserve: '#209875', timeout: '#d77818', error: '#d84d5b' };

function option(value, label) {
	return E('option', { 'value': value }, [label]);
}

function sampleText(sample) {
	var role = sample.role === 'reserve' ? _('Reserve') : _('Assigned');
	var result = sample.state === 'ok' ? sample.ms + ' ' + _('ms') :
		(sample.state === 'timeout' ? _('Timeout') : _('Error'));
	return [new Date(sample.at * 1000).toLocaleString(), role, sample.server, result].join(' · ');
}

function validSample(sample) {
	return sample && Number.isSafeInteger(sample.at) && sample.at > 0 &&
		(sample.role === 'active' || sample.role === 'reserve') &&
		typeof sample.server === 'string' && typeof sample.series === 'string' &&
		(sample.state === 'timeout' || sample.state === 'error' ||
			(sample.state === 'ok' && Number.isFinite(sample.ms) && sample.ms >= 0));
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

function draw(canvas, samples, now, hours) {
	var context = canvas.getContext('2d');
	if (!context)
		return [];

	var box = canvas.getBoundingClientRect();
	var width = Math.max(280, box.width || 720), height = box.height || 300;
	var pixelRatio = Math.min(window.devicePixelRatio || 1, 3);
	canvas.width = Math.round(width * pixelRatio);
	canvas.height = Math.round(height * pixelRatio);
	context.setTransform(pixelRatio, 0, 0, pixelRatio, 0, 0);
	context.font = '12px sans-serif';
	var left = 72, right = width - 12, top = 16, bottom = height - 66;
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
	var track = bottom + 22;
	line(left, track, right, track, gridColor, .16);
	context.fillText(_('Failures'), left - 6, track, left - 9);
	context.textBaseline = 'top';
	for (var at = begin; at <= now; at += stepX) {
		line(x(at), top, x(at), track + 7, gridColor, .13);
		context.textAlign = at === begin ? 'left' : (at === now ? 'right' : 'center');
		context.fillText(timeLabel(at, hours), x(at), height - 21);
	}

	var previousActive = null;
	samples.forEach(function(sample) {
		var point = { sample: sample, x: x(sample.at), y: sample.state === 'ok' ? y(sample.ms) : track };
		plotted.push(point);
		if (sample.role === 'active') {
			if (previousActive && sample.state === 'ok' && previousActive.sample.series === sample.series &&
				sample.at - previousActive.sample.at <= 300) {
				context.lineWidth = 1.5;
				line(previousActive.x, previousActive.y, point.x, point.y, colors.active, 1);
			}
			previousActive = sample.state === 'ok' ? point : null;
		}
	});

	plotted.forEach(function(point) {
		var state = point.sample.state;
		var radius = point.sample.role === 'reserve' ? 4 : 2.5;
		context.lineWidth = 1.5;
		context.fillStyle = state === 'ok' ? colors[point.sample.role] : colors[state];
		context.strokeStyle = context.fillStyle;
		context.beginPath();
		if (state === 'timeout') {
			context.moveTo(point.x, point.y - 5);
			context.lineTo(point.x + 5, point.y);
			context.lineTo(point.x, point.y + 5);
			context.lineTo(point.x - 5, point.y);
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
		var outbound = E('select', { 'id': 'v2raya-latency-outbound', 'class': 'cbi-input-select' });
		var range = E('select', { 'id': 'v2raya-latency-range', 'class': 'cbi-input-select' }, [
			option('1', _('Last hour')), option('6', _('Last 6 hours')), option('24', _('Last 24 hours'))
		]);
		var canvas = E('canvas', {
			'style': 'display:block;width:100%;height:300px', 'tabindex': '0', 'role': 'img',
			'aria-label': _('HTTPS latency chart. Use the arrow keys to review individual checks.')
		});
		var status = E('p', { 'role': 'status' });
		var detail = E('p', { 'style': 'min-height:1.5em;overflow-wrap:anywhere', 'aria-live': 'polite' });
		var heading = E('div', { 'style': 'display:flex;gap:1em;flex-wrap:wrap;align-items:center' }, [
			E('label', { 'for': outbound.id }, [_('Outbound')]), outbound,
			E('label', { 'for': range.id }, [_('Time range')]), range
		]);
		var graph = E('figure', { 'style': 'margin:1em 0 0' }, [canvas, E('figcaption', {}, [
			legendItem('━', colors.active, _('Assigned server')),
			legendItem('●', colors.reserve, _('Reserve check')),
			legendItem('◆', colors.timeout, _('Timeout')),
			legendItem('×', colors.error, _('Error'))
		]), detail]);
		var root = E('div', {}, [E('h2', {}, [_('HTTPS latency')]), heading, status, graph]);
		var outbounds = [], history = [], points = [], now = 0;
		var requestId = 0, busy = false, selectedPoint = -1, visiblePoints = [];

		function updateList(list) {
			if (!Array.isArray(list)) return;
			var names = Array.from(new Set(list.filter(function(name) { return typeof name === 'string' && name; })));
			if (names.join('\n') === outbounds.join('\n') && outbound.options.length) return;
			var selected = outbound.value;
			outbounds = names;
			dom.content(outbound, names.length ? names.map(function(name) { return option(name, name); }) :
				[option('', _('No outbounds'))]);
			outbound.disabled = !names.length;
			outbound.value = names.includes(selected) ? selected : (names[0] || '');
		}

		function review(index) {
			selectedPoint = index;
			var sample = points[index] && points[index].sample;
			detail.textContent = sample ? sampleText(sample) :
				(visiblePoints.length ? _('Latest check') + ' · ' + sampleText(visiblePoints[visiblePoints.length - 1]) : '');
		}

		function redraw() {
			var from = now - Number(range.value) * 3600;
			visiblePoints = history.filter(function(sample) { return sample.at >= from && sample.at <= now; });
			graph.hidden = !visiblePoints.length;
			if (visiblePoints.length)
				points = draw(canvas, visiblePoints, now, Number(range.value));
			else
				points = [];
			review(-1);
		}

		function refresh(force) {
			if (busy && force !== true) return Promise.resolve();
			var requested = outbound.value, id = ++requestId;
			busy = true;
			return readHistory(requested).then(function(reply) {
				if (id !== requestId) return;
				busy = false;
				if (!reply || !Array.isArray(reply.samples) || !Number.isSafeInteger(reply.router_unix) || reply.router_unix <= 0)
					throw new Error();
				updateList(reply.outbounds);
				if (outbound.value !== requested) return refresh(true);
				now = reply.router_unix;
				history = reply.samples.filter(validSample).sort(function(a, b) { return a.at - b.at; });
				redraw();
				status.textContent = visiblePoints.length ? '' :
					(requested ? _('No HTTPS checks in this time range.') : _('No outbounds available.'));
			}).catch(function() {
				if (id !== requestId) return;
				busy = false;
				status.textContent = history.length ? _('Unable to refresh the chart. Showing earlier checks.') :
					_('Unable to load latency history.');
			});
		}

		outbound.addEventListener('change', function() {
			history = [];
			redraw();
			status.textContent = _('Loading latency history…');
			refresh(true);
		});
		range.addEventListener('change', function() {
			redraw();
			status.textContent = visiblePoints.length ? '' : _('No HTTPS checks in this time range.');
		});
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

		updateList(initial && initial.outbounds);
		status.textContent = _('Loading latency history…');
		graph.hidden = true;
		var resize = typeof ResizeObserver === 'function' ? new ResizeObserver(redraw) : null;
		if (resize) resize.observe(canvas);
		refresh(true);
		function pollHistory() {
			if (root.isConnected === false) {
				if (resize) resize.disconnect();
				poll.remove(pollHistory);
				return Promise.resolve();
			}
			return refresh(false);
		}
		poll.add(pollHistory, 15);
		return root;
	}
});
