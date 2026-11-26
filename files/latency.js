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
var colors = { timeout: '#ef5362', error: '#df7847' };
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

function chartIsDark(canvas) {
	var surface = canvas.isConnected ? canvas.parentElement : document.body;
	for (var element = surface; element; element = element.parentElement) {
		var background = window.getComputedStyle(element).backgroundColor;
		var rgb = /^rgba?\((\d+),\s*(\d+),\s*(\d+)(?:,\s*1(?:\.0+)?)?\)$/.exec(background);
		if (rgb) return .2126 * rgb[1] + .7152 * rgb[2] + .0722 * rgb[3] < 128;
	}
	var scheme = document.documentElement.getAttribute('data-darkmode');
	return scheme == null ? window.matchMedia('(prefers-color-scheme: dark)').matches : scheme === 'true';
}

function draw(canvas, samples, now, hours, pens) {
	var context = canvas.getContext('2d');
	if (!context)
		return { points: [], events: [] };
	var height = 285;
	var box = canvas.getBoundingClientRect();
	var width = Math.max(280, box.width || 720);
	var pixelRatio = Math.min(window.devicePixelRatio || 1, 3);
	canvas.width = Math.round(width * pixelRatio);
	canvas.height = Math.round(height * pixelRatio);
	context.setTransform(pixelRatio, 0, 0, pixelRatio, 0, 0);
	context.font = '12px sans-serif';
	var left = width < 520 ? 71 : 86, right = width - 14, top = 18, bottom = 247;
	var dark = chartIsDark(canvas), gridColor = dark ? '#e0e0e0' : '#333333';
	context.fillStyle = dark ? '#222222' : '#ffffff';
	context.fillRect(0, 0, width, height);
	var begin = now - hours * 3600, maximum = 20;
	samples.forEach(function(sample) {
		if (sample.state === 'ok')
			maximum = Math.max(maximum, sample.ms);
	});
	var step = scaleStep(maximum), ceiling = Math.ceil(maximum / step) * step;
	var stepX = (now - begin) / (width < 520 ? 2 : 4);
	var plotted = [], events = [];

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
		line(left, y(tick), right, y(tick), gridColor, .24);
		context.fillText(tick + ' ' + _('ms'), left - 15, y(tick));
	}
	context.textBaseline = 'top';
	for (var at = begin; at <= now; at += stepX) {
		line(x(at), top, x(at), bottom, gridColor, .18);
		context.textAlign = at === begin ? 'left' : (at === now ? 'right' : 'center');
		context.fillText(timeLabel(at, hours), x(at), height - 21);
	}

	var previous = new Map();
	samples.forEach(function(sample) {
		var point = { sample: sample, x: x(sample.at), y: sample.state === 'ok' ? y(sample.ms) : top };
		plotted.push(point);
		if (sample.state !== 'ok') {
			var event = events[events.length - 1];
			if (!event || point.x - event.x >= 26) {
				event = { x: point.x, y: top, samples: [], timeout: false };
				events.push(event);
			}
			event.samples.push(sample);
			if (sample.state === 'timeout') event.timeout = true;
		}
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
		if (point.sample.state !== 'ok') return;
		var radius = point.sample.role === 'reserve' ? 4 : 2.5;
		context.lineWidth = 1.5;
		context.fillStyle = pens.get(point.sample.outbound).color;
		context.strokeStyle = context.fillStyle;
		context.beginPath();
		context.arc(point.x, point.y, radius, 0, 2 * Math.PI);
		if (point.sample.role === 'reserve') context.stroke();
		else context.fill();
	});
	context.font = 'bold 10px sans-serif';
	context.textAlign = 'center';
	context.textBaseline = 'middle';
	context.lineWidth = 2;
	events.forEach(function(event) {
		var count = event.samples.length, px = event.x, py = event.y;
		context.fillStyle = context.strokeStyle = event.timeout ? colors.timeout : colors.error;
		context.beginPath();
		if (count > 1) {
			context.fillRect(px - 12, py - 8, 24, 16);
			context.fillStyle = '#171717';
			context.fillText(count > 99 ? '99+' : count, px, py);
		} else if (event.timeout) {
			context.moveTo(px, py - 8);
			context.lineTo(px + 8, py);
			context.lineTo(px, py + 8);
			context.lineTo(px - 8, py);
			context.closePath();
			context.fill();
		} else {
			context.moveTo(px - 5, py - 5);
			context.lineTo(px + 5, py + 5);
			context.moveTo(px + 5, py - 5);
			context.lineTo(px - 5, py + 5);
			context.stroke();
		}
	});
	return { points: plotted, events: events };
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
			'style': 'display:block;width:100%;height:285px', 'tabindex': '0', 'role': 'img',
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
		var outbounds = [], history = [], points = [], events = [], now = 0;
		var busy = false, loadProblem = false, selectedPoint = -1;
		var selectedEvent = null;
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
			selectedEvent = null;
			var sample = points[index] && points[index].sample;
			detail.textContent = sample ? sampleText(sample) :
				(points.length ? _('Latest check') + ' · ' + sampleText(points[points.length - 1].sample) : '');
		}

		function reviewEvent(event) {
			if (event === selectedEvent) return;
			selectedEvent = event;
			selectedPoint = -1;
			if (event.samples.length === 1) {
				detail.textContent = sampleText(event.samples[0]);
				return;
			}
			var affected = new Set(event.samples.map(function(sample) {
				return sample.outbound + ' · ' + (sample.state === 'timeout' ? _('Timeout') : _('Error'));
			}));
			var first = event.samples[0].at, last = event.samples[event.samples.length - 1].at;
			var time = new Date(first * 1000).toLocaleTimeString();
			if (last !== first) time += ' – ' + new Date(last * 1000).toLocaleTimeString();
			detail.textContent = [_('%d failed checks').format(event.samples.length),
				time, Array.from(affected).join(', ')].join(' · ');
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
			var frame = visible.length ? draw(canvas, visible, now, hours, pens) : { points: [], events: [] };
			points = frame.points;
			events = frame.events;
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
		function reviewPointer(event) {
			var box = canvas.getBoundingClientRect(), closest = -1, distance = 16 * 16;
			var x = event.clientX - box.left, y = event.clientY - box.top;
			if (events.length && Math.abs(y - events[0].y) <= 10) {
				var marker = events.find(function(candidate) { return Math.abs(x - candidate.x) <= 13; });
				if (marker) {
					reviewEvent(marker);
					return;
				}
			}
			points.forEach(function(point, index) {
				if (point.sample.state !== 'ok') return;
				var dx = x - point.x, dy = y - point.y;
				var candidate = dx * dx + dy * dy;
				if (candidate < distance) { closest = index; distance = candidate; }
			});
			if (selectedEvent || closest !== selectedPoint) review(closest);
		}
		canvas.addEventListener('pointermove', reviewPointer);
		canvas.addEventListener('click', reviewPointer);
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
