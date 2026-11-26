'use strict';
'require view';
'require rpc';
'require poll';
'require v2raya-helper.menu as helperMenu';

var readStatus = rpc.declare({
	object: 'v2raya-helper',
	method: 'geodata_status',
	expect: { '': {} },
	reject: true
});
var startOperation = rpc.declare({
	object: 'v2raya-helper',
	method: 'geodata_start',
	params: ['action'],
	expect: { '': {} },
	reject: true
});

function validStatus(reply) {
	return reply && ['idle', 'running', 'ok', 'error'].includes(reply.state);
}

function statusMessage(reply) {
	if (typeof reply.message === 'string' && reply.message)
		return reply.message;
	switch (reply.state) {
	case 'running': return _('GeoData operation in progress…');
	case 'ok': return reply.action === 'restore' ? _('Previous GeoData restored.') : _('GeoData updated.');
	case 'error': return _('GeoData operation failed.');
	default: return _('No GeoData operation is running.');
	}
}

return view.extend({
	handleSave: null,
	handleSaveApply: null,
	handleReset: null,

	load: function() {
		helperMenu.refresh();
		return readStatus().catch(function() { return null; });
	},

	render: function(initialStatus) {
		var canWrite = L.hasViewPermission() === true;
		var current = validStatus(initialStatus) ? initialStatus : null;
		var starting = false;
		var status = E('p', { 'id': 'geodata-status', 'role': 'status' });
		var update = E('button', {
			'id': 'geodata-update', 'type': 'button', 'class': 'btn cbi-button cbi-button-action'
		}, [_('Update geodata')]);
		var restore = E('button', {
			'id': 'geodata-restore', 'type': 'button', 'class': 'btn cbi-button cbi-button-neutral'
		}, [_('Restore previous geodata')]);
		var actions = E('div', { 'class': 'cbi-page-actions', 'hidden': canWrite ? null : '' }, [update, ' ', restore]);
		var root = E('div', { 'class': 'cbi-map' }, [
			E('h2', {}, [_('GeoData')]),
			E('p', { 'class': 'cbi-section-descr' }, [
				_('Xray reads the selected files at its next normal restart. Updating or restoring GeoData leaves the running Xray process in place.')
			]),
			actions, status
		]);

		function updateControls() {
			update.disabled = !canWrite || starting || !current || current.state === 'running';
			restore.disabled = update.disabled || current.can_restore !== true;
		}

		function showStatus() {
			status.textContent = current ? statusMessage(current) : _('Could not read GeoData status.');
			updateControls();
		}

		async function checkStatus() {
			if (!root.isConnected) {
				poll.remove(checkStatus);
				return;
			}
			var reply = await readStatus().catch(function() { return null; });
			if (!validStatus(reply)) {
				status.textContent = _('Could not read GeoData status. Retrying…');
				return;
			}
			current = reply;
			showStatus();
			if (current.state !== 'running') poll.remove(checkStatus);
		}

		async function runAction(action) {
			if (action === 'update' ? update.disabled : restore.disabled) return;
			starting = true;
			status.textContent = _('Starting GeoData operation…');
			updateControls();
			try {
				var reply = await startOperation(action);
				if (!reply || reply.ok !== true) {
					status.textContent = reply && typeof reply.error === 'string' && reply.error || _('Could not start the GeoData operation.');
					return;
				}
				current = { state: 'running' };
				showStatus();
				poll.add(checkStatus, 2);
			} catch (error) {
				var refreshed = await readStatus().catch(function() { return null; });
				current = validStatus(refreshed) ? refreshed : null;
				if (current && current.state === 'running') {
					showStatus();
					poll.add(checkStatus, 2);
				} else {
					status.textContent = _('Could not confirm that the GeoData operation started.');
				}
			} finally {
				starting = false;
				updateControls();
			}
		}

		update.addEventListener('click', function() { runAction('update'); });
		restore.addEventListener('click', function() { runAction('restore'); });
		showStatus();
		if (current && current.state === 'running') {
			window.setTimeout(function() {
				if (root.isConnected) poll.add(checkStatus, 2);
			}, 0);
		}
		return root;
	}
});
