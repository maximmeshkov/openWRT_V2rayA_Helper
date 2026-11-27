'use strict';
'require baseclass';
'require request';
'require session';
'require ui';

var pages = ['compatibility', 'routinga', 'failover', 'latency', 'geodata'];
var refreshKey = 'v2raya-helper-menu-refreshed';
var checked = false;

function visiblePages(tree) {
	var node = tree;
	['admin', 'services', 'v2raya-helper'].forEach(function(name) {
		node = node && node.children && node.children[name];
	});
	if (!node || !node.satisfied || !node.children)
		return [];
	return pages.filter(function(name) { return node.children[name] && node.children[name].satisfied; });
}

return baseclass.extend({
	refresh: function() {
		if (checked || !ui.menu || typeof ui.menu.flushCache !== 'function')
			return;
		checked = true;
		return ui.menu.load().then(function(tree) {
			var cached = visiblePages(tree);
			if (cached.length === pages.length) {
				session.setLocalData(refreshKey, null);
				return;
			}
			return request.get(L.url('admin/menu')).then(function(reply) {
				var current = visiblePages(reply.json());
				var missing = current.filter(function(name) { return cached.indexOf(name) < 0; });
				var signature = cached.join(',') + '→' + current.join(',');
				if (missing.length && session.getLocalData(refreshKey) !== signature &&
				    session.setLocalData(refreshKey, signature)) {
					ui.menu.flushCache();
					window.location.reload();
				}
			});
		}).catch(function() {});
	}
});
