include $(TOPDIR)/rules.mk

PKG_NAME:=v2raya-helper
PKG_VERSION:=0.1.0
PKG_RELEASE:=50

# LuCI's asset version follows luci-base. Give these views package-specific URLs.
VIEW_VERSION:=$(subst .,-,$(PKG_VERSION))-$(PKG_RELEASE)
ROUTINGA_VIEW:=routinga-$(VIEW_VERSION)
FAILOVER_VIEW:=failover-$(VIEW_VERSION)
LATENCY_VIEW:=latency-$(VIEW_VERSION)
GEODATA_VIEW:=geodata-$(VIEW_VERSION)

include $(INCLUDE_DIR)/package.mk

define Package/v2raya-helper
  SECTION:=net
  CATEGORY:=Network
  TITLE:=Background monitor for v2rayA outbounds
  DEPENDS:=+libcurl +libjson-c +ca-bundle +rpcd
  URL:=https://github.com/maximmeshkov/openWRT_V2rayA_Helper
endef

define Package/luci-app-v2raya-helper
  SECTION:=luci
  CATEGORY:=LuCI
  SUBMENU:=3. Applications
  TITLE:=LuCI overview of v2rayA outbounds
  DEPENDS:=+luci-mod-status +v2raya-helper
  PKGARCH:=all
endef

define Package/v2raya-helper/conffiles
/etc/config/v2raya_helper
endef

define Build/Prepare
	$(INSTALL_DIR) $(PKG_BUILD_DIR)
	$(CP) ./src/. $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(TARGET_CC) $(TARGET_CPPFLAGS) $(TARGET_CFLAGS) -std=gnu11 \
		-o $(PKG_BUILD_DIR)/v2raya-helper $(PKG_BUILD_DIR)/*.c \
		$(TARGET_LDFLAGS) -lcurl -ljson-c
endef

define Package/v2raya-helper/install
	$(INSTALL_DIR) $(1)/usr/bin $(1)/etc/init.d $(1)/etc/config
	$(INSTALL_DIR) $(1)/usr/libexec/rpcd $(1)/usr/share/rpcd/acl.d
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/v2raya-helper $(1)/usr/bin/
	$(INSTALL_BIN) ./files/v2raya-helper.init $(1)/etc/init.d/v2raya-helper
	$(INSTALL_CONF) ./files/v2raya_helper.config $(1)/etc/config/v2raya_helper
	$(INSTALL_BIN) ./files/v2raya-helper.rpc $(1)/usr/libexec/rpcd/v2raya-helper
	$(INSTALL_BIN) ./files/v2raya-helper-geodata $(1)/usr/libexec/
	$(INSTALL_DATA) ./files/v2raya-helper.acl.json $(1)/usr/share/rpcd/acl.d/v2raya-helper.json
endef

define Package/v2raya-helper/postinst
#!/bin/sh
if [ -z "$${IPKG_INSTROOT}" ]; then
	methods="$$(ubus -v list v2raya-helper 2>/dev/null)"
	if ! printf '%s\n' "$$methods" | grep -q '"latency"' ||
	   ! printf '%s\n' "$$methods" | grep -q '"geodata_start"'; then
		/etc/init.d/rpcd reload
	fi
fi
endef

define Package/luci-app-v2raya-helper/install
	$(INSTALL_DIR) $(1)/www/luci-static/resources/view/status/include
	$(INSTALL_DIR) $(1)/www/luci-static/resources/view/v2raya-helper $(1)/usr/share/luci/menu.d
	$(INSTALL_DIR) $(1)/www/luci-static/resources/v2raya-helper
	$(INSTALL_DATA) ./files/helper-menu.js $(1)/www/luci-static/resources/v2raya-helper/menu.js
	$(INSTALL_DATA) ./files/29_v2raya_helper.js $(1)/www/luci-static/resources/view/status/include/
	$(INSTALL_DATA) ./files/routinga.js $(1)/www/luci-static/resources/view/v2raya-helper/$(ROUTINGA_VIEW).js
	$(INSTALL_DATA) ./files/failover.js $(1)/www/luci-static/resources/view/v2raya-helper/$(FAILOVER_VIEW).js
	$(INSTALL_DATA) ./files/latency.js $(1)/www/luci-static/resources/view/v2raya-helper/$(LATENCY_VIEW).js
	$(INSTALL_DATA) ./files/geodata.js $(1)/www/luci-static/resources/view/v2raya-helper/$(GEODATA_VIEW).js
	$(INSTALL_DATA) ./files/v2raya-helper.menu.json $(1)/usr/share/luci/menu.d/v2raya-helper.json
	$(SED) 's|"path": "v2raya-helper/routinga"|"path": "v2raya-helper/$(ROUTINGA_VIEW)"|' $(1)/usr/share/luci/menu.d/v2raya-helper.json
	$(SED) 's|"path": "v2raya-helper/failover"|"path": "v2raya-helper/$(FAILOVER_VIEW)"|' $(1)/usr/share/luci/menu.d/v2raya-helper.json
	$(SED) 's|"path": "v2raya-helper/latency"|"path": "v2raya-helper/$(LATENCY_VIEW)"|' $(1)/usr/share/luci/menu.d/v2raya-helper.json
	$(SED) 's|"path": "v2raya-helper/geodata"|"path": "v2raya-helper/$(GEODATA_VIEW)"|' $(1)/usr/share/luci/menu.d/v2raya-helper.json
endef

define Package/luci-app-v2raya-helper/postinst
#!/bin/sh
if [ -z "$${IPKG_INSTROOT}" ]; then
	rm -f /tmp/luci-indexcache.*.json
fi
endef

$(eval $(call BuildPackage,v2raya-helper))
$(eval $(call BuildPackage,luci-app-v2raya-helper))
