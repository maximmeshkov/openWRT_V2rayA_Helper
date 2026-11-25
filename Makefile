include $(TOPDIR)/rules.mk

PKG_NAME:=v2raya-helper
PKG_VERSION:=0.1.0
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/v2raya-helper
  SECTION:=net
  CATEGORY:=Network
  TITLE:=Background monitor for v2rayA outbounds
  DEPENDS:=+libcurl +libjson-c +libpthread +ca-bundle +rpcd
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
	$(TARGET_CC) $(TARGET_CPPFLAGS) $(TARGET_CFLAGS) -std=gnu11 -pthread \
		-o $(PKG_BUILD_DIR)/v2raya-helper $(PKG_BUILD_DIR)/*.c \
		$(TARGET_LDFLAGS) -lcurl -ljson-c -pthread
endef

define Package/v2raya-helper/install
	$(INSTALL_DIR) $(1)/usr/bin $(1)/etc/init.d $(1)/etc/config
	$(INSTALL_DIR) $(1)/usr/libexec/rpcd $(1)/usr/share/rpcd/acl.d
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/v2raya-helper $(1)/usr/bin/
	$(INSTALL_BIN) ./files/v2raya-helper.init $(1)/etc/init.d/v2raya-helper
	$(INSTALL_CONF) ./files/v2raya_helper.config $(1)/etc/config/v2raya_helper
	$(INSTALL_BIN) ./files/v2raya-helper.rpc $(1)/usr/libexec/rpcd/v2raya-helper
	$(INSTALL_DATA) ./files/v2raya-helper.acl.json $(1)/usr/share/rpcd/acl.d/v2raya-helper.json
endef

define Package/v2raya-helper/postinst
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] || /etc/init.d/rpcd reload
endef

define Package/luci-app-v2raya-helper/install
	$(INSTALL_DIR) $(1)/www/luci-static/resources/view/status/include
	$(INSTALL_DATA) ./files/85_v2raya_helper.js $(1)/www/luci-static/resources/view/status/include/
endef

$(eval $(call BuildPackage,v2raya-helper))
$(eval $(call BuildPackage,luci-app-v2raya-helper))
