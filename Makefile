include $(TOPDIR)/rules.mk
PKG_NAME:=netcontrol
#PKG_VERSION:=1.0.0
PKG_RELEASE:=1
PKG_LICENSE:=MIT
PKG_INSTALL:=1
PKG_BUILD_PARALLEL:=1

include $(INCLUDE_DIR)/package.mk

define Package/netcontrol
	SECTION:=utils
	CATEGORY:=Utilities
	TITLE:=netcontrol -- prints a snarky message
endef

define Package/netcontrol/description
	control net firewall
endef

define Package/netcontrol/install
	$(INSTALL_DIR) $(1)/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/netcontrol $(1)/bin/
endef

$(eval $(call BuildPackage,netcontrol))
