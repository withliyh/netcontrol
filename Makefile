include $(TOPDIR)/rules.mk
PKG_NAME:=netcontrol
PKG_RELEASE:=1
PKG_INSTALL:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)

PKG_BUILD_DEPENDS:=libc jansson libcurl libmicrohttpd

include $(INCLUDE_DIR)/package.mk




define Package/netcontrol
	SECTION:=utils
	DEPENDS:=+libc +jansson +libcurl +libmicrohttpd
	CATEGORY:=Utilities
	TITLE:=netcontrol -- prints a snarky message
endef

define Package/netcontrol/description
	control net firewall
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Package/netcontrol/install
	$(INSTALL_DIR) $(1)/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/netcontrol $(1)/bin/
	#$(CP) $(TOPDIR)/staging_dir/target-mips_34kc_uClibc-0.9.33.2/root-ar71xx/usr/lib/* $(1)/bin
	#$(CP) $(TOPDIR)/staging_dir/toolchain-mips_34kc_gcc-4.8-linaro_uClibc-0.9.33.2/lib/libc.so $(1)/bin/libc.so.6
endef

$(eval $(call BuildPackage,netcontrol))
