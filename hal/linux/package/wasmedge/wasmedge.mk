WASMEDGE_VERSION = 0.14.1
WASMEDGE_DOWNLOAD_URL = https://raw.githubusercontent.com/WasmEdge/WasmEdge/$(WASMEDGE_VERSION)/utils/install.sh

define WASMEDGE_INSTALL_TARGET_CMDS
    curl -sSf $(WASMEDGE_DOWNLOAD_URL) | bash -s -- -p $(TARGET_DIR)/usr -v $(WASMEDGE_VERSION)
    echo "source /usr/env" >> $(TARGET_DIR)/etc/profile
endef

$(eval $(generic-package))
