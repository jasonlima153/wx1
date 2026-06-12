THEOS_DEVICE_IP = 127.0.0.1
THEOS_DEVICE_PORT = 2222
TARGET := iphone:clang:latest:12.0
ARCHS = arm64
include $(THEOS)/makefiles/common.mk

TWEAK_NAME = WechatBypass

WechatBypass_FILES = Tweak.xm
WechatBypass_CFLAGS = -fobjc-arc
WechatBypass_FRAMEWORKS = UIKit Foundation Security
WechatBypass_PRIVATE_FRAMEWORKS = AppSupport
WechatBypass_LDFLAGS = -lsubstrate

include $(THEOS_MAKE_PATH)/tweak.mk

after-install::
	install.exec "killall -9 WeChat"
