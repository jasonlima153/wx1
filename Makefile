export THEOS=/opt/theos
TARGET = iphone:clang:latest:14.0
ARCHS = arm64 arm64e

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = WechatBlind
WechatBlind_FILES = Tweak.xm
WechatBlind_CFLAGS = -fobjc-arc
WechatBlind_FRAMEWORKS = UIKit CoreFoundation Security SystemConfiguration

include $(THEOS_MAKE_PATH)/tweak.mk
