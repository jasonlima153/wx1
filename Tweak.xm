#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <dlfcn.h>
#import <sys/sysctl.h>
#import <mach/mach.h>
#import <substrate.h>

// ptrace declaration and constants
extern int ptrace(int request, pid_t pid, caddr_t addr, int data);
#ifndef PT_DENY_ATTACH
#define PT_DENY_ATTACH 0
#endif

// NSBundle Hook - Bypass Bundle ID Check
static NSString* (*orig_bundleIdentifier)(NSBundle* self, SEL _cmd);
static NSString* hooked_bundleIdentifier(NSBundle* self, SEL _cmd) {
    if (self == [NSBundle mainBundle]) {
        NSLog(@"[WechatBypass] Intercepted bundleIdentifier, returning original");
        return @"com.tencent.xin";
    }
    return orig_bundleIdentifier(self, _cmd);
}

// SecTrustEvaluate Hook - Bypass Certificate Pinning
static OSStatus (*orig_SecTrustEvaluate)(SecTrustRef trust, SecTrustResultType *result);
static OSStatus hooked_SecTrustEvaluate(SecTrustRef trust, SecTrustResultType *result) {
    NSLog(@"[WechatBypass] SecTrustEvaluate bypassed");
    if (result) { *result = kSecTrustResultProceed; }
    return errSecSuccess;
}

// SecTrustEvaluateWithError Hook (iOS 12.0+)
static BOOL (*orig_SecTrustEvaluateWithError)(SecTrustRef trust, CFErrorRef *error);
static BOOL hooked_SecTrustEvaluateWithError(SecTrustRef trust, CFErrorRef *error) {
    NSLog(@"[WechatBypass] SecTrustEvaluateWithError bypassed");
    if (error) { *error = NULL; }
    return YES;
}

// ptrace Hook - Bypass Anti-Debug
static int (*orig_ptrace)(int request, pid_t pid, caddr_t addr, int data);
static int hooked_ptrace(int request, pid_t pid, caddr_t addr, int data) {
    if (request == PT_DENY_ATTACH) {
        NSLog(@"[WechatBypass] PTRACE_DENY_ATTACH blocked");
        return 0;
    }
    return orig_ptrace(request, pid, addr, data);
}

// sysctl Hook - Hide Debugger Detection
static int (*orig_sysctl)(int *name, u_int namelen, void *info, size_t *infosize, void *newinfo, size_t newinfosize);
static int hooked_sysctl(int *name, u_int namelen, void *info, size_t *infosize, void *newinfo, size_t newinfosize) {
    int ret = orig_sysctl(name, namelen, info, infosize, newinfo, newinfosize);
    if (namelen >= 4 && name[0] == CTL_KERN && name[1] == KERN_PROC && name[2] == KERN_PROC_PID && info) {
        struct kinfo_proc *kinfo = (struct kinfo_proc *)info;
        if (kinfo && (kinfo->kp_proc.p_flag & P_TRACED)) {
            kinfo->kp_proc.p_flag &= ~P_TRACED;
            NSLog(@"[WechatBypass] Debugger flag (P_TRACED) cleared");
        }
    }
    return ret;
}

// DYLD Environment Variable Hook
static char* (*orig_getenv)(const char *name);
static char* hooked_getenv(const char *name) {
    if (name && (strcmp(name, "DYLD_INSERT_LIBRARIES") == 0 ||
                  strcmp(name, "_MSSafeMode") == 0 ||
                  strcmp(name, "_SafeMode") == 0)) {
        NSLog(@"[WechatBypass] Hidden env var: %s", name);
        return NULL;
    }
    return orig_getenv(name);
}

// dlopen Hook - Log dynamically loaded libraries
static void* (*orig_dlopen)(const char* path, int mode);
static void* hooked_dlopen(const char* path, int mode) {
    if (path) {
        NSLog(@"[WechatBypass] dlopen: %s", path);
    }
    return orig_dlopen(path, mode);
}

// WTLoginApi Hook - Log Login Responses
static BOOL (*orig_loginWithPasswd)(id self, SEL _cmd, NSString* passwd, NSString* pwd, unsigned int bitmap, unsigned int flag, id data);
static BOOL hooked_loginWithPasswd(id self, SEL _cmd, NSString* passwd, NSString* pwd, unsigned int bitmap, unsigned int flag, id data) {
    NSLog(@"[WechatBypass] Login attempt detected, bitmap: %u, flag: %u", bitmap, flag);
    BOOL ret = orig_loginWithPasswd(self, _cmd, passwd, pwd, bitmap, flag, data);
    NSLog(@"[WechatBypass] Login result: %d", ret);
    return ret;
}

// DeviceInfo Hook - Log IDFA
static NSString* (*orig_idfaUUID)(id self, SEL _cmd);
static NSString* hooked_idfaUUID(id self, SEL _cmd) {
    NSString* original = orig_idfaUUID(self, _cmd);
    NSLog(@"[WechatBypass] IDFA UUID: %@", original);
    return original;
}

static __attribute__((constructor)) void WechatBypassInit() {
    NSLog(@"[WechatBypass] Tweak loaded - Educational Security Research");

    // NSBundle
    MSHookMessageEx(NSClassFromString(@"NSBundle"), @selector(bundleIdentifier),
                    (IMP)hooked_bundleIdentifier, (IMP *)&orig_bundleIdentifier);

    // SecTrustEvaluate
    MSHookFunction((void *)SecTrustEvaluate,
                   (void *)hooked_SecTrustEvaluate, (void **)&orig_SecTrustEvaluate);

    // SecTrustEvaluateWithError (iOS 12.0+)
    if (@available(iOS 12.0, *)) {
        MSHookFunction((void *)SecTrustEvaluateWithError,
                       (void *)hooked_SecTrustEvaluateWithError, (void **)&orig_SecTrustEvaluateWithError);
    }

    // ptrace
    MSHookFunction((void *)ptrace,
                   (void *)hooked_ptrace, (void **)&orig_ptrace);

    // sysctl
    MSHookFunction((void *)sysctl,
                   (void *)hooked_sysctl, (void **)&orig_sysctl);

    // getenv
    MSHookFunction((void *)getenv,
                   (void *)hooked_getenv, (void **)&orig_getenv);

    // dlopen
    MSHookFunction((void *)dlopen,
                   (void *)hooked_dlopen, (void **)&orig_dlopen);

    // WTLoginApi
    Class loginClass = NSClassFromString(@"WTLoginApi");
    if (loginClass) {
        MSHookMessageEx(loginClass,
                        NSSelectorFromString(@"loginWithPasswd:pwd:bitmap:flag:data:"),
                        (IMP)hooked_loginWithPasswd, (IMP *)&orig_loginWithPasswd);
    }

    // DeviceInfo
    Class deviceInfoClass = NSClassFromString(@"DeviceInfo");
    if (deviceInfoClass) {
        MSHookMessageEx(deviceInfoClass,
                        NSSelectorFromString(@"idfaUUID"),
                        (IMP)hooked_idfaUUID, (IMP *)&orig_idfaUUID);
    }
}
