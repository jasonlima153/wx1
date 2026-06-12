#import <UIKit/UIKit.h>
#import <Security/Security.h>
#import <objc/runtime.h>
#import <notify.h>

// ========== 配置区域 ==========
// 请替换为您自己从正版微信提取的合法 a2Key/a8Key 值（字符串）
static NSString *FAKE_A2KEY = @"fake_a2key_placeholder";
static NSString *FAKE_A8KEY = @"fake_a8key_placeholder";

// 从正版微信中提取的 deviceToken（32字节 NSData）
static NSData *FAKE_DEVICE_TOKEN = nil;

// 是否完全禁止检测网络请求
static BOOL BLOCK_ALL_REPORT = YES;

// ========== 辅助函数 ==========
static void initFakeData() {
    // 如果没有真实 token，生成一个假 token（32字节）
    if (!FAKE_DEVICE_TOKEN) {
        uint8_t bytes[32];
        for (int i = 0; i < 32; i++) bytes[i] = i;
        FAKE_DEVICE_TOKEN = [NSData dataWithBytes:bytes length:32];
        NSLog(@"[Blind] Using fake device token (generated)");
    }
}

// ========== 1. 拦截网络请求，阻止上报 ==========
%hook NSURLSession

- (NSURLSessionDataTask *)dataTaskWithRequest:(NSURLRequest *)request completionHandler:(void (^)(NSData *data, NSURLResponse *response, NSError *error))completionHandler {
    NSString *urlString = request.URL.absoluteString.lowercaseString;
    NSArray *blockPatterns = @[
        @"report", @"matrix", @"device", @"fingerprint", 
        @"signcheck", @"codecheck", @"keychain", @"apns"
    ];
    for (NSString *pattern in blockPatterns) {
        if ([urlString containsString:pattern]) {
            NSLog(@"[Blind] BLOCKED request: %@", urlString);
            // 返回一个空任务，不发请求，并立即调用 completionHandler 返回成功（伪造空响应）
            if (completionHandler) {
                NSHTTPURLResponse *fakeResponse = [[NSHTTPURLResponse alloc] initWithURL:request.URL statusCode:200 HTTPVersion:@"HTTP/1.1" headerFields:nil];
                completionHandler([NSData data], fakeResponse, nil);
            }
            return nil;
        }
    }
    return %orig;
}

- (NSURLSessionDataTask *)dataTaskWithRequest:(NSURLRequest *)request {
    // 同样拦截
    NSString *urlString = request.URL.absoluteString.lowercaseString;
    for (NSString *pattern in @[@"report", @"matrix", @"device", @"fingerprint", @"signcheck"]) {
        if ([urlString containsString:pattern]) {
            NSLog(@"[Blind] BLOCKED (simple) request: %@", urlString);
            return nil;
        }
    }
    return %orig;
}

%end

// 同时 Hook 老的 NSURLConnection
%hook NSURLConnection

+ (NSURLConnection *)connectionWithRequest:(NSURLRequest *)request delegate:(id)delegate {
    NSString *urlString = request.URL.absoluteString.lowercaseString;
    if ([urlString containsString:@"report"] || [urlString containsString:@"matrix"]) {
        NSLog(@"[Blind] BLOCKED NSURLConnection request: %@", urlString);
        return nil;
    }
    return %orig;
}

%end

// ========== 2. Hook Keychain 返回合法值 ==========
// 方式一：Hook 微信自己的工具类（需要逆向真实类名，这里用 MMKeychainUtil 示例）
%hook MMKeychainUtil

+ (NSString *)getValueForKey:(NSString *)key {
    NSString *original = %orig;
    if ([key isEqualToString:@"a2Key"]) {
        if (original.length == 0) {
            NSLog(@"[Blind] Returning fake a2Key");
            return FAKE_A2KEY;
        }
    } else if ([key isEqualToString:@"a8Key"]) {
        if (original.length == 0) {
            NSLog(@"[Blind] Returning fake a8Key");
            return FAKE_A8KEY;
        }
    }
    return original;
}

+ (BOOL)setValue:(NSString *)value forKey:(NSString *)key {
    // 阻止写入失败时的错误传播，直接返回成功
    if ([key isEqualToString:@"a2Key"] || [key isEqualToString:@"a8Key"]) {
        NSLog(@"[Blind] Intercepted setValue for %@ (no-op)", key);
        return YES;
    }
    return %orig;
}

%end

// 方式二：底层 Hook SecItemCopyMatching，伪造查询结果
%hookf(OSStatus, SecItemCopyMatching, CFDictionaryRef query, CFTypeRef *result) {
    CFStringRef service = CFDictionaryGetValue(query, kSecAttrService);
    if (service && CFStringCompare(service, CFSTR("com.tencent.xin"), 0) == kCFCompareEqualTo) {
        CFStringRef account = CFDictionaryGetValue(query, kSecAttrAccount);
        if (account) {
            NSString *key = (__bridge NSString *)account;
            if ([key isEqualToString:@"a2Key"] || [key isEqualToString:@"a8Key"]) {
                NSLog(@"[Blind] SecItemCopyMatching: returning fake data for %@", key);
                // 构造假数据返回
                NSData *fakeData = [key isEqualToString:@"a2Key"] ? [FAKE_A2KEY dataUsingEncoding:NSUTF8StringEncoding] : [FAKE_A8KEY dataUsingEncoding:NSUTF8StringEncoding];
                *result = (__bridge CFTypeRef)fakeData;
                return errSecSuccess;
            }
        }
    }
    return %orig(query, result);
}

// ========== 3. 伪造 APNs 注册和 deviceToken ==========
%hook UIApplication

- (void)registerForRemoteNotifications {
    NSLog(@"[Blind] registerForRemoteNotifications intercepted - fake registration");
    // 不调用原始注册，避免系统生成真实 token
    // 直接模拟注册成功，调用微信的 delegate 方法并传入伪造 token
    id delegate = [UIApplication sharedApplication].delegate;
    if ([delegate respondsToSelector:@selector(application:didRegisterForRemoteNotificationsWithDeviceToken:)]) {
        initFakeData();
        [delegate application:[UIApplication sharedApplication] didRegisterForRemoteNotificationsWithDeviceToken:FAKE_DEVICE_TOKEN];
    }
}

- (BOOL)isRegisteredForRemoteNotifications {
    // 强制返回 YES
    return YES;
}

%end

// 防止微信通过其他方式获取真实 deviceToken（如直接读取 UserDefaults）
%hook NSUserDefaults

- (id)objectForKey:(NSString *)defaultName {
    if ([defaultName containsString:@"deviceToken"]) {
        NSLog(@"[Blind] NSUserDefaults objectForKey:%@ -> returning fake token data", defaultName);
        initFakeData();
        return FAKE_DEVICE_TOKEN;
    }
    return %orig;
}

%end

// ========== 4. 伪造代码签名信息 ==========
// Hook 获取 Bundle 信息的底层函数
%hook NSBundle

- (NSString *)bundleIdentifier {
    NSString *orig = %orig;
    if ([orig containsString:@"wechat"] || [orig containsString:@"WeChat"]) {
        NSLog(@"[Blind] bundleIdentifier: %@ -> forced to com.tencent.xin", orig);
        return @"com.tencent.xin";
    }
    return orig;
}

- (id)objectForInfoDictionaryKey:(NSString *)key {
    if ([key isEqualToString:@"CFBundleIdentifier"]) {
        return @"com.tencent.xin";
    }
    return %orig;
}

%end

// Hook 获取签名证书信息的函数（示例，实际可能需要更多）
%hookf(SecCertificateRef, SecCodeCopySigningInformation, SecStaticCodeRef code, SecCSFlags flags, CFDictionaryRef *information) {
    OSStatus status = %orig(code, flags, information);
    if (status == errSecSuccess && information) {
        NSMutableDictionary *info = (__bridge NSMutableDictionary *)*information;
        // 修改证书信息中的 Team ID 和 Identifier
        [info setObject:@"88L2Q4487U" forKey:@"teamid"];  // 腾讯官方 Team ID 占位
        [info setObject:@"com.tencent.xin" forKey:@"identifier"];
        *information = (__bridge CFDictionaryRef)info;
    }
    return status;
}

// ========== 5. 阻止其他可能的检测线程 ==========
// 使用 method swizzling 阻止某些 selector 调用（具体需要逆向）
%hook MicroMessengerAppDelegate  // 微信的 AppDelegate 类名可能是这个

- (void)startReportTimer {
    NSLog(@"[Blind] Prevented startReportTimer");
    // 什么都不做
}

- (void)checkSignature {
    NSLog(@"[Blind] Prevented checkSignature");
}

%end

// ========== 初始化 ==========
%ctor {
    NSLog(@"[Blind] WeChat Blind Plugin Loaded - Attempting to block detection");
    initFakeData();
    
    // 可选：发送通知，提醒用户
    dispatch_async(dispatch_get_main_queue(), ^{
        UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"插件已激活" 
                                                                       message:@"已尝试阻断所有检测上报，但无法保证绕过服务器验证，ret=-6仍可能发生。" 
                                                                preferredStyle:UIAlertControllerStyleAlert];
        [alert addAction:[UIAlertAction actionWithTitle:@"知道了" style:UIAlertActionStyleCancel handler:nil]];
        UIViewController *root = [UIApplication sharedApplication].keyWindow.rootViewController;
        [root presentViewController:alert animated:YES completion:nil];
    });
}
