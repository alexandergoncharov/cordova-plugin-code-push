#import <Cordova/CDV.h>
#import <Cordova/CDVConfigParser.h>
#import <Cordova/CDVWebViewEngineProtocol.h>
#import "CodePush.h"
#import "CodePushPackageMetadata.h"
#import "CodePushPackageManager.h"
#import "Utilities.h"
#import "InstallOptions.h"
#import "InstallMode.h"
#import "CodePushReportingManager.h"
#import "StatusReport.h"
#import "UpdateHashUtils.h"
#import "CodePushJWT.h"

@implementation CodePush

bool didUpdate = false;
bool pendingInstall = false;
NSDate* lastResignedDate;
NSString* const DeploymentKeyPreference = @"codepushdeploymentkey";
NSString* const PublicKeyPreference = @"codepushpublickey";
StatusReport* rollbackStatusReport = nil;
NSString* specifiedServerPath = @"";

- (void)getBinaryHash:(CDVInvokedUrlCommand *)command {
    NSLog(@"qq getBinaryHash");
    [self.commandDelegate runInBackground:^{
        CDVPluginResult* pluginResult = nil;
        NSString* binaryHash = [CodePushPackageManager getCachedBinaryHash];
        if (binaryHash) {
            pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK
                                             messageAsString:binaryHash];
        } else {
            NSError* error;
            binaryHash = [UpdateHashUtils getBinaryHash:&error];
            if (error) {
                pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR
                                                 messageAsString:[@"An error occurred when trying to get the hash of the binary contents. " stringByAppendingString:error.description]];
            } else {
                [CodePushPackageManager saveBinaryHash:binaryHash];
                pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK
                                                 messageAsString:binaryHash];
            }
        }

        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    }];
}

- (void)getPackageHash:(CDVInvokedUrlCommand *)command {
    NSLog(@"qq getPackageHash");
    [self.commandDelegate runInBackground:^{
        NSString *path = [command argumentAtIndex:0 withDefault:nil andClass:[NSString class]];
        CDVPluginResult *pluginResult = nil;
        if (!path) {
            pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR
                                             messageAsString:@"No path supplied"];
        } else {
            path = [[[NSSearchPathForDirectoriesInDomains(NSLibraryDirectory, NSUserDomainMask, YES)[0]
                    stringByAppendingPathComponent:@"NoCloud"]
                    stringByAppendingPathComponent:path]
                    stringByAppendingPathComponent:@"www"];
            NSError *error;
            NSString *hash = [UpdateHashUtils getHashForPath:path error:&error];
            if (error) {
                pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR
                                                 messageAsString:[NSString stringWithFormat:@"An error occured when trying to get the hash of %@. %@", path, error.description]];
            } else {
                pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK
                                                 messageAsString:hash];
            }
        }

        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    }];
}

- (void)getPublicKey:(CDVInvokedUrlCommand *)command {
    NSLog(@"qq getPublicKey");
    [self.commandDelegate runInBackground:^{
        NSString *publicKey = ((CDVViewController *) self.viewController).settings[PublicKeyPreference];
        NSLog(@"qq %@publicKey", publicKey);
        CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK
                                                            messageAsString:publicKey];
        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    }];
}

- (void)decodeSignature:(CDVInvokedUrlCommand *)command {
    NSLog(@"qq decodeSignature");
    [self.commandDelegate runInBackground:^{
        NSString *publicKey = [command argumentAtIndex:0 withDefault:nil andClass:[NSString class]];

        // remove BEGIN / END tags and line breaks from public key string
        publicKey = [publicKey stringByReplacingOccurrencesOfString:@"-----BEGIN PUBLIC KEY-----\n"
                                                         withString:@""];
        publicKey = [publicKey stringByReplacingOccurrencesOfString:@"-----END PUBLIC KEY-----"
                                                         withString:@""];
        publicKey = [publicKey stringByReplacingOccurrencesOfString:@"\n"
                                                         withString:@""];

        NSString *jwt = [command argumentAtIndex:1 withDefault:nil andClass:[NSString class]];

        id <JWTAlgorithmDataHolderProtocol> verifyDataHolder = [JWTAlgorithmRSFamilyDataHolder new]
                .keyExtractorType([JWTCryptoKeyExtractor publicKeyWithPEMBase64].type)
                .algorithmName(@"RS256")
                .secret(publicKey);
        JWTCodingBuilder *verifyBuilder = [JWTDecodingBuilder decodeMessage:jwt].addHolder(verifyDataHolder);
        JWTCodingResultType *verifyResult = verifyBuilder.result;
        CDVPluginResult *pluginResult;
        if (verifyResult.successResult) {
            CPLog(@"JWT signature verification succeeded, payload content:  %@", verifyResult.successResult.payload);
            pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK
                                             messageAsString:verifyResult.successResult.payload[@"contentHash"]];
        } else {
            pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR
                                             messageAsString:[@"Signature verification failed: " stringByAppendingString:verifyResult.errorResult.error.description]];
        }
        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    }];
}

- (void)handleUnconfirmedInstall:(BOOL)navigate {
    NSLog(@"qq here is handleUnconfirmedInstall");
    if ([CodePushPackageManager installNeedsConfirmation]) {
        NSLog(@"qq install needs confirm");
        /* save reporting status */
        CodePushPackageMetadata* currentMetadata = [CodePushPackageManager getCurrentPackageMetadata];
        rollbackStatusReport = [[StatusReport alloc] initWithStatus:UPDATE_ROLLED_BACK
                                                           andLabel:currentMetadata.label
                                                      andAppVersion:currentMetadata.appVersion
                                                   andDeploymentKey:currentMetadata.deploymentKey];
        [CodePushPackageManager clearInstallNeedsConfirmation];
        [CodePushPackageManager revertToPreviousVersion];
        if (navigate) {
            NSLog(@"qq here is navigate is true");
            CodePushPackageMetadata* currentMetadata = [CodePushPackageManager getCurrentPackageMetadata];
            bool revertSuccess = (nil != currentMetadata && [self loadPackage:currentMetadata.localPath]);
            if (!revertSuccess) {
                /* first update failed, go back to store version */
                [self loadStoreVersion];
            }
        }
    }
}

- (void)notifyApplicationReady:(CDVInvokedUrlCommand *)command {
    NSLog(@"qq notifyApplicationReady");
    [self.commandDelegate runInBackground:^{
        if ([CodePushPackageManager isBinaryFirstRun]) {
            // Report first run of a store version app
            [CodePushPackageManager markBinaryFirstRunFlag];
            NSString* appVersion = [Utilities getApplicationVersion];
            NSString* deploymentKey = ((CDVViewController *)self.viewController).settings[DeploymentKeyPreference];
            StatusReport* statusReport = [[StatusReport alloc] initWithStatus:STORE_VERSION
                                                                     andLabel:nil
                                                                andAppVersion:appVersion
                                                             andDeploymentKey:deploymentKey];
            [CodePushReportingManager reportStatus:statusReport
                                       withWebView:self.webView];
            NSLog(@"qq notifyApplicationReady binary first run");
        } else if ([CodePushPackageManager installNeedsConfirmation]) {
            // Report CodePush update installation that has not been confirmed yet
            CodePushPackageMetadata* currentMetadata = [CodePushPackageManager getCurrentPackageMetadata];
            StatusReport* statusReport = [[StatusReport alloc] initWithStatus:UPDATE_CONFIRMED
                                                                     andLabel:currentMetadata.label
                                                                andAppVersion:currentMetadata.appVersion
                                                             andDeploymentKey:currentMetadata.deploymentKey];
            [CodePushReportingManager reportStatus:statusReport
                                    withWebView:self.webView];
        } else if (rollbackStatusReport) {
            // Report a CodePush update that rolled back
            NSLog(@"qq notifyApplicationReady Report a CodePush update that rolled back");
            [CodePushReportingManager reportStatus:rollbackStatusReport
                                       withWebView:self.webView];
            rollbackStatusReport = nil;
        } else if ([CodePushReportingManager hasFailedReport]) {
            NSLog(@"qq notifyApplicationReady Previous status report failed, so try it again");
            // Previous status report failed, so try it again
            [CodePushReportingManager reportStatus:[CodePushReportingManager getAndClearFailedReport]
                                       withWebView:self.webView];
        }

        // Mark the update as confirmed and not requiring a rollback
        NSLog(@"here is some clearing from notify application ready");
        [CodePushPackageManager clearInstallNeedsConfirmation];
        [CodePushPackageManager cleanOldPackage];
        CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK];
        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    }];
}

- (void)install:(CDVInvokedUrlCommand *)command {
    NSLog(@"qq install");
    [self.commandDelegate runInBackground:^{
        CDVPluginResult* pluginResult = nil;

        NSString* location = [command argumentAtIndex:0 withDefault:nil andClass:[NSString class]];
        NSString* installModeString = [command argumentAtIndex:1 withDefault:IMMEDIATE andClass:[NSString class]];
        NSString* minimumBackgroundDurationString = [command argumentAtIndex:2 withDefault:0 andClass:[NSString class]];

        InstallOptions* options = [[InstallOptions alloc] init];
        [options setInstallMode:[installModeString intValue]];
        [options setMinimumBackgroundDuration:[minimumBackgroundDurationString intValue]];

        if ([options installMode] == IMMEDIATE) {
            if (nil == location) {
                pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:@"Cannot read the start URL."];
            }
            else {
                bool applied = [self loadPackage: location];
                if (applied) {
                    [self markUpdate];
                    pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK];
                }
                else {
                    pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:@"An error happened during package install."];
                }
            }
        }
        else {
            /* install on restart or on resume */
            [CodePushPackageManager savePendingInstall:options];
            pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK];
        }

        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    }];
}

- (void)reportFailed:(CDVInvokedUrlCommand *)command {
    NSLog(@"qq reportFailed");
    [self.commandDelegate runInBackground:^{
        NSDictionary* statusReportDict = [command argumentAtIndex:0 withDefault:nil andClass:[NSDictionary class]];
        if (statusReportDict) {
            [CodePushReportingManager saveFailedReport:[[StatusReport alloc] initWithDictionary:statusReportDict]];
        }
    }];
}

- (void)reportSucceeded:(CDVInvokedUrlCommand *)command {
    NSLog(@"qq reportSucceeded");
    [self.commandDelegate runInBackground:^{
        NSDictionary* statusReportDict = [command argumentAtIndex:0 withDefault:nil andClass:[NSDictionary class]];
        if (statusReportDict) {
            [CodePushReportingManager saveSuccessfulReport:[[StatusReport alloc] initWithDictionary:statusReportDict]];
        }
    }];
}

- (void)restartApplication:(CDVInvokedUrlCommand *)command {
    NSLog(@"qq restart application");
    /* Callback before navigating */
    CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK];
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];

    CodePushPackageMetadata* deployedPackageMetadata = [CodePushPackageManager getCurrentPackageMetadata];
    if (deployedPackageMetadata && deployedPackageMetadata.localPath && [self getStartPageURLForLocalPackage:deployedPackageMetadata.localPath]) {
        [self loadPackage: deployedPackageMetadata.localPath];
        InstallOptions* pendingInstall = [CodePushPackageManager getPendingInstall];
        if (pendingInstall) {
            [self markUpdate];
            [CodePushPackageManager clearPendingInstall];
        }
    }
    else {
        [self loadStoreVersion];
    }
}

- (void) markUpdate {
    NSLog(@"qq markUpdate");
    didUpdate = YES;
    [CodePushPackageManager markInstallNeedsConfirmation];
}

- (void)preInstall:(CDVInvokedUrlCommand *)command {
    NSLog(@"qq preInstall");
    [self.commandDelegate runInBackground:^{
        CDVPluginResult* pluginResult = nil;

        NSString* location = [command argumentAtIndex:0 withDefault:nil andClass:[NSString class]];
        if (nil == location) {
            pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:@"Cannot read the start URL."];
        }
        else {
            NSURL* URL = [self getStartPageURLForLocalPackage:location];
            if (URL) {
                NSLog(@"preInstall url for start page local package%@", URL);
                pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK];
            }
            else {
                pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:@"Could not find start page in package."];
            }
        }

        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    }];
}

- (void)getServerURL:(CDVInvokedUrlCommand *)command {
    NSLog(@"qq getServerURL");
    [self sendResultForPreference:@"codepushserverurl" command:command];
}

- (void)getDeploymentKey:(CDVInvokedUrlCommand *)command {
    NSLog(@"qq getDeploymentKey");
    [self sendResultForPreference:DeploymentKeyPreference command:command];
}

- (void)getNativeBuildTime:(CDVInvokedUrlCommand *)command {
    NSLog(@"qq getNativeBuildTime");
    [self.commandDelegate runInBackground:^{
        NSString* timeStamp = [Utilities getApplicationTimestamp];
        CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsString:timeStamp];
        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    }];
}

- (void)sendResultForPreference:(NSString*)preferenceName command:(CDVInvokedUrlCommand*)command {
    NSLog(@"qq sendResultForPreference");
    [self.commandDelegate runInBackground:^{
        NSString* preferenceValue = ((CDVViewController *)self.viewController).settings[preferenceName];
        // length of NIL is zero
        CDVPluginResult* pluginResult;
        if ([preferenceValue length] > 0) {
            pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsString:preferenceValue];
        } else {
            pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:[NSString stringWithFormat:@"Could not find preference %@", preferenceName]];
        }

        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    }];
}

- (void)dealloc {
    NSLog(@"qq dealloc");
    [[NSNotificationCenter defaultCenter] removeObserver:self];
}

- (void)clearDeploymentsIfBinaryUpdated {
    NSLog(@"qq here is clear deploy if updated binary");
    // check if we have a deployed package
    CodePushPackageMetadata* deployedPackageMetadata = [CodePushPackageManager getCurrentPackageMetadata];
    if (deployedPackageMetadata) {
        NSLog(@"qq here is a new deploy belike so try clear it");
        NSString* deployedPackageNativeBuildTime = deployedPackageMetadata.nativeBuildTime;
        NSString* applicationBuildTime = [Utilities getApplicationTimestamp];

        NSString* deployedPackageVersion = deployedPackageMetadata.appVersion;
        NSString* applicationVersion = [Utilities getApplicationVersion];

        if (deployedPackageNativeBuildTime != nil && applicationBuildTime != nil &&
            deployedPackageVersion != nil && applicationVersion != nil) {
            NSLog(@"qq first condition to new deploy");
            if (![deployedPackageNativeBuildTime isEqualToString: applicationBuildTime] ||
                ![deployedPackageVersion isEqualToString: applicationVersion]) {
                NSLog(@"qq here is clear from code-push");
                // package version is incompatible with installed native version
                [CodePushPackageManager cleanDeployments];
                [CodePushPackageManager clearFailedUpdates];
                [CodePushPackageManager clearPendingInstall];
                [CodePushPackageManager clearInstallNeedsConfirmation];
                [CodePushPackageManager clearBinaryFirstRunFlag];
            }
        }
    }
}

- (void)navigateToLocalDeploymentIfExists {
    NSLog(@"qq navigateToLocalDeploymentIfExists");
    CodePushPackageMetadata* deployedPackageMetadata = [CodePushPackageManager getCurrentPackageMetadata];
    if (deployedPackageMetadata) {
        NSLog(@"navigate to local deployment path: %@", deployedPackageMetadata.localPath);
    }
    if (deployedPackageMetadata && deployedPackageMetadata.localPath) {
        [self redirectStartPageToURL: deployedPackageMetadata.localPath];
    }
}

- (void)pluginInitialize {
    NSLog(@"qq pluginInitialize");
    // register for "on resume", "on pause" notifications
    [self clearDeploymentsIfBinaryUpdated];
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(applicationWillEnterForeground) name:UIApplicationWillEnterForegroundNotification object:nil];
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(applicationWillResignActive) name:UIApplicationWillResignActiveNotification object:nil];
    InstallOptions* pendingInstall = [CodePushPackageManager getPendingInstall];
    if (!pendingInstall) {
        NSLog(@"qq pluginInitialize pending install");
        [self handleUnconfirmedInstall:NO];
    }

    [self navigateToLocalDeploymentIfExists];
    // handle both ON_NEXT_RESUME and ON_NEXT_RESTART - the application might have been killed after transitioning to the background
    if (pendingInstall && (pendingInstall.installMode == ON_NEXT_RESTART || pendingInstall.installMode == ON_NEXT_RESUME)) {
        [self markUpdate];
        NSLog(@"qq pluginInitialize here is clear pending install");
        [CodePushPackageManager clearPendingInstall];
    }
}

- (void)applicationWillEnterForeground {
    NSLog(@"qq application will entered foreground");
    InstallOptions* pendingInstall = [CodePushPackageManager getPendingInstall];
    // calculate the duration that the app was in the background
    long durationInBackground = lastResignedDate ? [[NSDate date] timeIntervalSinceDate:lastResignedDate] : 0;
    if (pendingInstall && pendingInstall.installMode == ON_NEXT_RESUME && durationInBackground >= pendingInstall.minimumBackgroundDuration) {
        CodePushPackageMetadata* deployedPackageMetadata = [CodePushPackageManager getCurrentPackageMetadata];
        if (deployedPackageMetadata && deployedPackageMetadata.localPath) {
            bool applied = [self loadPackage: deployedPackageMetadata.localPath];
            if (applied) {
                [self markUpdate];
                [CodePushPackageManager clearPendingInstall];
            }
        }
    } else if ([CodePushReportingManager hasFailedReport]) {
        [CodePushReportingManager reportStatus:[CodePushReportingManager getAndClearFailedReport] withWebView:self.webView];
    }
}

- (void)applicationWillResignActive {
    NSLog(@"qq applicationWillResignActive");
    // Save the current time so that when the app is later resumed, we can detect how long it was in the background
    lastResignedDate = [NSDate date];
}

- (BOOL)loadPackage:(NSString*)packageLocation {
    NSLog(@"qq loadPackage: %@packageLocation", packageLocation);
    NSURL* URL = [self getStartPageURLForLocalPackage:packageLocation];
    if (URL) {
        [self loadURL:URL];
        return YES;
    }

    return NO;
}

- (void)loadURL:(NSURL*)url {
    NSLog(@"qq loadURL: %@url", url);
    // In order to make use of the "modern" Cordova platform, while still
    // maintaining back-compat with Cordova iOS 3.9.0, we need to conditionally
    // use the WebViewEngine for performing navigations only if the host app
    // is running 4.0.0+, and fallback to directly using the WebView otherwise.
#ifdef __CORDOVA_4_0_0
    NSLog(@"qq!!! here is loadRequest5");
    [self.webViewEngine loadRequest:[NSURLRequest requestWithURL:url]];
#else
    NSLog(@"qq!!! here is loadRequest6");
    [(UIWebView*)self.webView loadRequest:[NSURLRequest requestWithURL:url]];
#endif
}

+ (Boolean) hasIonicWebViewEngine:(id<CDVWebViewEngineProtocol>) webViewEngine {
    NSString * webViewEngineClass = NSStringFromClass([webViewEngine class]);
    SEL setServerBasePath = NSSelectorFromString(@"setServerBasePath:");
    if ([webViewEngineClass  isEqual: @"CDVWKWebViewEngine"] && [webViewEngine respondsToSelector:setServerBasePath]) {
        NSLog(@"qq hasIonicWebViewEngine true");
        return true;
    } else {
        NSLog(@"qq hasIonicWebViewEngine false");
        return false;
    }
}

+ (void) setServerBasePath:(NSString*)serverPath webView:(id<CDVWebViewEngineProtocol>) webViewEngine {
    NSLog(@"qq setServerBasePath: %@", serverPath);
    NSLog(@"rr specified: %@", specifiedServerPath);
    if ([CodePush hasIonicWebViewEngine: webViewEngine]) {
        if ([specifiedServerPath isEqualToString:@""]) {
            specifiedServerPath = serverPath;
        } else if (!([specifiedServerPath containsString:@"codepush"] && ![serverPath containsString:@"codepush"])) {
            specifiedServerPath = serverPath;
        } else {
            return;
        }
        SEL setServerBasePath = NSSelectorFromString(@"setServerBasePath:");
        NSMutableArray * urlPathComponents = [serverPath pathComponents].mutableCopy;
        [urlPathComponents removeLastObject];
        NSString * serverBasePath = [urlPathComponents componentsJoinedByString:@"/"];
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"
        CDVInvokedUrlCommand * command = [CDVInvokedUrlCommand commandFromJson:[NSArray arrayWithObjects: @"", @"", @"", [NSMutableArray arrayWithObject:serverBasePath], nil]];
        dispatch_async(dispatch_get_main_queue(), ^{
            [webViewEngine performSelector: setServerBasePath withObject: command];
        });
#pragma clang diagnostic pop
    }
}

- (void)loadStoreVersion {
    NSLog(@"qq loadStoreVersion");
    NSString* mainBundlePath = [[NSBundle mainBundle] bundlePath];
    NSString* configStartPage = [self getConfigLaunchUrl];
    NSArray* realLocationArray = @[mainBundlePath, @"www", configStartPage];
    NSString* mainPageLocation = [NSString pathWithComponents:realLocationArray];
    NSLog(@"qq mainPageLocation %@location", mainPageLocation);
    if ([[NSFileManager defaultManager] fileExistsAtPath:mainPageLocation]) {
        NSURL* mainPagePath = [NSURL fileURLWithPath:mainPageLocation];
        NSLog(@"qq loadStoreVersion mainPageLocation exists");
        [self loadURL:mainPagePath];
    }
}

- (NSString*)getConfigLaunchUrl
{
    NSLog(@"qq getConfigLaunchUrl");
    CDVConfigParser* delegate = [[CDVConfigParser alloc] init];
    NSString* configPath = [[NSBundle mainBundle] pathForResource:@"config" ofType:@"xml"];
    NSLog(@"config path of launch url %@", configPath);
    NSURL* configUrl = [NSURL fileURLWithPath:configPath];

    NSXMLParser* configParser = [[NSXMLParser alloc] initWithContentsOfURL:configUrl];
    [configParser setDelegate:((id < NSXMLParserDelegate >)delegate)];
    [configParser parse];

    return delegate.startPage;
}

- (NSURL *)getStartPageURLForLocalPackage:(NSString*)packageLocation {
    NSLog(@"qq getStartPageURLForLocalPackage");
    if (packageLocation) {
        NSString* startPage = [self getConfigLaunchUrl];
        NSString* libraryLocation = [NSSearchPathForDirectoriesInDomains(NSLibraryDirectory, NSUserDomainMask, YES) objectAtIndex:0];
        NSArray* realLocationArray = @[libraryLocation, @"NoCloud", packageLocation, @"www", startPage];
        NSString* realStartPageLocation = [NSString pathWithComponents:realLocationArray];
        NSLog(@"qq getStartPageURLForLocalPackage real start page location: %@", realStartPageLocation);
        if ([[NSFileManager defaultManager] fileExistsAtPath:realStartPageLocation]) {
            NSLog(@"qq getStartPageURLForLocalPackage %@", realStartPageLocation);
            return [NSURL fileURLWithPath:realStartPageLocation];
        }
    }

    return nil;
}

- (void)redirectStartPageToURL:(NSString*)packageLocation{
    NSLog(@"qq redirectStartPageToURL %@packageLocation", packageLocation);
    NSURL* URL = [self getStartPageURLForLocalPackage:packageLocation];
    NSLog(@"redirectStartPageToURL URL: %@", URL);
    if (URL) {
        if ([CodePush hasIonicWebViewEngine: self.webViewEngine]) {
            [CodePush setServerBasePath:URL.path webView:self.webViewEngine];
            //[self loadURL:URL];
        } else {
            ((CDVViewController *)self.viewController).startPage = [URL absoluteString];
        }
    }
}

- (void)isFailedUpdate:(CDVInvokedUrlCommand *)command {
    NSLog(@"qq isFailedUpdate");
    [self.commandDelegate runInBackground:^{
        CDVPluginResult* result;
        NSString* packageHash = [command argumentAtIndex:0 withDefault:nil andClass:[NSString class]];
        if (nil == packageHash) {
            result = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:@"Invalid package hash parameter."];
        }
        else {
            BOOL failedHash = [CodePushPackageManager isFailedHash:packageHash];
            result = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsInt:failedHash ? 1 : 0];
        }

        [self.commandDelegate sendPluginResult:result callbackId:command.callbackId];
    }];
}

- (void)isFirstRun:(CDVInvokedUrlCommand *)command {
    NSLog(@"qq isFirstRun");
    [self.commandDelegate runInBackground:^{
        CDVPluginResult* result;
        BOOL isFirstRun = NO;

        NSString* packageHash = [command argumentAtIndex:0 withDefault:nil andClass:[NSString class]];
        CodePushPackageMetadata* currentPackageMetadata = [CodePushPackageManager getCurrentPackageMetadata];
        if (currentPackageMetadata) {
            isFirstRun = (nil != packageHash
                            && [packageHash length] > 0
                            && [packageHash isEqualToString:currentPackageMetadata.packageHash]
                            && didUpdate);
        }

        result = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsInt:isFirstRun ? 1 : 0];
        [self.commandDelegate sendPluginResult:result callbackId:command.callbackId];
    }];
}

- (void)isPendingUpdate:(CDVInvokedUrlCommand *)command {
    NSLog(@"qq isPendingUpdate");
    [self.commandDelegate runInBackground:^{
        CDVPluginResult* result;

        InstallOptions* pendingInstall = [CodePushPackageManager getPendingInstall];
        result = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsInt:pendingInstall ? 1 : 0];
        [self.commandDelegate sendPluginResult:result callbackId:command.callbackId];
    }];
}

- (void)getAppVersion:(CDVInvokedUrlCommand *)command {
    NSLog(@"qq getAppVersion");
    [self.commandDelegate runInBackground:^{
        NSString* version = [Utilities getApplicationVersion];
        CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsString:version];
        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    }];
}

@end

