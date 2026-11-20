#import "../Common.h"
#import "../Cases.h"

@implementation Case02CommandInjection

+ (NSString *)bad:(NSMutableDictionary *)q {
    NSString *host = QParam(q, @"host");
    NSString *cmd = [@"echo lookup " stringByAppendingString:host];
    return RunTask(@"/bin/sh", [NSArray arrayWithObjects:@"-c", cmd, nil]);
}

+ (NSString *)good:(NSMutableDictionary *)q {
    NSString *host = QParam(q, @"host");
    NSCharacterSet *allowed = [NSCharacterSet characterSetWithCharactersInString:
        @"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-"];
    if ([host length] == 0 || [host length] > 253 ||
        [host rangeOfCharacterFromSet:[allowed invertedSet]].location != NSNotFound) {
        [NSException raise:@"InvalidHost" format:@"invalid host"];
    }
    return RunTask(@"/bin/echo", [NSArray arrayWithObjects:@"lookup", host, nil]);
}

@end
