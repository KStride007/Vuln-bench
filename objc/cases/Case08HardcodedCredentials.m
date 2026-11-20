#import "../Common.h"
#import "../Cases.h"
#include <stdlib.h>

@implementation Case08HardcodedCredentials

+ (NSString *)bad:(NSMutableDictionary *)q {
    NSString *supplied = QParam(q, @"password");
    NSString *adminPassword = @"Winter2024!Prod";
    return [supplied isEqualToString:adminPassword] ? @"welcome admin" : @"denied";
}

+ (NSString *)good:(NSMutableDictionary *)q {
    NSString *supplied = QParam(q, @"password");
    const char *env = getenv("ADMIN_PASSWORD");
    if (env == NULL || env[0] == '\0') {
        return @"denied";
    }
    return [supplied isEqualToString:[NSString stringWithUTF8String:env]] ? @"welcome admin" : @"denied";
}

@end
