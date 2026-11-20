#import "../Common.h"
#import "../Cases.h"

@implementation Case09OpenRedirect

+ (NSString *)bad:(NSMutableDictionary *)q {
    NSString *target = QParam(q, @"next");
    [q setObject:[NSNumber numberWithInt:302] forKey:@"_status"];
    [q setObject:target forKey:@"_location"];
    return @"";
}

+ (NSString *)good:(NSMutableDictionary *)q {
    NSString *target = QParam(q, @"next");
    BOOL local = [target hasPrefix:@"/"] && ![target hasPrefix:@"//"] && ![target hasPrefix:@"/\\"];
    [q setObject:[NSNumber numberWithInt:302] forKey:@"_status"];
    [q setObject:(local ? target : @"/") forKey:@"_location"];
    return @"";
}

@end
