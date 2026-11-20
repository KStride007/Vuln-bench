#import "../Common.h"
#import "../Cases.h"

@implementation Case12FormatString

+ (NSString *)bad:(NSMutableDictionary *)q {
    NSString *input = QParam(q, @"msg");
    return [NSString stringWithFormat:input];
}

+ (NSString *)good:(NSMutableDictionary *)q {
    NSString *input = QParam(q, @"msg");
    return [NSString stringWithFormat:@"%@", input];
}

@end
