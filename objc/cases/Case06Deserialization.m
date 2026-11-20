#import "../Common.h"
#import "../Cases.h"

@implementation Case06Deserialization

+ (NSString *)bad:(NSMutableDictionary *)q {
    NSData *data = [[NSData alloc] initWithBase64EncodedString:QParam(q, @"data") options:0];
    id obj = [NSKeyedUnarchiver unarchiveObjectWithData:data];
    return [NSString stringWithFormat:@"%@ (%@)", obj, NSStringFromClass([obj class])];
}

+ (NSString *)good:(NSMutableDictionary *)q {
    NSData *data = [QParam(q, @"data") dataUsingEncoding:NSUTF8StringEncoding];
    id obj = [NSJSONSerialization JSONObjectWithData:data options:0 error:NULL];
    if (![obj isKindOfClass:[NSDictionary class]]) {
        [NSException raise:@"BadInput" format:@"expected a JSON object"];
    }
    return [NSString stringWithFormat:@"%@", obj];
}

@end
