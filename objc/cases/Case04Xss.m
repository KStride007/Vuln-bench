#import "../Common.h"
#import "../Cases.h"

@implementation Case04Xss

+ (NSString *)bad:(NSMutableDictionary *)q {
    NSString *name = QParam(q, @"name");
    return [NSString stringWithFormat:@"<html><body><h1>Hello %@</h1></body></html>", name];
}

+ (NSString *)good:(NSMutableDictionary *)q {
    NSMutableString *name = [NSMutableString stringWithString:QParam(q, @"name")];
    [name replaceOccurrencesOfString:@"&" withString:@"&amp;" options:0 range:NSMakeRange(0, [name length])];
    [name replaceOccurrencesOfString:@"<" withString:@"&lt;" options:0 range:NSMakeRange(0, [name length])];
    [name replaceOccurrencesOfString:@">" withString:@"&gt;" options:0 range:NSMakeRange(0, [name length])];
    [name replaceOccurrencesOfString:@"\"" withString:@"&quot;" options:0 range:NSMakeRange(0, [name length])];
    [name replaceOccurrencesOfString:@"'" withString:@"&#39;" options:0 range:NSMakeRange(0, [name length])];
    return [NSString stringWithFormat:@"<html><body><h1>Hello %@</h1></body></html>", name];
}

@end
