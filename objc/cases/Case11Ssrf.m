#import "../Common.h"
#import "../Cases.h"

@implementation Case11Ssrf

+ (NSString *)bad:(NSMutableDictionary *)q {
    NSURL *url = [NSURL URLWithString:QParam(q, @"url")];
    NSData *body = [NSData dataWithContentsOfURL:url];
    return [[NSString alloc] initWithData:body encoding:NSUTF8StringEncoding];
}

+ (NSString *)good:(NSMutableDictionary *)q {
    NSURL *url = [NSURL URLWithString:QParam(q, @"url")];
    NSArray *allowed = [NSArray arrayWithObjects:@"example.com", @"api.example.com", nil];
    if (![[url scheme] isEqualToString:@"https"]) {
        [NSException raise:@"BadScheme" format:@"https URL required"];
    }
    if (![allowed containsObject:[url host]]) {
        [NSException raise:@"BadHost" format:@"host not allowed"];
    }
    NSData *body = [NSData dataWithContentsOfURL:url];
    return [[NSString alloc] initWithData:body encoding:NSUTF8StringEncoding];
}

@end
