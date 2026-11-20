#import "../Common.h"
#import "../Cases.h"
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

@implementation Case10InsecureRandom

+ (NSString *)bad:(NSMutableDictionary *)q {
    srand((unsigned int)time(NULL));
    NSMutableString *token = [NSMutableString string];
    int i;
    for (i = 0; i < 16; i++) {
        [token appendFormat:@"%x", rand() % 16];
    }
    return [@"reset-token=" stringByAppendingString:token];
}

+ (NSString *)good:(NSMutableDictionary *)q {
    unsigned char buf[16];
    FILE *f = fopen("/dev/urandom", "rb");
    size_t n = f ? fread(buf, 1, sizeof(buf), f) : 0;
    if (f) { fclose(f); }
    if (n != sizeof(buf)) {
        [NSException raise:@"RandomUnavailable" format:@"no entropy source"];
    }
    return [@"reset-token=" stringByAppendingString:HexOf([NSData dataWithBytes:buf length:sizeof(buf)])];
}

@end
