#import <Foundation/Foundation.h>

#define DECLARE_CASE(NAME) \
@interface NAME : NSObject \
+ (NSString *)bad:(NSMutableDictionary *)q; \
+ (NSString *)good:(NSMutableDictionary *)q; \
@end

DECLARE_CASE(Case01SqlInjection)
DECLARE_CASE(Case02CommandInjection)
DECLARE_CASE(Case03PathTraversal)
DECLARE_CASE(Case04Xss)
DECLARE_CASE(Case05Xxe)
DECLARE_CASE(Case06Deserialization)
DECLARE_CASE(Case07WeakHash)
DECLARE_CASE(Case08HardcodedCredentials)
DECLARE_CASE(Case09OpenRedirect)
DECLARE_CASE(Case10InsecureRandom)
DECLARE_CASE(Case11Ssrf)
DECLARE_CASE(Case12FormatString)
