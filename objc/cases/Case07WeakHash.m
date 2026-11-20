#import "../Common.h"
#import "../Cases.h"
#import <openssl/md5.h>
#import <openssl/evp.h>
#import <openssl/rand.h>

@implementation Case07WeakHash

+ (NSString *)bad:(NSMutableDictionary *)q {
    NSData *pw = [QParam(q, @"password") dataUsingEncoding:NSUTF8StringEncoding];
    unsigned char digest[MD5_DIGEST_LENGTH];
    MD5([pw bytes], [pw length], digest);
    return HexOf([NSData dataWithBytes:digest length:MD5_DIGEST_LENGTH]);
}

+ (NSString *)good:(NSMutableDictionary *)q {
    NSData *pw = [QParam(q, @"password") dataUsingEncoding:NSUTF8StringEncoding];
    unsigned char salt[16];
    unsigned char out[32];
    RAND_bytes(salt, sizeof(salt));
    PKCS5_PBKDF2_HMAC([pw bytes], (int)[pw length], salt, sizeof(salt), 210000, EVP_sha256(), sizeof(out), out);
    return [NSString stringWithFormat:@"%@:%@", HexOf([NSData dataWithBytes:salt length:sizeof(salt)]),
            HexOf([NSData dataWithBytes:out length:sizeof(out)])];
}

@end
