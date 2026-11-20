#import "../Common.h"
#import "../Cases.h"

@implementation Case03PathTraversal

+ (NSString *)bad:(NSMutableDictionary *)q {
    NSString *name = QParam(q, @"file");
    NSString *path = [@"docs" stringByAppendingPathComponent:name];
    return [NSString stringWithContentsOfFile:path encoding:NSUTF8StringEncoding error:NULL];
}

+ (NSString *)good:(NSMutableDictionary *)q {
    NSString *name = QParam(q, @"file");
    NSString *root = [[[NSFileManager defaultManager] currentDirectoryPath]
                      stringByAppendingPathComponent:@"docs"];
    NSString *path = [[root stringByAppendingPathComponent:name] stringByStandardizingPath];
    if (![path hasPrefix:[root stringByAppendingString:@"/"]]) {
        [NSException raise:@"PathOutsideRoot" format:@"path outside document root"];
    }
    return [NSString stringWithContentsOfFile:path encoding:NSUTF8StringEncoding error:NULL];
}

@end
