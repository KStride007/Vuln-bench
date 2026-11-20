#import <Foundation/Foundation.h>
#import <sqlite3.h>

NSString *QParam(NSDictionary *q, NSString *key);
NSString *HexOf(NSData *data);
sqlite3 *SharedDb(void);
NSString *RunTask(NSString *path, NSArray *args);
