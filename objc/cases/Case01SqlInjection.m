#import "../Common.h"
#import "../Cases.h"

@implementation Case01SqlInjection

+ (NSString *)bad:(NSMutableDictionary *)q {
    NSString *name = QParam(q, @"name");
    NSString *sql = [NSString stringWithFormat:@"SELECT id, email FROM users WHERE name = '%@'", name];
    sqlite3_stmt *st = NULL;
    NSMutableString *out = [NSMutableString string];
    if (sqlite3_prepare_v2(SharedDb(), [sql UTF8String], -1, &st, NULL) != SQLITE_OK) {
        return [NSString stringWithFormat:@"sql error: %s", sqlite3_errmsg(SharedDb())];
    }
    while (sqlite3_step(st) == SQLITE_ROW) {
        [out appendFormat:@"%d,%s\n", sqlite3_column_int(st, 0), sqlite3_column_text(st, 1)];
    }
    sqlite3_finalize(st);
    return out;
}

+ (NSString *)good:(NSMutableDictionary *)q {
    NSString *name = QParam(q, @"name");
    sqlite3_stmt *st = NULL;
    NSMutableString *out = [NSMutableString string];
    sqlite3_prepare_v2(SharedDb(), "SELECT id, email FROM users WHERE name = ?", -1, &st, NULL);
    sqlite3_bind_text(st, 1, [name UTF8String], -1, SQLITE_TRANSIENT);
    while (sqlite3_step(st) == SQLITE_ROW) {
        [out appendFormat:@"%d,%s\n", sqlite3_column_int(st, 0), sqlite3_column_text(st, 1)];
    }
    sqlite3_finalize(st);
    return out;
}

@end
