#import "Common.h"

NSString *QParam(NSDictionary *q, NSString *key) {
    NSString *v = [q objectForKey:key];
    return v ? v : @"";
}

NSString *HexOf(NSData *data) {
    const unsigned char *b = [data bytes];
    NSMutableString *s = [NSMutableString string];
    NSUInteger i;
    for (i = 0; i < [data length]; i++) {
        [s appendFormat:@"%02x", b[i]];
    }
    return s;
}

sqlite3 *SharedDb(void) {
    static sqlite3 *db = NULL;
    if (db == NULL) {
        sqlite3_open(":memory:", &db);
        sqlite3_exec(db, "CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, email TEXT);"
                         "INSERT INTO users VALUES (1,'alice','alice@example.test');"
                         "INSERT INTO users VALUES (2,'bob','bob@example.test');", NULL, NULL, NULL);
    }
    return db;
}

NSString *RunTask(NSString *path, NSArray *args) {
    NSTask *task = [[NSTask alloc] init];
    NSPipe *pipe = [NSPipe pipe];
    [task setLaunchPath:path];
    [task setArguments:args];
    [task setStandardOutput:pipe];
    [task launch];
    NSData *out = [[pipe fileHandleForReading] readDataToEndOfFile];
    [task waitUntilExit];
    return [[NSString alloc] initWithData:out encoding:NSUTF8StringEncoding];
}
