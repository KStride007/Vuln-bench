#import "Common.h"
#import "Cases.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

static NSMutableDictionary *ParseQuery(NSString *raw) {
    NSMutableDictionary *q = [NSMutableDictionary dictionary];
    for (NSString *pair in [raw componentsSeparatedByString:@"&"]) {
        if ([pair length] == 0) { continue; }
        NSRange eq = [pair rangeOfString:@"="];
        NSString *k = eq.location == NSNotFound ? pair : [pair substringToIndex:eq.location];
        NSString *v = eq.location == NSNotFound ? @"" : [pair substringFromIndex:eq.location + 1];
        k = [[k stringByReplacingOccurrencesOfString:@"+" withString:@" "] stringByReplacingPercentEscapesUsingEncoding:NSUTF8StringEncoding];
        v = [[v stringByReplacingOccurrencesOfString:@"+" withString:@" "] stringByReplacingPercentEscapesUsingEncoding:NSUTF8StringEncoding];
        if (k && v) { [q setObject:v forKey:k]; }
    }
    return q;
}

static void SendAll(int fd, NSString *s) {
    NSData *d = [s dataUsingEncoding:NSUTF8StringEncoding];
    const char *p = [d bytes];
    size_t left = [d length];
    while (left > 0) {
        ssize_t n = write(fd, p, left);
        if (n <= 0) { break; }
        p += n; left -= (size_t)n;
    }
}

static void Handle(int fd, NSDictionary *routes) {
    char buf[8192];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    if (n <= 0) { return; }
    buf[n] = 0;
    NSString *req = [NSString stringWithUTF8String:buf];
    NSString *line = [[req componentsSeparatedByString:@"\r\n"] objectAtIndex:0];
    NSArray *parts = [line componentsSeparatedByString:@" "];
    if ([parts count] < 2) { return; }
    NSString *target = [parts objectAtIndex:1];
    NSRange qm = [target rangeOfString:@"?"];
    NSString *path = qm.location == NSNotFound ? target : [target substringToIndex:qm.location];
    NSString *query = qm.location == NSNotFound ? @"" : [target substringFromIndex:qm.location + 1];
    NSMutableDictionary *q = ParseQuery(query);
    int status = 200;
    NSString *body = @"VulnObjC: intentionally vulnerable. Routes: /caseNN/bad and /caseNN/good";
    NSArray *seg = [path componentsSeparatedByString:@"/"];
    if ([seg count] == 3 && [routes objectForKey:[seg objectAtIndex:1]]) {
        Class c = [routes objectForKey:[seg objectAtIndex:1]];
        SEL sel = [[seg objectAtIndex:2] isEqualToString:@"bad"] ? @selector(bad:) : @selector(good:);
        @try {
            body = [c performSelector:sel withObject:q];
            if (body == nil) { body = @""; }
        } @catch (NSException *e) {
            status = 500;
            body = [NSString stringWithFormat:@"error: %@: %@", [e name], [e reason]];
        }
        if ([q objectForKey:@"_status"]) { status = [[q objectForKey:@"_status"] intValue]; }
    }
    NSData *bd = [body dataUsingEncoding:NSUTF8StringEncoding];
    NSMutableString *head = [NSMutableString stringWithFormat:@"HTTP/1.1 %d X\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: %lu\r\nConnection: close\r\n",
                             status, (unsigned long)[bd length]];
    if ([q objectForKey:@"_location"]) { [head appendFormat:@"Location: %@\r\n", [q objectForKey:@"_location"]]; }
    [head appendString:@"\r\n"];
    SendAll(fd, head);
    SendAll(fd, body);
}

int main(int argc, char **argv) {
    {
        NSAutoreleasePool *mainPool = [[NSAutoreleasePool alloc] init];
        (void)mainPool;
        int port = argc > 1 ? atoi(argv[1]) : 8083;
        [[NSFileManager defaultManager] createDirectoryAtPath:@"docs" withIntermediateDirectories:YES attributes:nil error:NULL];
        [@"public document" writeToFile:@"docs/readme.txt" atomically:YES encoding:NSUTF8StringEncoding error:NULL];
        SharedDb();

        NSMutableDictionary *routes = [NSMutableDictionary dictionary];
        [routes setObject:[Case01SqlInjection class] forKey:@"case01"];
        [routes setObject:[Case02CommandInjection class] forKey:@"case02"];
        [routes setObject:[Case03PathTraversal class] forKey:@"case03"];
        [routes setObject:[Case04Xss class] forKey:@"case04"];
        [routes setObject:[Case05Xxe class] forKey:@"case05"];
        [routes setObject:[Case06Deserialization class] forKey:@"case06"];
        [routes setObject:[Case07WeakHash class] forKey:@"case07"];
        [routes setObject:[Case08HardcodedCredentials class] forKey:@"case08"];
        [routes setObject:[Case09OpenRedirect class] forKey:@"case09"];
        [routes setObject:[Case10InsecureRandom class] forKey:@"case10"];
        [routes setObject:[Case11Ssrf class] forKey:@"case11"];
        [routes setObject:[Case12FormatString class] forKey:@"case12"];

        int s = socket(AF_INET, SOCK_STREAM, 0);
        int one = 1;
        setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        struct sockaddr_in a;
        memset(&a, 0, sizeof(a));
        a.sin_family = AF_INET;
        a.sin_port = htons((unsigned short)port);
        a.sin_addr.s_addr = inet_addr("127.0.0.1");
        if (bind(s, (struct sockaddr *)&a, sizeof(a)) != 0 || listen(s, 16) != 0) {
            fprintf(stderr, "bind failed\n");
            return 1;
        }
        printf("listening on %d\n", port);
        fflush(stdout);
        for (;;) {
            int c = accept(s, NULL, NULL);
            if (c < 0) { continue; }
            { NSAutoreleasePool *p = [[NSAutoreleasePool alloc] init]; Handle(c, routes); [p release]; }
            close(c);
        }
    }
    return 0;
}
