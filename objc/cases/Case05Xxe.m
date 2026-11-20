#import "../Common.h"
#import "../Cases.h"

@interface XmlText : NSObject
{ @public NSMutableString *text; }
@end

@implementation XmlText
- (id)init {
    self = [super init];
    if (self) { text = [[NSMutableString alloc] init]; }
    return self;
}
- (void)parser:(NSXMLParser *)p foundCharacters:(NSString *)s { [text appendString:s]; }
@end

@implementation Case05Xxe

+ (NSString *)bad:(NSMutableDictionary *)q {
    NSData *xml = [QParam(q, @"xml") dataUsingEncoding:NSUTF8StringEncoding];
    NSXMLParser *parser = [[NSXMLParser alloc] initWithData:xml];
    XmlText *d = [[XmlText alloc] init];
    [parser setDelegate:d];
    [parser setShouldResolveExternalEntities:YES];
    [parser parse];
    return d->text;
}

+ (NSString *)good:(NSMutableDictionary *)q {
    NSData *xml = [QParam(q, @"xml") dataUsingEncoding:NSUTF8StringEncoding];
    NSXMLParser *parser = [[NSXMLParser alloc] initWithData:xml];
    XmlText *d = [[XmlText alloc] init];
    [parser setDelegate:d];
    [parser setShouldResolveExternalEntities:NO];
    [parser parse];
    return d->text;
}

@end
