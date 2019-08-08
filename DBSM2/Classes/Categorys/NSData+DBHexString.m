//
//  NSData+DBHexString.m
//  DBSM2
//
//  Created by 徐结兵 on 2019/6/27.
//

#import "NSData+DBHexString.h"

@implementation NSData (DBHexString)

+ (NSData *)dbDataFromHexString:(NSString *)hexString {
    const char *chars = [hexString UTF8String];
    NSInteger i = 0, len = hexString.length;
    NSMutableData *data = [NSMutableData dataWithCapacity:len / 2];
    char byteChars[3] = {'\0','\0','\0'};
    unsigned long wholeByte;
    while (i < len) {
        byteChars[0] = chars[i++];
        byteChars[1] = chars[i++];
        wholeByte = strtoul(byteChars, NULL, 16);
        [data appendBytes:&wholeByte length:1];
    }
    return data;
}

static inline char itoh(int i) {
    if (i > 9) return 'A' + (i - 10);
    return '0' + i;
}

- (NSString *)hexString {
    NSUInteger i, len;
    unsigned char *buf, *bytes;
    
    len = self.length;
    bytes = (unsigned char*)self.bytes;
    buf = malloc(len*2);
    
    for (i=0; i<len; i++) {
        buf[i*2] = itoh((bytes[i] >> 4) & 0xF);
        buf[i*2+1] = itoh(bytes[i] & 0xF);
    }
    
    return [[NSString alloc] initWithBytesNoCopy:buf
                                          length:len*2
                                        encoding:NSASCIIStringEncoding
                                    freeWhenDone:YES];
}

@end
