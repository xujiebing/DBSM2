//
//  SM2Coded.m
//  SM2Simple
//
//  Created by bolei on 16/12/6.
//  Copyright © 2016年 pingan. All rights reserved.
//

#import "SM2Coded.h"
#import "sm2.h"
#import "NSData+HexString.h"

#define kC1Length 64 //转成2进制后长度乘以2
#define kC3Length 32

@implementation SM2Coded


+ (NSString *)sm2Encode:(NSString *)str key:(NSString *)key {
    if ([str length] == 0 || [key length] == 0) {
        return @"";
    }
    
    return [self sm2EncodeWithData:[str dataUsingEncoding:NSUTF8StringEncoding] key:key];
}

+ (NSString *)sm2EncodeWithData:(NSData *)data key:(NSString *)key {
    if ([data length] == 0 || [key length] == 0) {
        return @"";
    }
    
    NSData *keyData =  [NSData dataFromHexString:key];
    NSData * encodeData = [self sm2EncodeWithData:data keyData:keyData mode:0];
    
    return [encodeData hexString];
    
}

+ (NSData *)sm2EncodeWithData:(NSData *)data keyData:(NSData *)keyData mode:(SM2Mode)mode{
    unsigned char result[1024] = {0};
    unsigned long outlen = 1024;
    int ret = GM_SM2Encrypt(result, &outlen, (unsigned char *)[data bytes], data.length, (unsigned char *)[keyData bytes], keyData.length);
    if (outlen < 2 || ret != MP_OKAY) {
        NSLog(@"%s encode error", __func__);
        return nil;
    }
    //多一位\x04 需要去掉
    NSData *encodeData = [NSData dataWithBytes:result + 1 length:outlen - 1];
    //    输出要求为 C1C2C3
    switch (mode) {
        case SM2ModeC123:
            
            break;
        case SM2ModeC132:
            //            从 C 方法出来默认就是C1C2C3
        {
            //    C1C3C2模式。
            NSData * c1 = [encodeData subdataWithRange:NSMakeRange(0, 64)];
            NSData * c2 = [encodeData subdataWithRange:NSMakeRange(64, encodeData.length - 96)];
            NSData * c3 = [encodeData subdataWithRange:NSMakeRange(encodeData.length - 32, 32)];
            NSMutableData * contentData = [NSMutableData data];
            [contentData appendData:c1];
            [contentData appendData:c3];
            [contentData appendData:c2];
            encodeData = contentData;
        }
            
            break;
        default:
            break;
    }
    
    return encodeData;
}

+ (NSString *)sm2Decode:(NSString *)str key:(NSString *)key {
    //密文长度至少也需要64+32位
    if ([str length] < 64 + 32 || [key length] == 0) {
        return @"";
    }
    NSData * decodeData = [self sm2DecodeData:str key:key];
    NSString * resultStr = [[NSString alloc]initWithData:decodeData encoding:NSUTF8StringEncoding];
    return resultStr;
}

+ (NSData *)sm2DecodeData:(NSString *)str key:(NSString *)key {
    //密文长度至少也需要64+32位
    if ([str length] < 64 + 32 || [key length] == 0) {
        NSLog(@"%s 参数错误", __func__);
        return nil;
    }
    
    NSData *data = [NSData dataFromHexString:str];
    NSData *keyData =  [NSData dataFromHexString:key];
    NSData * resultData = [self sm2DecodeData:data keyData:keyData mode:0];
    
    return resultData;
}

+ (NSData *)sm2DecodeData:(NSData *)data keyData:(NSData *)keyData mode:(SM2Mode)mode{
    if (data.length < 96 || keyData == nil) {
        return nil;
    }
    //    底层输入要求为 C1C2C3格式
    switch (mode) {
        case SM2ModeC123:
            break;
        case SM2ModeC132:
        {
            //    C1C3C2模式。
            NSData * c1 = [data subdataWithRange:NSMakeRange(0, 64)];
            NSData * c3 = [data subdataWithRange:NSMakeRange(64, 32)];
            NSData * c2 = [data subdataWithRange:NSMakeRange(96, data.length - 96)];
            NSMutableData * contentData = [NSMutableData data];
            [contentData appendData:c1];
            [contentData appendData:c2];
            [contentData appendData:c3];
            data = contentData;
        }
            break;
            
        default:
            break;
    }
    
    
    
    unsigned char result[1024] = {0};
    unsigned long outlen = 1024;
    unsigned char pass[1024] = {0};
    
    pass[0] = '\x04'; //需要补一位\x04
    memcpy(pass + 1, data.bytes, data.length);
    
    int ret = GM_SM2Decrypt((unsigned char *)result, &outlen, pass, data.length + 1, (unsigned char *)keyData.bytes, keyData.length);
    
    if (outlen == 0 || ret != MP_OKAY) {
        NSLog(@"%s sm2Decode error %d", __func__, ret);
        return nil;
    }
    NSData * resultData = [NSData dataWithBytes:result length:outlen];
    return resultData;
}

+ (NSString *)sm2_signPlainStringWithData:(NSData *)strData userId:(NSString *)userId withPrivateKey:(NSData *)keyData {

    if ([strData length] == 0 || [keyData length] == 0) {
        return @"";
    }
    
    unsigned char result[64] = {0};
    unsigned long outlen = 64;
//    const char *signData = [[str dataUsingEncoding:NSUTF8StringEncoding] bytes];
//    NSData *uidData = [userId dataUsingEncoding:NSUTF8StringEncoding];
//    const char * uidStr = [uidData bytes];
    const char *uidData = [userId cStringUsingEncoding:NSUTF8StringEncoding];
    
    int ret = GM_SM2Sign((unsigned char *)result, &outlen, (unsigned char *)strData.bytes, strData.length, (unsigned char *)uidData, strlen(uidData), (unsigned char *)keyData.bytes, keyData.length);
    if (outlen < 2 || ret != MP_OKAY) {
        NSLog(@"签名错误: %d", ret);
        return @"";
    }
    
    //多一位\x04 需要去掉
    NSData *data = [NSData dataWithBytes:result length:outlen];
    return [data hexString];
}

+ (NSString *)sm2_signPlainStringWithData:(NSData *)strData userIdData:(NSData *)userIdData withPrivateKey:(NSData *)keyData {
    
    if ([strData length] == 0 || [keyData length] == 0) {
        return @"";
    }
    
    unsigned char result[64] = {0};
    unsigned long outlen = 64;
    //    const char *signData = [[str dataUsingEncoding:NSUTF8StringEncoding] bytes];
//    NSData *uidData = [userId dataUsingEncoding:NSUTF8StringEncoding];
//    const char * uidStr = [uidData bytes];
    
    int ret = GM_SM2Sign((unsigned char *)result, &outlen, (unsigned char *)strData.bytes, strData.length, (unsigned char *)userIdData.bytes, userIdData.length, (unsigned char *)keyData.bytes, keyData.length);
    if (outlen < 2 || ret != MP_OKAY) {
        NSLog(@"签名错误: %d", ret);
        return @"";
    }
    
    //多一位\x04 需要去掉
    NSData *data = [NSData dataWithBytes:result length:outlen];
    return [data hexString];
}

+ (BOOL)sm2_verifyWithPlainStringWithData:(NSData *)strData withSigned:(NSString *)sign userId:(NSString *)userId withPublicKey:(NSData *)keyData {
    if ([strData length] == 0 || sign.length == 0 || [keyData length] == 0) {
        return false;
    }
//    const char *srcData = [str cStringUsingEncoding:NSUTF8StringEncoding];
    NSData *signData = [NSData dataFromHexString:sign];
    const char *uidData = [userId cStringUsingEncoding:NSUTF8StringEncoding];
    int ret = GM_SM2VerifySig((unsigned char *)signData.bytes, signData.length, (unsigned char *)strData.bytes, strData.length, (unsigned char *)uidData, strlen(uidData), (unsigned char *)keyData.bytes, keyData.length);
    
    return ret == 0;
}

+ (BOOL)sm2_verifyWithPlainStringWithData:(NSData *)strData withSigned:(NSString *)sign userIdData:(NSData *)userIdData withPublicKey:(NSData *)keyData {
    if ([strData length] == 0 || sign.length == 0 || [keyData length] == 0) {
        return false;
    }
    //    const char *srcData = [str cStringUsingEncoding:NSUTF8StringEncoding];
    NSData *signData = [NSData dataFromHexString:sign];
//    NSData * uidData = [userId dataUsingEncoding:NSUTF8StringEncoding];
//    const char *uidStr = [uidData bytes];
    int ret = GM_SM2VerifySig((unsigned char *)signData.bytes, signData.length, (unsigned char *)strData.bytes, strData.length, (unsigned char *)userIdData.bytes, userIdData.length, (unsigned char *)keyData.bytes, keyData.length);
    
    return ret == 0;
}

+ (NSDictionary *)generyKeyPair
{
    unsigned char buff[64] = {0};
    unsigned char prikeyBuff[2000] = {0};
    unsigned long priLen = 2000;
    
    GM_GenSM2keypair(prikeyBuff, &priLen, buff);
    
    NSData *pubXD = [NSData dataWithBytes:buff length:32];
    NSData *pubYD = [NSData dataWithBytes:buff+32 length:32];
    NSData *priD = [NSData dataWithBytes:prikeyBuff length:priLen];
    
    NSString *pubX = [pubXD hexString];
    NSString *pubY = [pubYD hexString];
    NSString *pri = [priD hexString];
    NSString * public_key_str = [NSString stringWithFormat:@"%@%@", pubX, pubY];
    NSLog(@"%@ %@", pubX, pubY);
    return @{PUBLICKEY: public_key_str, PRIVATEKEY: pri};
}



@end
