//
//  DBSM2Manager.m
//  DBSM2
//
//  Created by 徐结兵 on 2019/6/28.
//

#import "DBSM2Manager.h"
#import "sm2.h"
#import "NSData+DBHexString.h"

@implementation DBSM2Manager

+ (NSString *)dbSM2Encode:(NSString *)string
                      key:(NSString *)key {
    if (string.length == 0 || key.length == 0) {
        return nil;
    }
    return [self dbSM2EncodeWithData:[string dataUsingEncoding:NSUTF8StringEncoding] key:key];
}

+ (NSString *)dbSM2EncodeWithData:(NSData *)data
                              key:(NSString *)key {
    if (data.length == 0 || key.length == 0) {
        return nil;
    }
    NSData *keyData =  [NSData dbDataFromHexString:key];
    NSData *encodeData = [self dbSM2EncodeWithData:data keyData:keyData mode:DBSM2ModeC132];
    return [encodeData hexString];
}

+ (NSData *)dbSM2EncodeWithData:(NSData *)data
                        keyData:(NSData *)keyData
                           mode:(DBSM2Mode)mode {
    unsigned char result[1024] = {0};
    unsigned long outlen = 1024;
    int ret = GM_SM2Encrypt(result, &outlen, (unsigned char *)[data bytes], data.length, (unsigned char *)[keyData bytes], keyData.length);
    if (outlen < 2 || ret != MP_OKAY) {
        NSLog(@"%s encode error", __func__);
        return nil;
    }
    // 多一位\x04 需要去掉
    NSData *encodeData = [NSData dataWithBytes:result + 1 length:outlen - 1];
    // 输出要求为 C1C2C3
    switch (mode) {
            case DBSM2ModeC123:
            break;
            
            case DBSM2ModeC132:{
                // 从C方法出来默认就是C1C2C3
                // C1C3C2模式。
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

+ (NSString *)dbSM2Decode:(NSString *)string
                      key:(NSString *)key {
    //密文长度至少也需要64+32位
    if (string.length < 64 + 32 || key.length == 0) {
        return nil;
    }
    NSData *decodeData = [self dbSM2DecodeData:string key:key];
    NSString *resultStr = [[NSString alloc]initWithData:decodeData encoding:NSUTF8StringEncoding];
    return resultStr;
}

+ (NSData *)dbSM2DecodeData:(NSString *)string
                        key:(NSString *)key {
    // 密文长度至少也需要64+32位
    if (string.length < 64 + 32 || key.length == 0) {
        NSLog(@"%s 参数错误", __func__);
        return nil;
    }
    NSData *stringData =  [NSData dbDataFromHexString:string];
    NSData *keyData =  [NSData dbDataFromHexString:key];
    NSData *resultData = [self dbSM2DecodeData:stringData keyData:keyData mode:DBSM2ModeC132];
    return resultData;
}

+ (NSData *)dbSM2DecodeData:(NSData *)data
                    keyData:(NSData *)keyData
                       mode:(DBSM2Mode)mode {
    if (data.length < 96 || !keyData) {
        return nil;
    }
    // 底层输入要求为 C1C2C3格式
    switch (mode) {
            case DBSM2ModeC123:
            break;
            case DBSM2ModeC132:{
                // C1C3C2模式。
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

+ (NSString *)dbSM2SignWithData:(NSData *)data
                         userId:(NSString *)userId
                     privateKey:(NSData *)privateKeyData {
    if (!data || !privateKeyData) {
        return nil;
    }
    
    unsigned char result[64] = {0};
    unsigned long outlen = 64;
    //    const char *signData = [[str dataUsingEncoding:NSUTF8StringEncoding] bytes];
    //    NSData *uidData = [userId dataUsingEncoding:NSUTF8StringEncoding];
    //    const char * uidStr = [uidData bytes];
    const char *uidData = [userId cStringUsingEncoding:NSUTF8StringEncoding];
    
    int ret = GM_SM2Sign((unsigned char *)result, &outlen, (unsigned char *)data.bytes, data.length, (unsigned char *)uidData, strlen(uidData), (unsigned char *)privateKeyData.bytes, privateKeyData.length);
    if (outlen < 2 || ret != MP_OKAY) {
        NSLog(@"签名错误: %d", ret);
        return nil;
    }
    
    //多一位\x04 需要去掉
    NSData *resultData = [NSData dataWithBytes:result length:outlen];
    return [resultData hexString];
}

+ (NSString *)dbSM2SignWithData:(NSData *)data
                     userIdData:(NSData *)userIdData
                     privateKey:(NSData *)privateKeyData {
    if (!data || !privateKeyData) {
        return nil;
    }
    
    unsigned char result[64] = {0};
    unsigned long outlen = 64;
    //    const char *signData = [[str dataUsingEncoding:NSUTF8StringEncoding] bytes];
    //    NSData *uidData = [userId dataUsingEncoding:NSUTF8StringEncoding];
    //    const char * uidStr = [uidData bytes];
    
    int ret = GM_SM2Sign((unsigned char *)result, &outlen, (unsigned char *)data.bytes, data.length, (unsigned char *)userIdData.bytes, userIdData.length, (unsigned char *)privateKeyData.bytes, privateKeyData.length);
    if (outlen < 2 || ret != MP_OKAY) {
        NSLog(@"签名错误: %d", ret);
        return @"";
    }
    
    //多一位\x04 需要去掉
    NSData *resultData = [NSData dataWithBytes:result length:outlen];
    return [resultData hexString];
}

+ (BOOL)dbSM2VerifyWithData:(NSData *)data
                       sign:(NSString *)sign
                     userId:(NSString *)userId
                  publicKey:(NSData *)publicKeyData {
    if (!data || sign.length == 0 || !publicKeyData) {
        return false;
    }
    //    const char *srcData = [str cStringUsingEncoding:NSUTF8StringEncoding];
    NSData *signData = [NSData dbDataFromHexString:sign];
    const char *uidData = [userId cStringUsingEncoding:NSUTF8StringEncoding];
    int ret = GM_SM2VerifySig((unsigned char *)signData.bytes, signData.length, (unsigned char *)data.bytes, data.length, (unsigned char *)uidData, strlen(uidData), (unsigned char *)publicKeyData.bytes, publicKeyData.length);
    
    return ret == 0;
}

+ (BOOL)dbSM2VerifyWithData:(NSData *)data
                       sign:(NSString *)sign
                 userIdData:(NSData *)userIdData
                  publicKey:(NSData *)publicKeyData {
    if (!data || sign.length == 0 || !publicKeyData) {
        return false;
    }
    //    const char *srcData = [str cStringUsingEncoding:NSUTF8StringEncoding];
    NSData *signData = [NSData dbDataFromHexString:sign];
    //    NSData * uidData = [userId dataUsingEncoding:NSUTF8StringEncoding];
    //    const char *uidStr = [uidData bytes];
    int ret = GM_SM2VerifySig((unsigned char *)signData.bytes, signData.length, (unsigned char *)data.bytes, data.length, (unsigned char *)userIdData.bytes, userIdData.length, (unsigned char *)publicKeyData.bytes, publicKeyData.length);
    
    return ret == 0;
}

+ (NSDictionary *)generyKeyPair {
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
    NSString *public_key_str = [NSString stringWithFormat:@"%@%@", pubX, pubY];
    NSLog(@"publicKey=%@ \n privateKey=%@", public_key_str, pri);
    return @{@"publicKey": public_key_str, @"privateKey": pri};
}


@end
