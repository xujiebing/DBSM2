//
//  SM2Coded.h
//  SM2Simple
//
//  Created by bolei on 16/12/6.
//  Copyright © 2016年 pingan. All rights reserved.
//

#import <Foundation/Foundation.h>

#define PUBLICKEY @"public_key"
#define PRIVATEKEY @"private_key"


typedef NS_ENUM(NSUInteger, SM2Mode) {
    SM2ModeC132 = 0, // 默认模式
    SM2ModeC123
};

@interface SM2Coded : NSObject

+ (NSString *)sm2Encode:(NSString *)str key:(NSString *)key;

+ (NSString *)sm2EncodeWithData:(NSData *)data key:(NSString *)key;

+ (NSString *)sm2Decode:(NSString *)str key:(NSString *)key;

+ (NSData *)sm2DecodeData:(NSString *)str key:(NSString *)key;

+ (NSData *)sm2EncodeWithData:(NSData *)data keyData:(NSData *)keyData mode:(SM2Mode)mode;

+ (NSData *)sm2DecodeData:(NSData *)data keyData:(NSData *)keyData mode:(SM2Mode)mode;

/**
 签名接口
 
 @param strData 数据data
 @param userId  userid
 @param keyData  私钥
 @return 返回签名数据
 */
+ (NSString * _Nullable)sm2_signPlainStringWithData:(NSData *_Nonnull)strData
                                             userId:(NSString *_Nonnull)userId
                                     withPrivateKey:(NSData *_Nonnull)keyData;

/**
 签名接口
 
 @param strData 数据data
 @param userIdData  userid data
 @param keyData  私钥
 @return 返回签名数据
 */
+ (NSString * _Nullable)sm2_signPlainStringWithData:(NSData *_Nonnull)strData
                                         userIdData:(NSData *_Nonnull)userIdData
                                     withPrivateKey:(NSData *_Nonnull)keyData;

/**
 验签接口
 
 @param strData 原数据 data
 @param sign 签名后的数据
 @param userId  userid，验签的userid 要和签名的时候的一样
 @param keyData 公钥
 @return 验签是否成功
 */
+ (BOOL)sm2_verifyWithPlainStringWithData:(NSData *_Nonnull)strData
                               withSigned:(NSString *_Nonnull)sign
                                   userId:(NSString *_Nonnull)userId
                            withPublicKey:(NSData *_Nonnull)keyData;

/**
 验签接口
 
 @param strData 原数据 data
 @param sign 签名后的数据
 @param userIdData  userid data
 @param keyData 公钥
 @return 验签是否成功
 */
+ (BOOL)sm2_verifyWithPlainStringWithData:(NSData *_Nonnull)strData
                               withSigned:(NSString *_Nonnull)sign
                               userIdData:(NSData *_Nonnull)userIdData
                            withPublicKey:(NSData *_Nonnull)keyData;

/**生成密钥对*/
+ (NSDictionary *)generyKeyPair;

@end
