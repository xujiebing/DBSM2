//
//  DBSM2Manager.h
//  DBSM2
//
//  Created by 徐结兵 on 2019/6/28.
//

#import <Foundation/Foundation.h>

typedef NS_ENUM(NSUInteger, DBSM2Mode) {
    DBSM2ModeC132 = 0, // 默认模式
    DBSM2ModeC123
};

NS_ASSUME_NONNULL_BEGIN

@interface DBSM2Manager : NSObject

/**
 SM2加密

 @param string 待加密字符串
 @param key 秘钥
 @return 密文
 */
+ (NSString *_Nullable)dbSM2Encode:(NSString *_Nonnull)string
                               key:(NSString *_Nonnull)key;

/**
 SM2加密

 @param data 待加密数据（NSData）
 @param key 秘钥
 @return 密文
 */
+ (NSString *_Nullable)dbSM2EncodeWithData:(NSData *_Nonnull)data
                                       key:(NSString *_Nonnull)key;

/**
 SM2加密

 @param data 待加密数据（NSData）
 @param keyData 秘钥（NSData）
 @param mode 加密模式
 @return 密文
 */
+ (NSData *_Nullable)dbSM2EncodeWithData:(NSData *_Nonnull)data
                                 keyData:(NSData *_Nonnull)keyData mode:(DBSM2Mode)mode;

/**
 SM2解密

 @param string 密文
 @param key 秘钥
 @return 明文
 */
+ (NSString *_Nullable)dbSM2Decode:(NSString *_Nonnull)string
                               key:(NSString *_Nonnull)key;

/**
 SM2解密

 @param string 密文
 @param key 秘钥
 @return 明文
 */
+ (NSData *_Nullable)dbSM2DecodeData:(NSString *_Nonnull)string
                                 key:(NSString *_Nonnull)key;

/**
 SM2解密

 @param data 密文(NSData)
 @param keyData 秘钥(NSData)
 @param mode 解密模式
 @return 明文
 */
+ (NSData *_Nullable)dbSM2DecodeData:(NSData *_Nonnull)data
                             keyData:(NSData *_Nonnull)keyData
                                mode:(DBSM2Mode)mode;

/**
 签名接口
 
 @param data 待签名数据（NSData）
 @param userId  userId
 @param privateKeyData  私钥（NSData）
 @return 返回签名数据
 */
+ (NSString * _Nullable)dbSM2SignWithData:(NSData *_Nonnull)data
                                   userId:(NSString *_Nonnull)userId
                               privateKey:(NSData *_Nonnull)privateKeyData;

/**
 签名接口
 
 @param data 待签名数据（NSData）
 @param userIdData  userid data
 @param privateKeyData  私钥（NSData）
 @return 返回签名数据
 */
+ (NSString * _Nullable)dbSM2SignWithData:(NSData *_Nonnull)data
                               userIdData:(NSData *_Nonnull)userIdData
                               privateKey:(NSData *_Nonnull)privateKeyData;

/**
 验签接口
 
 @param data 原数据data（NSData）
 @param sign 签名后的数据
 @param userId  userid，验签的userid 要和签名的时候的一样
 @param publicKeyData 公钥（NSData）
 @return 验签是否成功
 */
+ (BOOL)dbSM2VerifyWithData:(NSData *_Nonnull)data
                       sign:(NSString *_Nonnull)sign
                     userId:(NSString *_Nonnull)userId
                  publicKey:(NSData *_Nonnull)publicKeyData;

/**
 验签接口
 
 @param data 原数据 data
 @param sign 签名后的数据
 @param userIdData  userid data
 @param publicKeyData 公钥
 @return 验签是否成功
 */
+ (BOOL)dbSM2VerifyWithData:(NSData *_Nonnull)data
                       sign:(NSString *_Nonnull)sign
                 userIdData:(NSData *_Nonnull)userIdData
                  publicKey:(NSData *_Nonnull)publicKeyData;

/**生成密钥对*/
+ (NSDictionary *)generyKeyPair;

@end

NS_ASSUME_NONNULL_END
