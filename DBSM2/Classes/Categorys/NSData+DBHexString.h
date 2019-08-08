//
//  NSData+DBHexString.h
//  DBSM2
//
//  Created by 徐结兵 on 2019/6/27.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface NSData (DBHexString)

+ (NSData *)dbDataFromHexString:(NSString *)hexString;

- (NSString *)hexString;

@end

NS_ASSUME_NONNULL_END
