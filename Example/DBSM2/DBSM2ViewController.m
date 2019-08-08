//
//  DBSM2ViewController.m
//  DBSM2
//
//  Created by xujiebing on 06/27/2019.
//  Copyright (c) 2019 xujiebing. All rights reserved.
//

#import "DBSM2ViewController.h"
#import "DBSM2Manager.h"
#import "NSData+DBHexString.h"

#import "SM2Coded.h"

@interface DBSM2ViewController ()

@property (nonatomic, copy, readwrite) NSString *publicKey;
@property (nonatomic, copy, readwrite) NSString *privateKey;

@end

@implementation DBSM2ViewController

- (void)viewDidLoad
{
    [super viewDidLoad];
	// Do any additional setup after loading the view, typically from a nib.
    NSDictionary *dic = [DBSM2Manager generyKeyPair];
    
    self.publicKey = @"63340040FBA90C6BFEB0467F87312462EA350F4F672AADF35F46A94ACF3848A6BA8D2A94BE83B3C316EFFAF6577E3B5526802FACAA5763C45375079DDF91623C";
    self.privateKey = @"1C18489313956312527BB2A9C4B8EDA07EFEF5DEAF105FB08427D14737AFC39C";
    [self p_sign];
}


- (void)p_sign {
    NSString *content = @"121109183777688203a73a6f0900000000000000000040";
    NSData *contentData = [self p_stringToHex:content];
    NSData *privateData = [NSData dbDataFromHexString:self.privateKey];
    NSString *userId = @"1234567812345678";
    NSString *sign = [DBSM2Manager dbSM2SignWithData:contentData userId:userId privateKey:privateData];
    NSData *publicData = [NSData dbDataFromHexString:self.publicKey];
    BOOL result = [DBSM2Manager dbSM2VerifyWithData:contentData sign:sign userId:userId publicKey:publicData];
    
    NSString *sign1 = [SM2Coded sm2_signPlainStringWithData:contentData userId:userId withPrivateKey:privateData];
    BOOL result1 =  [SM2Coded sm2_verifyWithPlainStringWithData:contentData withSigned:sign1 userId:userId withPublicKey:publicData];
    NSLog(@"");
}


- (NSData *)p_stringToHex:(NSString *)string {
    NSMutableData *hexData = [NSMutableData data];
    int idx;
    for (idx = 0; idx+2 <= string.length; idx+=2) {
        NSRange range = NSMakeRange(idx, 2);
        NSString *hexStr = [string substringWithRange:range];
        NSScanner *scanner = [NSScanner scannerWithString:hexStr];
        unsigned int intValue;
        [scanner scanHexInt:&intValue];
        [hexData appendBytes:&intValue length:1];
    }
    return hexData;
}

@end
