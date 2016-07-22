//
//  EncryptExtension.swift
//  Surf
//
//  Created by 孔祥波 on 7/14/16.
//  Copyright © 2016 yarshure. All rights reserved.
//

//
//  HMAC.swift
//
//  Created by Mihael Isaev on 21.04.15.
//  Copyright (c) 2014 Mihael Isaev inc. All rights reserved.
//
// ***********************************************************
//
// How to import CommonCrypto in Swift project without Obj-c briging header
//
// To work around this create a directory called CommonCrypto in the root of the project using Finder.
// In this directory create a file name module.map and copy the following into the file.
// You will need to alter the paths to ensure they point to the headers on your system.
//
// module CommonCrypto [system] {
//     header "/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS.sdk/usr/include/CommonCrypto/CommonCrypto.h"
//     export *
// }
// To make this module visible to Xcode, go to Build Settings, Swift Compiler – Search Paths
// and set Import Paths to point to the directory that contains the CommonCrypto directory.
//
// You should now be able to use import CommonCrypto in your Swift code.
//
// You have to set the Import Paths in every project that uses your framework so that Xcode can find it.
//
// ***********************************************************
//

import Foundation
import CommonCrypto

extension String {
    var md5x: String {
        return HMAC.hash(self, algo: HMACAlgo.MD5)
    }
    
    var sha1: String {
        return HMAC.hash(self, algo: HMACAlgo.SHA1)
    }
    
    var sha224: String {
        return HMAC.hash(self, algo: HMACAlgo.SHA224)
    }
    
    var sha256: String {
        return HMAC.hash(self, algo: HMACAlgo.SHA256)
    }
    
    var sha384: String {
        return HMAC.hash(self, algo: HMACAlgo.SHA384)
    }
    
    var sha512: String {
        return HMAC.hash(self, algo: HMACAlgo.SHA512)
    }
}
extension NSData {
    var md5x: NSData {
        return HMAC.hashData(self, algo: HMACAlgo.MD5)
    }
    
    var sha1: NSData {
        return HMAC.hashData(self, algo: HMACAlgo.SHA1)
    }
    
    var sha224: NSData {
        return HMAC.hashData(self, algo: HMACAlgo.SHA224)
    }
    
    var sha256: NSData {
        return HMAC.hashData(self, algo: HMACAlgo.SHA256)
    }
    
    var sha384: NSData {
        return HMAC.hashData(self, algo: HMACAlgo.SHA384)
    }
    
    var sha512: NSData {
        return HMAC.hashData(self, algo: HMACAlgo.SHA512)
    }
}
extension NSData {
//    func hmac(algorithm: HMACAlgo, cKey: NSData) -> NSData {
//        
//        
//        var result = [CUnsignedChar](count: Int(algorithm.digestLength()), repeatedValue: 0)
//        let length : Int = cKey.length
//        let data : Int = self.length
//        CCHmac(algorithm.toCCHmacAlgorithm(), cKey!,length , self, data, &result)
//        
//        let hmacData:NSData = NSData(bytes: result, length: (Int(algorithm.digestLength())))
//        
//        
//        
//        return hmacData
//    }
    
    
    func hmacsha1(keyData: NSData) -> NSData {
        let algorithm = HMACAlgo.SHA1
        let digestLen = algorithm.digestLength()
        let result = UnsafeMutablePointer<CUnsignedChar>.alloc(digestLen)
        
        CCHmac(algorithm.toCCEnum(), keyData.bytes, keyData.length, self.bytes, Int(self.length), result)
        let data = NSData(bytes: result, length: digestLen)
        result.dealloc(digestLen)
        return data.subdataWithRange(NSMakeRange(0, 10))
        //.base64EncodedStringWithOptions(NSDataBase64EncodingOptions.Encoding64CharacterLineLength)
    }

}

public struct HMAC {
    
    static func hash(inp: String, algo: HMACAlgo) -> String {
        if let stringData = inp.dataUsingEncoding(NSUTF8StringEncoding, allowLossyConversion: false) {
            return hexStringFromData(digest(stringData, algo: algo))
        }
        return ""
    }
    static func hashData(inp: NSData, algo: HMACAlgo) -> NSData {
        //if let stringData = inp.dataUsingEncoding(NSUTF8StringEncoding, allowLossyConversion: false) {
            return digest(inp, algo: algo)
        //}
        //return
    }
    private static func digest(input : NSData, algo: HMACAlgo) -> NSData {
        let digestLength = algo.digestLength()
        var hash = [UInt8](count: digestLength, repeatedValue: 0)
        switch algo {
        case .MD5:
            CC_MD5(input.bytes, UInt32(input.length), &hash)
            break
        case .SHA1:
            CC_SHA1(input.bytes, UInt32(input.length), &hash)
            break
        case .SHA224:
            CC_SHA224(input.bytes, UInt32(input.length), &hash)
            break
        case .SHA256:
            CC_SHA256(input.bytes, UInt32(input.length), &hash)
            break
        case .SHA384:
            CC_SHA384(input.bytes, UInt32(input.length), &hash)
            break
        case .SHA512:
            CC_SHA512(input.bytes, UInt32(input.length), &hash)
            break
        }
        return NSData(bytes: hash, length: digestLength)
    }
    
    private static func hexStringFromData(input: NSData) -> String {
        var bytes = [UInt8](count: input.length, repeatedValue: 0)
        input.getBytes(&bytes, length: input.length)
        
        var hexString = ""
        for byte in bytes {
            hexString += String(format:"%02x", UInt8(byte))
        }
        
        return hexString
    }
}

enum HMACAlgo {
    case MD5, SHA1, SHA224, SHA256, SHA384, SHA512
    
    func digestLength() -> Int {
        var result: CInt = 0
        switch self {
        case .MD5:
            result = CC_MD5_DIGEST_LENGTH
        case .SHA1:
            result = CC_SHA1_DIGEST_LENGTH
        case .SHA224:
            result = CC_SHA224_DIGEST_LENGTH
        case .SHA256:
            result = CC_SHA256_DIGEST_LENGTH
        case .SHA384:
            result = CC_SHA384_DIGEST_LENGTH
        case .SHA512:
            result = CC_SHA512_DIGEST_LENGTH
        }
        return Int(result)
    }
    func toCCEnum() -> CCHmacAlgorithm {
        var result: Int = 0
        switch self {
        case .MD5:
            result = kCCHmacAlgMD5
        case .SHA1:
            result = kCCHmacAlgSHA1
        case .SHA224:
            result = kCCHmacAlgSHA224
        case .SHA256:
            result = kCCHmacAlgSHA256
        case .SHA384:
            result = kCCHmacAlgSHA384
        case .SHA512:
            result = kCCHmacAlgSHA512
        }
        return CCHmacAlgorithm(result)
    }
}
