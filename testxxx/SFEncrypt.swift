//
//  SFEncrypt.swift
//  SSencrypt
//
//  Created by 孔祥波 on 7/8/16.
//  Copyright © 2016 Kong XiangBo. All rights reserved.
//

import Foundation
import CommonCrypto
import Security

let  supported_ciphers_iv_size = [
    0, 0, 16, 16, 16, 16, 8, 16, 16, 16, 8, 8, 8, 8, 16, 8, 8, 12
];

let supported_ciphers_key_size = [
    0, 16, 16, 16, 24, 32, 16, 16, 24, 32, 16, 8, 16, 16, 16, 32, 32, 32
];
let SODIUM_BLOCK_SIZE:UInt64 = 64
public enum  CryptoMethod:Int,CustomStringConvertible{
    //case NONE       =         -1
    case TABLE     =          0
    case RC4         =        1
    case RC4_MD5      =       2
    case AES_128_CFB   =      3
    case AES_192_CFB    =     4
    case AES_256_CFB     =    5
    case BF_CFB           =   6
    case CAMELLIA_128_CFB  =  7
    case CAMELLIA_192_CFB   = 8
    case CAMELLIA_256_CFB    = 9
    case CAST5_CFB  =         10
    case DES_CFB     =        11
    case IDEA_CFB     =       12
    case RC2_CFB       =      13
    case SEED_CFB       =     14
    case SALSA20         =    15
    case CHACHA20         =   16
    case CHACHA20IETF      =  17
    public var description: String {
        switch self {
            
        //case NONE:      return         "NONE"
        case TABLE:     return         "TABLE"
        case RC4:         return        "RC4"
        case RC4_MD5:      return       "RC4-MD5"
        case AES_128_CFB:   return      "AES-128-CFB"
        case AES_192_CFB:    return     "AES_192-CFB"
        case AES_256_CFB:     return    "AES-256-CFB"
        case BF_CFB:           return   "BF-CFB"
        case CAMELLIA_128_CFB:  return  "CAMELLIA-128-CFB"
        case CAMELLIA_192_CFB:   return "CAMELLIA-192-CFB"
        case CAMELLIA_256_CFB:    return "CAMELLIA-256-CFB"
        case CAST5_CFB:  return         "CAST5-CFB"
        case DES_CFB:     return        "DES-CFB"
        case IDEA_CFB:     return       "IDEA-CFB"
        case RC2_CFB:       return      "RC2-CFB"
        case SEED_CFB:       return     "SEED-CFB"
        case SALSA20:         return    "SALSA20"
        case CHACHA20:         return   "CHACHA20"
        case CHACHA20IETF:      return  "CHACHA20IETF"
         }
    }
    public var support:Bool {
        switch self {
        //case NONE:      return         false
        case TABLE:     return         false
        case RC4:         return        false
        case RC4_MD5:      return       false
        case AES_128_CFB:   return      true
        case AES_192_CFB:    return     true
        case AES_256_CFB:     return    true
        case BF_CFB:           return   false
        case CAMELLIA_128_CFB:  return  false
        case CAMELLIA_192_CFB:   return false
        case CAMELLIA_256_CFB:    return false
        case CAST5_CFB:  return         false
        case DES_CFB:     return        false
        case IDEA_CFB:     return       false
        case RC2_CFB:       return      false
        case SEED_CFB:       return     false
        case SALSA20:         return    true
        case CHACHA20:         return   true
        case CHACHA20IETF:      return  true
        }
    }
    public var ccmode:CCMode {
        switch self {
//            public var kCCModeECB: Int { get } 1
//        public var kCCModeCBC: Int { get } 2
//        public var kCCModeCFB: Int { get } 3
//        public var kCCModeCTR: Int { get } 4
//        public var kCCModeF8: Int { get } 5// Unimplemented for now (not included)
//        public var kCCModeLRW: Int { get } 6// Unimplemented for now (not included)
//        public var kCCModeOFB: Int { get } 7
//        public var kCCModeXTS: Int { get } 8
//        public var kCCModeRC4: Int { get } 9
//        public var kCCModeCFB8: Int { get } 10
        case RC4:         return        9
        case RC4_MD5:      return       9
        case AES_128_CFB:   return      3
        case AES_192_CFB:    return     3
        case AES_256_CFB:     return    3
        case BF_CFB:           return   3
//        case CAMELLIA_128_CFB:  return  false
//        case CAMELLIA_192_CFB:   return false
//        case CAMELLIA_256_CFB:    return false
        case CAST5_CFB:  return         3
        case DES_CFB:     return        3
        case IDEA_CFB:     return       3
        case RC2_CFB:       return      3
        case SEED_CFB:       return     3
//        case SALSA20:         return    true
//        case CHACHA20:         return   true
//        case CHACHA20IETF:      return  true

        default:
            return UInt32.max
        }
    }
//    func supported_ciphers() ->CCAlgorithm {
//        if self.rawValue != -1{
//            let algorithm = findCCAlgorithm(Int32(self.rawValue))
//            return algorithm
//        }else {
//            return UInt32.max
//        }
//        
//    }
    public var iv_size:Int {
        return supported_ciphers_iv_size[self.rawValue]
    }
    public var key_size:Int {
        return supported_ciphers_key_size[self.rawValue]
    }
    init(cipher:String){
        let up = cipher.uppercaseString
        var raw = 0
        switch up {
        //case "NONE":     raw = -1
        case "TABLE":     raw = 0
        case "RC4":         raw = 1
        case "RC4-MD5":      raw = 2
        case "AES-128-CFB":   raw = 3
        case "AES-192-CFB":    raw = 4
        case "AES-256-CFB":     raw = 5
        case "BF-CFB":           raw = 6
        case "CAMELLIA-128-CFB":  raw = 7
        case "CAMELLIA-192-CFB":   raw = 8
        case "CAMELLIA-256-CFB":    raw = 9
        case "CAST5-CFB":          raw = 10
        case "DES-CFB":     raw = 11
        case "IDEA-CFB":     raw = 12
        case "RC2-CFB":       raw = 13
        case "SEED-CFB":       raw = 14
        case "SALSA20":         raw = 15
        case "CHACHA20":         raw = 16
        case "CHACHA20IETF":      raw = 17
        default:
            raw = 0
        }
        self = CryptoMethod(rawValue:raw)!
    }
}


let  config_ciphers = [
    "table":false,
    "rc4":false,
    "rc4-md5":false,
    "aes-128-cfb":false,
    "aes-192-cfb":false,
    "aes-256-cfb":true,
    "bf-cfb":false,
    "camellia-128-cfb":false,
    "camellia-192-cfb":false,
    "camellia-256-cfb":false,
    "salsa20":false,
    "chacha20":false,
    "chacha20-ietf":false
]



let  ONETIMEAUTH_BYTES = 10
let  MAX_KEY_LENGTH =  64
let  MAX_IV_LENGTH = 16
let CLEN_BYTES = 2

class enc_ctx {
    var m:CryptoMethod
    static var sodiumInited = false
    var counter:UInt64 = 0
    var IV:NSData
    var ctx:CCCryptorRef
    func test (){
        let abcd = "aaaa"
        if abcd.hasPrefix("aa"){
            
        }
    }
    static func setupSodium() {
//        if !enc_ctx.sodiumInited {
//            if sodium_init() == -1 {
//                print("sodium_init failure")
//                AxLogger.log("sodium_init failure",level: .Error)
//            }
//        }
    }
    static func create_enc(op:CCOperation,key:NSData,iv:NSData,m:CryptoMethod) -> CCCryptorRef {
        
        let algorithm:CCAlgorithm = findCCAlgorithm(Int32(m.rawValue))
        var  cryptor :CCCryptorRef = nil
        
        let key_size = m.key_size
        let  createDecrypt:CCCryptorStatus = CCCryptorCreateWithMode(op, // operation
            m.ccmode, // mode CTR kCCModeRC4= 9
            algorithm,//CCAlgorithm(0),//kCCAlgorithmAES, // Algorithm
            CCPadding(0), // padding
            iv.bytes, // can be NULL, because null is full of zeros
            key.bytes, // key
            key_size, // keylength
            nil, //const void *tweak
            0, //size_t tweakLength,
            0, //int numRounds,
            0, //CCModeOptions options,
            &cryptor); //CCCryptorRef *cryptorRef
        if (createDecrypt == CCCryptorStatus(0)){
            return cryptor
        }else {
            AxLogger.log("create crypto ctx error")
            return nil
        }
        
    }
    init(key:NSData,iv:NSData,encrypt:Bool,method:CryptoMethod){
        
        if method.iv_size != iv.length {
            fatalError()
        }
        IV = iv
        m = method //
        let c = findCCAlgorithm(Int32(m.rawValue)) //m.supported_ciphers()
        if  c != UInt32.max {
            if encrypt {
                ctx = enc_ctx.create_enc(CCOperation(0), key: key,iv: iv,m:m)
            }else {
                ctx = enc_ctx.create_enc(CCOperation(1), key: key,iv: iv,m:m)
            }
        }else {
            ctx = nil
            if m == .SALSA20 || m == .CHACHA20 || m == .CHACHA20IETF {
                let sIV = NSMutableData.init(data: iv)
                sIV.length = 16
                IV = sIV
                enc_ctx.setupSodium()
            }else {
                
            }
           
        }
        
        
        
    }
    deinit {
        if ctx != nil {
            CCCryptorRelease(ctx)
        }
        
    }
}
class SSEncrypt {
   
    var m:CryptoMethod
    var send_ctx:enc_ctx?
    var recv_ctx:enc_ctx?
    //let block_size = 16
    var ramdonKey:NSData?
    static var iv_cache:[NSData] = []
    static func have_iv(i:NSData) ->Bool {
        for x in SSEncrypt.iv_cache {
            if x.isEqualToData(i){
                return true
            }
        }
        
        return false
        
    }
    deinit {
        
    }
    init(password:String,method:String) {
        
        m = CryptoMethod.init(cipher: method)

        ramdonKey  = SSEncrypt.evpBytesToKey(password,keyLen: m.key_size)
        if m.rawValue >= CryptoMethod.SALSA20.rawValue {
            let k = NSMutableData.init(data: ramdonKey!)
            k.length = 64
            ramdonKey  = k
        }
        print("\(m.description) key_size\(m.key_size) \(ramdonKey!.length)")
        let iv =  SSEncrypt.getSecureRandom(m.iv_size)
        AxLogger.log("\(m.key_size) \(m.iv_size) \(method)",level: .Debug)
        //        let x = password.dataUsingEncoding(NSUTF8StringEncoding)!
        //        let data = NSMutableData.init(length: 32)
        //memcpy((data?.mutableBytes)!, x.bytes, x.length)
        //receive_ctx = create_enc(CCOperation(kCCDecrypt), key: key)
        send_ctx = enc_ctx.init(key: ramdonKey!, iv: iv, encrypt: true,method:m )
        SSEncrypt.iv_cache.append(iv)
        
    }
    func recvCTX(iv:NSData){
        if SSEncrypt.have_iv(iv){
            print("cryto iv dup error")
            AxLogger.log("cryto iv dup error")
            recv_ctx = enc_ctx.init(key: ramdonKey!, iv: iv, encrypt: false,method:m)
            SSEncrypt.iv_cache.append(iv)
        }else {
            recv_ctx = enc_ctx.init(key: ramdonKey!, iv: iv, encrypt: false,method:m)
            SSEncrypt.iv_cache.append(iv)
        }
        
    }
    static func evpBytesToKey(password:String, keyLen:Int) ->NSData {
        let  md5Len:Int = 16
        
        let cnt = (keyLen - 1)/md5Len + 1
        let m = NSMutableData.init(length: cnt*md5Len)!
        let bytes = password.dataUsingEncoding(NSUTF8StringEncoding, allowLossyConversion: false)!
        // memcpy((m?.mutableBytes)!, bytes.bytes , password.characters.count)
        let md5 = bytes.md5
        m.setData(md5)
        
        
        // Repeatedly call md5 until bytes generated is enough.
        // Each call to md5 uses data: prev md5 sum + password.
        let d = NSMutableData.init(length: md5Len+bytes.length)!
        //d := make([]byte, md5Len+len(password))
        var start = 0
        for _ in 0 ..< cnt {//最长32,算法还不支持>32 的情况
            start += md5Len
            memcpy(d.mutableBytes,m.bytes , m.length)
            memcpy(d.mutableBytes+md5Len, bytes.bytes, bytes.length)
            let md5 = d.md5
            m.appendData(md5)
            if m.length >= keyLen {
                break;
            }
        }
        
        
        return m
    }
    func crypto_stream_xor_ic(cd:NSMutableData,md:NSData,mlen: UInt64, nd:NSData, ic:UInt64, kd:NSData)  ->Int32{
        
        let c:UnsafeMutablePointer<UInt8> = UnsafeMutablePointer<UInt8>.init(cd.mutableBytes)
        let m:UnsafePointer<UInt8> = UnsafePointer<UInt8>.init(md.bytes)
        let n:UnsafePointer<UInt8> = UnsafePointer<UInt8>.init(md.bytes)
        let k:UnsafePointer<UInt8> = UnsafePointer<UInt8>.init(kd.bytes)
        let xx = Int32(send_ctx!.m.rawValue)
        switch send_ctx!.m{
        case .SALSA20:
            return crypto_stream_salsa20_xor_ic(c, m, mlen, n, ic, k);
            //return crypto_stream_xor_icc(c, m, mlen, n, ic, k,xx)
        case .CHACHA20:
            return crypto_stream_chacha20_xor_ic(c, m, mlen, n, ic, k);
            //return crypto_stream_xor_icc(c, m, mlen, n, ic, k,xx)
        case .CHACHA20IETF:
            //return crypto_stream_chacha20_ietf_xor_ic(c, m, mlen, n, UInt32(ic), k);
            return 0 
        default:
            break
        }
        return 0
    }
    func genData(encrypt_bytes:NSData) ->NSData?{
        
        //Empty IV: initialization vector
        
        //self.iv = ivt
        let cipher:NSData?
        if recv_ctx == nil {
            let iv_len = send_ctx!.m.iv_size
            let iv  =  encrypt_bytes.subdataWithRange(NSMakeRange(0,iv_len))
            recvCTX(iv) //
            cipher = encrypt_bytes.subdataWithRange(NSMakeRange(iv_len,encrypt_bytes.length - iv_len ));
            print("iv \(iv) \(iv_len)")
            print("ramdonKey \(ramdonKey!)")
            print("data \(cipher!) \(cipher?.length) \(encrypt_bytes.length - iv_len)")
            print("encrypt_bytes 000 \(encrypt_bytes)")
        }else {
            cipher = encrypt_bytes
        }

        return cipher

    }
    func decrypt(encrypt_bytes:NSData) ->NSData?{
        if (  encrypt_bytes.length == 0 ) {
            
            return nil;
            
        }
        if recv_ctx == nil && encrypt_bytes.length < 16 {
            AxLogger.log("socket read less iv_len",level: .Error)
        }
        
        if let left = genData(encrypt_bytes) {
            
            // Alloc Data Out
            guard let  ctx =  recv_ctx else {
                print("ctx error")
                AxLogger.log("socket read less iv_len",level: .Error)
                return nil }
            
            if ctx.m.rawValue >= CryptoMethod.SALSA20.rawValue {
                print("iv \(ctx.IV)")
                print("ramdonKey \(ramdonKey!)")
                print("data \(left)")
                let padding = ctx.counter % SODIUM_BLOCK_SIZE;
                let cipher = NSMutableData.init(length:  left.length + Int(padding))
                
                //cipher.length += encrypt_bytes.length
                //            brealloc(cipher, iv_len + (padding + cipher->len) * 2, capacity);
                var  plain:NSMutableData
                if padding != 0 {
                    plain = NSMutableData.init(length: Int(padding))!
                    plain.appendData(left)
                    //plain.length =  plain.length + Int(padding)
                    //                brealloc(plain, plain->len + padding, capacity);
                    //                memmove(plain->array + padding, plain->array, plain->len);
                    //sodium_memzero(plain->array, padding);
                }else {
                    plain = NSMutableData.init(data: left)
                }
                //let enc_key = NSMutableData.init(data: ramdonKey!)
                //enc_key.length = ctx.m.key_size
                //            let ptr:UnsafeMutablePointer<UInt8> = UnsafeMutablePointer<UInt8>.init((cipher?.mutableBytes)!)
                //            let ptr2:UnsafePointer<UInt8> = UnsafePointer<UInt8>.init(encrypt_bytes.bytes)
                //let vvv = NSMutableData.init(data: ctx.IV)
                //vvv.length = 16
                crypto_stream_xor_ic(cipher! ,
                                     md: plain,
                                     mlen: UInt64(plain.length),
                                     nd: ctx.IV,
                                     ic: ctx.counter / SODIUM_BLOCK_SIZE,
                                     kd: ramdonKey!)
               
                
                print("padding \(padding) cipher \(cipher!)")
                ctx.counter += UInt64(left.length)
                
                 
                
                let result = cipher!.subdataWithRange(NSMakeRange(Int(padding), left.length + Int(padding) ))
                
                return result
                
                
                //todo add
//                int padding = ctx->counter % SODIUM_BLOCK_SIZE;
//                brealloc(plain, (plain->len + padding) * 2, capacity);
//                
//                if (padding) {
//                    brealloc(cipher, cipher->len + padding, capacity);
//                    memmove(cipher->array + iv_len + padding, cipher->array + iv_len,
//                        cipher->len - iv_len);
//                    sodium_memzero(cipher->array + iv_len, padding);
//                }
//                crypto_stream_xor_ic((uint8_t *)plain->array,
//                    (const uint8_t *)(cipher->array + iv_len),
//                    (uint64_t)(cipher->len - iv_len + padding),
//                    (const uint8_t *)ctx->evp.iv,
//                    ctx->counter / SODIUM_BLOCK_SIZE, enc_key,
//                    enc_method);
//                ctx->counter += cipher->len - iv_len;
//                if (padding) {
//                    memmove(plain->array, plain->array + padding, plain->len);
//                }

            }else {
                let cipherDataDecrypt:NSMutableData = NSMutableData.init(length: left.length)!;
                
                //alloc number of bytes written to data Out
                var  outLengthDecrypt:NSInteger = 0
                
                //Update Cryptor
                let updateDecrypt:CCCryptorStatus = CCCryptorUpdate(ctx.ctx,
                                                                    left.bytes, //const void *dataIn,
                    left.length,  //size_t dataInLength,
                    cipherDataDecrypt.mutableBytes, //void *dataOut,
                    cipherDataDecrypt.length, // size_t dataOutAvailable,
                    &outLengthDecrypt); // size_t *dataOutMoved)
                
                if (updateDecrypt == CCCryptorStatus(0))
                {
                    //Cut Data Out with nedded length
                    cipherDataDecrypt.length = outLengthDecrypt;
                    
                    // Data to String
                    //NSString* cipherFinalDecrypt = [[NSString alloc] initWithData:cipherDataDecrypt encoding:NSUTF8StringEncoding];
                    
                    //Final Cryptor
                    let final:CCCryptorStatus = CCCryptorFinal(ctx.ctx, //CCCryptorRef cryptorRef,
                        cipherDataDecrypt.mutableBytes, //void *dataOut,
                        cipherDataDecrypt.length, // size_t dataOutAvailable,
                        &outLengthDecrypt); // size_t *dataOutMoved)
                    
                    if (final != CCCryptorStatus( 0))
                    {
                        AxLogger.log("decrypt CCCryptorFinal failure")
                        //Release Cryptor
                        //CCCryptorStatus release =
                        //CCCryptorRelease(cryptor); //CCCryptorRef cryptorRef
                    }
                    
                    return cipherDataDecrypt ;//cipherFinalDecrypt;
                }else {
                    print("111 decrypt no Data")
                    AxLogger.log("decrypt CCCryptorUpdate failure")
                }

            }
            
        }else {
            print("000 decrypt no Data")
            AxLogger.log("decrypt no Data")
        }
        
        
        
        return nil
    }
    static func getSecureRandom(bytesCount:Int) ->NSData {
        // Swift
        //import Security
        
        //let bytesCount = 4 // number of bytes
        //var randomNum: UInt32 = 0 // variable for random unsigned 32 bit integer
        var randomBytes = [UInt8](count: bytesCount, repeatedValue: 0) // array to hold randoms bytes
        
        // Gen random bytes
        SecRandomCopyBytes(kSecRandomDefault, bytesCount, &randomBytes)
        
        // Turn bytes into data and pass data bytes into int
        return NSData(bytes: randomBytes, length: bytesCount) //getBytes(&randomNum, length: bytesCount)
    }
//    func padding(d:NSData) ->NSData{
//        let l = d.length % block_size
//        if l != 0 {
//            let x = NSMutableData.init(data: d)
//            x.length += l
//            return x
//        }else {
//            return d
//        }
//    }
    func encrypt(encrypt_bytes:NSData) ->NSData?{
        
        //let iv:NSData = NSData();
        //[NSMutableData dataWithLength:kCCBlockSizeAES128]
        
        
        
        //let encrypt_bytes = padding(encrypt_bytes_org)
        //alloc number of bytes written to data Out
        guard let ctx = send_ctx else {
            AxLogger.log("ss ctx error")
            return nil
        }
        
        //Update Cryptor
        if ctx.m.rawValue >= CryptoMethod.SALSA20.rawValue {
            debugLog("111 encrypt")
              let padding = ctx.counter % SODIUM_BLOCK_SIZE;
            let cipher = NSMutableData.init(length:  2*(encrypt_bytes.length + Int(padding)))
            
              //cipher.length += encrypt_bytes.length
//            brealloc(cipher, iv_len + (padding + cipher->len) * 2, capacity);
            var  plain:NSMutableData
            if padding != 0 {
                plain = NSMutableData.init(length: Int(padding))!
                plain.appendData(encrypt_bytes)
                //plain.length =  plain.length + Int(padding)
//                brealloc(plain, plain->len + padding, capacity);
//                memmove(plain->array + padding, plain->array, plain->len);
                //sodium_memzero(plain->array, padding);
            }else {
                 plain = NSMutableData.init(data: encrypt_bytes)
            }
            debugLog("222 encrypt")
            //let enc_key = NSMutableData.init(data: ramdonKey!)
            //enc_key.length = send_ctx!.m.key_size
//            let ptr:UnsafeMutablePointer<UInt8> = UnsafeMutablePointer<UInt8>.init((cipher?.mutableBytes)!)
//            let ptr2:UnsafePointer<UInt8> = UnsafePointer<UInt8>.init(encrypt_bytes.bytes)
            debugLog("333 encrypt")
            crypto_stream_xor_ic(cipher! ,
                                 md: plain,
                                 mlen: UInt64(plain.length),
                                 nd: ctx.IV,
                                 ic: ctx.counter / SODIUM_BLOCK_SIZE,
                                 kd: ramdonKey!)
            var result:NSMutableData
            if ctx.counter == 0 {
            
                result = NSMutableData.init(data: ctx.IV)
                result.length = m.iv_size
            }else {
                result = NSMutableData.init()
            }
            
            ctx.counter += UInt64(encrypt_bytes.length)
            
            
            if padding != 0 {
//                memmove(cipher->array + iv_len,
//                    cipher->array + iv_len + padding, cipher->len);
                result.appendData(cipher!.subdataWithRange(NSMakeRange(Int(padding), encrypt_bytes.length
                    )))
            }else {
                result.appendData(cipher!.subdataWithRange(NSMakeRange(0, encrypt_bytes.length
                    )))

            }
            debugLog("000 encrypt")
            return result
        }else {
            var  outLength:NSInteger = 0 ;
            // Alloc Data Out
            let cipherData:NSMutableData = NSMutableData.init(length: encrypt_bytes.length)!;
            let  update:CCCryptorStatus = CCCryptorUpdate(ctx.ctx,
                                                          encrypt_bytes.bytes,
                                                          encrypt_bytes.length,
                                                          cipherData.mutableBytes,
                                                          cipherData.length,
                                                          &outLength);
            if (update == CCCryptorStatus(0))
            {
                //Cut Data Out with nedded length
                cipherData.length = outLength;
                
                //Final Cryptor
                let final:CCCryptorStatus = CCCryptorFinal(ctx.ctx, //CCCryptorRef cryptorRef,
                    cipherData.mutableBytes, //void *dataOut,
                    cipherData.length, // size_t dataOutAvailable,
                    &outLength); // size_t *dataOutMoved)
                
                if (final == CCCryptorStatus(0))
                {
                    
                    //CCCryptorRelease(cryptor )
                }
                if ctx.counter == 0 {
                    ctx.counter += 1
                    let d:NSMutableData = NSMutableData()
                    d.appendData(ctx.IV);
                    
                    d.appendData(cipherData)
                    return d
                }else {
                    return cipherData
                }
                
                //AxLogger.log("cipher length:\(d.length % 16)")
                
                
            }

        }
        
        return nil
    }
    
    func ss_onetimeauth(buffer:NSData) ->NSData {
        
        let keyData = NSMutableData.init(data: send_ctx!.IV)
        //let key_size = send_ctx!.m.key_size
        //let ramdonK2 = ramdonKey?.subdataWithRange(NSMakeRange(0, key_size))
        keyData.appendData(ramdonKey!)
        let hash = buffer.hmacsha1(keyData)
        //let result = NSMutableData.init(data: buffer)
        //result.appendData(hash)
        //=result.sha1
        return hash
    }
    func ss_gen_hash(buffer:NSData,counter:Int32) ->NSData {
        
        let blen = buffer.length
        var chunk_len:UInt16 = UInt16(blen).bigEndian
        var c =  counter.bigEndian
        
        let keyData = NSMutableData.init(data: send_ctx!.IV)
        keyData.appendBytes(&c, length: 4)
        let hash = buffer.hmacsha1(keyData)
        let result = NSMutableData.init(bytes: &chunk_len, length: 2)
        
        result.appendData(hash)
        //result.appendData(buffer)
        //=result.sha1
        return result
    }
}
