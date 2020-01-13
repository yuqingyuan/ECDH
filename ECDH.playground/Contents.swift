import Foundation

var publicKey: SecKey?
var privateKey: SecKey?

//MARK: - 生成公钥和私钥
func generateKey() -> (publicKey: SecKey?, privateKey: SecKey?)? {
    
    let attributes: [String: Any] = [kSecAttrKeySizeInBits as String: 256,
                                     kSecAttrKeyType as String: kSecAttrKeyTypeEC,
                                     kSecPrivateKeyAttrs as String: [kSecAttrIsPermanent as String: false]]
    var error: Unmanaged<CFError>?
    let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error)
    if let pKey = privateKey {
        let publicKey = SecKeyCopyPublicKey(pKey)
        return (publicKey, pKey)
    }
    return nil
}

//MARK: - 加密
func encryptedData(sourceData: Data, algorithm: SecKeyAlgorithm) -> Data? {
    
    guard publicKey != nil else {
        return nil
    }
    
    var error: Unmanaged<CFError>?
    let encrypted = SecKeyCreateEncryptedData(publicKey!,
                                              algorithm,
                                              sourceData as CFData,
                                              &error)
    if error == nil {
        return encrypted! as Data
    }
    
    return nil
}

//MARK: - 解密
func decryptedData(sourceData: Data, algorithm: SecKeyAlgorithm) -> String? {
    
    var error: Unmanaged<CFError>?
    let resData = SecKeyCreateDecryptedData(privateKey!,
                                            algorithm,
                                            sourceData as CFData,
                                            &error)
    if error == nil {
        return String(data: resData! as Data, encoding: .utf8)
    }
    return nil
}

//MARK: - 示例
if let (pKey, sKey) = generateKey() {
    publicKey = pKey
    privateKey = sKey
    
    let data = "ECDH".data(using: .utf8)
    let encrypted = encryptedData(sourceData: data!, algorithm: .eciesEncryptionStandardX963SHA512AESGCM)
    let decrypted = decryptedData(sourceData: encrypted!, algorithm: .eciesEncryptionStandardX963SHA512AESGCM)
    print(encrypted!)
    print(decrypted!)
}
