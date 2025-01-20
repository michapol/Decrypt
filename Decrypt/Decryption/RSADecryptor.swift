//
//  RSADecryptor.swift
//  Decrypt
//
//  Created by Mike Pollard on 20/01/2025.
//

import Foundation

struct RSADecryptor: Decryptor {
    private let algorithm: SecKeyAlgorithm = .rsaEncryptionPKCS1
    private let attributes = [
        kSecAttrKeyType: kSecAttrKeyTypeRSA,
        kSecAttrKeyClass: kSecAttrKeyClassPrivate
    ] as CFDictionary

    func decrypt(payload: String, secret: String) throws -> String {
        var error: Unmanaged<CFError>?

        let privateKey = removeEncoding(pemEncoded: secret)
        guard let keyData = Data(base64Encoded: privateKey) else {
            throw DecryptionError.convertBase64ToData
        }
        guard let secKey = SecKeyCreateWithData(keyData as CFData, attributes, &error) else {
            throw DecryptionError.secKey
        }

        if SecKeyIsAlgorithmSupported(secKey, .decrypt, algorithm) {
            guard let data = Data(base64Encoded: payload) else {
                throw DecryptionError.convertBase64ToData
            }
            guard let decryptedData = SecKeyCreateDecryptedData(secKey, algorithm, data as CFData, &error) else {
                throw DecryptionError.decryptRSAData
            }
            guard let decryptedString = String(data: decryptedData as Data, encoding: .utf8) else {
                throw DecryptionError.convertDataToString
            }
            return decryptedString
        } else {
            throw DecryptionError.unsupportedRSA
        }
    }

    private func removeEncoding(pemEncoded pemString: String) -> String {
        let lines = pemString.components(separatedBy: "\n").filter { line in
            !line.hasPrefix("-----BEGIN") && !line.hasPrefix("-----END")
        }
        return lines.joined()
    }
}
