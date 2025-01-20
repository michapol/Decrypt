//
//  AESDecryptor.swift
//  Decrypt
//
//  Created by Mike Pollard on 20/01/2025.
//

import CryptoKit
import Foundation

struct AESDecryptor: Decryptor {
    func decrypt(payload: String, secret: String) throws -> String {
        let key: SymmetricKey

        guard let keyData = Data(hex: secret) else {
            throw DecryptionError.convertHexToData
        }
        key = SymmetricKey(data: keyData)

        let payload = payload.split(separator: ":")
        guard payload.count == 3 else {
            throw DecryptionError.payloadComponents
        }

        let ivHex = String(payload[0])
        let ciphertextHex = String(payload[1])
        let tagHex = String(payload[2])

        guard
            let iv = Data(hex: ivHex),
            let ciphertext = Data(hex: ciphertextHex),
            let tag = Data(hex: tagHex)
        else {
            throw DecryptionError.convertHexToData
        }

        let nonce: AES.GCM.Nonce = try .init(data: iv)

        let sealedBox: AES.GCM.SealedBox
        do {
            sealedBox = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertext, tag: tag)
        } catch {
            print("Error creating SealedBox: \(error)")
            throw error
        }

        do {
            let data = try AES.GCM.open(sealedBox, using: key)
            guard let string = String(data: data, encoding: .utf8) else {
                throw DecryptionError.convertDataToString
            }
            return string
        } catch {
            print("Error opening sealed box: \(error)")
            throw error
        }
    }
}
