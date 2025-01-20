//
//  Decryptor.swift
//  Decrypt
//
//  Created by Mike Pollard on 20/01/2025.
//

protocol Decryptor {
    func decrypt(payload: String, secret: String) throws -> String
}
