//
//  Program.swift
//  Decrypt
//
//  Created by Mike Pollard on 20/01/2025.
//

import ArgumentParser

@main
struct Program: ParsableCommand {
    @Option(help: "Specify AES or RSA") var algorithm: String = SupportedAlgorithm.aes.rawValue

    public func run() {
        let algorithm = SupportedAlgorithm(rawValue: algorithm)

        do {
            switch algorithm {
            case .aes:  try aesDemo()
            case .rsa:  try rsaDemo()
            case .none: print("Invalid Algorithm Specified!")
            }
        } catch {
            print(error.localizedDescription)
        }
    }

    private func aesDemo() throws {
        let demoSecret = DemoData.AES.secret
        let demoPayload = DemoData.AES.payload

        let decryptedString = try AESDecryptor().decrypt(payload: demoPayload, secret: demoSecret)

        print("Decrypted String: \(String(describing: decryptedString))")
    }

    private func rsaDemo() throws {
        let demoSecret = DemoData.RSA.secret
        let demoPayload = DemoData.RSA.payload

        let decryptedString = try RSADecryptor().decrypt(payload: demoPayload, secret: demoSecret)
        
        print("Decrypted String: \(String(describing: decryptedString))")
    }
}

enum SupportedAlgorithm: String {
    case aes
    case rsa
}
