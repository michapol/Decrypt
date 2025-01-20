//
//  DecryptionError.swift
//  Decrypt
//
//  Created by Mike Pollard on 20/01/2025.
//

enum DecryptionError: Error {
    case convertBase64ToData
    case convertDataToString
    case convertHexToData
    case decryptRSAData
    case payloadComponents
    case secKey
    case unsupportedRSA

    var localizedDescription: String {
        switch self {
        case .convertBase64ToData: return "Failed to convert base64 string to data"
        case .convertDataToString: return "Failed to convert data to string"
        case .convertHexToData: return "Failed to convert hex string to data"
        case .decryptRSAData: return "Failed to decrypt data with RSA"
        case .payloadComponents: return "The payload contains the wrong number of components"
        case .secKey: return "Failed to create a SecKey"
        case .unsupportedRSA: return "Unsupported RSA algorithm"
        }
    }
}
