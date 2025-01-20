//
//  Data+InitHex.swift
//  Decrypt
//
//  Created by Mike Pollard on 20/01/2025.
//

import Foundation

extension Data {
    init?(hex: String) {
        guard hex.count.isMultiple(of: 2) else {
            return nil
        }

        let chars = hex.map { $0 }
        let bytes = stride(from: 0, to: chars.count, by: 2)
            .map { String(chars[$0]) + String(chars[$0 + 1]) }
            .compactMap { UInt8($0, radix: 16) }

        guard hex.count / bytes.count == 2 else { return nil }
        self.init(bytes)
    }
}
