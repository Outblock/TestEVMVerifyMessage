//
//  TestSecureEnclave.swift
//  TestEVMVerifyMessageTests
//
//  Created by Hao Fu on 12/10/2024.
//

import XCTest
import Foundation
import CryptoKit

final class TestSecureEnclave: XCTestCase {
    
    let data = "this is a message".data(using: .utf8)!
    var dataToSign: Data {
        Data(SHA256.hash(data: data))
    }
    
    func testSE() throws {
        let pk1 = try SecureEnclave.P256.Signing.PrivateKey()
        let pk2 = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: pk1.dataRepresentation)
        XCTAssertEqual(pk1.publicKey.rawRepresentation, pk2.publicKey.rawRepresentation)
        let sig = try pk1.signature(for: dataToSign)
        let isValid = pk2.publicKey.isValidSignature(sig, for: dataToSign)
        XCTAssertTrue(isValid)
    }
    
    func testManyTimes() throws {
        for i in 0..<100 {
            print(i)
            try testSE()
        }
    }
    
}
