//
//  TestEVMVerifyMessageTests.swift
//  TestEVMVerifyMessageTests
//
//  Created by Hao Fu on 9/10/2024.
//

import XCTest
@testable import TestEVMVerifyMessage
import WalletCore
import web3swift
import Web3Core
import Flow
import BigInt
import CryptoKit

final class TestEVMVerifyMessageTests: XCTestCase {

    var provider: Web3HttpProvider!
    var web3: Web3!
    var hdWallet: HDWallet!
    let address = Flow.Address(hex: "0x8a3ad75d7a438f7e")
    let ethAddress = EthereumAddress("0x0000000000000000000000029a9d22fe53a8fc9f")!
    
    let magicValue = "0x1626ba7e"
    
    override func setUp() async throws {
        provider = try! await Web3HttpProvider(url: URL(string: "https://mainnet.evm.nodes.onflow.org")!, network: .Custom(networkID: 747))
        web3 = Web3(provider: provider)
        flow.configure(chainID: .mainnet)
        hdWallet = HDWallet(mnemonic: "kiwi erosion weather slam harvest move crumble zero juice steel start hotel", passphrase: "")!
    }
    
    
    //   f853c101888a3ad75d7a438f7e8365766df842b84089ee7683df3263811e143cf061bf26b6e7143c67a175014b26d6581572434b5a1319d285634a9d709d82750401972f30bc254b00e232a0f1d7fe1110f5bc743e
    /*
     [
       ["0x01"], // KeyIndex Array
       "0x8a3ad75d7a438f7e", // Flow Address
       "0x65766d", // Storage Path - "evm"
       [
         "0x89ee7683df3263811e143cf061bf26b6e7143c67a175014b26d6581572434b5a1319d285634a9d709d82750401972f30bc254b00e232a0f1d7fe1110f5bc743e" // Signature
       ]
     ]
     */
    
    func testSign() async throws {
        let pubkey = PublicKey(data: Data("04ef9854a8323d39ff7d742e904edfde35c04baff146f6fe2b7bdccced0f01e59998a157c1263ea07228cd4bc1a215c9df18a1e035ba4ff80bb92b5bdb67b2a42e".hexValue), type: .secp256k1Extended)!
        let data = "this is a message".data(using: .utf8)!
        print("data => \(data.hexValue)")
        
        guard let evmHashedData = Utilities.hashPersonalMessage(data) else { return }
        print("evmHashedData => \(evmHashedData.hexValue)")
        
        let joinData = Flow.DomainTag.user.normalize + evmHashedData
        print("joinData => \(joinData.hexValue)")
        
        let hashed = Data(SHA256.hash(data: joinData))
        print("hashed => \(hashed.hexValue)")
        
        let sig = Data("89ee7683df3263811e143cf061bf26b6e7143c67a175014b26d6581572434b5a1319d285634a9d709d82750401972f30bc254b00e232a0f1d7fe1110f5bc743e".hexValue)
        let result = pubkey.verify(signature: sig, message: hashed)
        print("result => \(result)")
        XCTAssertTrue(result)
    }
    
    func testABI() async throws {
        let contract = web3.contract(coaABI, at: EthereumAddress("0x0000000000000000000000029a8c7b0eda95e25f")!)!
        let encoded = "f853c101888a3ad75d7a438f7e8365766df842b84089ee7683df3263811e143cf061bf26b6e7143c67a175014b26d6581572434b5a1319d285634a9d709d82750401972f30bc254b00e232a0f1d7fe1110f5bc743e".hexValue
        
        // evmHashedData
        let evmHashedData = "29d8e880f198acda69a1cd82dd2c8e37edc6bb7e84da26527fb8a0cf7d482cda".hexValue
        let read = contract.createReadOperation("isValidSignature", parameters: [evmHashedData, encoded])!
        let response = try await read.callContractMethod()
        
        guard let data = response["0"] as? Data else {
            return
        }
        
        print(data.hexValue)
        XCTAssertEqual(data.hexValue.addHexPrefix(), magicValue)
    }

}
