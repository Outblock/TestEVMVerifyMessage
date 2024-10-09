//
//  Item.swift
//  TestEVMVerifyMessage
//
//  Created by Hao Fu on 9/10/2024.
//

import Foundation
import SwiftData

@Model
final class Item {
    var timestamp: Date
    
    init(timestamp: Date) {
        self.timestamp = timestamp
    }
}
