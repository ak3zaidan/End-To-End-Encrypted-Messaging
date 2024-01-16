To make an end to end encrypted messaging service follow the following steps:


1. During user registration using the following code (always import CryptoKit)

            let privateKey = Curve25519.KeyAgreement.PrivateKey()
            let privateKeyData = privateKey.rawRepresentation
            let privateKeyBase64 = privateKeyData.base64EncodedString()
            
            let publicKey = privateKey.publicKey
            let publicKeyData = publicKey.rawRepresentation
            let publicKeyBase64 = publicKeyData.base64EncodedString()

   Now Store the public key in the data base and store the private key on the client side. The private key should never leave the clients photo.
   For this case Apple keychain can be used.

       func save(userUID: String, privatekey: String) {
        let passwordData = privatekey.data(using: .utf8)!
        
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrSynchronizable as String: kCFBooleanTrue!,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlocked,
            kSecAttrService as String: "hustles/\(userUID)",
            kSecAttrAccount as String: userUID,
            kSecValueData as String: passwordData
        ]
        SecItemAdd(query as CFDictionary, nil)
    }


2. To send a message you have to use the other users public key and your private key to create a symmetric key that will encrypt a message:
   You also have to specify a Salt to make your encrypted string more secure. A strong protocol will always change the salt but for this example
   you can use a constant one.

                  func encrypt(text: String, i: Int) -> String? {
                    let temp_pub = chats[i].user.publicKey
                    if let publicKeyData = Data(base64Encoded: temp_pub) {
                        do {
                            let recipientPublicKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: publicKeyData)
                            let basic_salt = "Random Salt".data(using: .utf8)!
                            if let temp_priv = read(){
                                if let privateKeyData = Data(base64Encoded: temp_priv) {
                                    do {
                                        let privateKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privateKeyData)
                                        let sharedSecret = try! privateKey.sharedSecretFromKeyAgreement(with: recipientPublicKey)
                                        let symmetricKey = sharedSecret.hkdfDerivedSymmetricKey(using: SHA256.self,
                                                                                                salt: basic_salt,
                                                                                                sharedInfo: Data(),
                                                                                                outputByteCount: 32)
                                        let sensitiveMessage = text.data(using: .utf8)!
                                        let encryptedData = try! ChaChaPoly.seal(sensitiveMessage, using: symmetricKey).combined
                                        let final = encryptedData.base64EncodedString()
                                        return final
                                    } catch {
                                        return nil
                                    }
                                }
                            }
                        } catch { return nil }
                    }
                    return nil
                }

3. To decyrpt a message do the same thing but in reverse:

                func decrypt(text: String, key: String) -> String? {
                    if let publicKeyData = Data(base64Encoded: key) {
                        do {
                            let senderPublicKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: publicKeyData)
                            let basic_salt = "Hustlers Salt".data(using: .utf8)!
                            if let temp_priv = read(){
                                if let privateKeyData = Data(base64Encoded: temp_priv) {
                                    do {
                                        let privateKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privateKeyData)
                                        let sharedSecret = try! privateKey.sharedSecretFromKeyAgreement(with: senderPublicKey)
                                        let symmetricKey = sharedSecret.hkdfDerivedSymmetricKey(using: SHA256.self,
                                                                                                salt: basic_salt,
                                                                                                sharedInfo: Data(),
                                                                                                outputByteCount: 32)
                                        if let data = Data(base64Encoded: text) {
                                            let sealedBox = try! ChaChaPoly.SealedBox(combined: data)
                                            let decryptedData = try! ChaChaPoly.open(sealedBox, using: symmetricKey)
            
                                            let final = String(data: decryptedData, encoding: .utf8)
                                            return final ?? nil
                                        }
                                    } catch { return nil }
                                }
                            }
                        } catch { return nil }
                    }
                    return nil
                }



4. To read a private key from keychain you can do:

                func read() -> String? {
                    if let key = priv_Key_Saved {
                        return key
                    } else {
                        guard let uid = Auth.auth().currentUser?.uid else { return nil }
                        let query: [String: Any] = [
                            kSecClass as String: kSecClassGenericPassword,
                            kSecAttrSynchronizable as String: kCFBooleanTrue!,
                            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlocked,
                            kSecAttrService as String: "hustles/\(uid)",
                            kSecAttrAccount as String: uid,
                            kSecReturnData as String: kCFBooleanTrue!,
                            kSecMatchLimit as String: kSecMatchLimitOne
                        ]
                        
                        var item: CFTypeRef?
                        let status = SecItemCopyMatching(query as CFDictionary, &item)
                        
                        guard status == errSecSuccess else {
                            return nil
                        }
            
                        if let keyData = item as? Data,
                           let keyString = String(data: keyData, encoding: .utf8) {
                            return keyString
                        }
                        return nil
                    }
                }
