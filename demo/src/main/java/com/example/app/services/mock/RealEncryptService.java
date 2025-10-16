package com.example.app.services.mock;

import com.example.app.crypto.EncryptService;
import com.example.app.model.CryptoUtil;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Base64;

public class RealEncryptService implements EncryptService {
    
    private final RealKeyService keyService;
    
    public RealEncryptService(RealKeyService keyService) {
        this.keyService = keyService;
    }
    
    @Override
    public EncryptResult encrypt(String plaintext, boolean useEncryption) {
        try {
            if (!useEncryption) {
                // No encryption, just encode as base64
                return new EncryptResult(
                    Base64.getEncoder().encodeToString(plaintext.getBytes()),
                    "",
                    ""
                );
            }
            
            // Generate AES session key (new key for each message)
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(128);
            SecretKey sessionKey = keyGen.generateKey();
            
            // Generate random IV
            byte[] iv = new byte[12]; // GCM standard IV size
            SecureRandom random = new SecureRandom();
            random.nextBytes(iv);
            
            // Encrypt plaintext with AES
            byte[] ciphertext = CryptoUtil.aesEncrypt(sessionKey, plaintext.getBytes(), iv);
            String base64Cipher = Base64.getEncoder().encodeToString(ciphertext);
            
            // Wrap session key with RSA public key
            PublicKey publicKey = keyService.getPublicKey();
            byte[] wrappedKey = CryptoUtil.rsaEncrypt(publicKey, sessionKey.getEncoded());
            String base64WrappedKey = Base64.getEncoder().encodeToString(wrappedKey);
            
            String ivBase64 = Base64.getEncoder().encodeToString(iv);
            
            return new EncryptResult(base64Cipher, base64WrappedKey, ivBase64);
            
        } catch (Exception e) {
            throw new RuntimeException("Encryption failed", e);
        }
    }
    
    @Override
    public String decrypt(String base64Cipher, String base64WrappedKey, String ivBase64) {
        try {
            if (base64WrappedKey.isEmpty()) {
                // No encryption was used, just decode base64
                byte[] decoded = Base64.getDecoder().decode(base64Cipher);
                return new String(decoded);
            }
            
            // Decode base64 inputs
            byte[] ciphertext = Base64.getDecoder().decode(base64Cipher);
            byte[] wrappedKey = Base64.getDecoder().decode(base64WrappedKey);
            byte[] iv = Base64.getDecoder().decode(ivBase64);
            
            // Unwrap session key with RSA private key
            PrivateKey privateKey = keyService.getPrivateKey();
            byte[] sessionKeyBytes = CryptoUtil.rsaDecrypt(privateKey, wrappedKey);
            SecretKey sessionKey = CryptoUtil.aesKeyFromBytes(sessionKeyBytes);
            
            // Decrypt ciphertext with AES
            byte[] plaintext = CryptoUtil.aesDecrypt(sessionKey, ciphertext, iv);
            
            return new String(plaintext);
            
        } catch (Exception e) {
            throw new RuntimeException("Decryption failed: " + e.getMessage(), e);
        }
    }
}
