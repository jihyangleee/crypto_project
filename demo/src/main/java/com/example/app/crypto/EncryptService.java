package com.example.app.crypto;

public interface EncryptService {
    
    /**
     * Encrypt plaintext with AES and wrap session key with RSA
     * @return Base64 encoded cipher and wrapped key
     */
    EncryptResult encrypt(String plaintext, boolean useEncryption);
    
    /**
     * Decrypt ciphertext using wrapped session key
     */
    String decrypt(String base64Cipher, String base64WrappedKey, String ivBase64);
    
    class EncryptResult {
        public final String base64Cipher;
        public final String base64WrappedKey;
        public final String ivBase64;
        
        public EncryptResult(String base64Cipher, String base64WrappedKey, String ivBase64) {
            this.base64Cipher = base64Cipher;
            this.base64WrappedKey = base64WrappedKey;
            this.ivBase64 = ivBase64;
        }
    }
}
