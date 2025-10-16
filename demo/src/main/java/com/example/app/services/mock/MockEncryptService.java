package com.example.app.services.mock;

import com.example.app.crypto.EncryptService;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

public class MockEncryptService implements EncryptService {
    
    // Store plaintext by cipher for demo purposes
    private final Map<String, String> plaintextStore = new HashMap<>();
    
    @Override
    public EncryptResult encrypt(String plaintext, boolean useEncryption) {
        if (!useEncryption) {
            String base64Plain = Base64.getEncoder().encodeToString(plaintext.getBytes());
            plaintextStore.put(base64Plain, plaintext);
            return new EncryptResult(
                base64Plain,
                "",
                ""
            );
        }
        
        Random random = new Random();
        
        // Generate fake cipher
        byte[] fakeCipher = new byte[plaintext.length() + 16]; // Add some padding
        random.nextBytes(fakeCipher);
        String base64Cipher = Base64.getEncoder().encodeToString(fakeCipher);
        
        // Store the original plaintext with the cipher key
        plaintextStore.put(base64Cipher, plaintext);
        
        // Generate fake wrapped AES key
        byte[] fakeWrappedKey = new byte[256]; // RSA-2048 encrypted size
        random.nextBytes(fakeWrappedKey);
        String base64WrappedKey = Base64.getEncoder().encodeToString(fakeWrappedKey);
        
        // Generate fake IV
        byte[] fakeIv = new byte[16]; // AES IV size
        random.nextBytes(fakeIv);
        String ivBase64 = Base64.getEncoder().encodeToString(fakeIv);
        
        return new EncryptResult(base64Cipher, base64WrappedKey, ivBase64);
    }
    
    @Override
    public String decrypt(String base64Cipher, String base64WrappedKey, String ivBase64) {
        // Return the original plaintext if found, otherwise return error message
        String plaintext = plaintextStore.get(base64Cipher);
        if (plaintext != null) {
            return plaintext;
        }
        return "[Error] Original plaintext not found. This may be a received message.";
    }
}
