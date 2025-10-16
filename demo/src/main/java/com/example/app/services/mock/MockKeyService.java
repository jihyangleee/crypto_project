package com.example.app.services.mock;

import com.example.app.crypto.KeyService;
import com.example.app.domain.KeyInfo;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Random;

public class MockKeyService implements KeyService {
    
    private KeyInfo currentKeyInfo;
    
    @Override
    public KeyInfo generateKeyPair(String algorithm, int bits) {
        // Generate mock key info
        currentKeyInfo = new KeyInfo();
        currentKeyInfo.setAlgorithm(algorithm);
        currentKeyInfo.setKeyLength(bits);
        
        // Generate fake fingerprint
        Random random = new Random();
        byte[] fakeFingerprint = new byte[32];
        random.nextBytes(fakeFingerprint);
        StringBuilder hex = new StringBuilder();
        for (byte b : fakeFingerprint) {
            hex.append(String.format("%02x", b));
        }
        currentKeyInfo.setFingerprintHex(hex.toString());
        
        // Generate fake PEM
        byte[] fakeKey = new byte[294]; // Typical RSA public key size
        random.nextBytes(fakeKey);
        String base64Key = Base64.getEncoder().encodeToString(fakeKey);
        String pem = "-----BEGIN PUBLIC KEY-----\n";
        for (int i = 0; i < base64Key.length(); i += 64) {
            pem += base64Key.substring(i, Math.min(i + 64, base64Key.length())) + "\n";
        }
        pem += "-----END PUBLIC KEY-----";
        currentKeyInfo.setPublicKeyPem(pem);
        currentKeyInfo.setHasPrivateKey(true);
        
        return currentKeyInfo;
    }
    
    @Override
    public void savePublicKey(String path) {
        System.out.println("Mock: Saving public key to " + path);
    }
    
    @Override
    public void loadPublicKey(String path) {
        System.out.println("Mock: Loading public key from " + path);
        generateKeyPair("RSA", 2048); // Simulate loading
    }
    
    @Override
    public void savePrivateKey(String path) {
        System.out.println("Mock: Saving private key to " + path);
    }
    
    @Override
    public void loadPrivateKey(String path) {
        System.out.println("Mock: Loading private key from " + path);
        if (currentKeyInfo != null) {
            currentKeyInfo.setHasPrivateKey(true);
        }
    }
    
    @Override
    public KeyInfo getCurrentKeyInfo() {
        return currentKeyInfo;
    }
}
