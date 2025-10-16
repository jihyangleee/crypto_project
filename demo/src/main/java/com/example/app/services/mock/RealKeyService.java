package com.example.app.services.mock;

import com.example.app.crypto.KeyService;
import com.example.app.domain.KeyInfo;
import com.example.app.model.RSAKeyManager;

import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;

public class RealKeyService implements KeyService {
    
    private final RSAKeyManager keyManager = new RSAKeyManager();
    private KeyInfo currentKeyInfo;
    
    @Override
    public KeyInfo generateKeyPair(String algorithm, int bits) {
        try {
            KeyPair kp = keyManager.generateKeyPair(bits);
            
            currentKeyInfo = new KeyInfo();
            currentKeyInfo.setAlgorithm(algorithm);
            currentKeyInfo.setKeyLength(bits);
            
            // Calculate fingerprint (SHA-256 of public key)
            PublicKey pub = kp.getPublic();
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(pub.getEncoded());
            StringBuilder hex = new StringBuilder();
            for (byte b : digest) {
                hex.append(String.format("%02x", b));
            }
            currentKeyInfo.setFingerprintHex(hex.toString());
            
            // Get PEM format
            String pem = keyManager.getPublicKeyPem();
            currentKeyInfo.setPublicKeyPem(pem);
            currentKeyInfo.setHasPrivateKey(true);
            
            return currentKeyInfo;
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate key pair", e);
        }
    }
    
    @Override
    public void savePublicKey(String path) {
        try {
            keyManager.savePublicKey(Paths.get(path));
        } catch (Exception e) {
            throw new RuntimeException("Failed to save public key", e);
        }
    }
    
    @Override
    public void loadPublicKey(String path) {
        try {
            keyManager.loadPublicKey(Paths.get(path));
            // Update key info (simplified)
            currentKeyInfo = new KeyInfo();
            currentKeyInfo.setAlgorithm("RSA");
            currentKeyInfo.setKeyLength(2048);
            currentKeyInfo.setPublicKeyPem("(Loaded from file)");
            currentKeyInfo.setHasPrivateKey(false);
        } catch (Exception e) {
            throw new RuntimeException("Failed to load public key", e);
        }
    }
    
    @Override
    public void savePrivateKey(String path) {
        try {
            keyManager.savePrivateKey(Paths.get(path));
        } catch (Exception e) {
            throw new RuntimeException("Failed to save private key", e);
        }
    }
    
    @Override
    public void loadPrivateKey(String path) {
        try {
            keyManager.loadPrivateKey(Paths.get(path));
            if (currentKeyInfo != null) {
                currentKeyInfo.setHasPrivateKey(true);
            }
        } catch (Exception e) {
            throw new RuntimeException("Failed to load private key", e);
        }
    }
    
    @Override
    public KeyInfo getCurrentKeyInfo() {
        return currentKeyInfo;
    }
    
    /**
     * Get the underlying RSA key manager for crypto operations
     */
    public RSAKeyManager getKeyManager() {
        return keyManager;
    }
    
    /**
     * Get public key for encryption
     */
    public PublicKey getPublicKey() {
        if (currentKeyInfo == null) {
            throw new RuntimeException("No key pair available. Please generate keys first.");
        }
        return keyManager.getPublicKey();
    }
    
    /**
     * Get private key for decryption
     */
    public PrivateKey getPrivateKey() {
        if (currentKeyInfo == null || !currentKeyInfo.isHasPrivateKey()) {
            throw new RuntimeException("No private key available. Please generate keys first.");
        }
        return keyManager.getPrivateKey();
    }
}
