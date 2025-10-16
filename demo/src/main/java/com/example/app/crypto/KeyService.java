package com.example.app.crypto;

import com.example.app.domain.KeyInfo;

public interface KeyService {
    
    /**
     * Generate a new key pair with specified algorithm and bit length
     */
    KeyInfo generateKeyPair(String algorithm, int bits);
    
    /**
     * Save public key to file
     */
    void savePublicKey(String path);
    
    /**
     * Load public key from file
     */
    void loadPublicKey(String path);
    
    /**
     * Save private key to file (encrypted recommended)
     */
    void savePrivateKey(String path);
    
    /**
     * Load private key from file
     */
    void loadPrivateKey(String path);
    
    /**
     * Get current key info
     */
    KeyInfo getCurrentKeyInfo();
}
