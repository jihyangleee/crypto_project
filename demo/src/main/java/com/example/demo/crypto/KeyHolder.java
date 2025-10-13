package com.example.demo.crypto;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

public class KeyHolder {
    private KeyPair keyPair;

    public synchronized void setKeyPair(KeyPair kp) { this.keyPair = kp; }

    public synchronized KeyPair getKeyPair() {
        return keyPair;
    }

    public synchronized boolean hasKeyPair() {
        return keyPair != null;
    }

    /**
     * Ensure a keypair exists; if absent, generate a new 2048-bit RSA keypair and store it.
     * Returns the current or newly generated KeyPair.
     */
    public synchronized KeyPair generateIfAbsent() {
        if (keyPair == null) {
            try {
                KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
                gen.initialize(2048, new SecureRandom());
                keyPair = gen.generateKeyPair();
            } catch (Exception e) {
                throw new RuntimeException("Failed to generate RSA KeyPair", e);
            }
        }
        return keyPair;
    }

    public synchronized PublicKey getPublicKey() {
        return (keyPair == null) ? null : keyPair.getPublic();
    }

    public synchronized PrivateKey getPrivateKey() {
        return (keyPair == null) ? null : keyPair.getPrivate();
    }
}
