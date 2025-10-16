package com.example.app.services.mock;

import com.example.app.crypto.SignService;
import com.example.app.domain.VerifyResult;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Random;

public class MockSignService implements SignService {
    
    @Override
    public String sign(String plaintext) {
        // Generate fake signature
        Random random = new Random();
        byte[] fakeSignature = new byte[256]; // RSA-2048 signature size
        random.nextBytes(fakeSignature);
        return Base64.getEncoder().encodeToString(fakeSignature);
    }
    
    @Override
    public VerifyResult verify(String plaintext, String base64Signature, String publicKeyPem) {
        try {
            // Calculate real SHA-256 of plaintext
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(plaintext.getBytes());
            StringBuilder localDigest = new StringBuilder();
            for (byte b : digest) {
                localDigest.append(String.format("%02x", b));
            }
            
            // Generate fake signer digest (should match for demo)
            String signerDigest = localDigest.toString();
            
            // Mock verification always succeeds
            return new VerifyResult(signerDigest, localDigest.toString(), true);
        } catch (Exception e) {
            return new VerifyResult("", "", false);
        }
    }
    
    @Override
    public java.security.PublicKey parsePemPublicKey(String pem) throws Exception {
        // Mock implementation - just throw exception as this is not used in mock mode
        throw new UnsupportedOperationException("Mock implementation does not support PEM parsing");
    }
}
