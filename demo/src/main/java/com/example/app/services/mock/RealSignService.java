package com.example.app.services.mock;

import com.example.app.crypto.SignService;
import com.example.app.domain.VerifyResult;

import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Base64;

public class RealSignService implements SignService {
    
    private final RealKeyService keyService;
    
    public RealSignService(RealKeyService keyService) {
        this.keyService = keyService;
    }
    
    @Override
    public String sign(String plaintext) {
        try {
            // Get private key
            PrivateKey privateKey = keyService.getPrivateKey();
            
            // Create signature
            Signature sig = Signature.getInstance("SHA256withRSA");
            sig.initSign(privateKey);
            sig.update(plaintext.getBytes());
            byte[] signature = sig.sign();
            
            return Base64.getEncoder().encodeToString(signature);
            
        } catch (Exception e) {
            throw new RuntimeException("Signing failed", e);
        }
    }
    
    @Override
    public VerifyResult verify(String plaintext, String base64Signature, String publicKeyPem) {
        try {
            // Calculate local digest
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(plaintext.getBytes());
            StringBuilder localDigest = new StringBuilder();
            for (byte b : digest) {
                localDigest.append(String.format("%02x", b));
            }
            
            // Parse peer's public key from PEM
            PublicKey publicKey = parsePemPublicKey(publicKeyPem);
            
            // Verify signature using peer's public key
            Signature sig = Signature.getInstance("SHA256withRSA");
            sig.initVerify(publicKey);
            sig.update(plaintext.getBytes());
            
            byte[] signatureBytes = Base64.getDecoder().decode(base64Signature);
            boolean matches = sig.verify(signatureBytes);
            
            // For signer digest, we show the same since we're verifying our own signature
            String signerDigest = localDigest.toString();
            
            return new VerifyResult(signerDigest, localDigest.toString(), matches);
            
        } catch (Exception e) {
            throw new RuntimeException("Verification failed: " + e.getMessage(), e);
        }
    }
    
    @Override
    public PublicKey parsePemPublicKey(String pem) throws Exception {
        // Remove PEM headers and decode Base64
        String publicKeyPEM = pem
            .replace("-----BEGIN PUBLIC KEY-----", "")
            .replace("-----END PUBLIC KEY-----", "")
            .replaceAll("\\s", "");
        
        byte[] encoded = Base64.getDecoder().decode(publicKeyPEM);
        
        java.security.spec.X509EncodedKeySpec keySpec = new java.security.spec.X509EncodedKeySpec(encoded);
        java.security.KeyFactory keyFactory = java.security.KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(keySpec);
    }
}
