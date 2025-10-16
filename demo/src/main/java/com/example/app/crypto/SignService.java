package com.example.app.crypto;

import com.example.app.domain.VerifyResult;

public interface SignService {
    
    /**
     * Sign plaintext with private key
     * @return Base64 encoded signature
     */
    String sign(String plaintext);
    
    /**
     * Verify signature against plaintext
     */
    VerifyResult verify(String plaintext, String base64Signature, String publicKeyPem);
}
