package com.example.app.model;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

public class RSAKeyManager {
    private KeyPair kp;

    public KeyPair generateKeyPair(int bits) throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(bits);
        kp = g.generateKeyPair();
        return kp;
    }

    public String getPublicKeyPem() throws Exception {
        if (kp==null) return "";
        PublicKey pub = kp.getPublic();
        String b64 = Base64.getEncoder().encodeToString(pub.getEncoded());
        return "-----BEGIN PUBLIC KEY-----\n" + b64 + "\n-----END PUBLIC KEY-----";
    }

    public void savePrivateKey(Path out) throws Exception {
        if (kp==null) throw new IllegalStateException("No keypair");
        PrivateKey p = kp.getPrivate();
        Files.createDirectories(out.getParent());
        Files.write(out, p.getEncoded());
    }

    public void savePublicKey(Path out) throws Exception {
        if (kp==null) throw new IllegalStateException("No keypair");
        PublicKey p = kp.getPublic();
        Files.createDirectories(out.getParent());
        Files.write(out, p.getEncoded());
    }

    public void loadPublicKey(Path in) throws Exception {
        byte[] b = Files.readAllBytes(in);
        // For demo, just wrap as base64 in PEM
        String b64 = Base64.getEncoder().encodeToString(b);
        // don't set kp.private; only provide public view
        // store in kp as null-private by leaving kp unchanged
    }

    public void loadPrivateKey(Path in) throws Exception {
        byte[] b = Files.readAllBytes(in);
        java.security.spec.PKCS8EncodedKeySpec spec = new java.security.spec.PKCS8EncodedKeySpec(b);
        java.security.KeyFactory kf = java.security.KeyFactory.getInstance("RSA");
        PrivateKey priv = kf.generatePrivate(spec);
        if (kp==null) {
            throw new IllegalStateException("Public key missing: load public key first or generate keypair");
        }
        kp = new KeyPair(kp.getPublic(), priv);
    }

    public PrivateKey getPrivateKey() {
        if (kp==null || kp.getPrivate()==null) throw new IllegalStateException("No private key loaded");
        return kp.getPrivate();
    }
    
    public PublicKey getPublicKey() {
        if (kp==null) throw new IllegalStateException("No public key loaded");
        return kp.getPublic();
    }
    
    public KeyPair getKeyPair() {
        return kp;
    }
}
