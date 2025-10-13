package com.example.demo.crypto;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class CryptoUtil {

    public static KeyPair generateRsaKeyPair() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        return gen.generateKeyPair();
    }

    public static SecretKey generateAesKey() throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256);
        return kg.generateKey();
    }

    public static byte[] rsaEncrypt(PublicKey pub, byte[] data) throws Exception {
        Cipher c = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        c.init(Cipher.ENCRYPT_MODE, pub);
        return c.doFinal(data);
    }

    public static byte[] rsaDecrypt(PrivateKey priv, byte[] data) throws Exception {
        Cipher c = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        c.init(Cipher.DECRYPT_MODE, priv);
        return c.doFinal(data);
    }

    public static byte[] aesEncrypt(SecretKey key, byte[] data, byte[] iv) throws Exception {
        if (iv == null || iv.length != 12) throw new IllegalArgumentException("IV must be 12 bytes for GCM");
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        c.init(Cipher.ENCRYPT_MODE, key, spec);
        return c.doFinal(data);
    }

    public static byte[] aesDecrypt(SecretKey key, byte[] data, byte[] iv) throws Exception {
        if (iv == null || iv.length != 12) throw new IllegalArgumentException("IV must be 12 bytes for GCM");
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        c.init(Cipher.DECRYPT_MODE, key, spec);
        return c.doFinal(data);
    }

    public static byte[] sign(PrivateKey priv, byte[] data) throws Exception {
        Signature s = Signature.getInstance("SHA256withRSA");
        s.initSign(priv);
        s.update(data);
        return s.sign();
    }

    public static boolean verify(PublicKey pub, byte[] data, byte[] sig) throws Exception {
        Signature s = Signature.getInstance("SHA256withRSA");
        s.initVerify(pub);
        s.update(data);
        return s.verify(sig);
    }

    public static void savePublicKey(PublicKey key, Path path) throws Exception {
        X509EncodedKeySpec spec = new X509EncodedKeySpec(key.getEncoded());
        Files.write(path, spec.getEncoded());
    }

    public static PublicKey loadPublicKey(Path path) throws Exception {
        byte[] bytes = Files.readAllBytes(path);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(bytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }

    public static void savePrivateKey(PrivateKey key, Path path) throws Exception {
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(key.getEncoded());
        Files.write(path, spec.getEncoded());
    }

    public static PrivateKey loadPrivateKey(Path path) throws Exception {
        byte[] bytes = Files.readAllBytes(path);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(bytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }

    public static String toBase64(byte[] b) { return Base64.getEncoder().encodeToString(b); }
    public static byte[] fromBase64(String s) { return Base64.getDecoder().decode(s); }
}
