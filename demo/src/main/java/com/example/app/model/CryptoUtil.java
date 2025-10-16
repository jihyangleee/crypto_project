package com.example.app.model;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class CryptoUtil {
    public static PublicKey loadPublicKeyFromBytes(byte[] b) throws Exception {
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(new X509EncodedKeySpec(b));
    }

    public static byte[] rsaDecrypt(PrivateKey priv, byte[] data) throws Exception {
        Cipher c = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        c.init(Cipher.DECRYPT_MODE, priv);
        return c.doFinal(data);
    }

    public static SecretKey aesKeyFromBytes(byte[] raw) {
        return new SecretKeySpec(raw, "AES");
    }

    public static byte[] aesDecrypt(SecretKey key, byte[] ct, byte[] iv) throws Exception {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        c.init(Cipher.DECRYPT_MODE, key, spec);
        return c.doFinal(ct);
    }

    public static byte[] aesEncrypt(SecretKey key, byte[] plain, byte[] iv) throws Exception {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        c.init(Cipher.ENCRYPT_MODE, key, spec);
        return c.doFinal(plain);
    }

    public static byte[] rsaEncrypt(PublicKey pub, byte[] data) throws Exception {
        Cipher c = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        c.init(Cipher.ENCRYPT_MODE, pub);
        return c.doFinal(data);
    }
}
