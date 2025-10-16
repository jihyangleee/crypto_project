package com.example.app.model;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;

public class AESCipher {
    public static SecretKey newKey(int bits) throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(bits);
        return kg.generateKey();
    }

    public static byte[] randomIV12() {
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    public static byte[] encrypt(SecretKey key, byte[] iv, byte[] plain, byte[] aad) throws Exception {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        c.init(Cipher.ENCRYPT_MODE, key, spec);
        if (aad != null) c.updateAAD(aad);
        return c.doFinal(plain);
    }

    public static byte[] decrypt(SecretKey key, byte[] iv, byte[] ct, byte[] aad) throws Exception {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        c.init(Cipher.DECRYPT_MODE, key, spec);
        if (aad != null) c.updateAAD(aad);
        return c.doFinal(ct);
    }
}
