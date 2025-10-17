package com.example.app.model;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;

/**
 * 암호화/복호화 유틸리티 클래스
 * RSA-2048 OAEP와 AES-128-GCM을 사용한 하이브리드 암호화 구현
 */
public class CryptoUtil {
    
    /**
     * 바이트 배열에서 RSA 공개키 객체를 생성합니다.
     */
    public static PublicKey loadPublicKeyFromBytes(byte[] b) throws Exception {
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(new X509EncodedKeySpec(b));
    }

    /**
     * RSA 개인키로 데이터를 복호화합니다.
     * OAEP 패딩 사용 (RSA/ECB/OAEPWithSHA-256AndMGF1Padding)
     * 주로 AES 세션키를 복호화하는데 사용됩니다.
     */
    public static byte[] rsaDecrypt(PrivateKey priv, byte[] data) throws Exception {
        Cipher c = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        c.init(Cipher.DECRYPT_MODE, priv);
        return c.doFinal(data);
    }

    /**
     * 바이트 배열을 AES SecretKey 객체로 변환합니다.
     */
    public static SecretKey aesKeyFromBytes(byte[] raw) {
        return new SecretKeySpec(raw, "AES");
    }

    /**
     * AES-GCM 알고리즘으로 암호문을 복호화합니다.
     * GCM 모드는 인증 태그를 포함하여 무결성도 검증합니다.
     * @param key AES 세션키 (128비트)
     * @param ct 암호문 (ciphertext)
     * @param iv 초기화 벡터 (12바이트 권장)
     */
    public static byte[] aesDecrypt(SecretKey key, byte[] ct, byte[] iv) throws Exception {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv); // 128비트 태그 길이
        c.init(Cipher.DECRYPT_MODE, key, spec);
        return c.doFinal(ct);
    }

    /**
     * AES-GCM 알고리즘으로 평문을 암호화합니다.
     * GCM 모드는 암호화와 동시에 인증 태그도 생성합니다.
     * @param key AES 세션키 (128비트)
     * @param plain 평문
     * @param iv 초기화 벡터 (12바이트 권장)
     */
    public static byte[] aesEncrypt(SecretKey key, byte[] plain, byte[] iv) throws Exception {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv); // 128비트 태그 길이
        c.init(Cipher.ENCRYPT_MODE, key, spec);
        return c.doFinal(plain);
    }

    /**
     * RSA 공개키로 데이터를 암호화합니다.
     * OAEP 패딩 사용 (RSA/ECB/OAEPWithSHA-256AndMGF1Padding)
     * 주로 AES 세션키를 암호화하는데 사용됩니다.
     */
    public static byte[] rsaEncrypt(PublicKey pub, byte[] data) throws Exception {
        Cipher c = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        c.init(Cipher.ENCRYPT_MODE, pub);
        return c.doFinal(data);
    }
}
