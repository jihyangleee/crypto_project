package com.example.app.net;

import com.example.app.model.CryptoUtil;

import javax.crypto.SecretKey;
import java.io.File;
import java.io.FileInputStream;
import java.io.DataInputStream;
import java.nio.file.Files;
import java.util.Base64;

/**
 * Utility to decrypt files stored by ChatServer (format: repeated [ivLen][iv][ctLen][ct])
 */
public class StoredFileDecryptor {
    public static byte[] decryptStored(File storedFile, SecretKey aesKey) throws Exception {
        try (DataInputStream dis = new DataInputStream(new FileInputStream(storedFile))) {
            java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
            while (dis.available() > 0) {
                int ivlen = dis.readInt(); byte[] iv = new byte[ivlen]; dis.readFully(iv);
                int ctlen = dis.readInt(); byte[] ct = new byte[ctlen]; dis.readFully(ct);
                byte[] plain = CryptoUtil.aesDecrypt(aesKey, ct, iv);
                out.write(plain);
            }
            return out.toByteArray();
        }
    }

    public static SecretKey keyFromHex(String hex) {
        byte[] raw = new byte[hex.length()/2];
        for (int i=0;i<raw.length;i++) raw[i] = (byte) Integer.parseInt(hex.substring(2*i,2*i+2),16);
        return CryptoUtil.aesKeyFromBytes(raw);
    }

    public static SecretKey keyFromBase64(String b64) {
        return CryptoUtil.aesKeyFromBytes(Base64.getDecoder().decode(b64));
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.out.println("Usage: StoredFileDecryptor <stored-file-path> <aes-key-hex|base64> [hex|b64]");
            return;
        }
        File f = new File(args[0]);
        String keyStr = args[1];
        String mode = args.length>=3?args[2]:"hex";
        SecretKey key = mode.equals("b64")?keyFromBase64(keyStr):keyFromHex(keyStr);
        byte[] plain = decryptStored(f, key);
        Files.write(new File(f.getParentFile(), "decrypted-"+f.getName()).toPath(), plain);
        System.out.println("Decrypted output written to: " + new File(f.getParentFile(), "decrypted-"+f.getName()).getAbsolutePath());
    }
}
