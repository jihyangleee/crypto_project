package com.example.demo.net;

import com.example.demo.crypto.CryptoUtil;
import com.example.demo.crypto.KeyHolder;

import javax.crypto.SecretKey;
import java.io.*;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Random;
import java.util.concurrent.atomic.AtomicBoolean;

public class ChatClient {
    private final KeyHolder keyHolder;
    private Socket socket;
    private OutputStream out;
    private InputStream in;
    private SecretKey aesKey;
    private byte[] aesIv;
    private AtomicBoolean running = new AtomicBoolean(false);
    private MessageListener listener;
    private java.security.PublicKey serverPublicKey;

    public interface MessageListener { void onMessage(String from, String message); }

    public ChatClient(KeyHolder kh) { this.keyHolder = kh; }

    public void setListener(MessageListener l) { this.listener = l; }

    public void connect(String host, int port) throws Exception {
        socket = new Socket(host, port);
        in = socket.getInputStream();
        out = socket.getOutputStream();

        // 1) read server public key
        byte[] serverPub = readBytes(in);
        PublicKey serverPublic = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(serverPub));

        // 2) send my public key
    KeyPair kp = keyHolder.generateIfAbsent();
        writeBytes(out, kp.getPublic().getEncoded());

        // 3) create AES key and send encrypted to server
        javax.crypto.SecretKey aes = CryptoUtil.generateAesKey();
        byte[] aesRaw = aes.getEncoded();
        byte[] encAes = CryptoUtil.rsaEncrypt(serverPublic, aesRaw);
        writeBytes(out, encAes);

        // send iv
        byte[] iv = new byte[12]; new Random().nextBytes(iv);
        writeBytes(out, iv);

        this.aesKey = new javax.crypto.spec.SecretKeySpec(aesRaw, "AES");
        this.aesIv = iv;

        running.set(true);
        // start reader thread
        new Thread(this::readLoop).start();
    }

    public void sendMessage(String plain) throws Exception {
        if (out == null || aesKey == null) throw new IllegalStateException("Not connected or AES key missing");
        String payload = "MSG|" + plain;
        byte[] cipher = CryptoUtil.aesEncrypt(aesKey, payload.getBytes(java.nio.charset.StandardCharsets.UTF_8), aesIv);
        writeBytes(out, cipher);
    }

    public void sendFile(java.nio.file.Path path) throws Exception {
        if (out == null || aesKey == null) throw new IllegalStateException("Not connected or AES key missing");
        byte[] fileBytes = java.nio.file.Files.readAllBytes(path);
        // sign with my private key
        byte[] sig = CryptoUtil.sign(keyHolder.getPrivateKey(), fileBytes);
        String b64data = CryptoUtil.toBase64(fileBytes);
        String b64sig = CryptoUtil.toBase64(sig);
        String payload = "FILE|" + path.getFileName().toString() + "|" + b64sig + "|" + b64data;
        byte[] cipher = CryptoUtil.aesEncrypt(aesKey, payload.getBytes(java.nio.charset.StandardCharsets.UTF_8), aesIv);
        writeBytes(out, cipher);
    }

    public void disconnect() throws IOException {
        running.set(false);
        if (socket != null) socket.close();
    }

    private void readLoop() {
        try {
            while (running.get()) {
                byte[] data = readBytes(in);
                if (data == null) break;
                byte[] plain = CryptoUtil.aesDecrypt(aesKey, data, aesIv);
                String s = new String(plain, java.nio.charset.StandardCharsets.UTF_8);
                if (s.startsWith("MSG|")) {
                    String msg = s.substring(4);
                    if (listener != null) listener.onMessage("peer", msg);
                } else if (s.startsWith("FILE|")) {
                    // FILE|filename|sig|base64data
                    String[] parts = s.split("\\|",4);
                    if (parts.length==4) {
                        String filename = parts[1];
                        byte[] sig = CryptoUtil.fromBase64(parts[2]);
                        byte[] filedata = CryptoUtil.fromBase64(parts[3]);
                        // verify using serverPublicKey
                        boolean ok = false;
                        try { ok = CryptoUtil.verify(serverPublicKey, filedata, sig); } catch (Exception ex) { ok = false; }
                        // save to downloads
                        java.nio.file.Path outp = java.nio.file.Path.of("./received_"+filename);
                        java.nio.file.Files.write(outp, filedata);
                        String notice = "Received file " + filename + " saved to " + outp.toAbsolutePath() + " signature valid=" + ok;
                        if (listener != null) listener.onMessage("peer", notice);
                    }
                } else {
                    if (listener != null) listener.onMessage("peer", s);
                }
            }
        } catch (Exception e) {
            // connection closed or error
        }
    }

    private static void writeBytes(OutputStream out, byte[] data) throws IOException {
        DataOutputStream dos = new DataOutputStream(out);
        dos.writeInt(data.length);
        dos.write(data);
        dos.flush();
    }

    private static byte[] readBytes(InputStream in) throws IOException {
        DataInputStream dis = new DataInputStream(in);
        int len;
        try {
            len = dis.readInt();
        } catch (EOFException eof) { return null; }
        byte[] buf = new byte[len];
        dis.readFully(buf);
        return buf;
    }
}
