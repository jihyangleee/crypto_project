package com.example.demo.net;

import com.example.demo.crypto.CryptoUtil;
import com.example.demo.crypto.KeyHolder;

import javax.crypto.SecretKey;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Arrays;

public class ChatServer {
    private final com.example.demo.crypto.KeyHolder keyHolder;
    private java.net.ServerSocket serverSocket;
    private java.net.Socket clientSocket;
    private java.io.InputStream in;
    private java.io.OutputStream out;
    private javax.crypto.SecretKey aesKey;
    private byte[] aesIv;
    private volatile boolean running = false;
    private java.security.PublicKey clientPublicKey;

    public ChatServer(com.example.demo.crypto.KeyHolder kh) {
        this.keyHolder = kh;
    }

    public void start(int port) throws Exception {
        serverSocket = new java.net.ServerSocket(port);
        System.out.println("Server listening on port " + port);
        clientSocket = serverSocket.accept();
        System.out.println("Client connected: " + clientSocket.getRemoteSocketAddress());
        in = clientSocket.getInputStream();
        out = clientSocket.getOutputStream();

        // handshake: ensure we have our keypair (generate if missing)
    java.security.KeyPair kp = keyHolder.generateIfAbsent();
        if (kp == null) {
            try {
                kp = com.example.demo.crypto.CryptoUtil.generateRsaKeyPair();
                keyHolder.setKeyPair(kp);
                System.out.println("No keypair found on server; generated a new RSA keypair.");
            } catch (Exception e) {
                throw new RuntimeException("Failed to generate RSA keypair: " + e.getMessage(), e);
            }
        }
        byte[] pub = kp.getPublic().getEncoded();
        writeBytes(out, pub);

        // read client's public key
        byte[] clientPub = readBytes(in);
    java.security.PublicKey clientPublic = java.security.KeyFactory.getInstance("RSA").generatePublic(new java.security.spec.X509EncodedKeySpec(clientPub));
    this.clientPublicKey = clientPublic;

        // receive encrypted AES key
        byte[] encAes = readBytes(in);
        byte[] aesRaw = com.example.demo.crypto.CryptoUtil.rsaDecrypt(kp.getPrivate(), encAes);

        // receive iv
        byte[] iv = readBytes(in);
        this.aesKey = new javax.crypto.spec.SecretKeySpec(aesRaw, "AES");
        this.aesIv = iv;

        running = true;
        new Thread(this::readLoop).start();
    }

    public void sendMessage(String plain) throws Exception {
        if (out == null || aesKey == null) throw new IllegalStateException("Not connected or AES key missing");
        String payload = "MSG|" + plain;
        byte[] cipher = com.example.demo.crypto.CryptoUtil.aesEncrypt(aesKey, payload.getBytes(java.nio.charset.StandardCharsets.UTF_8), aesIv);
        writeBytes(out, cipher);
    }

    public void sendFile(java.nio.file.Path path) throws Exception {
        if (out == null || aesKey == null) throw new IllegalStateException("Not connected or AES key missing");
        byte[] fileBytes = java.nio.file.Files.readAllBytes(path);
        byte[] sig = com.example.demo.crypto.CryptoUtil.sign(keyHolder.getPrivateKey(), fileBytes);
        String b64data = com.example.demo.crypto.CryptoUtil.toBase64(fileBytes);
        String b64sig = com.example.demo.crypto.CryptoUtil.toBase64(sig);
        String payload = "FILE|" + path.getFileName().toString() + "|" + b64sig + "|" + b64data;
        byte[] cipher = com.example.demo.crypto.CryptoUtil.aesEncrypt(aesKey, payload.getBytes(java.nio.charset.StandardCharsets.UTF_8), aesIv);
        writeBytes(out, cipher);
    }

    public void stop() throws Exception {
        running = false;
        if (clientSocket != null) clientSocket.close();
        if (serverSocket != null) serverSocket.close();
    }

    private void readLoop() {
        try {
            while (running) {
                byte[] data = readBytes(in);
                if (data == null) break;
                byte[] plain = com.example.demo.crypto.CryptoUtil.aesDecrypt(aesKey, data, aesIv);
                System.out.println("Client: " + new String(plain));
            }
        } catch (Exception e) {
            // ignore
        }
    }

    private static void writeBytes(java.io.OutputStream out, byte[] data) throws java.io.IOException {
        java.io.DataOutputStream dos = new java.io.DataOutputStream(out);
        dos.writeInt(data.length);
        dos.write(data);
        dos.flush();
    }

    private static byte[] readBytes(java.io.InputStream in) throws java.io.IOException {
        java.io.DataInputStream dis = new java.io.DataInputStream(in);
        int len;
        try { len = dis.readInt(); } catch (java.io.EOFException eof) { return null; }
        byte[] buf = new byte[len];
        dis.readFully(buf);
        return buf;
    }
}
