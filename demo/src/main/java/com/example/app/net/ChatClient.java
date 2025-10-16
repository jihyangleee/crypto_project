package com.example.app.net;

import java.util.function.Consumer;
import com.example.app.model.CryptoUtil;
import javax.crypto.SecretKey;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

public class ChatClient {
    private boolean connected = false;
    private Consumer<String> onMessage;
    private java.util.function.Consumer<String> wireLogger;
    private java.net.Socket socket;
    private DataOutputStream out;
    private DataInputStream in;
    private SecretKey aesKey;
    private byte[] iv;
    private boolean encryptSignature = true;
    private java.security.PublicKey peerPublicKey; // Store peer's public key
    private java.security.KeyPair myKeyPair; // Store my key pair
    private java.util.function.Consumer<java.security.PublicKey> onPeerKeyReceived;

    public void setEncryptSignature(boolean v) { this.encryptSignature = v; }
    
    public void setOnPeerKeyReceived(java.util.function.Consumer<java.security.PublicKey> callback) {
        this.onPeerKeyReceived = callback;
    }
    
    public java.security.PublicKey getPeerPublicKey() { return peerPublicKey; }

    public void connect(String host, int port, java.security.PublicKey myPublicKey, java.security.PrivateKey myPrivateKey) throws Exception {
        // stub: assume immediate connection
        socket = new Socket(host, port);
        in = new DataInputStream(socket.getInputStream());
        out = new DataOutputStream(socket.getOutputStream());

        // Store my key pair
        this.myKeyPair = new KeyPair(myPublicKey, myPrivateKey);

        // 1) read server public key
        int len = in.readInt(); byte[] serverPub = new byte[len]; in.readFully(serverPub);
        this.peerPublicKey = CryptoUtil.loadPublicKeyFromBytes(serverPub);
        
        // Notify UI about received peer public key
        if (onPeerKeyReceived != null) {
            onPeerKeyReceived.accept(peerPublicKey);
        }

        // 2) send my public key
        byte[] myPub = myPublicKey.getEncoded();
        out.writeInt(myPub.length); out.write(myPub); out.flush();

        // 3) create AES key and send encrypted AES key
        javax.crypto.SecretKey aes = javax.crypto.KeyGenerator.getInstance("AES").generateKey();
        byte[] aesRaw = aes.getEncoded();
        byte[] encAes = CryptoUtil.rsaEncrypt(peerPublicKey, aesRaw);
        out.writeInt(encAes.length); out.write(encAes); out.flush();

        // send iv
        iv = new byte[12]; new java.security.SecureRandom().nextBytes(iv);
        out.writeInt(iv.length); out.write(iv); out.flush();

        this.aesKey = new javax.crypto.spec.SecretKeySpec(aesRaw, "AES");

        connected = true;
        if (onMessage!=null) onMessage.accept("[system] connected to " + host + ":" + port);

        // start reader thread
        new Thread(this::readLoop).start();
    }

    public void setWireLogger(java.util.function.Consumer<String> cb) { this.wireLogger = cb; }

    public void disconnect() {
        connected = false;
        try { if (socket!=null) socket.close(); } catch (Exception ignored) {}
        if (onMessage!=null) onMessage.accept("[system] disconnected");
    }

    public void send(String text) {
        // stub: echo back
        try {
            byte[] pt = text.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            
            // Sign the plaintext before encryption
            byte[] signature = signData(pt);
            
            // Send encrypted plaintext
            sendFramed(1, pt);
            
            // Send signature (frame type 5)
            sendFramed(5, signature);
        } catch (Exception ex) {
            if (onMessage!=null) onMessage.accept("send error: " + ex.getMessage());
        }
    }
    
    /**
     * Sign data with my private key using SHA256withRSA
     */
    private byte[] signData(byte[] data) throws Exception {
        java.security.Signature signer = java.security.Signature.getInstance("SHA256withRSA");
        signer.initSign(myKeyPair.getPrivate());
        signer.update(data);
        return signer.sign();
    }

    public void setOnMessage(Consumer<String> cb) { this.onMessage = cb; }

    private void readLoop() {
        try {
            while (connected) {
                int len;
                try { len = in.readInt(); } catch (Exception ex) { break; }
                byte[] ct = new byte[len]; in.readFully(ct);
                if (wireLogger!=null) wireLogger.accept("RECV (base64): " + java.util.Base64.getEncoder().encodeToString(ct));
                byte[] pt = CryptoUtil.aesDecrypt(aesKey, ct, iv);
                String s = new String(pt, java.nio.charset.StandardCharsets.UTF_8);
                if (onMessage!=null) onMessage.accept("peer: " + s);
            }
        } catch (Exception ex) {
            if (onMessage!=null) onMessage.accept("read error: " + ex.getMessage());
        }
    }

    // File transfer helpers
    public void sendFile(java.io.File f) throws Exception {
        if (onMessage != null) onMessage.accept("[FILE] Starting file transfer: " + f.getName() + " (" + f.length() + " bytes)");
        
        java.security.PrivateKey signingKey = myKeyPair.getPrivate();
        // read file and send meta
        byte[] nameB = f.getName().getBytes(java.nio.charset.StandardCharsets.UTF_8);
        java.io.ByteArrayOutputStream metaB = new java.io.ByteArrayOutputStream();
        java.io.DataOutputStream dos = new java.io.DataOutputStream(metaB);
        dos.writeInt(nameB.length); dos.write(nameB);
        dos.writeLong(f.length()); dos.flush();
        byte[] meta = metaB.toByteArray();
        
        if (onMessage != null) onMessage.accept("[FILE] Sending metadata frame (type 2)");
        sendFramed(2, meta);
        if (onMessage != null) onMessage.accept("[FILE] Metadata sent successfully");


        // send chunks; compute digest over plaintext (file content) then send encrypted chunks
        java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
        int chunkCount = 0;
        long totalBytes = 0;
        
        if (onMessage != null) onMessage.accept("[FILE] Starting to send file chunks");
        
        try (java.io.InputStream fis = new java.io.FileInputStream(f)) {
            byte[] buf = new byte[8192];
            int r;
            while ((r=fis.read(buf))>0) {
                byte[] chunk = java.util.Arrays.copyOf(buf, r);
                // update digest with plaintext chunk
                md.update(chunk);
                // send encrypted chunk
                sendFramed(3, chunk); // send encrypted chunk
                chunkCount++;
                totalBytes += r;
                
                if (chunkCount % 10 == 0 && onMessage != null) {
                    onMessage.accept("[FILE] Sent " + chunkCount + " chunks (" + totalBytes + " bytes)");
                }
            }
        }
        
        if (onMessage != null) onMessage.accept("[FILE] All chunks sent: " + chunkCount + " chunks, " + totalBytes + " total bytes");

        // signature of ciphertext digest
        if (onMessage != null) onMessage.accept("[FILE] Creating file signature");
        
        byte[] digest = md.digest();
        java.security.Signature sig = java.security.Signature.getInstance("SHA256withRSA");
        sig.initSign(signingKey); sig.update(digest);
        byte[] signature = sig.sign();
        
        if (encryptSignature) {
            // encrypt signature with AES and send as normal framed message
            if (onMessage != null) onMessage.accept("[FILE] Sending encrypted signature (type 5)");
            sendFramed(5, signature);
        } else {
            // send signature as plaintext frame (ivLen=0)
            if (onMessage != null) onMessage.accept("[FILE] Sending plaintext signature (type 5)");
            out.writeInt(5);
            out.writeInt(0); // iv length = 0 -> indicates plaintext signature
            out.writeInt(signature.length); out.write(signature); out.flush();
        }

        // end
        if (onMessage != null) onMessage.accept("[FILE] Sending end frame (type 4)");
        sendFramed(4, new byte[0]);
        
        if (onMessage != null) onMessage.accept("[FILE] File transfer complete: " + f.getName());
    }

    private byte[] sendFramed(int type, byte[] plain) throws Exception {
        // generate per-message IV
        byte[] midIv = new byte[12]; new java.security.SecureRandom().nextBytes(midIv);
        byte[] ct = CryptoUtil.aesEncrypt(aesKey, plain, midIv);
        out.writeInt(type);
        out.writeInt(midIv.length); out.write(midIv);
        out.writeInt(ct.length); out.write(ct); out.flush();
        if (wireLogger!=null) wireLogger.accept("SENT type="+type+" IV(b64)="+java.util.Base64.getEncoder().encodeToString(midIv)+" CT(b64)="+java.util.Base64.getEncoder().encodeToString(ct));
        return ct;
    }
}
