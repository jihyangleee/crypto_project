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
    private java.security.PublicKey peerPublicKey; // Store peer's public key
    private java.security.KeyPair myKeyPair; // Store my key pair
    private java.util.function.Consumer<java.security.PublicKey> onPeerKeyReceived;

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

    public void send(String text) throws Exception {
        send(text, true, true); // Default: encrypt and sign
    }
    
    public void send(String text, boolean encrypt, boolean sign) throws Exception {
        try {
            byte[] pt = text.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            
            if (encrypt) {
                // ENCRYPTED MODE
                if (sign) {
                    if (onMessage != null) onMessage.accept("[TEXT] Signing plaintext: '" + text + "' (" + pt.length + " bytes)");
                    byte[] signature = signData(pt);
                    if (onMessage != null) onMessage.accept("[TEXT] Signature created: " + signature.length + " bytes, hash: " + java.util.Arrays.hashCode(pt));
                    
                    // Send encrypted plaintext
                    sendFramed(1, pt);
                    // Send signature (frame type 5)
                    sendFramed(5, signature);
                    
                    if (onMessage != null) onMessage.accept("[TEXT] Encrypted message and signature sent");
                } else {
                    // Just encrypt, no signature
                    sendFramed(1, pt);
                    if (onMessage != null) onMessage.accept("[TEXT] Encrypted message sent (no signature)");
                }
            } else {
                // PLAINTEXT MODE (type 7)
                if (sign) {
                    if (onMessage != null) onMessage.accept("[TEXT] Sending as PLAINTEXT with signature");
                    byte[] signature = signData(pt);
                    
                    // Send plaintext (type 7, no encryption)
                    this.out.writeInt(7); // TYPE_PLAINTEXT_CHAT
                    this.out.writeInt(0);  // no IV
                    this.out.writeInt(pt.length); // plaintext length
                    this.out.write(pt);
                    
                    // Send plaintext signature (type 8)
                    this.out.writeInt(8); // TYPE_PLAINTEXT_SIGNATURE
                    this.out.writeInt(0);  // no IV
                    this.out.writeInt(signature.length);
                    this.out.write(signature);
                    this.out.flush();
                    
                    if (onMessage != null) onMessage.accept("[TEXT] Plaintext message and signature sent");
                } else {
                    // Just plaintext, no signature
                    if (onMessage != null) onMessage.accept("[TEXT] Sending as PLAINTEXT (no signature)");
                    this.out.writeInt(7); // TYPE_PLAINTEXT_CHAT
                    this.out.writeInt(0);  // no IV
                    this.out.writeInt(pt.length);
                    this.out.write(pt);
                    this.out.flush();
                    
                    if (onMessage != null) onMessage.accept("[TEXT] Plaintext message sent (no signature)");
                }
            }
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
        sendFile(f, true, true); // Default: encrypt and sign
    }
    
    public void sendFile(java.io.File f, boolean encrypt, boolean sign) throws Exception {
        if (onMessage != null) {
            String mode = encrypt ? "ENCRYPTED" : "PLAINTEXT";
            String sigMode = sign ? " with signature" : " without signature";
            onMessage.accept("[FILE] Starting " + mode + " file transfer" + sigMode + ": " + f.getName() + " (" + f.length() + " bytes)");
        }
        
        java.security.PrivateKey signingKey = myKeyPair.getPrivate();
        // read file and send meta
        byte[] nameB = f.getName().getBytes(java.nio.charset.StandardCharsets.UTF_8);
        java.io.ByteArrayOutputStream metaB = new java.io.ByteArrayOutputStream();
        java.io.DataOutputStream dos = new java.io.DataOutputStream(metaB);
        dos.writeInt(nameB.length); dos.write(nameB);
        dos.writeLong(f.length()); dos.flush();
        byte[] meta = metaB.toByteArray();
        
        if (onMessage != null) onMessage.accept("[FILE] Sending metadata frame");
        if (encrypt) {
            sendFramed(2, meta); // TYPE_FILE_META
        } else {
            // Send plaintext file metadata (type 9)
            this.out.writeInt(9); // TYPE_PLAINTEXT_FILE_META
            this.out.writeInt(0);  // no IV
            this.out.writeInt(meta.length);
            this.out.write(meta);
            this.out.flush();
        }
        if (onMessage != null) onMessage.accept("[FILE] Metadata sent successfully");


        // send chunks; compute digest over plaintext (file content) then send chunks
        java.security.MessageDigest md = sign ? java.security.MessageDigest.getInstance("SHA-256") : null;
        int chunkCount = 0;
        long totalBytes = 0;
        
        if (onMessage != null) onMessage.accept("[FILE] Starting to send file chunks");
        
        try (java.io.InputStream fis = new java.io.FileInputStream(f)) {
            byte[] buf = new byte[8192];
            int r;
            while ((r=fis.read(buf))>0) {
                byte[] chunk = java.util.Arrays.copyOf(buf, r);
                // update digest with plaintext chunk if signing
                if (md != null) {
                    md.update(chunk);
                }
                
                // send chunk (encrypted or plaintext)
                if (encrypt) {
                    sendFramed(3, chunk); // TYPE_FILE_CHUNK (encrypted)
                } else {
                    // Send plaintext chunk (type 10)
                    this.out.writeInt(10); // TYPE_PLAINTEXT_FILE_CHUNK
                    this.out.writeInt(0);  // no IV
                    this.out.writeInt(chunk.length);
                    this.out.write(chunk);
                    this.out.flush();
                }
                
                chunkCount++;
                totalBytes += r;
                
                if (chunkCount % 10 == 0 && onMessage != null) {
                    onMessage.accept("[FILE] Sent " + chunkCount + " chunks (" + totalBytes + " bytes)");
                }
            }
        }
        
        if (onMessage != null) onMessage.accept("[FILE] All chunks sent: " + chunkCount + " chunks, " + totalBytes + " total bytes");

        // signature of file digest (if signing enabled)
        if (sign && md != null) {
            if (onMessage != null) onMessage.accept("[FILE] Creating file signature");
            
            byte[] digest = md.digest();
            if (onMessage != null) onMessage.accept("[FILE] File digest: " + java.util.Base64.getEncoder().encodeToString(digest).substring(0, 32) + "...");
            
            java.security.Signature sig = java.security.Signature.getInstance("SHA256withRSA");
            sig.initSign(signingKey); sig.update(digest);
            byte[] signature = sig.sign();
            
            if (onMessage != null) onMessage.accept("[FILE] Signature created: " + signature.length + " bytes");
            
            if (encrypt) {
                // encrypt signature with AES and send as FILE signature frame (type 6)
                if (onMessage != null) onMessage.accept("[FILE] Sending encrypted file signature (type 6)");
                sendFramed(6, signature);
            } else {
                // send signature as plaintext (type 11 for plaintext file signature)
                if (onMessage != null) onMessage.accept("[FILE] Sending plaintext file signature (type 11)");
                this.out.writeInt(11); // TYPE_PLAINTEXT_FILE_SIGNATURE
                this.out.writeInt(0); // no IV
                this.out.writeInt(signature.length); 
                this.out.write(signature); 
                this.out.flush();
            }
        }

        // end frame
        if (onMessage != null) onMessage.accept("[FILE] Sending end frame");
        if (encrypt) {
            sendFramed(4, new byte[0]); // TYPE_FILE_END
        } else {
            // Plaintext file end (type 12)
            this.out.writeInt(12); // TYPE_PLAINTEXT_FILE_END
            this.out.writeInt(0);  // no IV
            this.out.writeInt(0);  // no data
            this.out.flush();
        }
        
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
