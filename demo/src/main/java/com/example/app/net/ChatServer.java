package com.example.app.net;

import com.example.app.model.CryptoUtil;

import javax.crypto.SecretKey;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.function.Consumer;

public class ChatServer {
    private volatile boolean running = false;
    private java.util.function.Consumer<PublicKey> onPeerKeyReceived;
    private java.util.function.Consumer<MessageData> onMessageReceived;
    private java.util.function.Consumer<SessionKeyData> onSessionKeyReceived;
    private java.util.function.Consumer<FileData> onFileReceived;
    
    public void setOnPeerKeyReceived(java.util.function.Consumer<PublicKey> callback) {
        this.onPeerKeyReceived = callback;
    }
    
    public void setOnMessageReceived(java.util.function.Consumer<MessageData> callback) {
        this.onMessageReceived = callback;
    }
    
    public void setOnSessionKeyReceived(java.util.function.Consumer<SessionKeyData> callback) {
        this.onSessionKeyReceived = callback;
    }
    
    public void setOnFileReceived(java.util.function.Consumer<FileData> callback) {
        this.onFileReceived = callback;
    }
    
    // Inner class to hold session key data
    public static class SessionKeyData {
        public final byte[] wrappedKey; // RSA encrypted AES key
        
        public SessionKeyData(byte[] wrappedKey) {
            this.wrappedKey = wrappedKey;
        }
    }
    
    // Inner class to hold received message data
    public static class MessageData {
        public final String plaintext;
        public final byte[] ciphertext;
        public final byte[] iv;
        public final String type; // "text" or "file"
        public final byte[] signature; // digital signature of plaintext
        public final boolean signatureVerified; // signature verification result
        
        public MessageData(String plaintext, byte[] ciphertext, byte[] iv, String type, byte[] signature, boolean signatureVerified) {
            this.plaintext = plaintext;
            this.ciphertext = ciphertext;
            this.iv = iv;
            this.type = type;
            this.signature = signature;
            this.signatureVerified = signatureVerified;
        }
    }
    
    // Inner class to hold received file data
    public static class FileData {
        public final String filename;
        public final long fileSize;
        public final String filePath;
        public final String decryptedFilePath; // Path to decrypted file
        public final byte[] signature; // file signature
        public final byte[] decryptedContent; // Decrypted file content (for small files)
        public final boolean signatureVerified; // Signature verification result
        
        public FileData(String filename, long fileSize, String filePath, String decryptedFilePath, 
                       byte[] signature, byte[] decryptedContent, boolean signatureVerified) {
            this.filename = filename;
            this.fileSize = fileSize;
            this.filePath = filePath;
            this.decryptedFilePath = decryptedFilePath;
            this.signature = signature;
            this.decryptedContent = decryptedContent;
            this.signatureVerified = signatureVerified;
        }
    }

    public void start(int port, Consumer<String> log, PublicKey myPublicKey, PrivateKey myPrivateKey) throws Exception {
        try (ServerSocket ss = new ServerSocket(port)) {
            running = true;
            log.accept("Server listening on " + port);
            Socket s = ss.accept();
            log.accept("Client connected: " + s.getRemoteSocketAddress());
            DataInputStream in = new DataInputStream(s.getInputStream());
            DataOutputStream out = new DataOutputStream(s.getOutputStream());

            // Use provided key pair instead of generating new one
            KeyPair kp = new KeyPair(myPublicKey, myPrivateKey);
            byte[] serverPub = myPublicKey.getEncoded();
            // send server public key
            out.writeInt(serverPub.length); out.write(serverPub); out.flush();
            log.accept("Sent server public key (" + serverPub.length + " bytes)");

            // read client public key
            int len = in.readInt();
            byte[] clientPubB = new byte[len]; in.readFully(clientPubB);
            PublicKey clientPub = CryptoUtil.loadPublicKeyFromBytes(clientPubB);
            log.accept("Received client public key (" + len + " bytes)");
            
            // Notify UI about received peer public key
            if (onPeerKeyReceived != null) {
                onPeerKeyReceived.accept(clientPub);
            }

            // read encrypted AES key
            int elen = in.readInt(); byte[] encAes = new byte[elen]; in.readFully(encAes);
            byte[] aesRaw = CryptoUtil.rsaDecrypt(kp.getPrivate(), encAes);
            SecretKey aesKey = CryptoUtil.aesKeyFromBytes(aesRaw);
            log.accept("Received AES session key (decrypted)");
            
            // Notify UI about wrapped session key
            if (onSessionKeyReceived != null) {
                SessionKeyData sessionData = new SessionKeyData(encAes);
                onSessionKeyReceived.accept(sessionData);
            }

            // save wrapped AES to disk for inspection
            java.io.File keydir = new java.io.File("received"); if (!keydir.exists()) keydir.mkdirs();
            java.io.File wrappedFile = new java.io.File(keydir, "wrapped-aes.bin");
            try (java.io.FileOutputStream kfos = new java.io.FileOutputStream(wrappedFile)) { kfos.write(encAes); }
            log.accept("Saved wrapped AES to: " + wrappedFile.getAbsolutePath());

            // read iv
            int ivlen = in.readInt(); byte[] iv = new byte[ivlen]; in.readFully(iv);

            // message types
            final int TYPE_CHAT = 1;
            final int TYPE_FILE_META = 2;
            final int TYPE_FILE_CHUNK = 3;
            final int TYPE_FILE_END = 4;
            final int TYPE_SIGNATURE = 5;

            java.io.DataOutputStream currentOut = null;
            java.io.DataOutputStream decryptedOut = null; // For decrypted file
            java.security.MessageDigest md = null;
            long expectedSize = -1;
            long received = 0;
            java.io.File outFile = null;
            java.io.File decryptedOutFile = null;
            String currentFileName = null;
            long currentFileSize = 0;
            byte[] currentFileSignature = null;
            boolean currentFileSignatureVerified = false;
            java.io.ByteArrayOutputStream decryptedBuffer = null; // Buffer for small files
            
            // Store last received message data for signature verification
            byte[] lastPlaintext = null;
            byte[] lastCiphertext = null;
            byte[] lastIv = null;

            while (true) {
                int type;
                try { type = in.readInt(); } catch (Exception ex) { break; }

                int msgIvLen = in.readInt(); byte[] msgIv = new byte[msgIvLen]; in.readFully(msgIv);
                int ctlen = in.readInt(); byte[] ct = new byte[ctlen]; in.readFully(ct);

                if (type == TYPE_CHAT) {
                    byte[] plain = CryptoUtil.aesDecrypt(aesKey, ct, msgIv);
                    String msg = new String(plain, java.nio.charset.StandardCharsets.UTF_8);
                    log.accept("Received encrypted message (" + plain.length + " bytes)");
                    
                    // Store for signature verification
                    lastPlaintext = plain;
                    lastCiphertext = ct;
                    lastIv = msgIv;
                    
                    // Don't notify UI yet - wait for signature
                } else if (type == TYPE_SIGNATURE) {
                    // Decrypt signature
                    byte[] signature = CryptoUtil.aesDecrypt(aesKey, ct, msgIv);
                    log.accept("Received text message signature (" + signature.length + " bytes)");
                    
                    // Verify signature with client's public key
                    boolean verified = false;
                    if (lastPlaintext != null && clientPub != null) {
                        try {
                            // Debug: Log plaintext info
                            String plaintextStr = new String(lastPlaintext, java.nio.charset.StandardCharsets.UTF_8);
                            log.accept("Verifying signature for plaintext: '" + plaintextStr + "' (" + lastPlaintext.length + " bytes)");
                            log.accept("Signature bytes (base64): " + java.util.Base64.getEncoder().encodeToString(signature).substring(0, Math.min(32, signature.length)));
                            log.accept("Client public key available: " + (clientPub != null));
                            
                            java.security.Signature sig = java.security.Signature.getInstance("SHA256withRSA");
                            sig.initVerify(clientPub);
                            sig.update(lastPlaintext);
                            verified = sig.verify(signature);
                            log.accept("Text message signature verify: " + verified + 
                                " | Plaintext hash: " + java.util.Arrays.hashCode(lastPlaintext));
                        } catch (Exception e) {
                            log.accept("Signature verification error: " + e.getMessage());
                            e.printStackTrace();
                        }
                    } else {
                        log.accept("Cannot verify signature - lastPlaintext: " + (lastPlaintext != null) + ", clientPub: " + (clientPub != null));
                    }
                    
                    // Now notify UI with message and signature verification result
                    if (onMessageReceived != null && lastPlaintext != null) {
                        String msg = new String(lastPlaintext, java.nio.charset.StandardCharsets.UTF_8);
                        MessageData data = new MessageData(msg, lastCiphertext, lastIv, "text", signature, verified);
                        onMessageReceived.accept(data);
                    }
                    
                    // Clear stored data
                    lastPlaintext = null;
                    lastCiphertext = null;
                    lastIv = null;
                } else if (type == TYPE_FILE_META) {
                    byte[] plain = CryptoUtil.aesDecrypt(aesKey, ct, msgIv);
                    java.io.DataInputStream ds = new java.io.DataInputStream(new java.io.ByteArrayInputStream(plain));
                    int nameLen = ds.readInt(); byte[] nameB = new byte[nameLen]; ds.readFully(nameB);
                    String fname = new String(nameB, java.nio.charset.StandardCharsets.UTF_8);
                    long fsize = ds.readLong();
                    log.accept("Incoming file: " + fname + " size=" + fsize);
                    
                    java.io.File dir = new java.io.File("received"); 
                    if (!dir.exists()) dir.mkdirs();
                    
                    // Save encrypted file (with IV and ciphertext)
                    outFile = new java.io.File(dir, fname + ".encrypted");
                    currentOut = new java.io.DataOutputStream(new java.io.FileOutputStream(outFile));
                    
                    // Save decrypted file
                    decryptedOutFile = new java.io.File(dir, fname);
                    decryptedOut = new java.io.DataOutputStream(new java.io.FileOutputStream(decryptedOutFile));
                    
                    // Initialize buffer for small files (< 1MB)
                    if (fsize < 1024 * 1024) {
                        decryptedBuffer = new java.io.ByteArrayOutputStream();
                    }
                    
                    md = java.security.MessageDigest.getInstance("SHA-256");
                    expectedSize = fsize; received = 0;
                    
                    // Store file info for callback
                    currentFileName = fname;
                    currentFileSize = fsize;
                } else if (type == TYPE_FILE_CHUNK) {
                    // decrypt chunk to update plaintext digest, but still store ciphertext
                    if (currentOut != null) {
                        // write iv length, iv, ct length, ct (encrypted file)
                        currentOut.writeInt(msgIvLen); currentOut.write(msgIv);
                        currentOut.writeInt(ctlen); currentOut.write(ct);
                        try {
                            byte[] plainChunk = CryptoUtil.aesDecrypt(aesKey, ct, msgIv);
                            
                            // Write decrypted chunk to decrypted file
                            if (decryptedOut != null) {
                                decryptedOut.write(plainChunk);
                            }
                            
                            // Buffer for UI (if file is small)
                            if (decryptedBuffer != null) {
                                decryptedBuffer.write(plainChunk);
                            }
                            
                            md.update(plainChunk);
                            received += plainChunk.length;
                        } catch (Exception ex) {
                            log.accept("chunk decrypt error: " + ex.getMessage());
                        }
                        log.accept("received encrypted chunk, total bytes stored=" + received + " (orig expected=" + expectedSize + ")");
                    }
                } else if (type == 6) {
                    // TYPE_FILE_SIG = 6 (signature frame for file)
                    // signature frame: if iv length == 0 it's plaintext signature; otherwise decrypt with AES
                    if (outFile != null && md != null) {
                        byte[] sigBytes;
                        if (msgIvLen==0) {
                            // plaintext signature
                            sigBytes = ct;
                        } else {
                            sigBytes = CryptoUtil.aesDecrypt(aesKey, ct, msgIv);
                        }
                        
                        // Store signature for callback
                        currentFileSignature = sigBytes;
                        
                        byte[] digest = md.digest();
                        log.accept("File digest computed: " + java.util.Base64.getEncoder().encodeToString(digest).substring(0, 20) + "...");
                        log.accept("Signature received: " + sigBytes.length + " bytes");
                        log.accept("Using client public key: " + (clientPub != null ? "YES" : "NO"));
                        
                        java.security.Signature signature = java.security.Signature.getInstance("SHA256withRSA");
                        signature.initVerify(clientPub);
                        signature.update(digest);
                        boolean ok = signature.verify(sigBytes);
                        currentFileSignatureVerified = ok;
                        log.accept("File signature verify (over plaintext digest): " + ok + 
                            " | Digest: " + java.util.Base64.getEncoder().encodeToString(digest).substring(0, 32) + "...");
                    } else {
                        log.accept("signature received but no file context");
                    }
                } else if (type == TYPE_FILE_END) {
                    if (currentOut != null) {
                        currentOut.close();
                        log.accept("encrypted file transfer complete: " + (outFile!=null?outFile.getAbsolutePath():"?"));
                        
                        // Close decrypted file
                        if (decryptedOut != null) {
                            decryptedOut.close();
                            log.accept("decrypted file saved: " + (decryptedOutFile!=null?decryptedOutFile.getAbsolutePath():"?"));
                        }
                        
                        // Get buffered content
                        byte[] decryptedContent = null;
                        if (decryptedBuffer != null) {
                            decryptedContent = decryptedBuffer.toByteArray();
                            log.accept("decrypted content buffered: " + decryptedContent.length + " bytes");
                        }
                        
                        // Notify UI about received file
                        if (onFileReceived != null && outFile != null) {
                            FileData fileData = new FileData(
                                currentFileName,
                                currentFileSize,
                                outFile.getAbsolutePath(),
                                decryptedOutFile != null ? decryptedOutFile.getAbsolutePath() : null,
                                currentFileSignature,
                                decryptedContent,
                                currentFileSignatureVerified
                            );
                            onFileReceived.accept(fileData);
                        }
                        
                        // Reset file transfer state
                        currentOut = null;
                        decryptedOut = null;
                        decryptedOutFile = null;
                        decryptedBuffer = null;
                        currentFileSignature = null;
                        currentFileSignatureVerified = false;
                        md = null;
                        expectedSize = -1;
                        received = 0;
                        outFile = null;
                        currentFileName = null;
                        currentFileSize = 0;
                        currentFileSignature = null;
                    }
                }
            }
        }
    }

    public void stop() { running = false; }
}
