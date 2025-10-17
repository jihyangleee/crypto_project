package com.example.app.net;

import java.util.function.Consumer;
import com.example.app.model.CryptoUtil;
import javax.crypto.SecretKey;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.Socket;
import java.security.KeyPair;

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

    /**
     * 서버에 연결하고 키 교환을 수행합니다.
     * 순서: 1) 서버 공개키 받기 → 2) 내 공개키 보내기 → 3) AES 세션키 생성 후 암호화해서 전송
     */
    public void connect(String host, int port, java.security.PublicKey myPublicKey, java.security.PrivateKey myPrivateKey) throws Exception {
        // 서버에 소켓 연결
        socket = new Socket(host, port);
        in = new DataInputStream(socket.getInputStream());
        out = new DataOutputStream(socket.getOutputStream());

        // 내 키페어를 저장해둠 (나중에 서명할 때 사용)
        this.myKeyPair = new KeyPair(myPublicKey, myPrivateKey);

        // 1) 서버의 RSA 공개키를 받아옴
        int len = in.readInt(); 
        byte[] serverPub = new byte[len]; 
        in.readFully(serverPub);
        this.peerPublicKey = CryptoUtil.loadPublicKeyFromBytes(serverPub);
        
        // UI에 상대방 공개키 받았다고 알림
        if (onPeerKeyReceived != null) {
            onPeerKeyReceived.accept(peerPublicKey);
        }

        // 2) 내 RSA 공개키를 서버에게 보냄
        byte[] myPub = myPublicKey.getEncoded();
        out.writeInt(myPub.length); 
        out.write(myPub); 
        out.flush();

        // 3) AES 세션키를 생성하고, 서버의 공개키로 암호화해서 전송
        // 이렇게 하면 서버만 자신의 개인키로 복호화해서 세션키를 알 수 있음
        javax.crypto.SecretKey aes = javax.crypto.KeyGenerator.getInstance("AES").generateKey();
        byte[] aesRaw = aes.getEncoded();
        byte[] encAes = CryptoUtil.rsaEncrypt(peerPublicKey, aesRaw); // RSA로 AES키 래핑
        out.writeInt(encAes.length); 
        out.write(encAes); 
        out.flush();

        // AES-GCM에 사용할 IV(Initialization Vector) 전송
        iv = new byte[12]; // GCM 표준 IV 크기
        new java.security.SecureRandom().nextBytes(iv);
        out.writeInt(iv.length); 
        out.write(iv); 
        out.flush();

        // 이제 이 AES 키로 메시지를 암호화할 준비 완료
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
    
    /**
     * 텍스트 메시지를 전송합니다.
     * @param text 보낼 메시지
     * @param encrypt true면 AES로 암호화, false면 평문 전송
     * @param sign true면 RSA 개인키로 서명 추가
     */
    public void send(String text, boolean encrypt, boolean sign) throws Exception {
        try {
            byte[] pt = text.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            
            if (encrypt) {
                // 암호화 모드: AES-GCM으로 메시지 암호화
                if (sign) {
                    // 암호화 + 서명 모드
                    if (onMessage != null) onMessage.accept("[TEXT] Signing plaintext: '" + text + "' (" + pt.length + " bytes)");
                    byte[] signature = signData(pt);
                    if (onMessage != null) onMessage.accept("[TEXT] Signature created: " + signature.length + " bytes, hash: " + java.util.Arrays.hashCode(pt));
                    
                    // 평문을 암호화해서 전송 (TYPE_CHAT = 1)
                    sendFramed(1, pt);
                    // 서명도 암호화해서 전송 (TYPE_SIGNATURE = 5)
                    sendFramed(5, signature);
                    
                    if (onMessage != null) onMessage.accept("[TEXT] Encrypted message and signature sent");
                } else {
                    // 암호화만, 서명 없음
                    sendFramed(1, pt);
                    if (onMessage != null) onMessage.accept("[TEXT] Encrypted message sent (no signature)");
                }
            } else {
                // 평문 모드: 암호화 없이 그대로 전송 (TYPE_PLAINTEXT_CHAT = 7)
                if (sign) {
                    // 평문 + 서명 모드
                    if (onMessage != null) onMessage.accept("[TEXT] Sending as PLAINTEXT with signature");
                    byte[] signature = signData(pt);
                    
                    // 평문 메시지 전송 (암호화 안함)
                    this.out.writeInt(7); // TYPE_PLAINTEXT_CHAT
                    this.out.writeInt(0);  // IV 없음
                    this.out.writeInt(pt.length);
                    this.out.write(pt);
                    
                    // 서명 전송 (암호화 안함)
                    this.out.writeInt(8); // TYPE_PLAINTEXT_SIGNATURE
                    this.out.writeInt(0);  // IV 없음
                    this.out.writeInt(signature.length);
                    this.out.write(signature);
                    this.out.flush();
                    
                    if (onMessage != null) onMessage.accept("[TEXT] Plaintext message and signature sent");
                } else {
                    // 평문만, 서명도 없음 (가장 기본 전송)
                    if (onMessage != null) onMessage.accept("[TEXT] Sending as PLAINTEXT (no signature)");
                    this.out.writeInt(7); // TYPE_PLAINTEXT_CHAT
                    this.out.writeInt(0);  // IV 없음
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
     * 데이터에 디지털 서명을 생성합니다.
     * SHA256으로 해시한 후 RSA 개인키로 서명 (SHA256withRSA)
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

    /**
     * 파일 전송 (기본값: 암호화 + 서명)
     */
    public void sendFile(java.io.File f) throws Exception {
        sendFile(f, true, true);
    }
    
    /**
     * 파일을 전송합니다.
     * @param f 전송할 파일
     * @param encrypt true면 AES로 암호화, false면 평문 전송
     * @param sign true면 파일 전체에 대한 서명 추가
     */
    public void sendFile(java.io.File f, boolean encrypt, boolean sign) throws Exception {
        if (onMessage != null) {
            String mode = encrypt ? "ENCRYPTED" : "PLAINTEXT";
            String sigMode = sign ? " with signature" : " without signature";
            onMessage.accept("[FILE] Starting " + mode + " file transfer" + sigMode + ": " + f.getName() + " (" + f.length() + " bytes)");
        }
        
        java.security.PrivateKey signingKey = myKeyPair.getPrivate();
        
        // 1) 파일 메타데이터 준비 (파일명 + 파일 크기)
        byte[] nameB = f.getName().getBytes(java.nio.charset.StandardCharsets.UTF_8);
        java.io.ByteArrayOutputStream metaB = new java.io.ByteArrayOutputStream();
        java.io.DataOutputStream dos = new java.io.DataOutputStream(metaB);
        dos.writeInt(nameB.length); 
        dos.write(nameB);
        dos.writeLong(f.length()); 
        dos.flush();
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
