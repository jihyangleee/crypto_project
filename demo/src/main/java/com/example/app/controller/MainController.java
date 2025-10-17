package com.example.app.controller;

import com.example.app.model.RSAKeyManager;
import com.example.app.net.ChatClient;
import com.example.app.net.ChatServer;
import javafx.application.Platform;
import javafx.fxml.FXML;
import javafx.scene.control.*;
import javafx.stage.FileChooser;

import java.io.File;
import java.nio.file.Path;

public class MainController {

    @FXML public RadioButton clientRadio;
    @FXML public RadioButton serverRadio;
    @FXML public Label statusLabel;
    @FXML public TextField infoField;

    @FXML public TextArea myKeyArea;
    @FXML public Button genKeyBtn;
    @FXML public Button loadKeyBtn;
    @FXML public Button saveKeyBtn;
    @FXML public Button sendPubBtn;
    @FXML public TextArea peerKeyArea;

    @FXML public TextArea chatLog;
    @FXML public TextField chatInput;
    @FXML public Button sendChatBtn;
    @FXML public TextField hostField;
    @FXML public TextField portField;
    @FXML public Button connectBtn;
    @FXML public Button startServerBtn;

    @FXML public TextArea fileLog;
    @FXML public Button selectFileBtn;
    @FXML public Button sendFileBtn;
    @FXML public ChoiceBox<String> policyBox;
    @FXML public Button demoBtn;
    @FXML public TextArea demoLog;
    @FXML public TextField inspectKeyField;
    @FXML public Button viewEncFileBtn;
    @FXML public Button decryptEncFileBtn;
    @FXML public Button viewEncSigBtn;
    @FXML public Button decryptEncSigBtn;
    @FXML public CheckBox encryptSigCheck;
    @FXML public TextArea wireLog;
    @FXML public Button viewWrappedAesBtn;
    @FXML public Button decryptWrappedAesBtn;
    @FXML public Button verifySigBtn;
    @FXML public TextField verifierPubField;

    private RSAKeyManager keyManager = new RSAKeyManager();
    private ChatClient client = new ChatClient();
    private ChatServer server = new ChatServer();
    private File selectedFile = null;

    @FXML
    public void initialize() {
        genKeyBtn.setOnAction(e -> onGenerateKeys());
        saveKeyBtn.setOnAction(e -> onSaveKeys());
        loadKeyBtn.setOnAction(e -> onLoadKeys());
        sendPubBtn.setOnAction(e -> onSendPublicKey());
        sendChatBtn.setOnAction(e -> onSendChat());
        selectFileBtn.setOnAction(e -> onSelectFile());
        sendFileBtn.setOnAction(e -> onSendFile());
        demoBtn.setOnAction(e -> onDemoSend());
        policyBox.getItems().addAll("Both (messages+files)", "Files only", "None (disabled)");
        policyBox.getSelectionModel().select(0);
        connectBtn.setOnAction(e -> onConnect());
        startServerBtn.setOnAction(e -> onStartServer());
    viewEncFileBtn.setOnAction(e -> onViewEncryptedFile());
    decryptEncFileBtn.setOnAction(e -> onDecryptEncryptedFile());
    viewEncSigBtn.setOnAction(e -> onViewEncryptedSig());
    decryptEncSigBtn.setOnAction(e -> onDecryptEncryptedSig());
    viewWrappedAesBtn.setOnAction(e -> onViewWrappedAes());
    decryptWrappedAesBtn.setOnAction(e -> onDecryptWrappedAes());
    // Encryption and signature options are now set per-message in MainViewController
    verifySigBtn.setOnAction(e -> onVerifySignature());

    // wire log from ChatClient
    client.setWireLogger(s -> Platform.runLater(() -> wireLog.appendText(s + "\n")));
    }

    public void appendChat(String s) {
        Platform.runLater(() -> chatLog.appendText(s + "\n"));
    }

    void onGenerateKeys() {
        try {
            keyManager.generateKeyPair(2048);
            myKeyArea.setText(keyManager.getPublicKeyPem());
            statusLabel.setText("Keys generated");
        } catch (Exception ex) {
            statusLabel.setText("Key gen error: " + ex.getMessage());
        }
    }

    void onSaveKeys() {
        try {
            Path out = Path.of("./mykeys");
            keyManager.savePrivateKey(out.resolve("private.key"));
            keyManager.savePublicKey(out.resolve("public.key"));
            statusLabel.setText("Keys saved to ./mykeys");
        } catch (Exception ex) {
            statusLabel.setText("Save error: " + ex.getMessage());
        }
    }

    void onLoadKeys() {
        try {
            Path pub = Path.of("./mykeys/public.key");
            keyManager.loadPublicKey(pub);
            myKeyArea.setText(keyManager.getPublicKeyPem());
            statusLabel.setText("Keys loaded");
        } catch (Exception ex) {
            statusLabel.setText("Load error: " + ex.getMessage());
        }
    }

    void onSendPublicKey() {
        // network stub: just copy to peer area
        peerKeyArea.setText(myKeyArea.getText());
        appendChat("Public key sent (stub)");
    }

    void onSendChat() {
        String t = chatInput.getText();
        if (t==null || t.isBlank()) return;
        appendChat("me: " + t);
        chatInput.clear();
        // send via ChatClient
        try {
            client.send(t);
        } catch (Exception ex) {
            appendChat("send error: " + ex.getMessage());
        }
    }

    void onSelectFile() {
        FileChooser chooser = new FileChooser();
        File f = chooser.showOpenDialog(null);
        if (f!=null) {
            selectedFile = f;
            fileLog.appendText("Selected: " + f.getAbsolutePath() + "\n");
        }
    }

    void onSendFile() {
        if (selectedFile==null) { fileLog.appendText("No file selected\n"); return; }
        new Thread(() -> {
            try {
                client.sendFile(selectedFile);
                Platform.runLater(() -> fileLog.appendText("File sent: " + selectedFile.getName() + "\n"));
            } catch (Exception ex) {
                Platform.runLater(() -> fileLog.appendText("Send file error: " + ex.getMessage() + "\n"));
            }
        }).start();
    }

    void onDemoSend() {
        if (selectedFile==null) { fileLog.appendText("No file selected\n"); return; }
        new Thread(() -> {
            try {
                // 1) generate sender and receiver RSA keypairs (simulate two parties)
                java.security.KeyPairGenerator kpg = java.security.KeyPairGenerator.getInstance("RSA");
                kpg.initialize(2048);
                java.security.KeyPair senderKP = kpg.generateKeyPair();
                java.security.KeyPair receiverKP = kpg.generateKeyPair();

                Platform.runLater(() -> { fileLog.appendText("Generated sender/receiver RSA keypairs\n"); demoLog.appendText("Generated sender/receiver RSA keypairs\n"); });

                // 2) session AES key
                javax.crypto.KeyGenerator kg = javax.crypto.KeyGenerator.getInstance("AES");
                kg.init(128);
                javax.crypto.SecretKey sessionKey = kg.generateKey();
                Platform.runLater(() -> { fileLog.appendText("Generated AES session key (128)\n"); demoLog.appendText("Generated AES session key (128)\n"); });

                // 3) encrypt file with AES-GCM
                byte[] fileBytes = java.nio.file.Files.readAllBytes(selectedFile.toPath());
                byte[] iv = new byte[12]; new java.security.SecureRandom().nextBytes(iv);
                byte[] cipher = com.example.app.model.CryptoUtil.aesEncrypt(sessionKey, fileBytes, iv);
                Platform.runLater(() -> { fileLog.appendText("Encrypted file with AES-GCM: " + cipher.length + " bytes (iv len="+iv.length+")\n"); demoLog.appendText("Encrypted file with AES-GCM: " + cipher.length + " bytes (iv len="+iv.length+")\n"); });

                // 4) wrap(sessionKey) with receiver public key (RSA-OAEP)
                byte[] wrappedKey = com.example.app.model.CryptoUtil.rsaEncrypt(receiverKP.getPublic(), sessionKey.getEncoded());
                Platform.runLater(() -> { fileLog.appendText("Wrapped session key with receiver public key: " + wrappedKey.length + " bytes\n"); demoLog.appendText("Wrapped session key with receiver public key: " + wrappedKey.length + " bytes\n"); });

                // 5) compute digest over plaintext file bytes and sign with sender private key
                java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
                md.update(fileBytes);
                byte[] cDigest = md.digest();
                java.security.Signature signer = java.security.Signature.getInstance("SHA256withRSA");
                signer.initSign(senderKP.getPrivate()); signer.update(cDigest);
                byte[] signature = signer.sign();
                Platform.runLater(() -> { fileLog.appendText("Signed ciphertext digest with sender private key: " + signature.length + " bytes\n"); demoLog.appendText("Signed ciphertext digest with sender private key: " + signature.length + " bytes\n"); });
                // save signature according to encryptSigCheck
                java.io.File sigDir = new java.io.File("received"); if (!sigDir.exists()) sigDir.mkdirs();
                if (encryptSigCheck!=null && encryptSigCheck.isSelected()) {
                    // encrypt signature with sessionKey and save framed
                    byte[] sigIv = new byte[12]; new java.security.SecureRandom().nextBytes(sigIv);
                    byte[] encSig = com.example.app.model.CryptoUtil.aesEncrypt(sessionKey, signature, sigIv);
                    try (java.io.DataOutputStream sdos = new java.io.DataOutputStream(new java.io.FileOutputStream(new java.io.File(sigDir, "encrypted-signature-"+selectedFile.getName()+".sig")))) {
                        sdos.writeInt(sigIv.length); sdos.write(sigIv);
                        sdos.writeInt(encSig.length); sdos.write(encSig);
                    }
                    String encSigB64 = java.util.Base64.getEncoder().encodeToString(encSig);
                    String sigIvB64 = java.util.Base64.getEncoder().encodeToString(sigIv);
                    Platform.runLater(() -> demoLog.appendText("Encrypted signature written to: received/encrypted-signature-"+selectedFile.getName()+".sig\n"));
                    Platform.runLater(() -> demoLog.appendText("Encrypted Signature IV (base64): " + sigIvB64 + "\n"));
                    Platform.runLater(() -> demoLog.appendText("Encrypted Signature (base64): " + encSigB64 + "\n"));
                } else {
                    java.nio.file.Files.write(java.nio.file.Path.of("received", "signature-"+selectedFile.getName()+".bin"), signature);
                    Platform.runLater(() -> demoLog.appendText("Plain signature written to: received/signature-"+selectedFile.getName()+".bin\n"));
                }

                // Simulate sending: receiver unwraps wrappedKey with its private key
                byte[] unwrappedKey = com.example.app.model.CryptoUtil.rsaDecrypt(receiverKP.getPrivate(), wrappedKey);
                javax.crypto.SecretKey receiverSession = com.example.app.model.CryptoUtil.aesKeyFromBytes(unwrappedKey);
                Platform.runLater(() -> { fileLog.appendText("Receiver unwrapped session key OK\n"); demoLog.appendText("Receiver unwrapped session key OK\n"); });

                // Receiver verifies signature using sender public key
                java.security.Signature verifier = java.security.Signature.getInstance("SHA256withRSA");
                verifier.initVerify(senderKP.getPublic()); verifier.update(cDigest);
                boolean verified = verifier.verify(signature);
                Platform.runLater(() -> { fileLog.appendText("Signature verification result: " + verified + "\n"); demoLog.appendText("Signature verification result: " + verified + "\n"); });

                // Receiver decrypts ciphertext with unwrapped AES key and IV
                byte[] plain = com.example.app.model.CryptoUtil.aesDecrypt(receiverSession, cipher, iv);
                Platform.runLater(() -> { fileLog.appendText("Receiver decrypted file OK, bytes="+plain.length+"\n"); demoLog.appendText("Receiver decrypted file OK, bytes="+plain.length+"\n"); });

                // Optionally write decrypted output to disk for visual check
                java.nio.file.Files.write(java.nio.file.Path.of("received", "demo-decrypted-"+selectedFile.getName()), plain);
                Platform.runLater(() -> { fileLog.appendText("Decrypted output written to received/demo-decrypted-"+selectedFile.getName()+"\n"); demoLog.appendText("Decrypted output written to received/demo-decrypted-"+selectedFile.getName()+"\n"); });

            } catch (Exception ex) {
                Platform.runLater(() -> fileLog.appendText("Demo error: " + ex.getMessage() + "\n"));
            }
        }).start();
    }

    void onConnect() {
        String host = hostField.getText();
        int port = Integer.parseInt(portField.getText());
        new Thread(() -> {
            try {
                client.setOnMessage(this::appendChat);
                // Use keys from keyManager
                client.connect(host, port, keyManager.getPublicKey(), keyManager.getPrivateKey());
                Platform.runLater(() -> statusLabel.setText("Connected to " + host + ":" + port));
            } catch (Exception ex) {
                Platform.runLater(() -> statusLabel.setText("Connect error: " + ex.getMessage()));
            }
        }).start();
    }

    void onStartServer() {
        int port = Integer.parseInt(portField.getText());
        new Thread(() -> {
            try {
                // Use keys from keyManager
                server.start(port, (msg) -> Platform.runLater(() -> appendChat(msg)), 
                    keyManager.getPublicKey(), keyManager.getPrivateKey());
                Platform.runLater(() -> statusLabel.setText("Server listening on " + port));
            } catch (Exception ex) {
                Platform.runLater(() -> statusLabel.setText("Server error: " + ex.getMessage()));
            }
        }).start();
    }

    // --- new handlers for inspecting stored encrypted artifacts ---
    void onViewEncryptedFile() {
        try {
            java.io.File dir = new java.io.File("received");
            java.io.File[] files = dir.listFiles((d,n) -> n.startsWith("encrypted-") && !n.endsWith(".sig"));
            if (files==null || files.length==0) { demoLog.appendText("No encrypted files found in received/\n"); return; }
            java.io.File f = files[0];
            // read framed iv+ct
            try (java.io.DataInputStream dis = new java.io.DataInputStream(new java.io.FileInputStream(f))) {
                int ivlen = dis.readInt(); byte[] iv = new byte[ivlen]; dis.readFully(iv);
                int ctlen = dis.readInt(); byte[] ct = new byte[ctlen]; dis.readFully(ct);
                demoLog.appendText("Encrypted file: " + f.getName() + "\n");
                demoLog.appendText("IV (base64): " + java.util.Base64.getEncoder().encodeToString(iv) + "\n");
                demoLog.appendText("Cipher (base64): " + java.util.Base64.getEncoder().encodeToString(ct) + "\n");
            }
        } catch (Exception ex) { demoLog.appendText("viewEncFile error: " + ex.getMessage() + "\n"); }
    }

    void onViewEncryptedSig() {
        try {
            java.io.File dir = new java.io.File("received");
            java.io.File[] files = dir.listFiles((d,n) -> n.startsWith("encrypted-signature-"));
            if (files==null || files.length==0) { demoLog.appendText("No encrypted signature files found in received/\n"); return; }
            java.io.File f = files[0];
            try (java.io.DataInputStream dis = new java.io.DataInputStream(new java.io.FileInputStream(f))) {
                int ivlen = dis.readInt(); byte[] iv = new byte[ivlen]; dis.readFully(iv);
                int ctlen = dis.readInt(); byte[] ct = new byte[ctlen]; dis.readFully(ct);
                demoLog.appendText("Encrypted signature: " + f.getName() + "\n");
                demoLog.appendText("IV (base64): " + java.util.Base64.getEncoder().encodeToString(iv) + "\n");
                demoLog.appendText("Cipher (base64): " + java.util.Base64.getEncoder().encodeToString(ct) + "\n");
            }
        } catch (Exception ex) { demoLog.appendText("viewEncSig error: " + ex.getMessage() + "\n"); }
    }

    void onDecryptEncryptedFile() {
        try {
            String keyIn = inspectKeyField.getText();
            if (keyIn==null || keyIn.isBlank()) { demoLog.appendText("Provide AES key (base64 or hex) in the Key field\n"); return; }
            byte[] keyBytes = parseKeyInput(keyIn);
            javax.crypto.SecretKey sk = com.example.app.model.CryptoUtil.aesKeyFromBytes(keyBytes);
            java.io.File dir = new java.io.File("received");
            java.io.File[] files = dir.listFiles((d,n) -> n.startsWith("encrypted-") && !n.endsWith(".sig"));
            if (files==null || files.length==0) { demoLog.appendText("No encrypted files found in received/\n"); return; }
            java.io.File f = files[0];
            byte[] plain;
            try (java.io.DataInputStream dis = new java.io.DataInputStream(new java.io.FileInputStream(f))) {
                int ivlen = dis.readInt(); byte[] iv = new byte[ivlen]; dis.readFully(iv);
                int ctlen = dis.readInt(); byte[] ct = new byte[ctlen]; dis.readFully(ct);
                plain = com.example.app.model.CryptoUtil.aesDecrypt(sk, ct, iv);
            }
            java.nio.file.Path out = java.nio.file.Path.of("received", "decrypted-"+f.getName());
            java.nio.file.Files.write(out, plain);
            demoLog.appendText("Decrypted file written to: " + out.toString() + "\n");
        } catch (Exception ex) { demoLog.appendText("decryptEncFile error: " + ex.getMessage() + "\n"); }
    }

    void onDecryptEncryptedSig() {
        try {
            String keyIn = inspectKeyField.getText();
            if (keyIn==null || keyIn.isBlank()) { demoLog.appendText("Provide AES key (base64 or hex) in the Key field\n"); return; }
            byte[] keyBytes = parseKeyInput(keyIn);
            javax.crypto.SecretKey sk = com.example.app.model.CryptoUtil.aesKeyFromBytes(keyBytes);
            java.io.File dir = new java.io.File("received");
            java.io.File[] files = dir.listFiles((d,n) -> n.startsWith("encrypted-signature-"));
            if (files==null || files.length==0) { demoLog.appendText("No encrypted signature files found in received/\n"); return; }
            java.io.File f = files[0];
            byte[] signature;
            try (java.io.DataInputStream dis = new java.io.DataInputStream(new java.io.FileInputStream(f))) {
                int ivlen = dis.readInt(); byte[] iv = new byte[ivlen]; dis.readFully(iv);
                int ctlen = dis.readInt(); byte[] ct = new byte[ctlen]; dis.readFully(ct);
                signature = com.example.app.model.CryptoUtil.aesDecrypt(sk, ct, iv);
            }
            java.nio.file.Path out = java.nio.file.Path.of("received", "decrypted-signature-"+f.getName()+".bin");
            java.nio.file.Files.write(out, signature);
            demoLog.appendText("Decrypted signature written to: " + out.toString() + "\n");
        } catch (Exception ex) { demoLog.appendText("decryptEncSig error: " + ex.getMessage() + "\n"); }
    }

    void onVerifySignature() {
        try {
            // find plaintext signature file first
            java.io.File dir = new java.io.File("received");
            // support either plaintext signature or encrypted signature file
            java.io.File[] sigFiles = dir.listFiles((d,n) -> n.startsWith("signature-") && n.endsWith(".bin"));
            java.io.File[] encSigFiles = dir.listFiles((d,n) -> n.startsWith("encrypted-signature-"));
            byte[] sig = null;
            if (sigFiles!=null && sigFiles.length>0) {
                java.io.File sigFile = sigFiles[0];
                sig = java.nio.file.Files.readAllBytes(sigFile.toPath());
            } else if (encSigFiles!=null && encSigFiles.length>0) {
                // decrypt encrypted signature: need AES key (either from unwrapped-aes.bin or from user)
                java.io.File encSigFile = encSigFiles[0];
                try (java.io.DataInputStream dis = new java.io.DataInputStream(new java.io.FileInputStream(encSigFile))) {
                    int ivlen = dis.readInt(); byte[] iv = new byte[ivlen]; dis.readFully(iv);
                    int ctlen = dis.readInt(); byte[] ct = new byte[ctlen]; dis.readFully(ct);
                    // try to load unwrapped AES
                    java.io.File unwrapped = new java.io.File("received/unwrapped-aes.bin");
                    javax.crypto.SecretKey sk = null;
                    if (unwrapped.exists()) {
                        byte[] raw = java.nio.file.Files.readAllBytes(unwrapped.toPath());
                        sk = com.example.app.model.CryptoUtil.aesKeyFromBytes(raw);
                    } else {
                        // prompt user to paste AES in inspectKeyField
                        String keyIn = inspectKeyField.getText();
                        if (keyIn==null || keyIn.isBlank()) { demoLog.appendText("Encrypted signature found but no AES key available; put AES (base64/hex) into Key field\n"); return; }
                        byte[] keyBytes = parseKeyInput(keyIn);
                        sk = com.example.app.model.CryptoUtil.aesKeyFromBytes(keyBytes);
                    }
                    sig = com.example.app.model.CryptoUtil.aesDecrypt(sk, ct, iv);
                }
            } else {
                demoLog.appendText("No signature file found to verify\n"); return;
            }

            // read corresponding encrypted file's ciphertext digest (we recompute digest over stored ciphertext frames)
            java.io.File[] encFiles = dir.listFiles((d,n) -> n.startsWith("encrypted-") && !n.endsWith(".sig"));
            if (encFiles==null || encFiles.length==0) { demoLog.appendText("No encrypted file frames found to compute digest\n"); return; }
            java.io.File encFile = encFiles[0];
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
            try (java.io.DataInputStream dis = new java.io.DataInputStream(new java.io.FileInputStream(encFile))) {
                while (dis.available()>0) {
                    int ivlen = dis.readInt(); dis.skipBytes(ivlen);
                    int ctlen = dis.readInt(); byte[] ct = new byte[ctlen]; dis.readFully(ct);
                    md.update(ct);
                }
            }
            byte[] digest = md.digest();

            // parse verifier public key input
            String pubIn = verifierPubField.getText();
            if (pubIn==null || pubIn.isBlank()) { demoLog.appendText("Provide verifier public key (PEM/base64/path)\n"); return; }
            byte[] pubBytes;
            java.io.File maybe = new java.io.File(pubIn);
            if (maybe.exists()) pubBytes = java.nio.file.Files.readAllBytes(maybe.toPath());
            else {
                String t = pubIn.trim();
                if (t.contains("-----BEGIN")) {
                    String inner = t.replaceAll("-----.*KEY-----", "").replaceAll("\n", "").trim();
                    pubBytes = java.util.Base64.getDecoder().decode(inner);
                } else {
                    try { pubBytes = java.util.Base64.getDecoder().decode(t); } catch (IllegalArgumentException ex) {
                        int len = t.length()/2; pubBytes = new byte[len]; for (int i=0;i<len;i++) pubBytes[i] = (byte) Integer.parseInt(t.substring(i*2,i*2+2),16);
                    }
                }
            }
            java.security.PublicKey pub = com.example.app.model.CryptoUtil.loadPublicKeyFromBytes(pubBytes);
            java.security.Signature verifier = java.security.Signature.getInstance("SHA256withRSA");
            verifier.initVerify(pub); verifier.update(digest);
            boolean ok = verifier.verify(sig);
            demoLog.appendText("Signature verify result: " + ok + "\n");
        } catch (Exception ex) { demoLog.appendText("verifySig error: " + ex.getMessage() + "\n"); }
    }

    private byte[] parseKeyInput(String s) {
        s = s.trim();
        try { return java.util.Base64.getDecoder().decode(s); } catch (IllegalArgumentException ignored) {}
        // try hex
        if (s.matches("^[0-9a-fA-F]+$")) {
            int len = s.length()/2; byte[] out = new byte[len];
            for (int i=0;i<len;i++) out[i] = (byte) Integer.parseInt(s.substring(i*2, i*2+2), 16);
            return out;
        }
        throw new IllegalArgumentException("Key not base64 or hex");
    }

    void onViewWrappedAes() {
        try {
            java.io.File f = new java.io.File("received/wrapped-aes.bin");
            if (!f.exists()) { demoLog.appendText("No wrapped-aes.bin found in received/\n"); return; }
            byte[] enc = java.nio.file.Files.readAllBytes(f.toPath());
            demoLog.appendText("Wrapped AES (base64): " + java.util.Base64.getEncoder().encodeToString(enc) + "\n");
        } catch (Exception ex) { demoLog.appendText("viewWrappedAes error: " + ex.getMessage() + "\n"); }
    }

    void onDecryptWrappedAes() {
        try {
            String pkIn = inspectKeyField.getText();
            if (pkIn==null || pkIn.isBlank()) { demoLog.appendText("Provide RSA private key (PEM base64 or raw PKCS8 hex/base64) in Key field\n"); return; }
            byte[] privBytes = null;
            // if PK file path provided
            java.io.File maybe = new java.io.File(pkIn);
            if (maybe.exists()) { privBytes = java.nio.file.Files.readAllBytes(maybe.toPath()); }
            else {
                // try parse as PEM or base64 or hex
                String t = pkIn.trim();
                if (t.contains("-----BEGIN")) {
                    String inner = t.replaceAll("-----.*KEY-----", "").replaceAll("\n", "").trim();
                    privBytes = java.util.Base64.getDecoder().decode(inner);
                } else {
                    try { privBytes = java.util.Base64.getDecoder().decode(t); } catch (IllegalArgumentException ex) {
                        // hex
                        int len = t.length()/2; privBytes = new byte[len]; for (int i=0;i<len;i++) privBytes[i] = (byte) Integer.parseInt(t.substring(i*2,i*2+2),16);
                    }
                }
            }

            java.io.File f = new java.io.File("received/wrapped-aes.bin");
            if (!f.exists()) { demoLog.appendText("No wrapped-aes.bin found in received/\n"); return; }
            byte[] enc = java.nio.file.Files.readAllBytes(f.toPath());

            java.security.spec.PKCS8EncodedKeySpec spec = new java.security.spec.PKCS8EncodedKeySpec(privBytes);
            java.security.KeyFactory kf = java.security.KeyFactory.getInstance("RSA");
            java.security.PrivateKey priv = kf.generatePrivate(spec);

            byte[] aesRaw = com.example.app.model.CryptoUtil.rsaDecrypt(priv, enc);
            String aesB64 = java.util.Base64.getEncoder().encodeToString(aesRaw);
            demoLog.appendText("Unwrapped AES (base64): " + aesB64 + "\n");
            // save to file
            java.nio.file.Path out = java.nio.file.Path.of("received", "unwrapped-aes.bin");
            java.nio.file.Files.write(out, aesRaw);
            demoLog.appendText("Unwrapped AES written to: " + out.toString() + "\n");
        } catch (Exception ex) { demoLog.appendText("decryptWrappedAes error: " + ex.getMessage() + "\n"); }
    }
}
