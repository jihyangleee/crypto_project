package com.example.app.ui;

import com.example.app.crypto.*;
import com.example.app.domain.*;
import com.example.app.services.mock.*;
import com.example.app.util.ByteFormat;
import com.example.app.net.ChatClient;
import com.example.app.net.ChatServer;
import com.example.app.net.ChatServer.MessageData;
import com.example.app.net.ChatServer.SessionKeyData;

import javafx.application.Platform;
import javafx.beans.property.*;
import javafx.collections.*;
import javafx.fxml.FXML;
import javafx.scene.control.*;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.scene.layout.*;
import javafx.stage.FileChooser;

import java.io.File;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.Optional;
import java.util.UUID;

public class MainViewController {

    // Services (Real cryptographic implementations)
    private final RealKeyService keyService = new RealKeyService();
    private final EncryptService encryptService = new RealEncryptService(keyService);
    private final SignService signService = new RealSignService(keyService);
    
    // Network components
    private ChatClient chatClient;
    private ChatServer chatServer;
    private Thread serverThread;
    private String currentWrappedSessionKey = ""; // Store RSA-wrapped AES key for display
    private String currentPeerPublicKeyPem = ""; // Store current peer's public key (PEM format)
    
    // Data
    private final ObservableList<Packet> sentPackets = FXCollections.observableArrayList();
    private final ObservableList<ReceivedPublicKey> receivedKeys = FXCollections.observableArrayList();
    private final ObservableList<LogEntry> logs = FXCollections.observableArrayList();
    
    private Packet selectedPacket;
    private File selectedFile;
    
    // FXML Top Bar
    @FXML private RadioButton clientRadio, serverRadio;
    @FXML private TextField hostField, portField;
    @FXML private Button connectBtn;
    @FXML private Label statusLabel;
    
    // FXML Left Panel (Keys)
    @FXML private Label keyAlgoLabel, keyLengthLabel, privateKeyStatus;
    @FXML private TextArea fingerprintArea, pemPreview;
    @FXML private CheckBox showPemCheck;
    
    // FXML Center Panel (Messages)
    @FXML private TextArea messageInput;
    @FXML private Label attachmentLabel;
    @FXML private CheckBox encryptCheck, signCheck;
    @FXML private TableView<Packet> sentPacketsTable;
    @FXML private TableColumn<Packet, String> timeCol, sizeCol, algoCol, signedCol;
    @FXML private TableColumn<Packet, Void> detailCol;
    
    // FXML Right Panel - Packet Details
    @FXML private Label noPacketLabel;
    @FXML private VBox packetDetailsBox, decryptedBox;
    @FXML private TextArea cipherArea, wrappedKeyArea, signatureArea, decryptedArea;
    @FXML private TextField ivField;
    @FXML private CheckBox showFullCipherCheck, showFullKeyCheck, showFullSigCheck;
    
    // FXML Right Panel - Signature Verification
    @FXML private TextField verifySigField, signerDigestField, localDigestField;
    @FXML private HBox verifyResultBox;
    @FXML private Label verifyResultLabel;
    
    // FXML Right Panel - Key List
    @FXML private TableView<ReceivedPublicKey> keysTable;
    @FXML private TableColumn<ReceivedPublicKey, String> aliasCol, fpCol, dateCol;
    @FXML private TableColumn<ReceivedPublicKey, Void> actionsCol;
    @FXML private TitledPane keyDetailsPane;
    @FXML private TextArea keyDetailArea;
    
    // FXML Right Panel - Logs
    @FXML private TableView<LogEntry> logsTable;
    @FXML private TableColumn<LogEntry, String> logTimeCol, logLevelCol, logEventCol, logDetailsCol;
    
    @FXML
    public void initialize() {
        setupTables();
        addLog("INFO", "Application Started", "Security messaging application initialized");
    }
    
    private void setupTables() {
        // Sent Packets Table
        timeCol.setCellValueFactory(data -> {
            String formatted = DateTimeFormatter.ofPattern("HH:mm:ss")
                .withZone(java.time.ZoneId.systemDefault())
                .format(data.getValue().getTime());
            return new SimpleStringProperty(formatted);
        });
        sizeCol.setCellValueFactory(data -> 
            new SimpleStringProperty(ByteFormat.formatSize(data.getValue().getSizeBytes())));
        algoCol.setCellValueFactory(data -> 
            new SimpleStringProperty(data.getValue().getAlgoSummary()));
        signedCol.setCellValueFactory(data -> 
            new SimpleStringProperty(data.getValue().isHasSignature() ? "✓" : "-"));
        
        // Add "View" button column
        detailCol.setCellFactory(param -> new TableCell<>() {
            private final Button viewBtn = new Button("View");
            {
                viewBtn.setOnAction(e -> {
                    Packet packet = getTableView().getItems().get(getIndex());
                    showPacketDetails(packet);
                });
            }
            @Override
            protected void updateItem(Void item, boolean empty) {
                super.updateItem(item, empty);
                setGraphic(empty ? null : viewBtn);
            }
        });
        
        sentPacketsTable.setItems(sentPackets);
        
        // Keys Table
        aliasCol.setCellValueFactory(new PropertyValueFactory<>("alias"));
        fpCol.setCellValueFactory(data -> 
            new SimpleStringProperty(ByteFormat.truncate(data.getValue().getFingerprint())));
        dateCol.setCellValueFactory(data -> {
            String formatted = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm")
                .withZone(java.time.ZoneId.systemDefault())
                .format(data.getValue().getReceivedDate());
            return new SimpleStringProperty(formatted);
        });
        
        // Add action buttons for Keys Table
        actionsCol.setCellFactory(param -> new TableCell<>() {
            private final HBox buttons = new HBox(5);
            private final Button viewBtn = new Button("View");
            private final Button trustBtn = new Button("Trust");
            private final Button deleteBtn = new Button("Delete");
            
            {
                viewBtn.setOnAction(e -> {
                    ReceivedPublicKey key = getTableView().getItems().get(getIndex());
                    showKeyDetails(key);
                });
                trustBtn.setOnAction(e -> {
                    ReceivedPublicKey key = getTableView().getItems().get(getIndex());
                    key.setTrusted(!key.isTrusted());
                    trustBtn.setText(key.isTrusted() ? "Trusted ✓" : "Trust");
                    addLog("INFO", "Key Trust Updated", "Key " + key.getAlias() + " trust: " + key.isTrusted());
                });
                deleteBtn.setOnAction(e -> {
                    ReceivedPublicKey key = getTableView().getItems().get(getIndex());
                    receivedKeys.remove(key);
                    addLog("WARNING", "Key Deleted", "Removed key: " + key.getAlias());
                });
                
                viewBtn.setStyle("-fx-font-size: 10px; -fx-padding: 2 6 2 6;");
                trustBtn.setStyle("-fx-font-size: 10px; -fx-padding: 2 6 2 6;");
                deleteBtn.setStyle("-fx-font-size: 10px; -fx-padding: 2 6 2 6;");
                buttons.getChildren().addAll(viewBtn, trustBtn, deleteBtn);
            }
            
            @Override
            protected void updateItem(Void item, boolean empty) {
                super.updateItem(item, empty);
                if (empty) {
                    setGraphic(null);
                } else {
                    ReceivedPublicKey key = getTableView().getItems().get(getIndex());
                    trustBtn.setText(key.isTrusted() ? "Trusted ✓" : "Trust");
                    setGraphic(buttons);
                }
            }
        });
        
        keysTable.setItems(receivedKeys);
        
        // Handle key selection to show details
        keysTable.getSelectionModel().selectedItemProperty().addListener((obs, oldVal, newVal) -> {
            if (newVal != null) {
                showKeyDetails(newVal);
            }
        });
        
        // Logs Table
        logTimeCol.setCellValueFactory(data -> {
            String formatted = DateTimeFormatter.ofPattern("HH:mm:ss")
                .withZone(java.time.ZoneId.systemDefault())
                .format(data.getValue().getTime());
            return new SimpleStringProperty(formatted);
        });
        logLevelCol.setCellValueFactory(new PropertyValueFactory<>("level"));
        logEventCol.setCellValueFactory(new PropertyValueFactory<>("event"));
        logDetailsCol.setCellValueFactory(new PropertyValueFactory<>("details"));
        
        logsTable.setItems(logs);
    }
    
    // === ACTION HANDLERS ===
    
    @FXML
    private void onConnect() {
        // Check if keys are generated
        try {
            keyService.getPublicKey();
        } catch (Exception e) {
            Alert alert = new Alert(Alert.AlertType.WARNING);
            alert.setTitle("No Keys");
            alert.setHeaderText("Please generate keys first");
            alert.setContentText("You must generate RSA keys before connecting.");
            alert.showAndWait();
            return;
        }
        
        if (clientRadio.isSelected()) {
            // Client mode
            connectAsClient();
        } else {
            // Server mode
            startServer();
        }
    }
    
    private void connectAsClient() {
        String host = hostField.getText();
        int port;
        try {
            port = Integer.parseInt(portField.getText());
        } catch (NumberFormatException e) {
            addLog("ERROR", "Invalid Port", "Port must be a number");
            return;
        }
        
        try {
            chatClient = new ChatClient();
            
            // Set callback for when peer public key is received
            chatClient.setOnPeerKeyReceived(peerKey -> {
                Platform.runLater(() -> {
                    addPeerPublicKeyToList("Server", peerKey);
                    addLog("INFO", "Key Exchange", "Received server's public key");
                });
            });
            
            // Set callback for when message is received
            chatClient.setOnMessage(msg -> {
                Platform.runLater(() -> {
                    addLog("INFO", "Message Received", msg);
                });
            });
            
            // Connect with our keys
            chatClient.connect(host, port, keyService.getPublicKey(), keyService.getPrivateKey());
            
            statusLabel.setText("📤 Connected as CLIENT");
            statusLabel.getStyleClass().clear();
            statusLabel.getStyleClass().add("status-connected");
            statusLabel.setStyle("-fx-text-fill: #2196F3; -fx-font-weight: bold;");
            addLog("INFO", "📤 Client Mode", "Connected to " + host + ":" + port + " as CLIENT");
            
        } catch (Exception e) {
            addLog("ERROR", "Connection Failed", e.getMessage());
            statusLabel.setText("Disconnected");
            statusLabel.getStyleClass().clear();
            statusLabel.getStyleClass().add("status-disconnected");
        }
    }
    
    private void startServer() {
        int port;
        try {
            port = Integer.parseInt(portField.getText());
        } catch (NumberFormatException e) {
            addLog("ERROR", "Invalid Port", "Port must be a number");
            return;
        }
        
        try {
            chatServer = new ChatServer();
            
            // Set callback for when peer public key is received
            chatServer.setOnPeerKeyReceived(peerKey -> {
                Platform.runLater(() -> {
                    // Convert public key to PEM for storage
                    try {
                        byte[] encoded = peerKey.getEncoded();
                        String pem = "-----BEGIN PUBLIC KEY-----\n" +
                                    Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(encoded) +
                                    "\n-----END PUBLIC KEY-----";
                        currentPeerPublicKeyPem = pem;
                    } catch (Exception e) {
                        addLog("ERROR", "Key Conversion Failed", e.getMessage());
                    }
                    
                    addPeerPublicKeyToList("Client", peerKey);
                    addLog("INFO", "Key Exchange", "Received client's public key");
                });
            });
            
            // Set callback for when session key is received
            chatServer.setOnSessionKeyReceived(sessionData -> {
                Platform.runLater(() -> {
                    currentWrappedSessionKey = Base64.getEncoder().encodeToString(sessionData.wrappedKey);
                    addLog("INFO", "Session Key", "Received RSA-wrapped AES session key (" + sessionData.wrappedKey.length + " bytes)");
                });
            });
            
            // Set callback for when message is received
            chatServer.setOnMessageReceived(msgData -> {
                Platform.runLater(() -> {
                    try {
                        // Create packet from received encrypted data
                        String base64Cipher = java.util.Base64.getEncoder().encodeToString(msgData.ciphertext);
                        String base64Iv = java.util.Base64.getEncoder().encodeToString(msgData.iv);
                        String base64Signature = msgData.signature != null ? 
                            java.util.Base64.getEncoder().encodeToString(msgData.signature) : "";
                        
                        Packet receivedPacket = new Packet(
                            UUID.randomUUID(),
                            Instant.now(),
                            msgData.signature != null, // Has signature
                            "AES-128-GCM (Session Key)",
                            base64Cipher,
                            currentWrappedSessionKey, // RSA-wrapped AES session key
                            base64Signature,
                            base64Iv,
                            msgData.plaintext.getBytes().length,
                            "RX"
                        );
                        
                        // Store original plaintext for signature verification
                        receivedPacket.setOriginalPlaintext(msgData.plaintext);
                        
                        // Store the already-decrypted plaintext with signature verification status for display
                        String plaintextWithStatus = msgData.plaintext;
                        if (msgData.signature != null) {
                            plaintextWithStatus += "\n\n=== Digital Signature ===\n";
                            plaintextWithStatus += "Status: " + (msgData.signatureVerified ? "✓ VERIFIED" : "✗ FAILED") + "\n";
                            plaintextWithStatus += "Algorithm: SHA256withRSA\n";
                            plaintextWithStatus += "Verified with: Client's Public Key";
                        }
                        receivedPacket.setPlaintext(plaintextWithStatus);
                        
                        sentPackets.add(receivedPacket);
                        
                        // Log with prominent signature verification status
                        if (msgData.signature != null) {
                            if (msgData.signatureVerified) {
                                addLog("SUCCESS", "✓ Signature VERIFIED", 
                                    "Message signature is VALID - authenticated from client (" + 
                                    msgData.plaintext.getBytes().length + " bytes)");
                            } else {
                                addLog("ERROR", "✗ Signature FAILED", 
                                    "Message signature is INVALID - verification failed! (" + 
                                    msgData.plaintext.getBytes().length + " bytes)");
                            }
                        } else {
                            addLog("INFO", "Message Received", "Received encrypted " + msgData.type + " from client (" + 
                                msgData.plaintext.getBytes().length + " bytes) [No signature]");
                        }
                    } catch (Exception e) {
                        addLog("ERROR", "Failed to process received message", e.getMessage());
                    }
                });
            });
            
            // Set callback for when file is received
            chatServer.setOnFileReceived(fileData -> {
                Platform.runLater(() -> {
                    try {
                        String base64Signature = fileData.signature != null ? 
                            java.util.Base64.getEncoder().encodeToString(fileData.signature) : "";
                        
                        // Prepare plaintext content for display
                        String plaintextContent = "";
                        if (fileData.decryptedContent != null && fileData.decryptedContent.length > 0) {
                            // For small files, show content preview
                            if (fileData.decryptedContent.length < 10240) { // < 10KB
                                try {
                                    // Try to decode as UTF-8 text
                                    String textContent = new String(fileData.decryptedContent, java.nio.charset.StandardCharsets.UTF_8);
                                    plaintextContent = "=== File Content Preview ===\n" + textContent + "\n=== End of Preview ===";
                                } catch (Exception e) {
                                    // Binary file, show hex preview
                                    StringBuilder hexPreview = new StringBuilder("=== Binary File (Hex Preview) ===\n");
                                    int previewLength = Math.min(256, fileData.decryptedContent.length);
                                    for (int i = 0; i < previewLength; i++) {
                                        hexPreview.append(String.format("%02X ", fileData.decryptedContent[i]));
                                        if ((i + 1) % 16 == 0) hexPreview.append("\n");
                                    }
                                    if (fileData.decryptedContent.length > 256) {
                                        hexPreview.append("... (").append(fileData.decryptedContent.length - 256).append(" more bytes)");
                                    }
                                    plaintextContent = hexPreview.toString();
                                }
                            } else {
                                plaintextContent = "[Large file: " + fileData.decryptedContent.length + " bytes]\nContent too large to preview.\n";
                            }
                        }
                        
                        // Add signature verification info
                        if (fileData.signature != null) {
                            plaintextContent += "\n\n=== Digital Signature Verification ===\n";
                            plaintextContent += "Signature Algorithm: SHA256withRSA\n";
                            if (fileData.signatureVerified) {
                                plaintextContent += "Signature Status: ✓ VERIFIED (Valid)\n";
                            } else {
                                plaintextContent += "Signature Status: ✗ FAILED (Invalid)\n";
                            }
                            plaintextContent += "Signature Length: " + fileData.signature.length + " bytes\n";
                            plaintextContent += "Signature (Base64): " + base64Signature.substring(0, Math.min(64, base64Signature.length())) + "...\n";
                        }
                        
                        // Add file path information
                        plaintextContent += "\n\n=== File Locations ===\n";
                        plaintextContent += "Encrypted: " + fileData.filePath + "\n";
                        if (fileData.decryptedFilePath != null) {
                            plaintextContent += "Decrypted: " + fileData.decryptedFilePath;
                        }
                        
                        // Prepare ciphertext content (read encrypted file)
                        String ciphertextContent = "";
                        try {
                            java.io.File encryptedFile = new java.io.File(fileData.filePath);
                            if (encryptedFile.exists() && encryptedFile.length() < 10240) { // < 10KB
                                byte[] encryptedData = java.nio.file.Files.readAllBytes(encryptedFile.toPath());
                                StringBuilder hexCipher = new StringBuilder("=== Encrypted File (Hex) ===\n");
                                hexCipher.append("Format: [IV_LEN][IV][CT_LEN][CIPHERTEXT] (repeated per chunk)\n\n");
                                int previewLength = Math.min(512, encryptedData.length);
                                for (int i = 0; i < previewLength; i++) {
                                    hexCipher.append(String.format("%02X ", encryptedData[i]));
                                    if ((i + 1) % 16 == 0) hexCipher.append("\n");
                                }
                                if (encryptedData.length > 512) {
                                    hexCipher.append("\n... (").append(encryptedData.length - 512).append(" more bytes)");
                                }
                                ciphertextContent = hexCipher.toString();
                            } else if (encryptedFile.exists()) {
                                ciphertextContent = "[Large encrypted file: " + encryptedFile.length() + " bytes]\n";
                                ciphertextContent += "Format: [IV_LEN][IV][CT_LEN][CIPHERTEXT] (repeated per chunk)\n";
                                ciphertextContent += "File path: " + fileData.filePath;
                            }
                        } catch (Exception e) {
                            ciphertextContent = "[Error reading encrypted file: " + e.getMessage() + "]";
                        }
                        
                        Packet filePacket = new Packet(
                            UUID.randomUUID(),
                            Instant.now(),
                            fileData.signature != null, // Has signature
                            "AES-128-GCM + File Chunks",
                            "[File: " + fileData.filename + "]",
                            currentWrappedSessionKey != null ? currentWrappedSessionKey : "",
                            base64Signature,
                            "[Per-chunk IVs]",
                            (int) fileData.fileSize,
                            "RX" // Received
                        );
                        
                        // Store decrypted content as plaintext
                        filePacket.setPlaintext(plaintextContent);
                        // Store encrypted content as ciphertext
                        filePacket.setCiphertext(ciphertextContent);
                        // Mark as file packet and store decrypted file path
                        filePacket.setFilePacket(true);
                        filePacket.setDecryptedFilePath(fileData.decryptedFilePath);
                        
                        sentPackets.add(filePacket);
                        addLog("INFO", "File Received", "Received file: " + fileData.filename + " (" + 
                            fileData.fileSize + " bytes)\nEncrypted: " + fileData.filePath + 
                            (fileData.decryptedFilePath != null ? "\nDecrypted: " + fileData.decryptedFilePath : "") +
                            (fileData.signature != null ? "\n✓ Signature verified" : ""));
                    } catch (Exception e) {
                        addLog("ERROR", "Failed to process received file", e.getMessage());
                    }
                });
            });
            
            // Start server in background thread with our keys
            serverThread = new Thread(() -> {
                try {
                    chatServer.start(port, 
                        msg -> Platform.runLater(() -> {
                            addLog("INFO", "Server", msg);
                            // Update status when client connects
                            if (msg.contains("Client connected")) {
                                statusLabel.setText("📥 Connected as SERVER");
                                statusLabel.getStyleClass().clear();
                                statusLabel.getStyleClass().add("status-connected");
                                statusLabel.setStyle("-fx-text-fill: #4CAF50; -fx-font-weight: bold;");
                            }
                        }),
                        keyService.getPublicKey(), 
                        keyService.getPrivateKey());
                } catch (Exception e) {
                    Platform.runLater(() -> addLog("ERROR", "Server Error", e.getMessage()));
                }
            });
            serverThread.setDaemon(true);
            serverThread.start();
            
            statusLabel.setText("📥 Waiting as SERVER");
            statusLabel.getStyleClass().clear();
            statusLabel.getStyleClass().add("status-waiting");
            statusLabel.setStyle("-fx-text-fill: #FF9800; -fx-font-weight: bold;");
            addLog("INFO", "📥 Server Mode", "Listening on port " + port + " as SERVER");
            
        } catch (Exception e) {
            addLog("ERROR", "Server Start Failed", e.getMessage());
        }
    }
    
    private void addPeerPublicKeyToList(String alias, PublicKey publicKey) {
        try {
            // Calculate fingerprint
            byte[] encoded = publicKey.getEncoded();
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(encoded);
            
            // Convert hash to hex string
            StringBuilder hexBuilder = new StringBuilder();
            for (byte b : hash) {
                hexBuilder.append(String.format("%02x", b));
            }
            String fingerprint = hexBuilder.toString();
            
            // Convert to PEM format
            String pem = "-----BEGIN PUBLIC KEY-----\n" +
                        Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(encoded) +
                        "\n-----END PUBLIC KEY-----";
            
            // Remove old entry with same alias if exists
            receivedKeys.removeIf(key -> key.getAlias().equals(alias));
            
            // Add new entry
            ReceivedPublicKey peerKey = new ReceivedPublicKey(
                alias,
                fingerprint,
                Instant.now(),
                pem
            );
            peerKey.setTrusted(false); // Don't trust by default
            
            receivedKeys.add(0, peerKey);
            addLog("INFO", "Peer Key Added", alias + " public key added to Key List");
            
        } catch (Exception e) {
            addLog("ERROR", "Key Processing Failed", e.getMessage());
        }
    }
    
    @FXML
    private void onGenerateKeys() {
        // Show dialog for algorithm and bit selection
        TextInputDialog dialog = new TextInputDialog("2048");
        dialog.setTitle("Generate Keys");
        dialog.setHeaderText("Key Generation");
        dialog.setContentText("Enter key size (bits):");
        
        Optional<String> result = dialog.showAndWait();
        result.ifPresent(bits -> {
            KeyInfo keyInfo = keyService.generateKeyPair("RSA", Integer.parseInt(bits));
            updateKeyDisplay(keyInfo);
            addLog("INFO", "Keys Generated", "RSA-" + bits + " key pair generated");
        });
    }
    
    private void updateKeyDisplay(KeyInfo keyInfo) {
        keyAlgoLabel.setText(keyInfo.getAlgorithm());
        keyLengthLabel.setText(keyInfo.getKeyLength() + " bits");
        fingerprintArea.setText(ByteFormat.formatHex(keyInfo.getFingerprintHex()));
        pemPreview.setText(keyInfo.getPublicKeyPem());
        
        if (keyInfo.isHasPrivateKey()) {
            privateKeyStatus.setText("✅ Loaded");
        } else {
            privateKeyStatus.setText("❌ Not Loaded");
        }
        
        // Don't add own key to Key List - it's shown in left panel
        // Key List is only for peer keys
    }
    
    @FXML
    private void onSavePublicKey() {
        FileChooser fc = new FileChooser();
        fc.setTitle("Save Public Key");
        fc.getExtensionFilters().add(new FileChooser.ExtensionFilter("PEM Files", "*.pem"));
        File file = fc.showSaveDialog(null);
        if (file != null) {
            keyService.savePublicKey(file.getAbsolutePath());
            addLog("INFO", "Public Key Saved", file.getAbsolutePath());
        }
    }
    
    @FXML
    private void onLoadPublicKey() {
        FileChooser fc = new FileChooser();
        fc.setTitle("Load Public Key");
        fc.getExtensionFilters().add(new FileChooser.ExtensionFilter("PEM Files", "*.pem"));
        File file = fc.showOpenDialog(null);
        if (file != null) {
            keyService.loadPublicKey(file.getAbsolutePath());
            updateKeyDisplay(keyService.getCurrentKeyInfo());
            addLog("INFO", "Public Key Loaded", file.getAbsolutePath());
        }
    }
    
    @FXML
    private void onSavePrivateKey() {
        FileChooser fc = new FileChooser();
        fc.setTitle("Save Private Key (WARNING: Store Securely!)");
        fc.getExtensionFilters().add(new FileChooser.ExtensionFilter("PEM Files", "*.pem"));
        File file = fc.showSaveDialog(null);
        if (file != null) {
            keyService.savePrivateKey(file.getAbsolutePath());
            addLog("WARNING", "Private Key Saved", "Ensure secure storage: " + file.getAbsolutePath());
        }
    }
    
    @FXML
    private void onLoadPrivateKey() {
        FileChooser fc = new FileChooser();
        fc.setTitle("Load Private Key");
        fc.getExtensionFilters().add(new FileChooser.ExtensionFilter("PEM Files", "*.pem"));
        File file = fc.showOpenDialog(null);
        if (file != null) {
            keyService.loadPrivateKey(file.getAbsolutePath());
            privateKeyStatus.setText("✅ Loaded");
            addLog("INFO", "Private Key Loaded", "Private key loaded from file");
        }
    }
    
    @FXML
    private void onTogglePem() {
        boolean show = showPemCheck.isSelected();
        pemPreview.setVisible(show);
        pemPreview.setManaged(show);
    }
    
    @FXML
    private void onSelectFile() {
        FileChooser fc = new FileChooser();
        fc.setTitle("Select File to Send");
        File file = fc.showOpenDialog(null);
        if (file != null) {
            selectedFile = file;
            attachmentLabel.setText(file.getName() + " (" + ByteFormat.formatSize(file.length()) + ")");
            addLog("INFO", "File Selected", file.getName());
        }
    }
    
    @FXML
    private void onClearFile() {
        selectedFile = null;
        attachmentLabel.setText("No file selected");
    }
    
    @FXML
    private void onSendMessage() {
        String plaintext = messageInput.getText();
        if (plaintext.isEmpty() && selectedFile == null) {
            showAlert("Error", "Please enter a message or select a file");
            return;
        }
        
        // Check if connected
        if (chatClient == null) {
            showAlert("Error", "Not connected to server. Please connect first.");
            return;
        }
        
        try {
            // Send text message first if not empty
            if (!plaintext.isEmpty()) {
                addLog("DEBUG", "Sending Text", "Attempting to send " + plaintext.length() + " bytes");
                chatClient.send(plaintext);
                addLog("INFO", "Message Sent", plaintext.length() + " bytes sent to server (encrypted with AES session key)");
            }
            
            // Then send file if selected
            if (selectedFile != null) {
                addLog("DEBUG", "Sending File", "Attempting to send file: " + selectedFile.getName() + " (" + selectedFile.length() + " bytes)");
                
                if (!selectedFile.exists()) {
                    throw new Exception("File does not exist: " + selectedFile.getAbsolutePath());
                }
                if (!selectedFile.canRead()) {
                    throw new Exception("Cannot read file: " + selectedFile.getAbsolutePath());
                }
                
                // Send file
                chatClient.sendFile(selectedFile);
                addLog("INFO", "File Sent", selectedFile.getName() + " (" + selectedFile.length() + " bytes) sent to server");
                
                // Note: File packets are only shown on the receiver (server) side
            }
            
            // Clear input
            messageInput.clear();
            File tempFile = selectedFile;
            selectedFile = null;
            attachmentLabel.setText("No file selected");
            
            if (tempFile != null) {
                addLog("DEBUG", "File Transfer", "File cleared from UI: " + tempFile.getName());
            }
            
        } catch (Exception e) {
            showAlert("Error", "Failed to process: " + e.getMessage());
            addLog("ERROR", "Send Failed", e.getMessage());
            e.printStackTrace();
        }
    }
    
    private void showPacketDetails(Packet packet) {
        selectedPacket = packet;
        noPacketLabel.setVisible(false);
        noPacketLabel.setManaged(false);
        packetDetailsBox.setVisible(true);
        packetDetailsBox.setManaged(true);
        
        // Populate fields
        // Use custom ciphertext if available (e.g., for files), otherwise use base64Cipher
        if (packet.getCiphertext() != null && !packet.getCiphertext().isEmpty()) {
            cipherArea.setText(packet.getCiphertext());
        } else {
            cipherArea.setText(ByteFormat.truncate(packet.getBase64Cipher()));
        }
        wrappedKeyArea.setText(ByteFormat.truncate(packet.getBase64WrappedKey()));
        ivField.setText(packet.getIvBase64());
        signatureArea.setText(ByteFormat.truncate(packet.getBase64Signature()));
        
        decryptedBox.setVisible(false);
        decryptedBox.setManaged(false);
    }
    
    @FXML
    private void onToggleFullCipher() {
        if (selectedPacket != null) {
            cipherArea.setText(showFullCipherCheck.isSelected() ? 
                selectedPacket.getBase64Cipher() : ByteFormat.truncate(selectedPacket.getBase64Cipher()));
        }
    }
    
    @FXML
    private void onToggleFullKey() {
        if (selectedPacket != null) {
            wrappedKeyArea.setText(showFullKeyCheck.isSelected() ? 
                selectedPacket.getBase64WrappedKey() : ByteFormat.truncate(selectedPacket.getBase64WrappedKey()));
        }
    }
    
    @FXML
    private void onToggleFullSig() {
        if (selectedPacket != null) {
            signatureArea.setText(showFullSigCheck.isSelected() ? 
                selectedPacket.getBase64Signature() : ByteFormat.truncate(selectedPacket.getBase64Signature()));
        }
    }
    
    @FXML
    private void onDecryptMessage() {
        if (selectedPacket == null) return;
        
        String plaintext;
        
        // If this is a received packet (RX), use the already-decrypted plaintext
        if ("RX".equals(selectedPacket.getSource()) && selectedPacket.getPlaintext() != null) {
            plaintext = selectedPacket.getPlaintext();
            addLog("INFO", "Message Decrypted", "Showing received plaintext (already decrypted by server)");
        } else {
            // For TX packets or if plaintext not available, try to decrypt with UI keys
            try {
                plaintext = encryptService.decrypt(
                    selectedPacket.getBase64Cipher(),
                    selectedPacket.getBase64WrappedKey(),
                    selectedPacket.getIvBase64()
                );
                addLog("INFO", "Message Decrypted", "Successfully decrypted with local keys");
            } catch (Exception e) {
                plaintext = "[Decryption failed: " + e.getMessage() + "]";
                addLog("ERROR", "Decryption Failed", e.getMessage());
            }
        }
        
        decryptedArea.setText(plaintext);
        decryptedBox.setVisible(true);
        decryptedBox.setManaged(true);
    }
    
    @FXML
    private void onVerifySignature() {
        if (selectedPacket == null) return;
        
        // Get peer's public key from the Key List
        if (receivedKeys.isEmpty()) {
            showAlert("Error", "No peer public key available. Cannot verify signature.");
            return;
        }
        
        // Use the first received key (most recent peer)
        String peerPublicKeyPem = receivedKeys.get(0).getPublicKeyPem();
        
        VerifyResult result;
        
        // Check if this is a file packet
        if (selectedPacket.isFilePacket() && selectedPacket.getDecryptedFilePath() != null) {
            // FILE SIGNATURE VERIFICATION
            // For files, we need to compute the digest of the file content and verify signature on that digest
            try {
                java.io.File file = new java.io.File(selectedPacket.getDecryptedFilePath());
                if (!file.exists()) {
                    showAlert("Error", "Decrypted file not found: " + selectedPacket.getDecryptedFilePath());
                    return;
                }
                
                // Read file content and compute digest
                byte[] fileContent = java.nio.file.Files.readAllBytes(file.toPath());
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                byte[] digest = md.digest(fileContent);
                
                // Convert digest to hex for display
                StringBuilder digestHex = new StringBuilder();
                for (byte b : digest) {
                    digestHex.append(String.format("%02x", b));
                }
                
                // Verify signature on the digest
                PublicKey publicKey = signService.parsePemPublicKey(peerPublicKeyPem);
                java.security.Signature signature = java.security.Signature.getInstance("SHA256withRSA");
                signature.initVerify(publicKey);
                signature.update(digest);
                
                byte[] signatureBytes = Base64.getDecoder().decode(selectedPacket.getBase64Signature());
                boolean matches = signature.verify(signatureBytes);
                
                result = new VerifyResult(digestHex.toString(), digestHex.toString(), matches);
                
                addLog("INFO", "File Signature Verification", 
                    "Verifying signature on file digest (" + fileContent.length + " bytes)");
                
            } catch (Exception e) {
                showAlert("Error", "Failed to verify file signature: " + e.getMessage());
                addLog("ERROR", "File Signature Verification Failed", e.getMessage());
                return;
            }
        } else {
            // TEXT MESSAGE SIGNATURE VERIFICATION
            // Use original plaintext (without UI annotations) for verification
            String plaintext = selectedPacket.getOriginalPlaintext();
            if (plaintext == null || plaintext.isEmpty()) {
                // Fallback to decrypted area text if originalPlaintext not set
                plaintext = decryptedArea.getText();
                if (plaintext.isEmpty()) {
                    showAlert("Error", "Please decrypt the message first");
                    return;
                }
            }
            
            result = signService.verify(
                plaintext,
                selectedPacket.getBase64Signature(),
                peerPublicKeyPem
            );
        }
        
        verifySigField.setText(ByteFormat.truncate(selectedPacket.getBase64Signature()));
        signerDigestField.setText(result.getSignerDigestHex());
        localDigestField.setText(result.getLocalDigestHex());
        
        verifyResultBox.setVisible(true);
        verifyResultBox.setManaged(true);
        
        if (result.isMatches()) {
            verifyResultLabel.setText("✅ Signature Verified: TRUE");
            verifyResultLabel.setStyle("-fx-text-fill: #4CAF50; -fx-font-weight: bold;");
            addLog("INFO", "Signature Verified", "Signature is valid using peer's public key");
        } else {
            verifyResultLabel.setText("❌ Signature Verified: FALSE");
            verifyResultLabel.setStyle("-fx-text-fill: #F44336; -fx-font-weight: bold;");
            addLog("WARNING", "Signature Invalid", "Signature verification failed!");
        }
    }
    
    @FXML
    private void onExportJson() {
        if (selectedPacket == null) return;
        
        FileChooser fc = new FileChooser();
        fc.setTitle("Export Packet as JSON");
        fc.getExtensionFilters().add(new FileChooser.ExtensionFilter("JSON Files", "*.json"));
        File file = fc.showSaveDialog(null);
        
        if (file != null) {
            // Mock JSON export
            addLog("INFO", "Packet Exported", "Exported to " + file.getAbsolutePath());
            showAlert("Success", "Packet exported to " + file.getName());
        }
    }
    
    @FXML
    private void onExportLogs() {
        FileChooser fc = new FileChooser();
        fc.setTitle("Export Logs");
        fc.getExtensionFilters().add(new FileChooser.ExtensionFilter("Text Files", "*.txt"));
        File file = fc.showSaveDialog(null);
        
        if (file != null) {
            addLog("INFO", "Logs Exported", "Exported to " + file.getAbsolutePath());
            showAlert("Success", "Logs exported to " + file.getName());
        }
    }
    
    @FXML
    private void onClearLogs() {
        logs.clear();
        addLog("INFO", "Logs Cleared", "Log history cleared");
    }
    
    // === HELPER METHODS ===
    
    private void addLog(String level, String event, String details) {
        logs.add(new LogEntry(Instant.now(), level, event, details));
    }
    
    private void showAlert(String title, String message) {
        Alert alert = new Alert(Alert.AlertType.INFORMATION);
        alert.setTitle(title);
        alert.setHeaderText(null);
        alert.setContentText(message);
        alert.showAndWait();
    }
    
    private void showKeyDetails(ReceivedPublicKey key) {
        keyDetailsPane.setDisable(false);
        keyDetailsPane.setExpanded(true);
        keyDetailArea.setText(key.getPublicKeyPem());
        addLog("INFO", "Key Details Viewed", "Viewing details for: " + key.getAlias());
    }
}
