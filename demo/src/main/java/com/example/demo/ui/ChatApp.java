package com.example.demo.ui;

import com.example.demo.crypto.CryptoUtil;
import com.example.demo.crypto.KeyHolder;
import com.example.demo.net.ChatClient;
import com.example.demo.net.ChatServer;
import javafx.application.Application;
import javafx.application.Platform;
import javafx.geometry.Insets;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.VBox;
import javafx.stage.Stage;

import java.nio.file.Path;

public class ChatApp extends Application {

    private final KeyHolder keyHolder = new KeyHolder();
    private ChatServer server;
    private ChatClient client;

    private TextArea messagesArea;
    private TextField inputField;

    @Override
    public void start(Stage primaryStage) {
        primaryStage.setTitle("Secure Chat - GUI");

        BorderPane root = new BorderPane();

        // Top: mode selection and status
        HBox topBox = new HBox(10);
        ToggleGroup modeGroup = new ToggleGroup();
        RadioButton clientMode = new RadioButton("Client"); clientMode.setToggleGroup(modeGroup);
        RadioButton serverMode = new RadioButton("Server"); serverMode.setToggleGroup(modeGroup);
        clientMode.setSelected(true);
        Label status = new Label("Not connected");
        topBox.getChildren().addAll(new Label("Mode:"), clientMode, serverMode, status);
        topBox.setPadding(new Insets(8));
        root.setTop(topBox);

        messagesArea = new TextArea();
        messagesArea.setEditable(false);
        messagesArea.setWrapText(true);
        root.setCenter(messagesArea);

        VBox right = new VBox(8);
        right.setPadding(new Insets(8));

        Button genBtn = new Button("Key generation");
        genBtn.setOnAction(e -> {
            try { keyHolder.generateIfAbsent(); append("Keys generated or already present"); }
            catch (Exception ex) { append("Key gen error: " + ex.getMessage()); }
        });

        Button saveBtn = new Button("Save into a file");
        saveBtn.setOnAction(e -> {
            try { var kp = keyHolder.generateIfAbsent(); Path p = Path.of("./mykeys"); p.toFile().mkdirs(); CryptoUtil.savePrivateKey(kp.getPrivate(), p.resolve("private.key")); CryptoUtil.savePublicKey(kp.getPublic(), p.resolve("public.key")); append("Keys saved to ./mykeys"); }
            catch (Exception ex) { append("Save error: " + ex.getMessage()); }
        });

        Button loadBtn = new Button("Load from a file");
        loadBtn.setOnAction(e -> {
            try { var pub = CryptoUtil.loadPublicKey(Path.of("./mykeys/public.key")); var priv = CryptoUtil.loadPrivateKey(Path.of("./mykeys/private.key")); keyHolder.setKeyPair(new java.security.KeyPair(pub, priv)); append("Keys loaded"); }
            catch (Exception ex) { append("Load error: " + ex.getMessage()); }
        });

        HBox serverBox = new HBox(8);
        TextField portField = new TextField("9999"); portField.setPrefWidth(80);
        Button startServerBtn = new Button("Start Server");
        startServerBtn.setOnAction(e -> {
            int port = Integer.parseInt(portField.getText());
            server = new ChatServer(keyHolder);
            new Thread(() -> { try { server.start(port); Platform.runLater(() -> status.setText("Server: listening " + port)); } catch (Exception ex) { Platform.runLater(() -> append("Server error: " + ex.getMessage())); } }).start();
            append("Server starting on " + port);
        });
        serverBox.getChildren().addAll(new Label("Port:"), portField, startServerBtn);

        HBox clientBox = new HBox(8);
        TextField hostField = new TextField("127.0.0.1"); hostField.setPrefWidth(120);
        TextField clientPort = new TextField("9999"); clientPort.setPrefWidth(80);
        Button connectBtn = new Button("Connect");
        connectBtn.setOnAction(e -> {
            try {
                client = new ChatClient(keyHolder);
                client.setListener((from, msg) -> Platform.runLater(() -> append(from + ": " + msg)));
                new Thread(() -> { try { client.connect(hostField.getText(), Integer.parseInt(clientPort.getText())); Platform.runLater(() -> status.setText("Client: connected to " + hostField.getText() + ":" + clientPort.getText())); Platform.runLater(() -> append("Connected to " + hostField.getText() + ":" + clientPort.getText())); } catch (Exception ex) { Platform.runLater(() -> append("Connect error: " + ex.getMessage())); } }).start();
            } catch (Exception ex) { append("Client error: " + ex.getMessage()); }
        });
        clientBox.getChildren().addAll(new Label("Host:"), hostField, new Label("Port:"), clientPort, connectBtn);

        inputField = new TextField(); inputField.setPrefWidth(300);
        Button sendBtn = new Button("Send");
        sendBtn.setOnAction(e -> {
            String text = inputField.getText();
            try {
                if (serverMode.isSelected()) {
                    if (server == null) { append("Server not started"); return; }
                    server.sendMessage(text);
                    append("me (server): " + text);
                } else {
                    if (client == null) { append("Client not connected"); return; }
                    client.sendMessage(text);
                    append("me (client): " + text);
                }
                inputField.clear();
            } catch (Exception ex) { append("Send error: " + ex.getMessage()); }
        });

    right.getChildren().addAll(genBtn, saveBtn, loadBtn, new Separator(), new Label("Server:"), serverBox, new Separator(), new Label("Client:"), clientBox, new Separator(), new Label("Message:"), inputField, sendBtn);

        // Public key display and send public key button
        TextArea pubArea = new TextArea(); pubArea.setEditable(false); pubArea.setPrefRowCount(4);
        Button sendPubBtn = new Button("Send public key");
        sendPubBtn.setOnAction(e -> {
            try {
                var kp = keyHolder.getKeyPair(); if (kp==null) { append("No keys"); return; }
                var pub = kp.getPublic().getEncoded(); pubArea.setText(java.util.Base64.getEncoder().encodeToString(pub));
                append("Public key prepared (base64 shown)");
            } catch (Exception ex) { append("Error: " + ex.getMessage()); }
        });

        Button fileSendBtn = new Button("Send file");
        fileSendBtn.setOnAction(e -> {
            javafx.stage.FileChooser chooser = new javafx.stage.FileChooser();
            java.io.File f = chooser.showOpenDialog(primaryStage);
            if (f != null) {
                try {
                    if (serverMode.isSelected()) {
                        if (server == null) { append("Server not started"); return; }
                        server.sendFile(f.toPath());
                        append("Server sent file: " + f.getName());
                    } else {
                        if (client == null) { append("Client not connected"); return; }
                        client.sendFile(f.toPath());
                        append("Client sent file: " + f.getName());
                    }
                } catch (Exception ex) { append("File send error: " + ex.getMessage()); }
            }
        });

        right.getChildren().addAll(new Separator(), new Label("Public key (Base64):"), pubArea, sendPubBtn, fileSendBtn);

        root.setRight(right);

        primaryStage.setScene(new Scene(root, 900, 500));
        primaryStage.show();
    }

    private void append(String s) { messagesArea.appendText(s + "\n"); }

    public static void main(String[] args) { launch(args); }
}
