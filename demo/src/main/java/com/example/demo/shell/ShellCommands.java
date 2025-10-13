package com.example.demo.shell;

import com.example.demo.crypto.CryptoUtil;
import com.example.demo.crypto.KeyHolder;
import com.example.demo.net.ChatClient;
import com.example.demo.net.ChatServer;
import org.springframework.shell.standard.ShellComponent;
import org.springframework.shell.standard.ShellMethod;
import org.springframework.shell.standard.ShellOption;

import java.nio.file.Path;

@ShellComponent
public class ShellCommands {

    private final KeyHolder keyHolder = new KeyHolder();
    private ChatServer server;
    private ChatClient client;

    @ShellMethod("Generate RSA keypair")
    public String genKeys() throws Exception {
        keyHolder.setKeyPair(CryptoUtil.generateRsaKeyPair());
        return "Generated RSA keypair";
    }

    @ShellMethod("Save keys to path")
    public String saveKeys(@ShellOption(defaultValue = "./mykeys") String path) throws Exception {
        var kp = keyHolder.getKeyPair();
        if (kp == null) return "No keypair generated";
        Path p = Path.of(path);
        if (!p.toFile().exists()) p.toFile().mkdirs();
        CryptoUtil.savePrivateKey(kp.getPrivate(), p.resolve("private.key"));
        CryptoUtil.savePublicKey(kp.getPublic(), p.resolve("public.key"));
        return "Saved keys to " + p.toAbsolutePath();
    }

    @ShellMethod("Load keys from path")
    public String loadKeys(@ShellOption(defaultValue = "./mykeys") String path) throws Exception {
        Path p = Path.of(path);
        var pub = CryptoUtil.loadPublicKey(p.resolve("public.key"));
        var priv = CryptoUtil.loadPrivateKey(p.resolve("private.key"));
        keyHolder.setKeyPair(new java.security.KeyPair(pub, priv));
        return "Loaded keys from " + p.toAbsolutePath();
    }

    @ShellMethod("Start server on port")
    public String startServer(@ShellOption(defaultValue = "9999") int port) throws Exception {
        server = new ChatServer(keyHolder);
        new Thread(() -> {
            try { server.start(port); } catch (Exception e) { e.printStackTrace(); }
        }).start();
        return "Server started on " + port;
    }

    @ShellMethod("Connect to host:port")
    public String connect(@ShellOption(defaultValue = "127.0.0.1") String host, @ShellOption(defaultValue = "9999") int port) throws Exception {
        client = new ChatClient(keyHolder);
        new Thread(() -> {
            try { client.connect(host, port); } catch (Exception e) { e.printStackTrace(); }
        }).start();
        return "Connecting to " + host + ":" + port;
    }
}
