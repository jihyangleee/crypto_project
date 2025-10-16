package com.example.app.net;

import java.io.File;

public class E2ETest {
    public static void main(String[] args) throws Exception {
        int port = 6000;

        // Generate key pairs for both server and client
        java.security.KeyPairGenerator kpg = java.security.KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        java.security.KeyPair serverKp = kpg.generateKeyPair();
        java.security.KeyPair clientKp = kpg.generateKeyPair();

        ChatServer server = new ChatServer();
        Thread st = new Thread(() -> {
            try { 
                server.start(port, System.out::println, serverKp.getPublic(), serverKp.getPrivate()); 
            } catch (Exception ex) { 
                ex.printStackTrace(); 
            }
        });
        st.setDaemon(true); st.start();

        // wait a bit
        Thread.sleep(500);

        ChatClient client = new ChatClient();
        client.setOnMessage(System.out::println);

        client.connect("127.0.0.1", port, clientKp.getPublic(), clientKp.getPrivate());

        // create small test file
        File tmp = new File("test-send.txt");
        try (java.io.FileWriter fw = new java.io.FileWriter(tmp)) { fw.write("Hello E2E file\n"); }

        client.sendFile(tmp);

        // give time for transfer
        Thread.sleep(2000);
        System.out.println("E2E test done");
        client.disconnect();
    }
}
