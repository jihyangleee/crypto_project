import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Random;

public class TestClient {
    public static void main(String[] args) throws Exception {
        String host = "127.0.0.1";
        int port = 9999;
        try (Socket s = new Socket(host, port)) {
            DataInputStream dis = new DataInputStream(s.getInputStream());
            DataOutputStream dos = new DataOutputStream(s.getOutputStream());

            // read server pub
            int len = dis.readInt();
            byte[] serverPub = new byte[len];
            dis.readFully(serverPub);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PublicKey serverPublic = kf.generatePublic(new X509EncodedKeySpec(serverPub));

            // generate my keypair and send public
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            KeyPair kp = kpg.generateKeyPair();
            byte[] myPub = kp.getPublic().getEncoded();
            dos.writeInt(myPub.length);
            dos.write(myPub);
            dos.flush();

            // generate AES key
            KeyGenerator kg = KeyGenerator.getInstance("AES");
            kg.init(256);
            SecretKey aes = kg.generateKey();
            byte[] aesRaw = aes.getEncoded();

            // encrypt AES with server public (OAEP SHA-256)
            Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            rsa.init(Cipher.ENCRYPT_MODE, serverPublic);
            byte[] encAes = rsa.doFinal(aesRaw);
            dos.writeInt(encAes.length);
            dos.write(encAes);

            // send iv
            byte[] iv = new byte[12]; new Random().nextBytes(iv);
            dos.writeInt(iv.length);
            dos.write(iv);

            // send encrypted message
            Cipher aesC = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec spec = new GCMParameterSpec(128, iv);
            aesC.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(aesRaw, "AES"), spec);
            String payload = "MSG|Hello from external test client";
            byte[] cipher = aesC.doFinal(payload.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            dos.writeInt(cipher.length);
            dos.write(cipher);
            dos.flush();

            System.out.println("sent test message");
        }
    }
}
