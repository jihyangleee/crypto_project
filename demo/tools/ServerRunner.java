import com.example.demo.crypto.KeyHolder;
import com.example.demo.net.ChatServer;

public class ServerRunner {
    public static void main(String[] args) throws Exception {
        int port = 9998;
        if (args.length>0) port = Integer.parseInt(args[0]);
        KeyHolder kh = new KeyHolder();
        // ensure keys exist
        kh.generateIfAbsent();
        ChatServer server = new ChatServer(kh);
        System.out.println("Starting headless server on port " + port);
        server.start(port);
    }
}
