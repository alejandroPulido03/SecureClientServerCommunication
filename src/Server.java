import java.io.IOException;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;

public class Server {

    private static final BigInteger G = new BigInteger("2");
    private static final BigInteger P = new BigInteger("00:a7:e0:a6:63:4c:1f:ff:eb:2b:2c:df:bc:16:b7:c3:58:21:f5:95:83:c3:5c:c5:c2:48:9b:c4:8b:b4:9c:12:65:af:de:2a:43:61:84:03:9f:a9:4b:b7:2b:3d:14:8e:d0:f7:38:dc:d8:7a:bf:10:dd:42:b3:4f:17:86:be:f3:55:e4:13:f1:a0:fa:2d:ce:2b:82:0f:06:ca:68:d3:16:00:8e:8a:12:1c:61:0f:a3:45:09:d4:ac:fa:b4:1b:81:47:71:4f:bb:1a:99:f5:85:a7:93:43:58:1f:df:db:21:ef:f3:80:8a:b6:de:fd:79:c1:86:51:fe:5a:87:4a:d9:c7");

    private ServerSocket serverSocket;

    public Server(int port) throws IOException {
        this.serverSocket = new ServerSocket(port);
        // Server listens in all loopback interfaces i.e. from 127.0.0.1 to
        // 127.255.255.255
    }

    public void initServer() throws IOException {
        System.out.println("Secure Server started...");
        System.out.println("Server listening on port " + getPort());
        System.out.println("Server is listening in all loopback interfaces");
        System.out.println("Press Ctrl+C to stop the server");
        while (true) {
            Socket socket = this.serverSocket.accept();
            new SocketHandler(socket).start();
        }
    }

    public int getPort() {
        return serverSocket.getLocalPort();
    }

}
