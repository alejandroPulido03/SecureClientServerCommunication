import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SignatureException;

//SERVIDOR
public class Server {

    private DataInputStream dataInputStream;
    private DataOutputStream dataOutputStream;
    private ServerSocket serverSocket;
    private PrivateKey privateKey;
    private SocketHandler socketHandler;

    public Server(int port) throws IOException, NoSuchAlgorithmException {
        this.serverSocket = new ServerSocket(port);
        // Server listens in all loopback interfaces i.e. from 127.0.0.1 to
        // 127.255.255.255

    }

    public void initServer() throws IOException, InvalidKeyException, NoSuchAlgorithmException, SignatureException {
        System.out.println("Secure Server started...");
        System.out.println("Server listening on port " + getPort());
        System.out.println("Server is listening in all loopback interfaces");
        System.out.println("Press Ctrl+C to stop the server");
        while (true) {
            Socket socket = this.serverSocket.accept();
            socketHandler = new SocketHandler(socket, this.privateKey);
            socketHandler.start();

        }
    }

    public int getPort() {
        return serverSocket.getLocalPort();
    }

}
