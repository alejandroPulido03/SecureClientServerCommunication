import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

public class Server {

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
