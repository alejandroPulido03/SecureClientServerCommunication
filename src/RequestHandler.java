import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;

public class RequestHandler extends Thread {
    private Socket socket;
    private DataInputStream dataInputStream;
    private DataOutputStream dataOutputStream;

    private String request_message;

    public RequestHandler(String request_message, String host, int port) throws IOException {
        this.socket = new Socket(host, port);
        this.dataInputStream = new DataInputStream(socket.getInputStream());
        this.dataOutputStream = new DataOutputStream(socket.getOutputStream());
        this.request_message = request_message;
    }

    private void openCommunicationProtocol() throws IOException {
        this.dataOutputStream.writeUTF("SECURE INIT");
        int challenge = 123456789;
        this.dataOutputStream.writeInt(challenge);
        System.out.println("Challenge sent: " + challenge);
        int cipheredChallenge = this.dataInputStream.readInt();
        System.out.println("Ciphered challenge received: " + cipheredChallenge);
        this.dataOutputStream.writeUTF("OK");

        // getDiffieHellmanValues();
    }

    private void ping() throws IOException {
        this.dataOutputStream.writeUTF("ping");
        System.out.println("Server says: " + this.dataInputStream.readUTF());

    }

    @Override
    public void run() {
        try {
            openCommunicationProtocol();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

}
