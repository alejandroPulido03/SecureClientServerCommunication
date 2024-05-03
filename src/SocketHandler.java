import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;

public class SocketHandler extends Thread {
    private Socket socket;
    private DataInputStream dataInputStream;
    private DataOutputStream dataOutputStream;

    public SocketHandler(Socket accepted_socket) throws IOException {
        this.socket = accepted_socket;
        this.dataInputStream = new DataInputStream(accepted_socket.getInputStream());
        this.dataOutputStream = new DataOutputStream(accepted_socket.getOutputStream());
    }

    private void openCommunicationProtocol() throws IOException {

        String secure_init_message = this.dataInputStream.readUTF();

        if (!secure_init_message.equals("SECURE INIT")) {
            throw new IOException("Invalid secure init message");
        }
        System.out.println("Secure init message received: " + secure_init_message);
        try {
            int challenge = this.dataInputStream.readInt();
            System.out.println("Challenge received: " + challenge);
            
            int cipheredChallenge = challenge; // TODO cipher challenge

            this.dataOutputStream.writeInt(cipheredChallenge);
        } catch (IOException e) {
            throw new IOException("Invalid challenge integer" + e.getMessage());
        }

        String response = this.dataInputStream.readUTF();
        if (!response.equals("OK")) {
            throw new IOException("Invalid response");
        }

        // shareDiffieHellmanValues();

    }

    private void shareDiffieHellmanValues() throws IOException {
        int g = 0;
        int p = 0;
        int gX = 0;
        int iv = 0;
        int cyphered_dh_values = 0;
        // TODO generate g, p, gX, iv, cyphered_dh_values
        this.dataOutputStream.writeInt(g);
        this.dataOutputStream.writeInt(p);
        this.dataOutputStream.writeInt(gX);
        this.dataOutputStream.writeInt(iv);
        this.dataOutputStream.writeInt(cyphered_dh_values);
    }

    private void pong() throws IOException {
        this.dataOutputStream.writeUTF("pong");
        System.out.println("Client says: " + this.dataInputStream.readUTF());
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
