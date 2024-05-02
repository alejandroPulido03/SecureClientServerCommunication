import java.io.IOException;

public class Channel {

    public void initServer(int port) {
        try {
            Server server = new Server(port);
            server.initServer();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void handleRequest(String host, int port) {
        Client client = new Client();
        client.handleRequest(host, port);
    }

    public static void main(String[] args) {
        Channel channel = new Channel();
        if (args[0].equals("server")) {
            channel.initServer(Integer.parseInt(args[1]));
        } else if (args[0].equals("client")) {
            channel.handleRequest(args[1], Integer.parseInt(args[2]));
        } else {
            System.out.println("Invalid arguments");
        }
    }
}
