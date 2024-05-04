import java.io.IOException;

public class Client {
    public void handleRequest(String host, int port) {
        try {
            new RequestHandler(host, port).start();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
