public class Client {
    public void handleRequest(String host, int port) {
        try {
            RequestHandler r = new RequestHandler(host, port);
            r.start();
            r.join();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
