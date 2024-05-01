import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class DigestGenerator {
    
    public byte[] sha256(String message) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(message.getBytes());

        byte[] digest = md.digest();
        return digest;
    }
    public byte[] sha512(String message) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-512");
        md.update(message.getBytes());

        byte[] digest = md.digest();
        return digest;
    }
}
