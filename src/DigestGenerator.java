import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.SecretKey;


public class DigestGenerator {

    public static byte[] sha256(String message) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(message.getBytes());

        byte[] digest = md.digest();
        return digest;
    }

    public static byte[] sha512(String message) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-512");
        md.update(message.getBytes());

        byte[] digest = md.digest();
        return digest;
    }

    public static byte[] Hmac(String data, SecretKey key) throws NoSuchAlgorithmException, InvalidKeyException {
        
        Mac mac = Mac.getInstance("hmacSHA256");
        mac.init(key);
        return mac.doFinal(data.getBytes());
    }

}
