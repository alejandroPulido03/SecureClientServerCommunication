import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

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

    public static byte[] Hmac(String data, byte[] key) throws NoSuchAlgorithmException, InvalidKeyException {
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "hmacSHA256");
        Mac mac = Mac.getInstance("hmacSHA256");
        mac.init(secretKeySpec);
        return mac.doFinal(data.getBytes());
    }

}
