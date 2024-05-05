import java.security.*;

public class CryptoTest {
    public static void main(String[] args) {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            KeyPair keyPair = keyGen.generateKeyPair();

            byte[] data = "Mensaje de prueba".getBytes();

            Signature signer = Signature.getInstance("SHA256withRSA");
            signer.initSign(keyPair.getPrivate());
            signer.update(data);
            byte[] signature = signer.sign();

            Signature verifier = Signature.getInstance("SHA256withRSA");
            verifier.initVerify(keyPair.getPublic());
            verifier.update(data);
            boolean verified = verifier.verify(signature);

            System.out.println("Signature verified: " + verified);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}