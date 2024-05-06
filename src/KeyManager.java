
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

public class KeyManager {

    
   
    public static BigInteger generateX(BigInteger p) {
        Random rand = new Random();
        BigInteger maxLimit = p.subtract(BigInteger.ONE); 
        BigInteger result;
        do {
            result = new BigInteger(maxLimit.bitLength() - 1, rand);
        } 
        while (result.compareTo(maxLimit) >= 0);
        return result;
    }

    public static byte[] generateIV() {
        byte[] ivBytes = new byte[16]; // Define un arreglo de 16 bytes
        SecureRandom secureRandom = new SecureRandom(); // Crea una instancia de SecureRandom
        secureRandom.nextBytes(ivBytes); // Llena el arreglo con datos aleatorios seguros
        return ivBytes;
    }

    public static byte[] generateChallenge() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] challengeBytes = new byte[256]; // Crea un arreglo de bytes del tamaño especificado
        secureRandom.nextBytes(challengeBytes); // Llena el arreglo con datos aleatorios seguros
        return challengeBytes;
    }
    

    
}

