import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class CryptoUtils {

    private static final String PADDING = "AES/CBC/PKCS5Padding";
	
	
	
    
	public static byte[] cifrarSimetrico(SecretKey llave, String texto, byte[] iv) {
		try {
			Cipher cifrador = Cipher.getInstance(PADDING);
			byte[] textoClaro = texto.getBytes();
			IvParameterSpec ivSpec = new IvParameterSpec(iv);
	
			cifrador.init(Cipher.ENCRYPT_MODE, llave, ivSpec);
			byte[] textoCifrado = cifrador.doFinal(textoClaro);
			byte[] textoCifradoConIv = new byte[iv.length + textoCifrado.length];
			System.arraycopy(iv, 0, textoCifradoConIv, 0, iv.length);
			System.arraycopy(textoCifrado, 0, textoCifradoConIv, iv.length, textoCifrado.length);
	
			return textoCifradoConIv;
		} catch (Exception e) {
			e.printStackTrace(); // Más informativo que solo mostrar el mensaje
			return null;
		}
	}

    public static byte[] descifrarSimetrico(SecretKey llave, byte[] textoCifradoConIv, byte[] iv) {
		try {
			// Asumiendo que el tamaño del IV es el mismo que el bloque de cifrado (usualmente 16 bytes para AES)
			
			System.arraycopy(textoCifradoConIv, 0, iv, 0, iv.length);
	
			// Extraer el texto cifrado real, omitiendo el IV al principio
			byte[] textoCifrado = new byte[textoCifradoConIv.length - iv.length];
			System.arraycopy(textoCifradoConIv, iv.length, textoCifrado, 0, textoCifrado.length);
	
			Cipher cifrador = Cipher.getInstance(PADDING);
			IvParameterSpec ivSpec = new IvParameterSpec(iv);
			cifrador.init(Cipher.DECRYPT_MODE, llave, ivSpec);
			return cifrador.doFinal(textoCifrado);
		} catch (Exception e) {
			e.printStackTrace(); // Más informativo que solo mostrar el mensaje
			return null;
		}
	}

    public static byte[] cifrarAsimetrico(Key llave, String texto) {
		byte[] textoCifrado;
		
		try {
			Cipher cifrador = Cipher.getInstance("RSA");
			byte[] textoClaro = texto.getBytes();
			
			cifrador.init(Cipher.ENCRYPT_MODE, llave);
			textoCifrado = cifrador.doFinal(textoClaro);
			
			return textoCifrado;
		} catch (Exception e) {
			System.out.println("Exception: " + e.getMessage());
			return null;
		}
	}

    public static byte[] descifrarAsimetrico(Key llave, String algoritmo, byte[] texto) {
		byte[] textoClaro;
		
		try {
			Cipher cifrador = Cipher.getInstance("RSA");
			cifrador.init(Cipher.DECRYPT_MODE, llave);
			textoClaro = cifrador.doFinal(texto);
		} catch (Exception e) {
			System.out.println("Exception: " + e.getMessage());
			return null;
		}
		return textoClaro;
	}

	public static byte[] firmar(PrivateKey llave, byte[] mensaje) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException{
		
		Signature signature = Signature.getInstance("SHA256withRSA");
		signature.initSign(llave);
		
		signature.update(mensaje);
		byte[] firma = signature.sign();
		return firma;
	}

	public static boolean verificarFirma(PublicKey llavePublica, byte[] mensaje, byte[] firma)
            throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        
        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(llavePublica);
        verifier.update(mensaje);
        
        return verifier.verify(firma);
    }
}
