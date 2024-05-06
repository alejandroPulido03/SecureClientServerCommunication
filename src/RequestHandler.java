import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Random;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

//CLIENTE
public class RequestHandler extends Thread {
    private Socket socket;
    private DataInputStream dataInputStream;
    private DataOutputStream dataOutputStream;
    private byte[] challenge;
    long startTime, endTime;
    long startTime2, endTime2;

    public RequestHandler(String host, int port) throws IOException {
        this.socket = new Socket(host, port);
        this.dataInputStream = new DataInputStream(socket.getInputStream());
        this.dataOutputStream = new DataOutputStream(socket.getOutputStream());
    }

    public static PublicKey readPublicKeyFromFile(String publicKeyFilePath) {
        try {
            // Lee los bytes de la clave pública desde un archivo
            FileInputStream fis = new FileInputStream(publicKeyFilePath);
            byte[] publicKeyBytes = fis.readAllBytes();
            fis.close();

            // Convierte los bytes a una PublicKey
            X509EncodedKeySpec spec = new X509EncodedKeySpec(publicKeyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePublic(spec);
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
            return null;
        }
    }

    private void openCommunicationProtocol()
            throws IOException, InvalidKeyException, NoSuchAlgorithmException, SignatureException {

        this.dataOutputStream.writeUTF("SECURE INIT");
        System.err.println("SECURE INIT");

        challenge = KeyManager.generateChallenge();

        this.dataOutputStream.write(challenge);

        System.out.println("frima enviada");
        byte[] Rprima = new byte[256];
        byte[] llavePublica = new byte[2048];
        this.dataInputStream.read(Rprima);
        this.dataInputStream.read(llavePublica);

        System.out.println("Firma a verificar");
        PublicKey publicKey = readPublicKeyFromFile("publicKey.key");

        boolean revisoR = CryptoUtils.verificarFirma(publicKey, challenge, Rprima);
        System.out.println("Resultado de verificación ");
        if (revisoR) {
            this.dataOutputStream.writeUTF("OK");
            System.out.println("Firma correcta");
        } else {
            this.dataOutputStream.writeUTF("ERROR");
            this.dataOutputStream.writeUTF("FIN DE LA COMUNICACION");
            System.out.println("Error en la firma");
        }

        byte[] gByte = new byte[1];
        this.dataInputStream.read(gByte);
        System.out.println("g recibido");

        byte[] pByte = new byte[129];
        this.dataInputStream.read(pByte);
        System.out.println("p recibido");
        byte[] gXByte = new byte[this.dataInputStream.readInt()];
        this.dataInputStream.read(gXByte);

        System.out.println("gx recibido");
        byte[] iv = new byte[16];
        this.dataInputStream.read(iv);
        System.out.println("iv recibido");
        byte[] firmaCripto = new byte[256];
        this.dataInputStream.read(firmaCripto);
        System.out.println("Firma recibida");

        int totalLength = gByte.length + pByte.length + gXByte.length;

        byte[] conc = new byte[totalLength];
        System.arraycopy(gByte, 0, conc, 0, gByte.length);
        System.arraycopy(pByte, 0, conc, gByte.length, pByte.length);
        System.arraycopy(gXByte, 0, conc, gByte.length + pByte.length, gXByte.length);

        startTime = System.nanoTime();
        boolean revisoValores = CryptoUtils.verificarFirma(publicKey, conc, firmaCripto);
        endTime = System.nanoTime();
        if (revisoValores) {
            this.dataOutputStream.writeUTF("OK");
            System.out.println("Firma correcta de valores");
            System.out.println("Tiempo para verificar firma: " + (endTime - startTime) / 1000000.0 + " milisegundos.");
        } else {
            this.dataOutputStream.writeUTF("ERROR");
            this.dataOutputStream.writeUTF("FIN DE LA COMUNICACION");
            System.out.println("Error en la firma");
        }

        BigInteger g = new BigInteger(gByte);

        BigInteger p = new BigInteger(pByte);

        BigInteger x = KeyManager.generateX(p);

        BigInteger gX = new BigInteger(gXByte);

        startTime = System.nanoTime();
        BigInteger gY = g.modPow(x, p);
        endTime = System.nanoTime();

        byte[] gYByte = gY.toByteArray();

        // MANDO GY ES LO ULTIMO QUE MANDA EL CLIENTE
        this.dataOutputStream.writeInt(gYByte.length);
        this.dataOutputStream.write(gYByte);
        System.out.println("Gy enviado");
        System.out.println("Tiempo para Gy: " + (endTime - startTime) / 1000000.0 + " milisegundos.");

        BigInteger z = gX.modPow(x, p);

        byte[] zBytes = z.toByteArray();
        // Dividir zBytes en dos partes de 256 bits
        byte[] keyForEncryption = Arrays.copyOfRange(zBytes, 0, 32); // Primeros 32

        byte[] keyForHMAC = Arrays.copyOfRange(zBytes, 32, 64); // Últimos 32 bytes

        // Crear las llaves para cifrado y para HMAC
        SecretKey K_AB1 = new SecretKeySpec(keyForEncryption, "AES");
        SecretKey K_AB2 = new SecretKeySpec(keyForHMAC, "HmacSHA256");

        // CALC LAS LLAVES FIN PARTE 1

        System.out.println("Continuar parte 2");
        this.dataInputStream.readUTF();

        String user = "gaviotica911"; // Lee el string ingresado por el usuario

        String contraseña = "NosVamosASacar5*1234";

        this.dataOutputStream.write(CryptoUtils.cifrarSimetrico(K_AB1, user, iv));
        this.dataOutputStream.write(CryptoUtils.cifrarSimetrico(K_AB1, contraseña, iv));
        System.out.println("Usuario y contraseña enviados");

        String response = this.dataInputStream.readUTF();

        if (!response.equals("OK")) {
            throw new IOException("Invalid response");
        }

        Random rand = new Random();
        int numeroAleatorio = rand.nextInt(100) + 1; // Genera un número entre 1 y 100
        System.out.println("Número aleatorio entre 1 y 100: " + numeroAleatorio);

        startTime = System.nanoTime();
        byte[] a = CryptoUtils.cifrarSimetrico(K_AB1, String.valueOf(numeroAleatorio), iv);
        endTime = System.nanoTime();

        startTime2 = System.nanoTime();
        byte[] b = DigestGenerator.Hmac(String.valueOf(numeroAleatorio), K_AB2);
        endTime2 = System.nanoTime();

        this.dataOutputStream.write(a);
        this.dataOutputStream.write(b);
        System.out.println("Consulta enviada");
        System.out.println("Tiempo cifrado consulta: " + (endTime - startTime) / 1000000.0 + " milisegundos.");
        System.out.println(
                "Tiempo generar codigo de autenticacion: " + (endTime2 - startTime2) / 1000000.0 + " milisegundos.");

        byte[] rtaEncrypted = new byte[32];
        this.dataInputStream.read(rtaEncrypted);
        System.out.println("Respuesta recibida");
        byte[] rtaDigest = new byte[32];
        this.dataInputStream.read(rtaDigest);
        System.out.println("Digest recibido");

        String rta = new String(CryptoUtils.descifrarSimetrico(K_AB1, rtaEncrypted, iv));
        byte[] verificandorta = DigestGenerator.Hmac(rta, K_AB2);
        if (Arrays.equals(verificandorta, rtaDigest)) {
            System.out.println("respuesta integra");
            int rtaNum = Integer.parseInt(rta);
            int respuestaVerdadera = numeroAleatorio - 1;
            if (rtaNum == (respuestaVerdadera)) {
                System.out.println("La respuesta es correcta");
                System.out.println("Petición enviada: " + numeroAleatorio + "\nRespuesta recibida: " + rtaNum);
                this.dataOutputStream.writeUTF("OK");
            } else {
                this.dataOutputStream.writeUTF("ERROR");
                this.dataOutputStream.writeUTF("FIN DE LA COMUNICACION");
                System.out.println("Respuesta incorrecta");
            }
        } else {
            this.dataOutputStream.writeUTF("ERROR");
            this.dataOutputStream.writeUTF("FIN DE LA COMUNICACION");
            System.out.println("Respuesta no integra");
        }

    }

    private void ping() throws IOException {
        this.dataOutputStream.writeUTF("ping");
        System.out.println("Server says: " + this.dataInputStream.readUTF());

    }

    @Override
    public void run() {
        try {

            openCommunicationProtocol();
        } catch (Exception e) {

            e.printStackTrace();
        }

    }

}
