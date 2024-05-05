import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.util.Arrays;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class SocketHandler extends Thread {
    private Socket socket;
    private DataInputStream dataInputStream;
    private DataOutputStream dataOutputStream;
    long startTime, endTime;

    private static final BigInteger G = new BigInteger("2");

    private static final BigInteger P = new BigInteger(
            "00a7e0a6634c1fffeb2b2cdfbc16b7c35821f59583c35cc5c2489bc48bb49c1265afde2a436184039fa94bb72b3d148ed0f738dcd87abf10dd42b34f1786bef355e413f1a0fa2dce2b820f06ca68d316008e8a121c610fa34509d4acfab41b81474714fbb1a99f585a79343581fdfdb21eff3808ab6defd79c18651fe5a874ad9c7",
            16);

    private BigInteger z;
    private String user;
    private byte[] password;
    private byte[] iv;
    private static PrivateKey privateKey;

    public static void generateKeyPairAndSavePublicKey(String publicKeyFilePath) {
        try {
            // Genera el par de claves
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            KeyPair pair = keyGen.generateKeyPair();
            PublicKey publicKey = pair.getPublic();
            privateKey = pair.getPrivate();

            // Convierte la clave pública a bytes
            byte[] publicKeyBytes = publicKey.getEncoded();

            // Escribe la clave pública en un archivo
            try (FileOutputStream fos = new FileOutputStream(publicKeyFilePath)) {
                fos.write(publicKeyBytes);
                fos.flush();
            }
        } catch (NoSuchAlgorithmException | IOException e) {
            e.printStackTrace();
        }
    }

    public SocketHandler(Socket accepted_socket) throws IOException, NoSuchAlgorithmException {
        this.socket = accepted_socket;
        this.dataInputStream = new DataInputStream(accepted_socket.getInputStream());
        this.dataOutputStream = new DataOutputStream(accepted_socket.getOutputStream());
        this.user = "gaviotica911";
        this.password = DigestGenerator.sha256("NosVamosASacar5*1234");

    }

    private void openCommunicationProtocol()
            throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {

        String secure_init_message = this.dataInputStream.readUTF();

        if (!secure_init_message.equals("SECURE INIT")) {
            throw new IOException("Invalid secure init message");
        }
        System.out.println("Secure init message received: " + secure_init_message);

        byte[] challenge = new byte[256];

        this.dataInputStream.read(challenge);
        System.out.println("challenge recibido");
        generateKeyPairAndSavePublicKey("publicKey.key");
        startTime = System.nanoTime();
        byte[] retoFirmado = CryptoUtils.firmar(privateKey, challenge);
        endTime = System.nanoTime();
        System.out.println("Firma generada");
        System.out.println("Tiempo generación de firma: " + (endTime - startTime)/1000000.0 + " milisegundos.");
        this.dataOutputStream.write(retoFirmado);
        this.dataOutputStream.write(privateKey.getEncoded());
        System.out.println("Reto firmado enviado");

        String response = this.dataInputStream.readUTF();
        if (!response.equals("OK")) {
            throw new IOException("Invalid response");
        }

        shareDiffieHellmanValues();
        byte[] zBytes = z.toByteArray();
        // Dividir zBytes en dos partes de 256 bits
        byte[] keyForEncryption = Arrays.copyOfRange(zBytes, 0, 32); // Primeros 32

        byte[] keyForHMAC = Arrays.copyOfRange(zBytes, 32, 64); // Últimos 32 bytes

        // Crear las llaves para cifrado y para HMAC
        SecretKey K_AB1 = new SecretKeySpec(keyForEncryption, "AES");
        SecretKey K_AB2 = new SecretKeySpec(keyForHMAC, "HmacSHA256");

        // CALC LAS LLAVES FIN PARTE 1
        this.dataOutputStream.writeUTF("CONTINUAR");

        byte[] userEncrypted = new byte[32];
        this.dataInputStream.read(userEncrypted);
        System.out.println("Usuario recibido");
        byte[] passwordEncrypted = new byte[48];
        this.dataInputStream.read(passwordEncrypted);
        System.out.println("Contraseña recibida");
        byte[] usuario = CryptoUtils.descifrarSimetrico(K_AB1, userEncrypted, iv);
        String mensajeDescifrado = new String(usuario, StandardCharsets.UTF_8);

        String contra = new String(CryptoUtils.descifrarSimetrico(K_AB1, passwordEncrypted, iv));
        byte[] contraHash = DigestGenerator.sha256(contra);

        if (mensajeDescifrado.equals(this.user) && Arrays.equals(contraHash, this.password)) {
            this.dataOutputStream.writeUTF("OK");
            System.out.println("Usuario y contraseña correctos");
        } else {
            this.dataOutputStream.writeUTF("ERROR");
            this.dataOutputStream.writeUTF("FIN DE LA COMUNICACION");
            System.out.println("Usuario o contraseña incorrectos");
        }
        byte[] consultaEncrypted = new byte[32];
        this.dataInputStream.read(consultaEncrypted);
        System.out.println("Consulta recibida");
        byte[] consultaDigest = new byte[32];
        this.dataInputStream.read(consultaDigest);
        System.out.println("Digest recibido");

        startTime = System.nanoTime();
        String consulta = new String(CryptoUtils.descifrarSimetrico(K_AB1, consultaEncrypted,iv));
        endTime = System.nanoTime();
        System.out.println("Tiempo para decifrar consulta: " + (endTime - startTime)/1000000.0 + " milisegundos.");
        startTime = System.nanoTime();
        byte[] verificandoConsulta = DigestGenerator.Hmac(consulta, K_AB2);
        if (Arrays.equals(verificandoConsulta, consultaDigest)) {
            endTime = System.nanoTime();
            System.err.println("hay integridad");
            System.out.println("Tiempo verificacion codigo de autenticacion: " + (endTime - startTime)/1000000.0 + " milisegundos.");
            int numero = Integer.parseInt(consulta);
            int resultado = numero - 1;
            String respuesta = Integer.toString(resultado);
            this.dataOutputStream.write(CryptoUtils.cifrarSimetrico(K_AB1, respuesta, iv));
            System.out.println("Respuesta enviada");
            this.dataOutputStream.write(DigestGenerator.Hmac(respuesta, K_AB2));
            System.out.println("Digest enviado");
        } else {
            this.dataOutputStream.writeUTF("ERROR");
            this.dataOutputStream.writeUTF("FIN DE LA COMUNICACION");
            System.out.println("Consulta no verificada");
        }
        if (response.equals("OK")) {
            System.out.println("consulta finalizada con exito");
           
        }else{
            throw new IOException("Invalid response");
        }

    }

    private void shareDiffieHellmanValues()
            throws IOException, InvalidKeyException, NoSuchAlgorithmException, SignatureException {

        BigInteger x = KeyManager.generateX(P);
        BigInteger gX = G.modPow(x, P);
        iv = KeyManager.generateIV();

        byte[] gByte = G.toByteArray();
        byte[] pByte = P.toByteArray();

        byte[] gXByte = gX.toByteArray();

        int totalLength = gByte.length + pByte.length + gXByte.length;

        // Crear el arreglo de bytes con la longitud total
        this.dataOutputStream.write(gByte);
        System.out.println("G enviado");
        this.dataOutputStream.write(pByte);
        System.out.println("P enviado");
        this.dataOutputStream.write(gXByte);
        System.out.println("GX enviado");
        this.dataOutputStream.write(iv);
        System.out.println("IV enviado");

        byte[] conc = new byte[totalLength];

        // Copiar los bytes de cada arreglo en el arreglo conc
        System.arraycopy(gByte, 0, conc, 0, gByte.length);
        System.arraycopy(pByte, 0, conc, gByte.length, pByte.length);
        System.arraycopy(gXByte, 0, conc, gByte.length + pByte.length, gXByte.length);

        byte[] cyphered_dh_values = CryptoUtils.firmar(privateKey, conc);

        this.dataOutputStream.write(cyphered_dh_values);

        System.out.println("Valores DH firmados enviados");
        this.dataInputStream.readUTF();

        byte[] gYNum = new byte[129];
        this.dataInputStream.read(gYNum);

        System.out.println("Gy recibido");

        BigInteger gY = new BigInteger(1, gYNum);

        z = gY.modPow(x, P);

    }
    /*
     * private void pong() throws IOException {
     * this.dataOutputStream.writeUTF("pong");
     * System.out.println("Client says: " + this.dataInputStream.readUTF());
     * }
     */

    @Override
    public void run() {
        try {
            // pong();
            openCommunicationProtocol();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
