import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;

public class SocketHandler extends Thread {
    private Socket socket;
    private DataInputStream dataInputStream;
    private DataOutputStream dataOutputStream;
    private PrivateKey privateKey;
    public static PublicKey publicKey;
    private KeyPairGenerator keyGen;
    private KeyPair pair;
    private static final BigInteger G = new BigInteger("2");

    private static final BigInteger P = new BigInteger(
            "00a7e0a6634c1fffeb2b2cdfbc16b7c35821f59583c35cc5c2489bc48bb49c1265afde2a436184039fa94bb72b3d148ed0f738dcd87abf10dd42b34f1786bef355e413f1a0fa2dce2b820f06ca68d316008e8a121c610fa34509d4acfab41b81474714fbb1a99f585a79343581fdfdb21eff3808ab6defd79c18651fe5a874ad9c7",
            16);

    private BigInteger z;
    private String user;
    private byte[] password;
    private byte[] iv;

    public SocketHandler(Socket accepted_socket, PrivateKey privateKey) throws IOException, NoSuchAlgorithmException {
        this.socket = accepted_socket;
        this.privateKey = privateKey;
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
        keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        pair = keyGen.generateKeyPair();
        publicKey = pair.getPublic();
        privateKey = pair.getPrivate();
        byte[] challenge = new byte[1024];
        this.dataInputStream.read(challenge);
        System.out.println("Challenge recibido");
        byte[] retoFirmado = CryptoUtils.firmar(privateKey, challenge);
        this.dataOutputStream.write(retoFirmado);
        System.out.println("Reto firmado enviado");
        /*
         * 
         * 
         * 
         * 
         * String response = this.dataInputStream.readUTF();
         * if (!response.equals("OK")) {
         * throw new IOException("Invalid response");
         * }
         * 
         * shareDiffieHellmanValues();
         * 
         * byte[] zBytes = z.toByteArray();
         * // Dividir zBytes en dos partes de 256 bits
         * byte[] keyForEncryption = Arrays.copyOfRange(zBytes, 0, 32); // Primeros 32
         * bytes (256 bits)
         * byte[] keyForHMAC = Arrays.copyOfRange(zBytes, 32, 64); // Últimos 32 bytes
         * (256 bits)
         * 
         * // Crear las llaves para cifrado y para HMAC
         * SecretKey K_AB1 = new SecretKeySpec(keyForEncryption, "AES");
         * SecretKey K_AB2 = new SecretKeySpec(keyForHMAC, "HmacSHA256");
         * 
         * // CALC LAS LLAVES FIN PARTE 1
         * this.dataOutputStream.writeUTF("CONTINUAR");
         * 
         * byte[] userEncrypted = this.dataInputStream.readAllBytes();
         * System.out.println("Usuario recibido");
         * byte[] passwordEncrypted = this.dataInputStream.readAllBytes();
         * System.out.println("Contraseña recibida");
         * 
         * String usuario = new String(CryptoUtils.descifrarSimetrico(K_AB1,
         * userEncrypted));
         * String contra = new String(CryptoUtils.descifrarSimetrico(K_AB1,
         * passwordEncrypted));
         * byte[] contraHash = DigestGenerator.sha256(contra);
         * if (usuario.equals(this.user) && Arrays.equals(contraHash, this.password)) {
         * this.dataOutputStream.writeUTF("OK");
         * System.out.println("Usuario y contraseña correctos");
         * } else {
         * this.dataOutputStream.writeUTF("ERROR");
         * this.dataOutputStream.writeUTF("FIN DE LA COMUNICACION");
         * System.out.println("Usuario o contraseña incorrectos");
         * }
         * 
         * byte[] consultaEncrypted = this.dataInputStream.readAllBytes();
         * System.out.println("Consulta recibida");
         * byte[] consultaDigest = this.dataInputStream.readAllBytes();
         * System.out.println("Digest recibido");
         * 
         * String consulta = new String(CryptoUtils.descifrarSimetrico(K_AB1,
         * consultaEncrypted));
         * byte[] verificandoConsulta = DigestGenerator.Hmac(consulta, K_AB2);
         * if (Arrays.equals(verificandoConsulta, consultaDigest)) {
         * int numero = Integer.parseInt(consulta);
         * int resultado = numero - 1;
         * String respuesta = Integer.toString(resultado);
         * this.dataOutputStream.write(CryptoUtils.cifrarSimetrico(K_AB1, respuesta,
         * iv));
         * System.out.println("Respuesta enviada");
         * this.dataOutputStream.write(DigestGenerator.Hmac(respuesta, K_AB2));
         * System.out.println("Digest enviado");
         * 
         * } else {
         * this.dataOutputStream.writeUTF("ERROR");
         * this.dataOutputStream.writeUTF("FIN DE LA COMUNICACION");
         * System.out.println("Consulta no verificada");
         * }
         */
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
        String response = this.dataInputStream.readUTF();
        if (!response.equals("OK")) {
            throw new IOException("Invalid response");
        }
        BigInteger gY = new BigInteger(this.dataInputStream.readAllBytes());
        System.out.println("Gy recibido");

        z = gY.modPow(x, P);

    }

    private void pong() throws IOException {
        this.dataOutputStream.writeUTF("pong");
        System.out.println("Client says: " + this.dataInputStream.readUTF());
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

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
