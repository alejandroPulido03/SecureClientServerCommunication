import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.Arrays;
import java.util.Scanner;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

//CLIENTE
public class RequestHandler extends Thread {
    private Socket socket;

    private DataInputStream dataInputStream;
    private DataOutputStream dataOutputStream;
    private byte[] challenge;
    

    public RequestHandler( String host, int port) throws IOException {
        this.socket = new Socket(host, port);
        this.dataInputStream = new DataInputStream(socket.getInputStream());
        this.dataOutputStream = new DataOutputStream(socket.getOutputStream());
    }

    private void openCommunicationProtocol() throws IOException, InvalidKeyException, NoSuchAlgorithmException, SignatureException {
        System.out.println("Secure Client started...");
        System.out.println("Client is listening in all loopback interfaces");
        System.out.println("Press Ctrl+C to stop the client");

        this.dataOutputStream.writeUTF("SECURE INIT");
        System.err.println("SECURE INIT");

        challenge = KeyManager.generateChallenge();
        
        this.dataOutputStream.write(challenge);
        System.out.println("Challenge enviado");

        byte[] Rprima = this.dataInputStream.readAllBytes();
        System.out.println("Rprima recibido");
        boolean revisoR= CryptoUtils.verificarFirma(SocketHandler.publicKey, Rprima, challenge);

        if (revisoR) {
            this.dataOutputStream.writeUTF("OK");
            System.out.println("Firma correcta");
        } else {
            this.dataOutputStream.writeUTF("ERROR");
            this.dataOutputStream.writeUTF("FIN DE LA COMUNICACION");
            System.out.println("Error en la firma");
            
            
        }

        byte[] gByte = this.dataInputStream.readAllBytes();
        System.out.println("g recibido");
        byte[] pByte = this.dataInputStream.readAllBytes();
        System.out.println("p recibido");
        byte[] gXByte = this.dataInputStream.readAllBytes();
        System.out.println("gx recibido");
        byte[] iv = this.dataInputStream.readAllBytes();
        System.out.println("iv recibido");
        byte[] firmaCripto = this.dataInputStream.readAllBytes();
        System.out.println("Firma recibida");


        int totalLength = gByte.length + pByte.length + gXByte.length;


        byte[] conc = new byte[totalLength];


        boolean revisoValores= CryptoUtils.verificarFirma(SocketHandler.publicKey, firmaCripto, conc);

        if (revisoValores) {
            this.dataOutputStream.writeUTF("OK");
            System.out.println("Firma correcta de valores");
        } else {
            this.dataOutputStream.writeUTF("ERROR");
            this.dataOutputStream.writeUTF("FIN DE LA COMUNICACION");
            System.out.println("Error en la firma");
            
        }

        BigInteger g = new BigInteger(gByte);
        BigInteger p = new BigInteger(pByte);
        BigInteger x = KeyManager.generateX(p);

        BigInteger gX = new BigInteger(gXByte);

       
        BigInteger gY = g.modPow(x, p);

        byte[] gYByte=gY.toByteArray();
//MANDO GY ES LO ULTIMO QUE MANDA EL CLIENTE

        this.dataOutputStream.write(gYByte);
        System.out.println("Gy enviado");


        BigInteger z = gX.modPow(x, p);
        byte[] zBytes=z.toByteArray();
        // Dividir zBytes en dos partes de 256 bits
        byte[] keyForEncryption = Arrays.copyOfRange(zBytes, 0, 32); // Primeros 32 bytes (256 bits)
        byte[] keyForHMAC = Arrays.copyOfRange(zBytes, 32, 64); // Últimos 32 bytes (256 bits)

        // Crear las llaves para cifrado y para HMAC
            SecretKey K_AB1 = new SecretKeySpec(keyForEncryption, "AES");
            SecretKey K_AB2 = new SecretKeySpec(keyForHMAC, "HmacSHA256");

        // CALC LAS LLAVES FIN PARTE 1
            this.dataInputStream.readUTF();
            this.dataOutputStream.writeUTF("CONTINUAR");
            System.out.println("Continuar parte 2");

            Scanner scanner = new Scanner(System.in); // Crea un objeto Scanner para leer la entrada del usuario
            
            System.out.print("Ingrese su usuario: "); // Solicita al usuario que ingrese un string
            String user = scanner.nextLine(); // Lee el string ingresado por el usuario

            System.out.print("Ingrese su contraseña: "); 
            String contraseña = scanner.nextLine(); 

            scanner.close(); // Close the Scanner object to release resources

            this.dataOutputStream.write(CryptoUtils.cifrarSimetrico(K_AB1, user, iv));
            this.dataOutputStream.write(CryptoUtils.cifrarSimetrico(K_AB1, contraseña, iv));
            System.out.println("Usuario y contraseña enviados");

            String response = this.dataInputStream.readUTF();
            if (!response.equals("OK")) {
                throw new IOException("Invalid response");
            }

            scanner = new Scanner(System.in); 
            System.out.print("Ingrese un numero de consulta: "); 
            String consulta = (scanner.nextLine()); 
            scanner.close(); 
            this.dataOutputStream.write(CryptoUtils.cifrarSimetrico(K_AB1, consulta, iv));
            this.dataOutputStream.write(DigestGenerator.Hmac( consulta,K_AB2));
            System.out.println("Consulta enviada");



            byte[] rtaEncrypted = this.dataInputStream.readAllBytes();
            System.out.println("Respuesta recibida");
            byte[] rtaDigest = this.dataInputStream.readAllBytes();
            System.out.println("Digest recibido");

            String rta = new String(CryptoUtils.descifrarSimetrico(K_AB1, rtaEncrypted));
            byte[] verificandorta = DigestGenerator.Hmac(rta, K_AB2);
            if (Arrays.equals(verificandorta, rtaDigest)) {
                int numMenos1= Integer.parseInt(rta);
                if (numMenos1 == Integer.parseInt(consulta)-1){
                    System.out.println("La respuesta es correcta");
                    this.dataOutputStream.writeUTF("OK. Fin");
                } else {
                    this.dataOutputStream.writeUTF("ERROR");
                    this.dataOutputStream.writeUTF("FIN DE LA COMUNICACION");
                    System.out.println("rta incorrecta");
                }

            } else {
                this.dataOutputStream.writeUTF("ERROR");
                this.dataOutputStream.writeUTF("FIN DE LA COMUNICACION");
                System.out.println("rta no integra");
            }


    }

    private void ping() throws IOException {
        this.dataOutputStream.writeUTF("ping");
        System.out.println("Server says: " + this.dataInputStream.readUTF());

    }

    @Override
    public void run() {
        try {
            ping();
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
         // openCommunicationProtocol();
    }

}
