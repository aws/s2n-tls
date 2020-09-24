import java.net.*;
import java.io.*;
import javax.net.ssl.*;

/*
 * Simple JDK SSL client for integration testing purposes
 */

public class SSLSocketClient {
    public static void main(String[] args) throws Exception {
        int port = Integer.parseInt(args[0]);
        String host = "localhost";
        String[] protocols = new String[] {"TLSv1.3", "TLSv1.2"};
        byte[] buffer = new byte[100];

        /* Java uses a different certificate format than s2n */
        System.setProperty("javax.net.ssl.trustStore", "../pems/ecdsa_p384_pkcs1.p12");
        System.setProperty("javax.net.ssl.trustStorePassword", "password");
        System.setProperty("javax.net.debug", "all");
        
        SSLSocketFactory factory = (SSLSocketFactory)SSLSocketFactory.getDefault();
        InetAddress address = InetAddress.getByName(host);

        try (
            SSLSocket socket = 
            (SSLSocket)factory.createSocket(address, port);
            OutputStream out = new BufferedOutputStream(socket.getOutputStream());
            BufferedInputStream stdIn = new BufferedInputStream(System.in);
        ) {
            socket.setEnabledProtocols(protocols);
            socket.startHandshake();
            System.out.println("Starting handshake");

            while (stdIn.read(buffer) != -1) {
                out.write(buffer);
            }
            out.flush();

            out.close();
            socket.close();
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
