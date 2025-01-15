import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.security.KeyStore;
import java.io.FileInputStream;
import java.io.OutputStream;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.SSLSocket;

/*
 * Simple JDK SSL client for integration testing purposes
 */

public class SSLSocketClient {
    public static void main(String[] args) throws Exception {
        int port = Integer.parseInt(args[0]);
        String certificatePath = args[1];
        String[] cipher = new String[] {args[2]};
        // We assume that args[3] is the intended protocol to negotiated, like "TLS1.3"
        // or "TLS1.2". args[4] is optional, and if included it's value must be "SSLv2Hello".
        String[] protocolList = Arrays.copyOfRange(args, 3, args.length);
        for (int i = 0; i < protocolList.length; i++) {
            protocolList[i] = sslProtocols(protocolList[i]);
        }

        String host = "localhost";
        byte[] buffer = new byte[100];

        SSLSocketFactory socketFactory = createSocketFactory(certificatePath, protocolList[0]);

        try (
            SSLSocket socket = (SSLSocket)socketFactory.createSocket(host, port);
            OutputStream out = new BufferedOutputStream(socket.getOutputStream());
            BufferedInputStream stdIn = new BufferedInputStream(System.in);
        ) {
            socket.setEnabledProtocols(protocolList);
            socket.setEnabledCipherSuites(cipher);
            socket.startHandshake();
            System.out.println("Starting handshake");

            while (true) {
                int read = stdIn.read(buffer);
                if (read == -1)
                    break;
                out.write(buffer, 0, read);
            }
            out.flush();

            out.close();
            socket.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static SSLSocketFactory createSocketFactory(String certificatePath, String protocol) {

        try {
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");

            FileInputStream is = new FileInputStream(certificatePath);

            X509Certificate cert = (X509Certificate) certFactory.generateCertificate(is);
            is.close();

            KeyStore caKeyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            caKeyStore.load(null, null);
            caKeyStore.setCertificateEntry("ca-certificate", cert);

            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(
                    TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(caKeyStore);

            SSLContext context = SSLContext.getInstance(protocol);
            context.init(null, trustManagerFactory.getTrustManagers(), null);

            return context.getSocketFactory();

        } catch(Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static String sslProtocols(String s2nProtocol) {
        switch (s2nProtocol) {
            case "TLS1.3":
                return "TLSv1.3";
            case "TLS1.2":
                return "TLSv1.2";
            case "TLS1.1":
                return "TLSv1.1";
            case "TLS1.0":
                return "TLSv1.0";
            // This "protocol" forces the ClientHello message to use SSLv2 format.
            case "SSLv2Hello":
                return "SSLv2Hello";
        }

        throw new RuntimeException("unrecognized protocol version:" + s2nProtocol);
    }
}
