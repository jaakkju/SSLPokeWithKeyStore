package sslpokewithjks;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

/**
 *
 * @author jaakkju
 */
public class SSLPokeWithKeyStore {

	/**
	 * @param args the command line arguments
	 */
	public static void main(String[] args) {
		if (args.length != 5) {
			System.out.println("Usage: <url> <keystore> <password> <method> <verify hostname boolean>");
			System.exit(1);
		}

		try {
			System.out.println(String.format("Testing HTTPS %s %s using KeyStore %s and password '%s'", args[3], args[0], args[1], args[2]));
			KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());

			keyStore.load(new FileInputStream(args[1]), args[2].toCharArray());
			TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
			tmf.init(keyStore);

			SSLContext ctx = SSLContext.getInstance("TLS");
			ctx.init(null, tmf.getTrustManagers(), new SecureRandom());

			SSLSocketFactory factory = ctx.getSocketFactory();
			URL url = new URL(args[0]);

			HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
			conn.setSSLSocketFactory(factory);
			conn.setRequestMethod(args[3]);

			if (!Boolean.valueOf(args[4])) {
				System.out.println("Using HostnameVerifier: " + Boolean.valueOf(args[4]));
				conn.setHostnameVerifier(new HostnameVerifier() {

					@Override
					public boolean verify(String string, SSLSession ssls) {
						return true;
					}
				});
			}

			BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream()));
			String inputLine;
			while ((inputLine = in.readLine()) != null) {
				System.out.println(inputLine);
			}
			System.out.println("Successfully connected!");

		} catch (KeyStoreException | IOException | NoSuchAlgorithmException | KeyManagementException | NumberFormatException | CertificateException ex) {
			ex.printStackTrace(System.out);
		}
	}
}
