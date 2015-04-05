package kellinwood.security.zipsigner.optional;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import kellinwood.security.zipsigner.ZipSigner;

public class CustomKeySigner {

	/** KeyStore-type agnostic. This method will sign the zip file handling both JKS or BKS key stores. */
	public static void signZip(String keystorePath, char[] keystorePw, String certAlias, char[] certPw,
			String signatureAlgorithm, String inputZipFilename, String outputZipFilename) throws Exception {
		KeyStore keystore = KeyStoreFileManager.loadKeyStore(keystorePath, keystorePw);

		X509Certificate publicKey = (X509Certificate) keystore.getCertificate(certAlias);
		PrivateKey privateKey = (PrivateKey) keystore.getKey(certAlias, certPw);

		ZipSigner.signZip(publicKey, privateKey, signatureAlgorithm, inputZipFilename, outputZipFilename);
	}

}
