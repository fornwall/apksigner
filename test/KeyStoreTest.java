import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import kellinwood.security.zipsigner.ZipSigner;
import kellinwood.security.zipsigner.optional.CustomKeySigner;
import kellinwood.security.zipsigner.optional.KeyStoreFileManager;
import kellinwood.security.zipsigner.optional.LoadKeystoreException;

import org.junit.Assert;
import org.junit.Test;

/**
 * <pre>
 * $ keytool -genkey -v -keystore test.keystore -alias the_alias -keyalg RSA -keysize 2048 -validity 10000
 * Enter keystore password: abcdefgh  
 * Re-enter new password: abcdefgh
 * What is your first and last name?
 *   [Unknown]:  Mr Test
 * What is the name of your organizational unit?
 *   [Unknown]:  Testing Inc
 * What is the name of your organization?
 *   [Unknown]:  Testing Org
 * What is the name of your City or Locality?
 *   [Unknown]:  Chicago
 * What is the name of your State or Province?
 *   [Unknown]:  Wales
 * What is the two-letter country code for this unit?
 *   [Unknown]:  SE
 * Is CN=Mr Test, OU=Testing Inc, O=Testing Org, L=Chicago, ST=Wales, C=SE correct?
 *   [no]:  yes
 * 
 * Generating 2,048 bit RSA key pair and self-signed certificate (SHA256withRSA) with a validity of 10,000 days
 *     for: CN=Mr Test, OU=Testing Inc, O=Testing Org, L=Chicago, ST=Wales, C=SE
 * Enter key password for <the_alias>
 *     (RETURN if same as keystore password): ijklmnop  
 * Re-enter new password: ijklmnop
 * </pre>
 */
public class KeyStoreTest {

	@Test
	public void testRead() throws Exception {
		// Key password verification is optional:
		for (String keypassword : new String[] { "abcdefgh", null }) {
			KeyStore keyStore = KeyStoreFileManager.loadKeyStore(getClass().getResource("/test.keystore").getFile(),
					keypassword == null ? null : keypassword.toCharArray());
			Assert.assertNotNull(keyStore);
			Assert.assertTrue(keyStore.containsAlias("the_alias"));
			Assert.assertFalse(keyStore.containsAlias("other_alias"));

			X509Certificate publicKey = (X509Certificate) keyStore.getCertificate("the_alias");
			Assert.assertNotNull(publicKey);
			publicKey.checkValidity();

			Key key = keyStore.getKey("the_alias", "ijklmnop".toCharArray());
			PrivateKey privateKey = (PrivateKey) key;
			Assert.assertNotNull(privateKey);
			Assert.assertEquals(privateKey.getAlgorithm(), "RSA");
		}

		try {
			KeyStoreFileManager.loadKeyStore(getClass().getResource("/test.keystore").getFile(),
					"wrong_password".toCharArray());
			Assert.fail("Wrong keystore password should throw");
		} catch (LoadKeystoreException e) {
			// Expected.
		}
	}

	@Test
	public void testSign() throws Exception {
		String keystorePath = getClass().getResource("/test.keystore").getFile();
		String alias = "the_alias";
		char[] keyPasssword = "ijklmnop".toCharArray();
		String inputFile = getClass().getResource("/simple_test.zip").getFile();
		File outputFile = new File(new File(inputFile).getParent(), "test_signed.jar");

		try {
			ZipSigner signer = new ZipSigner();
			CustomKeySigner.signZip(signer, keystorePath, null, alias, keyPasssword, "SHA1withRSA", inputFile,
					outputFile.getAbsolutePath());

			Process jarsignerProcess = Runtime.getRuntime().exec("jarsigner -verify " + outputFile.getAbsolutePath());
			BufferedReader in = new BufferedReader(new InputStreamReader(jarsignerProcess.getInputStream()));
			String firstOutputLine = in.readLine();
			Assert.assertEquals("jar verified.", firstOutputLine);
			Assert.assertEquals(0, jarsignerProcess.waitFor());
		} finally {
			outputFile.delete();
		}
	}

}
