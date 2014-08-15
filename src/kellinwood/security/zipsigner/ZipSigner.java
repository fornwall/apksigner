/*
 * Copyright (C) 2010 Ken Ellinwood
 * Copyright (C) 2008 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* This file is a heavily modified version of com.android.signapk.SignApk.java.
 * The changes include:
 *   - addition of the signZip() convenience methods
 *   - addition of a progress listener interface
 *   - removal of main()
 *   - switch to a signature generation method that verifies
 *     in Android recovery
 *   - eliminated dependency on sun.security and sun.misc APIs by 
 *     using signature block template files.
 */

package kellinwood.security.zipsigner;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.net.URL;
import java.security.DigestOutputStream;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.jar.Attributes;
import java.util.jar.JarFile;
import java.util.jar.Manifest;
import java.util.regex.Pattern;

import javax.crypto.Cipher;
import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import kellinwood.security.zipsigner.optional.SignatureBlockGenerator;
import kellinwood.zipio.ZioEntry;
import kellinwood.zipio.ZipInput;
import kellinwood.zipio.ZipOutput;

import org.spongycastle.jce.provider.BouncyCastleProvider;

/**
 * This is a modified copy of com.android.signapk.SignApk.java. It provides an API to sign JAR files (including APKs and
 * Zip/OTA updates) in a way compatible with the mincrypt verifier, using SHA1 and RSA keys.
 *
 * Please see the README.txt file in the root of this project for usage instructions.
 */
public class ZipSigner {

	static {
		Security.insertProviderAt(new BouncyCastleProvider(), 1);
	}

	private static final String CERT_SF_NAME = "META-INF/CERT.SF";
	private static final String CERT_RSA_NAME = "META-INF/CERT.RSA";

	// Files matching this pattern are not copied to the output.
	private static final Pattern stripPattern = Pattern.compile("^META-INF/(.*)[.](SF|RSA|DSA)$");

	public static X509Certificate readPublicKey(URL publicKeyUrl) throws IOException, GeneralSecurityException {
		try (InputStream input = publicKeyUrl.openStream()) {
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			return (X509Certificate) cf.generateCertificate(input);
		}
	}

	/**
	 * Decrypt an encrypted PKCS 8 format private key.
	 *
	 * Based on ghstark's post on Aug 6, 2006 at http://forums.sun.com/thread.jspa?threadID=758133&messageID=4330949
	 *
	 * @param encryptedPrivateKey
	 *            The raw data of the private key
	 * @param keyPassword
	 *            the key password
	 */
	private static KeySpec decryptPrivateKey(byte[] encryptedPrivateKey, String keyPassword)
			throws GeneralSecurityException {
		EncryptedPrivateKeyInfo epkInfo;
		try {
			epkInfo = new EncryptedPrivateKeyInfo(encryptedPrivateKey);
		} catch (IOException ex) {
			// Probably not an encrypted key.
			return null;
		}

		char[] keyPasswd = keyPassword.toCharArray();

		SecretKeyFactory skFactory = SecretKeyFactory.getInstance(epkInfo.getAlgName());
		Key key = skFactory.generateSecret(new PBEKeySpec(keyPasswd));

		Cipher cipher = Cipher.getInstance(epkInfo.getAlgName());
		cipher.init(Cipher.DECRYPT_MODE, key, epkInfo.getAlgParameters());

		try {
			return epkInfo.getKeySpec(cipher);
		} catch (InvalidKeySpecException ex) {
			System.err.println("signapk: Password for private key may be bad.");
			throw ex;
		}
	}

	/** Fetch the content from the given stream and return it as a byte array. */
	public static byte[] readContentAsBytes(InputStream input) throws IOException {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		byte[] buffer = new byte[4096];
		int numRead;
		while ((numRead = input.read(buffer)) != -1)
			baos.write(buffer, 0, numRead);
		return baos.toByteArray();
	}

	/** Read a PKCS 8 format private key. */
	public static PrivateKey readPrivateKey(URL privateKeyUrl, String keyPassword) throws IOException,
			GeneralSecurityException {
		try (DataInputStream input = new DataInputStream(privateKeyUrl.openStream())) {
			byte[] privateKeyBytes = readContentAsBytes(input);

			KeySpec spec = decryptPrivateKey(privateKeyBytes, keyPassword);
			if (spec == null)
				spec = new PKCS8EncodedKeySpec(privateKeyBytes);

			try {
				return KeyFactory.getInstance("RSA").generatePrivate(spec);
			} catch (InvalidKeySpecException ex) {
				return KeyFactory.getInstance("DSA").generatePrivate(spec);
			}
		}
	}

	/** Add the SHA1 of every file to the manifest, creating it if necessary. */
	private static Manifest addDigestsToManifest(Map<String, ZioEntry> entries) throws IOException,
			GeneralSecurityException {
		Manifest input = null;
		ZioEntry manifestEntry = entries.get(JarFile.MANIFEST_NAME);
		if (manifestEntry != null) {
			input = new Manifest();
			input.read(manifestEntry.getInputStream());
		}
		Manifest output = new Manifest();
		Attributes main = output.getMainAttributes();
		if (input != null) {
			main.putAll(input.getMainAttributes());
		} else {
			main.putValue("Manifest-Version", "1.0");
			main.putValue("Created-By", "1.0 (Android SignApk)");
		}

		MessageDigest md = MessageDigest.getInstance("SHA1");
		byte[] buffer = new byte[512];
		int num;

		// We sort the input entries by name, and add them to the output manifest in sorted order. We expect that the
		// output map will be deterministic.
		TreeMap<String, ZioEntry> byName = new TreeMap<>();
		byName.putAll(entries);

		// if (debug) getLogger().debug("Manifest entries:");
		for (ZioEntry entry : byName.values()) {
			String name = entry.getName();
			// if (debug) getLogger().debug(name);
			if (!entry.isDirectory() && !name.equals(JarFile.MANIFEST_NAME) && !name.equals(CERT_SF_NAME)
					&& !name.equals(CERT_RSA_NAME) && (stripPattern == null || !stripPattern.matcher(name).matches())) {

				InputStream data = entry.getInputStream();
				while ((num = data.read(buffer)) > 0) {
					md.update(buffer, 0, num);
				}

				Attributes attr = null;
				if (input != null) {
					java.util.jar.Attributes inAttr = input.getAttributes(name);
					if (inAttr != null)
						attr = new Attributes(inAttr);
				}
				if (attr == null)
					attr = new Attributes();
				attr.putValue("SHA1-Digest", Base64.encode(md.digest()));
				output.getEntries().put(name, attr);
			}
		}

		return output;
	}

	/** Write the signature file to the given output stream. */
	private static byte[] generateSignatureFile(Manifest manifest) throws IOException, GeneralSecurityException {
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		out.write(("Signature-Version: 1.0\r\n").getBytes());
		out.write(("Created-By: 1.0 (Android SignApk)\r\n").getBytes());

		MessageDigest md = MessageDigest.getInstance("SHA1");
		PrintStream print = new PrintStream(new DigestOutputStream(new ByteArrayOutputStream(), md), true, "UTF-8");

		// Digest of the entire manifest
		manifest.write(print);
		print.flush();

		out.write(("SHA1-Digest-Manifest: " + Base64.encode(md.digest()) + "\r\n\r\n").getBytes());

		Map<String, Attributes> entries = manifest.getEntries();
		for (Map.Entry<String, Attributes> entry : entries.entrySet()) {
			// Digest of the manifest stanza for this entry.
			String nameEntry = "Name: " + entry.getKey() + "\r\n";
			print.print(nameEntry);
			for (Map.Entry<Object, Object> att : entry.getValue().entrySet()) {
				print.print(att.getKey() + ": " + att.getValue() + "\r\n");
			}
			print.print("\r\n");
			print.flush();

			out.write(nameEntry.getBytes());
			out.write(("SHA1-Digest: " + Base64.encode(md.digest()) + "\r\n\r\n").getBytes());
		}
		return out.toByteArray();
	}

	/**
	 * Sign the file using the given public key cert, private key, and signature block template. The signature block
	 * template parameter may be null, but if so android-sun-jarsign-support.jar must be in the classpath.
	 */
	public static void signZip(X509Certificate publicKey, PrivateKey privateKey, String signatureAlgorithm,
			String inputZipFilename, String outputZipFilename) throws IOException, GeneralSecurityException {
		KeySet keySet = new KeySet(publicKey, privateKey, signatureAlgorithm);

		File inFile = new File(inputZipFilename).getCanonicalFile();
		File outFile = new File(outputZipFilename).getCanonicalFile();
		if (inFile.equals(outFile))
			throw new IllegalArgumentException("Input and output files are the same");

		try (ZipInput input = new ZipInput(inputZipFilename)) {
			try (ZipOutput zipOutput = new ZipOutput(new FileOutputStream(outputZipFilename))) {
				// Assume the certificate is valid for at least an hour.
				long timestamp = keySet.publicKey.getNotBefore().getTime() + 3600L * 1000;

				// MANIFEST.MF
				Manifest manifest = addDigestsToManifest(input.entries);
				ZioEntry ze = new ZioEntry(JarFile.MANIFEST_NAME);
				ze.setTime(timestamp);
				manifest.write(ze.getOutputStream());
				zipOutput.write(ze);

				byte[] certSfBytes = generateSignatureFile(manifest);

				// CERT.SF
				ze = new ZioEntry(CERT_SF_NAME);
				ze.setTime(timestamp);
				ze.getOutputStream().write(certSfBytes);
				zipOutput.write(ze);

				// CERT.RSA
				ze = new ZioEntry(CERT_RSA_NAME);
				ze.setTime(timestamp);
				ze.getOutputStream().write(SignatureBlockGenerator.generate(keySet, certSfBytes));
				zipOutput.write(ze);

				// Copy all the files in a manifest from input to output. We set the modification times in the output to
				// a fixed time, so as to reduce variation in the output file and make incremental OTAs more efficient.
				Map<String, Attributes> entries = manifest.getEntries();
				List<String> names = new ArrayList<>(entries.keySet());
				Collections.sort(names);
				for (String name : names) {
					ZioEntry inEntry = input.entries.get(name);
					inEntry.setTime(timestamp);
					zipOutput.write(inEntry);
				}
			}
		}
	}

}