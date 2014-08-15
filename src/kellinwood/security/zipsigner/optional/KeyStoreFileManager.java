package kellinwood.security.zipsigner.optional;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;

import org.spongycastle.jce.provider.BouncyCastleProvider;

public class KeyStoreFileManager {

	static final Provider provider = new BouncyCastleProvider();

	static {
		// Add the spongycastle version of the BC provider so that the implementation classes returned from the keystore
		// are all from the spongycastle libs.
		Security.addProvider(provider);
	}

	private static class JksKeyStore extends KeyStore {
		public JksKeyStore() {
			super(new JKS(), provider, "jks");
		}
	}

	public static KeyStore createKeyStore(String keystorePath, char[] password) throws Exception {
		KeyStore ks = null;
		if (keystorePath.toLowerCase().endsWith(".bks")) {
			ks = KeyStore.getInstance("bks", new BouncyCastleProvider());
		} else
			ks = new JksKeyStore();
		ks.load(null, password);
		return ks;
	}

	public static KeyStore loadKeyStore(String keystorePath, char[] password) throws Exception {
		KeyStore ks = null;
		try {
			ks = new JksKeyStore();
			try (FileInputStream fis = new FileInputStream(keystorePath)) {
				ks.load(fis, password);
			}
			return ks;
		} catch (LoadKeystoreException x) {
			// This type of exception is thrown when the keystore is a JKS keystore, but the file is malformed or the
			// validity/password check failed. In this case don't bother to attempt loading it as a BKS keystore.
			throw x;
		} catch (Exception x) {
			try {
				ks = KeyStore.getInstance("bks", provider);
				try (FileInputStream fis = new FileInputStream(keystorePath)) {
					ks.load(fis, password);
				}
				return ks;
			} catch (Exception e) {
				throw new RuntimeException("Failed to load keystore: " + e.getMessage(), e);
			}
		}
	}

	public static void writeKeyStore(KeyStore ks, String keystorePath, char[] password) throws Exception {
		File keystoreFile = new File(keystorePath);
		try {
			if (keystoreFile.exists()) {
				// I've had some trouble saving new versions of the key store file in which the file becomes
				// empty/corrupt. Saving the new version to a new file and creating a backup of the old version.
				File tmpFile = File.createTempFile(keystoreFile.getName(), null, keystoreFile.getParentFile());
				FileOutputStream fos = new FileOutputStream(tmpFile);
				ks.store(fos, password);
				fos.flush();
				fos.close();
				/*
				 * create a backup of the previous version int i = 1; File backup = new File( keystorePath + "." + i +
				 * ".bak"); while (backup.exists()) { i += 1; backup = new File( keystorePath + "." + i + ".bak"); }
				 * renameTo(keystoreFile, backup);
				 */
				renameTo(tmpFile, keystoreFile);
			} else {
				FileOutputStream fos = new FileOutputStream(keystorePath);
				ks.store(fos, password);
				fos.close();
			}
		} catch (Exception x) {
			try {
				File logfile = File.createTempFile("zipsigner-error", ".log", keystoreFile.getParentFile());
				PrintWriter pw = new PrintWriter(new FileWriter(logfile));
				x.printStackTrace(pw);
				pw.flush();
				pw.close();
			} catch (Exception y) {
			}
			throw x;
		}
	}

	static void copyFile(File srcFile, File destFile, boolean preserveFileDate) throws IOException {
		if (destFile.exists() && destFile.isDirectory())
			throw new IOException("Destination '" + destFile + "' exists but is a directory");
		FileInputStream input = new FileInputStream(srcFile);
		try {
			FileOutputStream output = new FileOutputStream(destFile);
			try {
				byte[] buffer = new byte[4096];
				int n = 0;
				while (-1 != (n = input.read(buffer))) {
					output.write(buffer, 0, n);
				}
			} finally {
				try {
					output.close();
				} catch (IOException x) {
				} // Ignore
			}
		} finally {
			try {
				input.close();
			} catch (IOException x) {
			}
		}

		if (srcFile.length() != destFile.length()) {
			throw new IOException("Failed to copy full contents from '" + srcFile + "' to '" + destFile + "'");
		}
		if (preserveFileDate)
			destFile.setLastModified(srcFile.lastModified());
	}

	public static void renameTo(File fromFile, File toFile) throws IOException {
		copyFile(fromFile, toFile, true);
		if (!fromFile.delete())
			throw new IOException("Failed to delete " + fromFile);
	}

}
