package kellinwood.zipsigner.cmdline;

import java.io.File;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;

import org.apache.commons.cli.BasicParser;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

import kellinwood.security.zipsigner.ZipSigner;
import kellinwood.security.zipsigner.optional.CertCreator;
import kellinwood.security.zipsigner.optional.KeyStoreFileManager;

/** Sign files from the command line using zipsigner-lib. */
public class Main {

	static void usage(Options options) {
		new HelpFormatter().printHelp("apksigner [options] keystore input-apk output.apk",
				"Signs an input APK file using the specified keystore to produce a signed and zipaligned output APK.",
				options, "");
		System.exit(1);
	}

	public static void main(String... args) throws Exception {
		Options options = new Options();
		CommandLine cmdLine = null;
		Option helpOption = new Option("h", "help", false, "Display usage information.");
		options.addOption(helpOption);

		// Option storePasswordOption = new Option("s", "storepass", false, "password for keystore integrity");
		// storePasswordOption.setArgs(1);
		// options.addOption(storePasswordOption);

		Option keyPasswordOption = new Option("p", "password", false, "Password for private key (default:android).");
		keyPasswordOption.setArgs(1);
		options.addOption(keyPasswordOption);

		try {
			cmdLine = new BasicParser().parse(options, args);
		} catch (ParseException x) {
			System.err.println(x.getMessage());
			usage(options);
		}

		if (cmdLine.hasOption(helpOption.getOpt())) {
			usage(options);
		}

		@SuppressWarnings("unchecked")
		List<String> argList = cmdLine.getArgList();
		if (argList.size() != 3) {
			usage(options);
		}

		String keystorePath = argList.get(0);
		String inputFile = argList.get(1);
		String outputFile = argList.get(2);

		// char[] storePassword;
		// if (cmdLine.hasOption(storePasswordOption.getOpt())) {
		// String optionValue = cmdLine.getOptionValue(storePasswordOption.getOpt());
		// if (optionValue == null || optionValue.equals("")) {
		// storePassword = null;
		// } else {
		// storePassword = optionValue.toCharArray();
		// }
		// } else {
		// storePassword = null;
		// }

		char[] keyPassword;
		if (cmdLine.hasOption(keyPasswordOption.getOpt())) {
			String optionValue = cmdLine.getOptionValue(keyPasswordOption.getOpt());
			if (optionValue == null || optionValue.equals("")) {
				keyPassword = null;
			} else {
				keyPassword = optionValue.toCharArray();
			}
		} else {
			keyPassword = "android".toCharArray();
		}

		File keystoreFile = new File(keystorePath);
		if (!keystoreFile.exists()) {
			String alias = "alias";
			System.out.println("Creating new keystore (using '" + new String(keyPassword) + "' as password and '"
					+ alias + "' as the key alias).");
			CertCreator.DistinguishedNameValues nameValues = new CertCreator.DistinguishedNameValues();
			nameValues.setCommonName("APK Signer");
			nameValues.setOrganization("Earth");
			nameValues.setOrganizationalUnit("Earth");
			CertCreator.createKeystoreAndKey(keystorePath, keyPassword, "RSA", 2048, alias, keyPassword, "SHA1withRSA",
					30, nameValues);
		}

		KeyStore keyStore = KeyStoreFileManager.loadKeyStore(keystorePath, null);
		String alias = keyStore.aliases().nextElement();

		X509Certificate publicKey = (X509Certificate) keyStore.getCertificate(alias);
		PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, keyPassword);
		ZipSigner.signZip(publicKey, privateKey, "SHA1withRSA", inputFile, outputFile);
	}

}
