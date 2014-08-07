/*
 * Copyright (C) 2010 Ken Ellinwood
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
package kellinwood.zipsigner.cmdline;

import java.io.File;
import java.net.URL;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.List;

import kellinwood.security.zipsigner.ZipSigner;
import kellinwood.security.zipsigner.optional.CustomKeySigner;
import kellinwood.security.zipsigner.optional.KeyStoreFileManager;

import org.apache.commons.cli.BasicParser;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.MissingOptionException;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.commons.cli.Parser;

/** Sign files from the command line using zipsigner-lib. */
public class Main {

	static void usage(Options options) {
		new HelpFormatter()
				.printHelp(
						140,
						"Usage: jarsigner [options] jar-file alias",
						"       jarsigner [options] jar-file [alias...]\n\n"
								+ "REAL Usage: jarsigner [options] <input.zip> <output.zip>"
								+ "Sign the input file and write the result to the given output file\n\n"
								+ "Examples:\n\n"
								+ "  java -jar zipsigner.jar input.zip output-signed.zip (signs in auto-testkey mode)\n\n"
								+ "  java -jar zipsigner.jar -m <keyMode> input.zip output-signed.zip (signs in specified mode)\n\n"
								+ "  java -jar zipsigner.jar -s <keystore file> input.zip output-signed.zip (signs with first key in the keystore)\n\n"
								+ "  java -jar zipsigner.jar -s <keystore file> -a <key alias> input.zip output-signed.zip (signs with specified key in keystore)",
						options, "");
		System.exit(1);
	}

	static char[] readPassword(String prompt) {
		System.out.print(prompt + ": ");
		System.out.flush();
		return System.console().readPassword();
	}

	public static void main(String[] args) {
		try {

			Options options = new Options();
			CommandLine cmdLine = null;
			Option helpOption = new Option("h", "help", false, "Display usage information");

			Option keyOption = new Option("k", "key", false, "PCKS#8 encoded private key file");
			keyOption.setArgs(1);

			Option pwOption = new Option("p", "keypass", false, "Private key password");
			pwOption.setArgs(1);

			Option certOption = new Option("c", "cert", false, "X.509 public key certificate file");
			certOption.setArgs(1);

			Option sbtOption = new Option("t", "template", false, "Signature block template file");
			sbtOption.setArgs(1);

			Option keystoreOption = new Option("s", "keystore", true, "Keystore file");
			keystoreOption.setArgs(1);

			Option aliasOption = new Option("a", "alias", true, "Alias for key/cert in the keystore");
			aliasOption.setArgs(1);

			options.addOption(helpOption);
			options.addOption(keyOption);
			options.addOption(certOption);
			options.addOption(sbtOption);
			options.addOption(pwOption);
			options.addOption(keystoreOption);
			options.addOption(aliasOption);

			Parser parser = new BasicParser();

			try {
				cmdLine = parser.parse(options, args);
			} catch (MissingOptionException x) {
				System.out.println("One or more required options are missing: " + x.getMessage());
				usage(options);
			} catch (ParseException x) {
				System.err.println(x.getClass().getSimpleName() + ": " + x.getMessage());
				usage(options);
			}

			if (cmdLine.hasOption(helpOption.getOpt()))
				usage(options);

			@SuppressWarnings("unchecked")
			List<String> argList = cmdLine.getArgList();
			if (argList.size() != 2)
				usage(options);

			ZipSigner signer = new ZipSigner();

			PrivateKey privateKey = null;
			if (cmdLine.hasOption(keyOption.getOpt())) {
				if (!cmdLine.hasOption(certOption.getOpt())) {
					System.out.println("Certificate file is required when specifying a private key");
					usage(options);
				}

				String keypw = null;
				if (cmdLine.hasOption(pwOption.getOpt()))
					keypw = pwOption.getValue();
				else {
					keypw = new String(readPassword("Key password"));
					if (keypw.equals(""))
						keypw = null;
				}
				URL privateKeyUrl = new File(keyOption.getValue()).toURI().toURL();

				privateKey = signer.readPrivateKey(privateKeyUrl, keypw);
			}

			X509Certificate cert = null;
			if (cmdLine.hasOption(certOption.getOpt())) {
				if (!cmdLine.hasOption(keyOption.getOpt())) {
					System.out.println("Private key file is required when specifying a certificate");
					usage(options);
				}
				URL certUrl = new File(certOption.getValue()).toURI().toURL();
				cert = signer.readPublicKey(certUrl);
			}

			byte[] sigBlockTemplate = null;
			if (cmdLine.hasOption(sbtOption.getOpt())) {
				URL sbtUrl = new File(sbtOption.getValue()).toURI().toURL();
				sigBlockTemplate = signer.readContentAsBytes(sbtUrl);
			}

			if (cmdLine.hasOption(keyOption.getOpt())) {
				signer.setKeys(cert, privateKey, sigBlockTemplate);
				signer.signZip(argList.get(0), argList.get(1));
			} else if (cmdLine.hasOption((keystoreOption.getOpt()))) {
				String keystorePath = cmdLine.getOptionValue(keystoreOption.getOpt());
				String alias = null;
				if (!cmdLine.hasOption(aliasOption.getOpt())) {
					KeyStore keyStore = KeyStoreFileManager.loadKeyStore(keystorePath, (char[]) null);
					for (Enumeration<String> e = keyStore.aliases(); e.hasMoreElements();) {
						alias = e.nextElement();
						System.out.println("Signing with alias: " + alias);
						break;
					}
				} else {
					alias = aliasOption.getValue();
				}
				String keypw = null;
				if (cmdLine.hasOption(pwOption.getOpt()))
					keypw = cmdLine.getOptionValue(pwOption.getOpt());
				else {
					keypw = new String(readPassword("Key password"));
					if (keypw.equals(""))
						keypw = null;
				}

				CustomKeySigner.signZip(signer, keystorePath, null, alias, keypw.toCharArray(), "SHA1withRSA",
						argList.get(0), argList.get(1));
			} else {
				System.err.println("No keystore given!");
			}
		} catch (Throwable t) {
			t.printStackTrace();
		}
	}

}
