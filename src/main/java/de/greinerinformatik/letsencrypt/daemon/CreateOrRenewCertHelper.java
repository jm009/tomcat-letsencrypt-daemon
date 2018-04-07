package de.greinerinformatik.letsencrypt.daemon;

import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;
import java.net.URI;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.shredzone.acme4j.Account;
import org.shredzone.acme4j.AccountBuilder;
import org.shredzone.acme4j.Authorization;
import org.shredzone.acme4j.Certificate;
import org.shredzone.acme4j.Order;
import org.shredzone.acme4j.Session;
import org.shredzone.acme4j.Status;
import org.shredzone.acme4j.challenge.Http01Challenge;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.util.CSRBuilder;
import org.shredzone.acme4j.util.KeyPairUtils;

public class CreateOrRenewCertHelper {

	private static final int KEY_SIZE = 2048; // 4096 if you want
	
	static { Security.addProvider(new BouncyCastleProvider()); }
	

	public static Cert createOrRenew(String domainName, Config config)
					throws IOException, AcmeException {
		File letsEncryptUserKeyFile = config.getLetsEncryptUserKeyFile();
		KeyPair userKeyPair;
		try {
			userKeyPair = createOrReadKeyPair(letsEncryptUserKeyFile);
		}
		catch (IOException ioe) {
			throw new IOException("Error while reading or creating '" + letsEncryptUserKeyFile.getAbsolutePath() + "'.");
		}
		// Create a session for Let's Encrypt
		Session session = config.isUseStagingEnvironment() ?
				new Session("acme://letsencrypt.org/staging")
				: new Session("acme://letsencrypt.org");
		URI termsOfService = session.getMetadata().getTermsOfService();
		System.out.println("Terms of Service: " + termsOfService);
		// Register a new user
		AccountBuilder accountBuilder = new AccountBuilder();
		if (config.isAcceptTermsOfService()) {
			accountBuilder.agreeToTermsOfService();
		}
		Account account = accountBuilder.useKeyPair(userKeyPair).create(session);
		//try {
		//	RegistrationBuilder regBuilder = RegistrationBuilder.bind(session);
		//	for (URI contactURI : config.getLetsEncryptContacts()) {
		//		regBuilder.addContact(contactURI);
		//	}
		//	reg = regBuilder.create();
		//	System.out.println("Registered a new user, URI: " + reg.getLocation());
		//	URI agreement = reg.getAgreement();
		//	System.out.println("Terms of Service: " + agreement);
		//	reg.modify().setAgreement(agreement).commit();
		//} catch (AcmeConflictException ex) {
		//	reg = Registration.bind(session, ex.getLocation());
		//	System.out.println("Account does already exist, URI: " + reg.getLocation());
		//}
		String[] domains = domainName.matches("^www\\.[^\\.]*\\.[^\\.]*$") ?
				new String[] { domainName, domainName.substring(4) } :
				new String[] { domainName };
		Order order = account.newOrder().domains(domains).create();
		for (Authorization auth : order.getAuthorizations()) {
			if (auth.getStatus() != Status.VALID) {
				System.out.println("New authorization for domain " + auth.getDomain());
				Http01Challenge challenge = httpChallenge(auth, config.getLetsEncryptHttpChallengeTokensDir());
				challenge.trigger();

				if (challenge.getStatus() != Status.VALID) {
					challenge.trigger();

					// Poll for the challenge to complete
					int attempts = 10;
					while (challenge.getStatus() != Status.VALID && attempts > 0) {
						if (challenge.getStatus() == Status.INVALID) {
							File challengeTokenFile = challengeTokenFile(config.getLetsEncryptHttpChallengeTokensDir(), challenge);
							challengeTokenFile.delete();
							throw new AcmeException("Challenge failed... Giving up. Reason: "
										+ challenge.getError().getTitle() + " - " + challenge.getError().getDetail());
						}
						try {
							Thread.sleep(3000L);
						} catch (InterruptedException ex) {
							ex.printStackTrace();
						}
						challenge.update();
						attempts--;
					}
					File challengeTokenFile = challengeTokenFile(config.getLetsEncryptHttpChallengeTokensDir(), challenge);
					challengeTokenFile.delete();
					if (challenge.getStatus() != Status.VALID) {
						throw new AcmeException("Failed to pass the challenge... Giving up.");
					}
				}
			}
			// else the authorization is already valid. No need to process a challenge.
		}
		// Load or create a key pair for the domain
		KeyPair domainKeyPair;
		try {
			domainKeyPair = createOrReadKeyPair(config.getDomainKeyFile(domainName));
		}
		catch (IOException ioe) {
			throw new IOException("Error while reading or creating '" + config.getDomainKeyFile(domainName) + "'.");
		}
		// Generate a CSR for the domain
		CSRBuilder csrb = new CSRBuilder();
		csrb.addDomains(domains);
		csrb.setCountry("Germany");
		csrb.setLocality("Stuttgart");
		csrb.setOrganization("Greiner Informatik-Dienstleistungen");
		csrb.setState("Baden-Württemberg");
		csrb.setOrganizationalUnit("post@greiner-informatik.de");
		csrb.sign(domainKeyPair);

		try (Writer out = new FileWriter(config.getDomainCsrFile(domainName))) {
			csrb.write(out);
		}
		// Order the certificate
		order.execute(csrb.getEncoded());
		// Wait for the order to complete
		try {
			int attempts = 10;
			while (order.getStatus() != Status.VALID && attempts-- > 0) {
				// Did the order fail?
				if (order.getStatus() == Status.INVALID) {
					throw new AcmeException("Order failed... Giving up.");
				}

				// Wait for a few seconds
				Thread.sleep(3000L);

				// Then update the status
				order.update();
			}
		}
		catch (InterruptedException ex) {}

		// Get the certificate
		Certificate certificate = order.getCertificate();

		System.out.println("Success! The certificate for domains " + Arrays.toString(domains) + " has been generated!");
		System.out.println("Certificate URI: " + certificate.getLocation());

		// Write a combined file containing the certificate and chain.
		try (FileWriter fw = new FileWriter(config.getDomainCrtAndChainFile(domainName))) {
			certificate.writeCertificate(fw);
		}

		// Download the certificate
		X509Certificate cert = certificate.getCertificate();

		List<X509Certificate> chain = certificate.getCertificateChain();

		if (config.isCreateKeyStore()) {
			try {
				config.getKeyStoreFile(domainName).delete();
				KeyStore keyStore = KeyStore.getInstance("PKCS12");
				keyStore.load(null, config.getKeyStorePassword(domainName).toCharArray());
				X509Certificate[] certificates = new X509Certificate[chain.size()];
				for (int certChainCounter = 0; certChainCounter < chain.size(); certChainCounter++) {
					certificates[certChainCounter] = chain.get(certChainCounter);
				}
				keyStore.setKeyEntry(domainName, domainKeyPair.getPrivate(),
							config.getKeyStorePassword(domainName).toCharArray(), certificates);
				FileOutputStream fos = new FileOutputStream(config.getKeyStoreFile(domainName));
				   keyStore.store(fos, config.getKeyStorePassword(domainName).toCharArray());
				   fos.close();
			}
			catch (KeyStoreException|CertificateException|NoSuchAlgorithmException|IOException e) {
				throw new IOException("Error creating keystore file '"
								+ config.getKeyStoreFile(domainName).getAbsolutePath() +"'.", e);
			}
		}

		return new Cert(domainName, cert);
	}
	
	private static KeyPair createOrReadKeyPair(File keyFile) throws IOException {
		KeyPair keyPair;
		if (keyFile.exists()) {
			FileReader fr = new FileReader(keyFile);
			keyPair = KeyPairUtils.readKeyPair(fr);
			fr.close();
		}
		else {
			keyPair = KeyPairUtils.createKeyPair(KEY_SIZE);
			FileWriter fw = new FileWriter(keyFile);
			KeyPairUtils.writeKeyPair(keyPair, fw);
			fw.close();
		}
		return keyPair;
	}
	
	private static Http01Challenge httpChallenge(Authorization auth,
						File letsEncryptHttpChallengeTokensDir) throws AcmeException {
		// Find a single http-01 challenge
		Http01Challenge challenge = auth.findChallenge(Http01Challenge.TYPE);
		if (challenge == null) {
			throw new AcmeException("Found no " + Http01Challenge.TYPE + " challenge, don't know what to do...");
		}
		
		// // Output the challenge, wait for acknowledge...
		// LOG.info("Please create a file in your web server's base directory.");
		// LOG.info("It must be reachable at: http://" + domain + "/.well-known/acme-challenge/" + challenge.getToken());
		// LOG.info("File name: " + challenge.getToken());
		// LOG.info("Content: " + challenge.getAuthorization());
		// LOG.info("The file must not contain any leading or trailing whitespaces or line breaks!");
		// LOG.info("If you're ready, dismiss the dialog...");

		String challengeToken = challenge.getToken();
		if (!challengeToken.matches("^[A-Za-z0-9\\-_]{3,300}$")) { // don't allow to create arbitrary files on the system, especially not with File.separator in the name
			if (challengeToken.length() > 300) {
				challengeToken = challengeToken.substring(0,300) + "...";
			}
			throw new AcmeException("Refusing to create a challenge token file with file name '" + challengeToken + "'.");
		}
		File challengeTokenFile = challengeTokenFile(letsEncryptHttpChallengeTokensDir, challenge);
		try {
			FileWriter fw = new FileWriter(challengeTokenFile);
			fw.write(challenge.getAuthorization());
			fw.close();
		} catch (IOException ioe) {
			throw new AcmeException("Failed to create Let's Encrypt challenge token file '" + challengeTokenFile.getAbsolutePath() + "'.", ioe);
		}
		// String challengeTokenUrlString = "http://" + domain + "/.well-known/acme-challenge/" + challengeToken;
		// URL challengeTokenUrl;
		// try {
		//	 challengeTokenUrl = new URL(challengeTokenUrlString);
		// } catch (MalformedURLException mue) {
		//	 throw new AcmeException("Malformed URL '" + challengeTokenUrlString + "'.", mue);
		// }
		// int urlConnectionResponseCode;
		// try {
		//	 HttpURLConnection urlConnection = (HttpURLConnection)challengeTokenUrl.openConnection();
		//	urlConnectionResponseCode = urlConnection.getResponseCode();
		//	urlConnection.disconnect();
		// } catch (IOException ioe) {
		//	throw new AcmeException("Error connecting to '" + challengeTokenUrlString + "'.");
		// }
		// if (urlConnectionResponseCode != 200) {
		//	 throw new AcmeException("Response code from '" + challengeTokenUrlString + "' is '" + urlConnectionResponseCode + "', 200 was expected.");
		// }
		return challenge;
	}
	
	private static File challengeTokenFile(File letsEncryptHttpChallengeTokensDir, Http01Challenge challenge) {
		return new File(letsEncryptHttpChallengeTokensDir.getAbsolutePath()
				+ File.separator + challenge.getToken());
	}
}
