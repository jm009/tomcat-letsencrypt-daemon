package de.greinerinformatik.letsencrypt.daemon;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Map;
import java.util.Properties;

import javax.mail.internet.AddressException;
import javax.mail.internet.InternetAddress;

import org.shredzone.acme4j.util.CertificateUtils;

public class Config {
	
	private File certsDirectory;
	private File userKeyFile;
	private Collection<URI> letsEncryptContacts = new LinkedList<URI>();
	private Collection<String> domainNames = new LinkedList<String>();
	private Map<String, Cert> certs = new HashMap<String, Cert>();
	private File letsEncryptHttpChallengeTokensDir;
	private Boolean createJksKeystore = null;
	private Boolean useStagingEnvironment = null;
	private Boolean agreeToTermsOfService = null;
		
	public Map<String, Cert> getCerts() {
		return certs;
	}

	public Collection<String> getDomainNames() {
		return domainNames;
	}
	
	public static Config readConfigFileAndCerts(String certsDirectory) throws IOException {
		Config config = new Config();
		config.certsDirectory = new File(certsDirectory);
		if (!config.certsDirectory.isDirectory()) {
			throw new IOException("'" + certsDirectory + "' is not a directory.");
		}
		config.userKeyFile = new File(certsDirectory + File.separator
				+ "letsEncryptUserKey" + File.separator + "letsEncryptUser.key");
		config.letsEncryptHttpChallengeTokensDir
			= new File(certsDirectory + File.separator + "letsEncryptHttpChallengeTokens");
		if (!config.letsEncryptHttpChallengeTokensDir.isDirectory()) {
			throw new IOException("'" + certsDirectory + "' is not a directory.");
		}
		config.readHostNamesAndContacts();
		config.readCerts();
		return config;
	}

	private void readCerts() throws IOException {
		for (String domainName : domainNames) {
			File f = getDomainCrtFile(domainName);
			if (f.exists()) {
				X509Certificate x509;
				try {
					FileInputStream fis = new FileInputStream(f);
					CertificateFactory cf = CertificateFactory.getInstance("X.509");
					x509 = (X509Certificate)cf.generateCertificate(fis);
					fis.close();
				} catch (IOException|CertificateException e) {
					throw new IOException("Error reading certificate file '" + f.getAbsolutePath()
															+ "' from disk.", e);
				}
				Cert cert = new Cert(domainName, x509);
				certs.put(domainName, cert);
			}
		}
	}

	private void readHostNamesAndContacts() throws IOException {
		Properties p = new Properties();
		String certsConfigPath = certsDirectory.getAbsolutePath() + File.separator + "certsConfig.properties";
		try {
			p.load(new InputStreamReader(new FileInputStream(certsConfigPath), "UTF-8"));
		}
		catch (FileNotFoundException fnfe) {
			throw new IOException("Certificates config file '" + certsConfigPath + "' not found.", fnfe);
		}
		catch (UnsupportedEncodingException uee) {
			uee.printStackTrace(); // should never happen
		}
		catch (IOException ioe) {
			throw new IOException("Error reading certificates config file (properties format) '"
					+ certsConfigPath + "'.", ioe);
		}
		for (String propertyName : p.stringPropertyNames()) {
			String propertyNameLowerCase = propertyName.toLowerCase();
			if (propertyNameLowerCase.startsWith("domainname")) {
				String domainName = p.getProperty(propertyName);
				if (!domainName.equals(domainName.toLowerCase())) {
					throw new IOException("Entry '" + propertyName + "' in '" + certsConfigPath + "' must contain a domain name in all lower case.");
				}
				if (domainName.matches("^[^\\.]*\\.[^\\.]*$")) { // only one dot (.)
					throw new IOException("Host name '" + domainName
							+ "' not allowed in config '" + certsConfigPath +
							"'. Please prepend 'www.'. Certificate for '" + domainName
							+ "' (without 'www.') will be included automatically.");
				}
				if (domainNames.contains(domainName)) {
					throw new IOException("Duplicate entry for domain '" + domainName + "' in '" + certsConfigPath + "'.");
				}
				domainNames.add(domainName);
			}
			else if (propertyNameLowerCase.startsWith("letsencryptcontact")) {
				String contact = p.getProperty(propertyName);
				InternetAddress email;
				try {
					email = new InternetAddress(contact, true);
				} catch (AddressException ae) {
					throw new IOException("Invalid email address in '" + certsConfigPath + "': '"
							+ propertyName + "' - '" + contact + "'.", ae);
				}
				URI mailtoURI;
				try {
					mailtoURI = new URI("mailto", email.toString() , null);
				} catch (URISyntaxException use) {
					throw new IOException("Invalid email address in '" + certsConfigPath + "': '"
							+ propertyName + "' - '" + contact + "'.", use);
				}
				letsEncryptContacts.add(mailtoURI);
			}
			else if (propertyNameLowerCase.equals("createjkskeystore")) {
				if (createJksKeystore != null) throw new IOException("Duplicate entry 'createJksKeystore' in '" + certsConfigPath + "'.");
				createJksKeystore = readBooleanValue(p, propertyName, certsConfigPath);
			}
			else if (propertyNameLowerCase.equals("usestagingenvironment")) {
				if (useStagingEnvironment != null) throw new IOException("Duplicate entry 'useStagingEnvironment' in '" + certsConfigPath + "'.");
				useStagingEnvironment = readBooleanValue(p, propertyName, certsConfigPath);
			}
			else if (propertyNameLowerCase.equals("agreetotermsofservice")) {
				if (agreeToTermsOfService != null) throw new IOException("Duplicate entry 'agreeToTermsOfService' in '" + certsConfigPath + "'.");
				agreeToTermsOfService = readBooleanValue(p, propertyName, certsConfigPath);
			}
			else {
				throw new IOException("Unknown entry '" + propertyName + "' in '" + certsConfigPath + "' - ignored.");
			}
		}
		if (this.createJksKeystore == null) {
			throw new IOException("Entry 'createJksKeystore' in '" + certsConfigPath + "' not found.");
		}
		if (this.useStagingEnvironment == null) {
			throw new IOException("Entry 'useStagingEnvironment' in '" + certsConfigPath + "' not found.");
		}
		if (this.agreeToTermsOfService == null) {
			throw new IOException("Entry 'agreeToTermsOfService' in '" + certsConfigPath + "' not found.");
		}
	}

	private Boolean readBooleanValue(Properties p, String propertyName, String certsConfigPath) throws IOException {
		String stringValue = p.getProperty(propertyName).toLowerCase();
		if ("true".equals(stringValue) || "yes".equals(stringValue)) {
			return Boolean.TRUE;
		}
		else if ("false".equals(stringValue) || "no".equals(stringValue)) {
			return Boolean.FALSE;
		}
		else {
			throw new IOException("Entry '" + propertyName + "' in '" + certsConfigPath + "' must be 'true' or 'false'.");
		}
	}

	public void addCert(Cert cert) {
		certs.put(cert.getDomainName(), cert);
	}
	
	public File getLetsEncryptUserKeyFile() {
		return userKeyFile;
	}
	
	public Collection<URI> getLetsEncryptContacts() {
		return letsEncryptContacts;
	}
	
	public File getLetsEncryptHttpChallengeTokensDir() {
		return letsEncryptHttpChallengeTokensDir;
	}

	public File getDomainKeyFile(String domainName) {
		if (domainName.matches("^[^\\.]*\\.[^\\.]*$")) { // only one dot (.)
			throw new IllegalArgumentException("'getDomainKeyFile(String domainName)' may not be called with a domain name with only one dot (.). Prepend 'www.'. The certificiate will contain a non-'www.' version too.");
		}
		return new File(certsDirectory.getAbsolutePath() + File.separator + domainName + File.separator + "domain.key");
	}

	public File getDomainCsrFile(String domainName) {
		if (domainName.matches("^[^\\.]*\\.[^\\.]*$")) { // only one dot (.)
			throw new IllegalArgumentException("'getDomainCsrFile(String domainName)' may not be called with a domain name with only one dot (.). Prepend 'www.'. The certificiate will contain a non-'www.' version too.");
		}
		return new File(certsDirectory.getAbsolutePath() + File.separator + domainName + File.separator + "domain.csr");
	}

	public File getDomainCrtAndChainFile(String domainName) {
		if (domainName.matches("^[^\\.]*\\.[^\\.]*$")) { // only one dot (.)
			throw new IllegalArgumentException("'getDomainCrtAndChainFile(String domainName)' may not be called with a domain name with only one dot (.). Prepend 'www.'. The certificiate will contain a non-'www.' version too.");
		}
		return new File(certsDirectory.getAbsolutePath() + File.separator + domainName + File.separator + "domain_and_chain.crt");
	}

	public File getDomainCrtFile(String domainName) {
		if (domainName.matches("^[^\\.]*\\.[^\\.]*$")) { // only one dot (.)
			throw new IllegalArgumentException("'getDomainCrtFile(String domainName)' may not be called with a domain name with only one dot (.). Prepend 'www.'. The certificiate will contain a non-'www.' version too.");
		}
		return new File(certsDirectory.getAbsolutePath() + File.separator + domainName + File.separator + "domain.crt");
	}

	public File getChainCrtFile(String domainName) {
		if (domainName.matches("^[^\\.]*\\.[^\\.]*$")) { // only one dot (.)
			throw new IllegalArgumentException("'getChainCrtFile(String domainName)' may not be called with a domain name with only one dot (.). Prepend 'www.'. The certificiate will contain a non-'www.' version too.");
		}
		return new File(certsDirectory.getAbsolutePath() + File.separator + domainName + File.separator + "chain.crt");
	}

	public File getKeyStoreFile(String domainName) {
		if (domainName.matches("^[^\\.]*\\.[^\\.]*$")) { // only one dot (.)
			throw new IllegalArgumentException("'getKeyStoreFile(String domainName)' may not be called with a domain name with only one dot (.). Prepend 'www.'. The certificiate will contain a non-'www.' version too.");
		}
		return new File(certsDirectory.getAbsolutePath() + File.separator + domainName + File.separator + "keystore.pkcs12");

	}
	
	public String getKeyStorePassword(String domainName) {
		return "changeit";
	}

	public boolean isCreateKeyStore() {
		return createJksKeystore.booleanValue();
	}

	public boolean isUseStagingEnvironment() {
		return useStagingEnvironment.booleanValue();
	}

	public boolean isAcceptTermsOfService() {
		return agreeToTermsOfService.booleanValue();
	}
}
