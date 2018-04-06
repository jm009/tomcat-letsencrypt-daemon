package de.greinerinformatik.letsencrypt.daemon;

import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Date;

public class Cert {
	
	private String domainName;
	private X509Certificate x509;

	public Cert(String domainName, X509Certificate x509) {
		this.domainName = domainName;
		this.x509 = x509;
	}
	
	public String getDomainName() {
		return domainName;
	}

	public boolean below30Days() {
		try {
			x509.checkValidity(new Date(System.currentTimeMillis() + 2592000000L));
		}
		catch (CertificateExpiredException cee) {
			return true;
		}
		catch (CertificateNotYetValidException cnyve) {
			System.out.println("Certificate for '" + domainName + "' not yet valid in 30 days... Strange... Where did you get this certificate?");
		}
		return false;
	}

	public boolean below14Days() {
		try {
			x509.checkValidity(new Date(System.currentTimeMillis() + 1209600000L));
		}
		catch (CertificateExpiredException cee) {
			return true;
		}
		catch (CertificateNotYetValidException cnyve) {
			System.out.println("Certificate for '" + domainName + "' not yet valid in 14 days... Strange... Where did you get this certificate?");
		}
		return false;
	}

}
