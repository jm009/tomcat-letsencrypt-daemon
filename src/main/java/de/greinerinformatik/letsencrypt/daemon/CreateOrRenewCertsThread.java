package de.greinerinformatik.letsencrypt.daemon;

import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Collection;
import java.util.Map;

import javax.servlet.ServletException;

import org.shredzone.acme4j.exception.AcmeException;

public class CreateOrRenewCertsThread extends javax.servlet.http.HttpServlet
						implements Runnable {

	private static final long serialVersionUID = 2000718698641462343L;
	
	private Config config;
	
	public CreateOrRenewCertsThread() {
	}

	public CreateOrRenewCertsThread(Config config) {
		this.config = config;
	}

	@Override
	public void init() throws ServletException {
		String certsDirectory = getInitParameter("certsDirectory");
		if (certsDirectory == null || certsDirectory.length() < 2) {
			throw new ServletException("Servlet init parameter 'certsDirectory' not set.");
		}
		Config config;
		try {
			config = Config.readConfigFileAndCerts(certsDirectory);
		}
		catch (IOException ioe) {
			throw new ServletException(ioe);
		}
		CreateOrRenewCertsThread corct = new CreateOrRenewCertsThread(config);
		Thread t = new Thread(corct, "CreateOrRenewCertsThread");
		t.start();
	}
	
	@Override
	public void run() {
		try {
			Thread.sleep(60000); // wait a minute for tomcat to completely start 
		}
		catch (InterruptedException ie) {}
		Calendar now = Calendar.getInstance();
		if (now.get(Calendar.HOUR_OF_DAY) <= 1) {
			createAndRenewCerts();
			now = Calendar.getInstance();
			Calendar todayThreeOClock = (Calendar)now.clone();
			todayThreeOClock.set(Calendar.HOUR_OF_DAY, 3);
			todayThreeOClock.set(Calendar.MINUTE, 7);
			long sleepMillis = todayThreeOClock.getTimeInMillis() - now.getTimeInMillis();
			if (sleepMillis > 0) {
				try {
					Thread.sleep(sleepMillis);
				}
				catch (InterruptedException ie) {}
			}
		}
		while (true) {
			createAndRenewCerts();
			now = Calendar.getInstance();
			Calendar tomorrowThreeOClock = (Calendar)now.clone();
			tomorrowThreeOClock.add(Calendar.DAY_OF_MONTH, 1);
			tomorrowThreeOClock.set(Calendar.HOUR_OF_DAY, 3);
			tomorrowThreeOClock.set(Calendar.MINUTE, 7);
			long sleepMillis = tomorrowThreeOClock.getTimeInMillis() - now.getTimeInMillis();
			if (sleepMillis > 0) {
				try {
					Thread.sleep(sleepMillis);
				}
				catch (InterruptedException ie) {}
			}
		}
	}
	
	public void createAndRenewCerts() {
		Calendar startTime = Calendar.getInstance();
		System.out.println("createAndRenewCerts start time: '"
				+ (new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss").format(startTime.getTime())));
		// Objective: Try to renew all certs on the same day.
		// Don't renew certificates, that are younger than 90 days.
		// So in this case wait up to another 14 days, to get the expiry dates closer.
		Map<String, Cert> certs = config.getCerts();
		Collection<String> domainNames = config.getDomainNames();
		boolean missingCert = false;
		for (String domainName : domainNames) {
			if (!certs.containsKey(domainName)) {
				missingCert = true;
				Cert c = null;
				try {
					System.out.println("No certificate found for '" + domainName + "'. Creating new one...");
					c = CreateOrRenewCertHelper.createOrRenew(domainName, config);
				} catch (IOException ioe) {
					(new AcmeException("Error creating certificate for '" + domainName + "'.", ioe)).printStackTrace();
				} catch (AcmeException ae) {
					(new AcmeException("Error creating certificate for '" + domainName + "'.", ae)).printStackTrace();
				}
				if (c != null) {
					config.addCert(c);
				}
			}
		}
		if (missingCert) {  // at least one cert was just created, expiry dates will
							// not get closer, renew all
			for (String domainName : certs.keySet()) {
				Cert cert = certs.get(domainName);
				if (cert.below30Days()) {
					try {
						System.out.println("Certificate valid for less than 30 days: '" + domainName + "'. Renewing...");
						CreateOrRenewCertHelper.createOrRenew(domainName, config);
					} catch (IOException ioe) {
						(new AcmeException("Error creating certificate for '" + domainName + "'.", ioe)).printStackTrace();
					} catch (AcmeException ae) {
						(new AcmeException("Error creating certificate for '" + domainName + "'.", ae)).printStackTrace();
					}
				}
			}
		}
		else { // no new or just renewed certs
			boolean haveBelow14DaysCert = false;
			int nbBelow30DaysCerts = 0;
			for (String hostName : certs.keySet()) {
				Cert cert = certs.get(hostName);
				if (cert.below30Days()) {
					nbBelow30DaysCerts++;
					if (cert.below14Days()) {
						haveBelow14DaysCert = true;
					}
				}
			}
			if (haveBelow14DaysCert || nbBelow30DaysCerts == certs.size()) {
					// || all certificates are about to expire in less than 30 days -> don't wait
				for (String domainName : certs.keySet()) {
					Cert cert = certs.get(domainName);
					if (cert.below30Days()) {
						try {
							System.out.println("Certificate for '" + domainName + "' valid for less than 14 days, or all certificates valid for less than 30 days. Renewing...");
							CreateOrRenewCertHelper.createOrRenew(domainName, config);
						} catch (IOException ioe) {
							(new AcmeException("Error creating certificate for '" + domainName + "'.", ioe)).printStackTrace();
						} catch (AcmeException ae) {
							(new AcmeException("Error creating certificate for '" + domainName + "'.", ae)).printStackTrace();
						}
					}
				}
			}
		}
		Calendar endTime = Calendar.getInstance();
		System.out.println("createAndRenewCerts run for "
		+ ((endTime.getTimeInMillis() - startTime.getTimeInMillis()) / 1000L) + " seconds.");
	}

}
