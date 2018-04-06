tomcat-letsencrypt-daemon
=====

What it is
-----

Handle regular updates for certificates from Let's encrypt for tomcat (must be renewed every three to four months). 

Developed with a handfull of domains in mind (should work for a lot of domains)

How it works
-----

From time to time a new domain is added, and the certificate is created immediately.

Then, maybe, for two years, no domain is added. The initially differing three month renewal periods converge, and some day all certificates are renewed the same day, 30 days before they expire.

Minimum time before renewing an expiring certificate is, when 14 days of validity are left.

Certificates for second level domains (example.com) will always contain in addition the domain name with www (example.com and www.example.com).

Certificates for higher level domains (blog.example.com) will not contain a www part.


Installation
-----

In this version, the tool is supposed to be started as a servlet (without servlet functionality, only to start the renewal thread) with the following in your WEB-INF/web.xml:

	<servlet>
	    <servlet-name>CreateOrRenewCertsThread-Servlet</servlet-name>
	    <description>
	      Run a separate thread, and check once a day, if letsencrypt certificates
	      should be renewed.
	    </description>
	    <servlet-class>de.greinerinformatik.letsencrypt.daemon.CreateOrRenewCertsThread</servlet-class>
	    <init-param>
	      <param-name>certsDirectory</param-name>
	      <param-value>/etc/tomcat9/ssl/</param-value>
	    </init-param>
	    <load-on-startup>10</load-on-startup>
	</servlet>  

This was not the best choice to take, because anyway, Tomcat needs to be restarted to use the new certificate. That can be done with a cron job with restartTomcatOnNewCert.sh.

In the next version, the tool will be started as a standalone process right away :-)

To allow Let's encrypt to verify, that you own the domain, you have to setup the AcmeTokenServlet. Put the following in your WEB-INF/web.xml:

	<servlet>
	    <servlet-name>AcmeTokenServlet</servlet-name>
	    <description>
	      Handle letsencrypt http challenge
	    </description>
	    <servlet-class>de.greinerinformatik.letsencrypt.servlet.AcmeTokenServlet</servlet-class>
	    <init-param>
	      <param-name>certsDirectory</param-name>
	      <param-value>/etc/tomcat9/ssl/</param-value>
	    </init-param>
	</servlet>
	
	<servlet-mapping>
	    <servlet-name>AcmeTokenServlet</servlet-name>
	    <url-pattern>/.well-known/acme-challenge/*</url-pattern>
	</servlet-mapping>

Trailer
-----

This is far from beeing finished, but works for me.

Feedback, pull requests, filing bug reports are welcome.
