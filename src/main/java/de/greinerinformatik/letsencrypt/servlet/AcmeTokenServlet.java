package de.greinerinformatik.letsencrypt.servlet;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class AcmeTokenServlet extends HttpServlet {

	private static final long serialVersionUID = -6484386936056831983L;

	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp)
			throws ServletException, IOException {
		resp.setContentType("text/plain;charset=UTF-8");
		String certsDirectoryPath = getInitParameter("certsDirectory");
		if (certsDirectoryPath == null || certsDirectoryPath.length() < 2) {
			throw new ServletException("Servlet init parameter 'certsDirectory' not set.");
		}
		File certsDirectory = new File(certsDirectoryPath);
		if (!certsDirectory.isDirectory()) {
			throw new ServletException("Directory '" + certsDirectory.getAbsolutePath() + "' not found.");
		}
		String letsEncryptHttpChallengeTokensDirPath = certsDirectory.getAbsolutePath()
				+ File.separator + "letsEncryptHttpChallengeTokens";
		String servletPath = req.getServletPath() + req.getPathInfo();
		int lastSlashIndex = servletPath.lastIndexOf('/');
		if (!"/.well-known/acme-challenge".equals(servletPath.substring(0, lastSlashIndex))) {
			throw new ServletException("Invalid servlet path.");
		}
		String requestedToken = servletPath.substring(lastSlashIndex + 1);
		if (!requestedToken.matches("^[A-Za-z0-9\\-_]{3,300}$")) { // don't allow to read arbitrary files on the system, especially not with File.separator in the name
			throw new ServletException("Invalid token file name.");
		}
		char[] c = new char[16384];
		int nbCharsRead;
		FileReader fr;
        try {
           fr = new FileReader(new File(letsEncryptHttpChallengeTokensDirPath
                        + File.separator + requestedToken));
        }
        catch (FileNotFoundException fnfe) {
        	fnfe.printStackTrace();
            throw new FileNotFoundException("<certsDirectory>/<tokensDir>/" + requestedToken + "(No such file or directory). See details in the server log.");
        }
		nbCharsRead = fr.read(c);
		fr.close();
		PrintWriter out = resp.getWriter();
		out.write(c, 0, nbCharsRead);
		out.close();
	}
}
