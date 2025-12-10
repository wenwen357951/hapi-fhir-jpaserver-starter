package tw.org.csh.aic.fhir.servlet;

import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.io.PrintWriter;

@WebServlet(
	name = "SmartConfigurationServlet",
	urlPatterns = {"/fhir/.well-known/smart-configuration"}
)
public class SmartConfigurationServlet extends HttpServlet {

	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		resp.setStatus(HttpServletResponse.SC_OK);
		resp.setContentType("application/json;charset=UTF-8");
		String metadata = """
			{
			  "issuer": "http://localhost/auth/realms/smart-subscription-platform",
			  "token_endpoint": "http://localhost/auth/realms/smart-subscription-platform/protocol/openid-connect/token",
			  "authorization_endpoint": "http://localhost/auth/realms/smart-subscription-platform/protocol/openid-connect/auth",
			  "grant_types_supported": [
			    "authorization_code",
			    "client_credentials"
			  ],
			  "scopes_supported": [
			    "openid",
			    "launch",
			    "fhirUser",
			    "profile"
			  ],
			  "capabilities": [
			    "launch-standalone",
			    "client-public"
			  ],
			  "code_challenge_methods_supported": ["S256"]
			}
			""";
		try (PrintWriter writer = resp.getWriter()) {
			writer.write(metadata);
		}
	}
}
