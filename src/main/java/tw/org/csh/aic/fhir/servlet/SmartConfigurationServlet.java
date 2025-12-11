package tw.org.csh.aic.fhir.servlet;

import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.PrintWriter;

@Component
@WebServlet(
	name = "SmartConfigurationServlet",
	urlPatterns = {"/fhir/.well-known/smart-configuration"}
)
public class SmartConfigurationServlet extends HttpServlet {

	@Value("${smart.oauth.issuer}")
	public String issuer;
	@Value("${smart.oauth.token_endpoint}")
	public String tokenEndpoint;
	@Value("${smart.oauth.authorization_endpoint}")
	public String authorizationEndpoint;

	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		resp.setStatus(HttpServletResponse.SC_OK);
		resp.setContentType("application/json;charset=UTF-8");
		String metadata = """
			{
			  "issuer": "%s",
			  "token_endpoint": "%s",
			  "authorization_endpoint": "%s",
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
			""".formatted(
			this.issuer,
			this.tokenEndpoint,
			this.authorizationEndpoint
		);
		try (PrintWriter writer = resp.getWriter()) {
			writer.write(metadata);
		}
	}
}
