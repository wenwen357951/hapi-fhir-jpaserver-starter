package tw.org.csh.aic.fhir.servlet;

import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.jena.atlas.json.JsonBuilder;
import org.apache.jena.atlas.json.JsonValue;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.PrintWriter;

@Component
@WebServlet(
	name = "SmartConfigurationServlet",
	urlPatterns = {"/fhir/.well-known/smart-configuration"}
)
public final class SmartConfigurationServlet extends HttpServlet {

	@Value("${smart.oauth.issuer}")
	public String issuer;
	@Value("${smart.oauth.jwks-uri}")
	public String jwksUri;
	@Value("${smart.oauth.token-endpoint}")
	public String tokenEndpoint;
	@Value("${smart.oauth.authorization-endpoint}")
	public String authorizationEndpoint;
	@Value("${smart.oauth.introspection-endpoint}")
	public String introspectionEndpoint;

	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		resp.setStatus(HttpServletResponse.SC_OK);
		resp.setContentType("application/json;charset=UTF-8");
		JsonValue jsonValue = JsonBuilder.create()
			.startObject()
			.pair("issuer", this.issuer)                                      // CONDITIONAL
			.pair("jwks_uri", this.jwksUri)
			/* --- Endpoint --- */
			.pair("token_endpoint", this.tokenEndpoint)                       // REQUIRED
			.pair("authorization_endpoint", this.authorizationEndpoint)       // CONDITIONAL
			.pair("introspection_endpoint", this.introspectionEndpoint)       // RECOMMENDED
//			.pair("management_endpoint", "")												// RECOMMENDED
//			.pair("revocation_endpoint", "")												// RECOMMENDED
			/* --- Grant Type --- */
			.key("grant_types_supported").startArray()                        // REQUIRED
			.value("authorization_code")
			.value("client_credentials")
			.finishArray()
			/* --- Scopes --- */
			.key("scopes_supported").startArray()                             // RECOMMENDED
			.value("openid")
			.value("launch")
			.value("profile")
			.finishArray()
			/* --- Capabilities --- */
			.key("capabilities").startArray()                                 // REQUIRED
			.value("launch-ehr")
			.value("client-public")
			.value("client-confidential-asymmetric")
			.value("sso-openid-connect")
			.finishArray()
			/* --- Code Challenge Methods --- */
			.key("code_challenge_methods_supported").startArray()             // REQUIRED
			.value("S256")
			.finishArray()
			.finishObject()
			.build();

		try (PrintWriter writer = resp.getWriter()) {
			writer.write(jsonValue.toString());
		}
	}
}
