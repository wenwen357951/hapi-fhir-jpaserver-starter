package tw.org.csh.aic.fhir.interceptor;

import ca.uhn.fhir.rest.api.server.RequestDetails;
import ca.uhn.fhir.rest.server.interceptor.auth.AuthorizationInterceptor;
import ca.uhn.fhir.rest.server.interceptor.auth.IAuthRule;
import ca.uhn.fhir.rest.server.interceptor.auth.RuleBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.PathMatcher;

import java.util.List;
import java.util.Objects;

@Component
public class SmartAuthorizationInterceptor extends AuthorizationInterceptor {

	private static final String DEFAULT_TENANT = "DEFAULT";
	private static final String CLAIM_TENANT = "tenant_id";
	private static final PathMatcher PATH_MATCHER = new AntPathMatcher();
	private static final String[] EXCLUDED_PATHS = {
		"/fhir/.well-known/smart-configuration",
		"/fhir/metadata",
		"/fhir/api-docs",
		"/actuator/**",
		"/fhir/swagger-ui/",
		"/fhir/swagger-ui/**"
	};

	@Override
	public List<IAuthRule> buildRuleList(RequestDetails theRequestDetails) {
		String path = extractPath(theRequestDetails);
		if (isExcluded(path)) {
			return new RuleBuilder().allowAll().build();
		}

		String targetTenant = normalize(theRequestDetails.getTenantId());
		if (targetTenant == null) targetTenant = DEFAULT_TENANT;

		Authentication auth = SecurityContextHolder.getContext().getAuthentication();
		if (!(auth instanceof JwtAuthenticationToken jwtAuth)) {
			return new RuleBuilder().denyAll("Authentication is not JWT-based").build();
		}

		String tokenTenant = normalize(jwtAuth.getToken().getClaimAsString(CLAIM_TENANT));
		if (tokenTenant == null) tokenTenant = DEFAULT_TENANT;

		if (!Objects.equals(tokenTenant, targetTenant)) {
			return new RuleBuilder().denyAll("Tenant mismatch between token and request").build();
		}

		return new RuleBuilder().allowAll().build();
	}

	private static boolean isExcluded(String path) {
		if (path == null) return false;
		for (String pattern : EXCLUDED_PATHS) {
			if (PATH_MATCHER.match(pattern, path)) return true;
		}
		return false;
	}

	private static String extractPath(RequestDetails request) {
		String complete = request.getCompleteUrl();
		if (complete == null || complete.isBlank()) return null;

		// cut off query string
		int q = complete.indexOf('?');
		String noQuery = (q >= 0) ? complete.substring(0, q) : complete;

		// if it's absolute URL, strip scheme/host
		int scheme = noQuery.indexOf("://");
		if (scheme >= 0) {
			int firstSlash = noQuery.indexOf('/', scheme + 3);
			return (firstSlash >= 0) ? noQuery.substring(firstSlash) : "/";
		}

		return noQuery.startsWith("/") ? noQuery : "/" + noQuery;
	}

	private static String normalize(String s) {
		return (s == null || s.isBlank()) ? null : s.trim();
	}
}
