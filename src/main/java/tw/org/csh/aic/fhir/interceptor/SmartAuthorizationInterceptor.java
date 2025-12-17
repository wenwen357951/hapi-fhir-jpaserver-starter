package tw.org.csh.aic.fhir.interceptor;

import ca.uhn.fhir.rest.api.server.RequestDetails;
import ca.uhn.fhir.rest.server.interceptor.auth.AuthorizationInterceptor;
import ca.uhn.fhir.rest.server.interceptor.auth.IAuthRule;
import ca.uhn.fhir.rest.server.interceptor.auth.RuleBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Objects;

@Component
public class SmartAuthorizationInterceptor extends AuthorizationInterceptor {

	private static final String DEFAULT_TENANT = "DEFAULT";
	private static final String CLAIM_TENANT = "tenant_id";

	@Override
	public List<IAuthRule> buildRuleList(RequestDetails theRequestDetails) {
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

	private static String normalize(String s) {
		return (s == null || s.isBlank()) ? null : s.trim();
	}
}
