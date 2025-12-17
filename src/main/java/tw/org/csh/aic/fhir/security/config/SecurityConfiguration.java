package tw.org.csh.aic.fhir.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;

import java.util.*;
import java.util.stream.Collectors;

@Configuration
public class SecurityConfiguration {

	@Bean
	public SecurityFilterChain securityFilterChain(
		HttpSecurity http,
		HandlerMappingIntrospector introspector
	) throws Exception {
		return http
			.cors(Customizer.withDefaults())
			.csrf(AbstractHttpConfigurer::disable)
			.formLogin(AbstractHttpConfigurer::disable)
			.oauth2ResourceServer(oauth2 -> oauth2
				.jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter()))
			)
			.authorizeHttpRequests(auth -> auth
				.requestMatchers(
					"/fhir/.well-known/smart-configuration",
					"/fhir/metadata",
					"/actuator/**",
					"/fhir/swagger-ui"
				).permitAll()
				.requestMatchers("/fhir/DEFAULT/$partition*", "/fhir/$partition*").hasAuthority("ROLE_realm-admin")
				.requestMatchers("/fhir/{tenantId}/**").authenticated()
				.anyRequest().denyAll()
			)
			.build();
	}

	@Bean
	public CorsConfigurationSource corsConfigurationSource() {
		CorsConfiguration config = new CorsConfiguration();
		config.setAllowedMethods(List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
		config.setAllowedOrigins(List.of("*"));
		config.setAllowedHeaders(List.of("*"));
		config.setAllowCredentials(false);
		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/fhir/**", config);
		return source;
	}

	@Bean
	public JwtAuthenticationConverter jwtAuthenticationConverter() {
		JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
		converter.setJwtGrantedAuthoritiesConverter(jwt -> {
			Collection<GrantedAuthority> authorities = new ArrayList<>();

			Object scopeObj = jwt.getClaims().get("scope");
			if (scopeObj instanceof String scopeStr) {
				Arrays.stream(scopeStr.split("\\s+"))
					.filter(s -> !s.isBlank())
					.map(s -> new SimpleGrantedAuthority("SCOPE_" + s))
					.forEach(authorities::add);
			}
			Object raObj = jwt.getClaims().get("resource_access");
			if (raObj instanceof Map<?, ?> ra) {
				Object rmObj = ra.get("realm-management");
				if (rmObj instanceof Map<?, ?> rm) {
					Object rolesObj = rm.get("roles");
					if (rolesObj instanceof Collection<?> roles) {
						roles.stream()
							.filter(Objects::nonNull)
							.map(Object::toString)
							.map(r -> new SimpleGrantedAuthority("ROLE_" + r))
							.forEach(authorities::add);
					}
				}
			}
			return authorities;
		});
		return converter;
	}
}
