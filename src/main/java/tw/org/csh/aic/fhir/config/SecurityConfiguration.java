package tw.org.csh.aic.fhir.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@Configuration
public class SecurityConfiguration {

	@Bean
	public SecurityFilterChain securityFilterChain(
		HttpSecurity http,
		ClientRegistrationRepository clientRegistrationRepository
	) throws Exception {
		LogoutSuccessHandler oidcLogoutSuccessHandler =
			this.oidcLogoutSuccessHandler(clientRegistrationRepository);
		return http
			.cors(Customizer.withDefaults())
			.csrf(AbstractHttpConfigurer::disable)
			.formLogin(AbstractHttpConfigurer::disable)
			.sessionManagement(session -> session.sessionCreationPolicy(
				SessionCreationPolicy.IF_REQUIRED
			))
			.oauth2Login(Customizer.withDefaults())
			.logout(logout -> logout
				.logoutUrl("/logout")
				.logoutSuccessHandler(oidcLogoutSuccessHandler)
			)
			.oauth2ResourceServer(oauth2 -> oauth2
				.jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter()))
			)
			.authorizeHttpRequests(auth -> auth
				.requestMatchers("/fhir/.well-known/smart-configuration").permitAll()
				.requestMatchers("/fhir/metadata").permitAll()
				.requestMatchers("/actuator/**").permitAll()
				.requestMatchers("/fhir/**").authenticated()
				.anyRequest().denyAll()
			)
			.build();
	}

	private LogoutSuccessHandler oidcLogoutSuccessHandler(ClientRegistrationRepository clientRegistrationRepository) {
		OidcClientInitiatedLogoutSuccessHandler successHandler =
			new OidcClientInitiatedLogoutSuccessHandler(clientRegistrationRepository);
		successHandler.setPostLogoutRedirectUri("{baseUrl}");
		return successHandler;
	}

	@Bean
	public CorsConfigurationSource corsConfigurationSource() {
		CorsConfiguration config = new CorsConfiguration();
		config.setAllowedOrigins(List.of(
			"https://wenwen357951.github.io"
		));
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
			Object scopeObj = jwt.getClaims().get("scope");
			if (scopeObj == null) {
				return List.of();
			}

			String scope = scopeObj.toString();
			return Arrays.stream(scope.split(" "))
				.map(s -> new SimpleGrantedAuthority("SCOPE_" + s))
				.collect(Collectors.toSet());
		});

		return converter;
	}
}
