package tw.org.csh.aic.fhir.config;

import ca.uhn.fhir.rest.server.RestfulServer;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.context.annotation.Configuration;
import tw.org.csh.aic.fhir.interceptor.SmartAuthorizationInterceptor;

@Configuration
public class FhirInterceptorAutoRegister implements BeanPostProcessor {
	private final SmartAuthorizationInterceptor smartAuthorizationInterceptor;

	@Autowired
	public FhirInterceptorAutoRegister(SmartAuthorizationInterceptor smartAuthorizationInterceptor) {
		this.smartAuthorizationInterceptor = smartAuthorizationInterceptor;
	}

	@Nullable
	@Override
	public Object postProcessAfterInitialization(@NonNull Object bean, @NonNull String beanName) throws BeansException {
		if (bean instanceof RestfulServer server) {
			server.registerInterceptor(smartAuthorizationInterceptor);
		}
		return bean;
	}
}
