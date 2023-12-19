package ee.ria.eudi.qeaa.issuer.configuration;

import ee.ria.eudi.qeaa.issuer.controller.resolver.DPoPAuthorizationHeaderArgumentResolver;
import ee.ria.eudi.qeaa.issuer.controller.resolver.DPoPHeaderArgumentResolver;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.util.List;

@Configuration
public class WebConfig implements WebMvcConfigurer {

    @Override
    public void addArgumentResolvers(List<HandlerMethodArgumentResolver> argumentResolvers) {
        argumentResolvers.add(new DPoPAuthorizationHeaderArgumentResolver());
        argumentResolvers.add(new DPoPHeaderArgumentResolver());
    }
}
