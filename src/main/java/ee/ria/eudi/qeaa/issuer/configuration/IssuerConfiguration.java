package ee.ria.eudi.qeaa.issuer.configuration;

import com.nimbusds.oauth2.sdk.dpop.verifiers.DefaultDPoPSingleUseChecker;
import ee.ria.eudi.qeaa.issuer.configuration.properties.IssuerProperties;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationPropertiesScan
public class IssuerConfiguration {

    @Bean
    public DefaultDPoPSingleUseChecker dPoPSingleUseChecker(IssuerProperties.Issuer issuer) {
        long ttl = issuer.dPoPExpiryTime().toSeconds() + issuer.maxClockSkew().toSeconds();
        return new DefaultDPoPSingleUseChecker(ttl, ttl); // TODO: Implement db backed version
    }
}
