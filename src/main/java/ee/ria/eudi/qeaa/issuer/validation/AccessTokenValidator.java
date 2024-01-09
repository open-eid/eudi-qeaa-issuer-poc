package ee.ria.eudi.qeaa.issuer.validation;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import ee.ria.eudi.qeaa.issuer.configuration.properties.IssuerProperties;
import ee.ria.eudi.qeaa.issuer.error.ServiceException;
import ee.ria.eudi.qeaa.issuer.service.AuthorizationServerMetadataService;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.text.ParseException;
import java.time.Clock;

import static ee.ria.eudi.qeaa.issuer.error.ErrorCode.INVALID_TOKEN;

@Component
@RequiredArgsConstructor
public class AccessTokenValidator {
    private final IssuerProperties issuerProperties;
    private final AuthorizationServerMetadataService asMetadataService;
    @Getter
    private final Clock systemClock = Clock.systemUTC();

    public JWTClaimsSet validate(SignedJWT accessToken) {
        try {
            JWKSet jwkSet = asMetadataService.getJWKSet();
            JWSAlgorithm jwsAlgorithm = accessToken.getHeader().getAlgorithm();
            ImmutableJWKSet<SecurityContext> immutableJWKSet = new ImmutableJWKSet<>(jwkSet);
            JWSKeySelector<SecurityContext> jwsKeySelector = new JWSVerificationKeySelector<>(jwsAlgorithm, immutableJWKSet);
            ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
            jwtProcessor.setJWSKeySelector(jwsKeySelector);
            jwtProcessor.setJWTClaimsSetVerifier(getClaimsVerifier());
            jwtProcessor.process(accessToken, null);
            return accessToken.getJWTClaimsSet();
        } catch (ParseException | BadJOSEException | JOSEException ex) {
            throw new ServiceException(INVALID_TOKEN, "Invalid access token", ex);
        }
    }

    private AccessTokenClaimsVerifier getClaimsVerifier() {
        return new AccessTokenClaimsVerifier(
            asMetadataService.getMetadata().getIssuer().getValue(),
            issuerProperties.issuer().baseUrl(),
            issuerProperties.issuer().maxClockSkew().toSeconds(),
            getSystemClock());
    }
}
