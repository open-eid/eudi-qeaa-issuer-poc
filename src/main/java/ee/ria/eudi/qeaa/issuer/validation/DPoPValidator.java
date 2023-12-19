package ee.ria.eudi.qeaa.issuer.validation;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.oauth2.sdk.dpop.verifiers.DPoPIssuer;
import com.nimbusds.oauth2.sdk.dpop.verifiers.DefaultDPoPSingleUseChecker;
import ee.ria.eudi.qeaa.issuer.configuration.properties.IssuerProperties;
import ee.ria.eudi.qeaa.issuer.error.ServiceException;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.util.Set;

import static ee.ria.eudi.qeaa.issuer.controller.CredentialController.CREDENTIAL_REQUEST_MAPPING;
import static ee.ria.eudi.qeaa.issuer.error.ErrorCode.INVALID_DPOP_PROOF;

@Component
@RequiredArgsConstructor
public class DPoPValidator {
    public static final String JOSE_TYPE_DPOP_JWT = "dpop+jwt";
    private final JwsHeaderKeySelector jwsHeaderKeySelector = new JwsHeaderKeySelector(Set.of(JWSAlgorithm.RS256,
        JWSAlgorithm.RS384, JWSAlgorithm.RS512, JWSAlgorithm.ES256, JWSAlgorithm.ES384, JWSAlgorithm.ES512));
    private final IssuerProperties issuerProperties;
    private final DefaultDPoPSingleUseChecker dPoPSingleUseChecker;
    @Getter
    private final Clock systemClock = Clock.systemUTC();

    public void validate(SignedJWT dPoPProof, String clientId, String expectedKeyThumbprint, String expectedAccessTokenHash) {
        try {
            ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
            jwtProcessor.setJWSKeySelector(jwsHeaderKeySelector);
            jwtProcessor.setJWSTypeVerifier(new DefaultJOSEObjectTypeVerifier<>(new JOSEObjectType(JOSE_TYPE_DPOP_JWT)));
            jwtProcessor.setJWTClaimsSetVerifier(getClaimsVerifier(clientId, expectedAccessTokenHash));
            jwtProcessor.process(dPoPProof, null);
            validateKeyProof(dPoPProof, expectedKeyThumbprint);
        } catch (BadJOSEException | JOSEException ex) {
            throw new ServiceException(INVALID_DPOP_PROOF, "Invalid DPoP", ex);
        }
    }

    private DPoPClaimsVerifier getClaimsVerifier(String clientId, String expectedAccessTokenHash) {
        IssuerProperties.Issuer issuer = issuerProperties.issuer();
        return new DPoPClaimsVerifier(issuer.baseUrl() + CREDENTIAL_REQUEST_MAPPING,
            HttpMethod.POST.name(),
            expectedAccessTokenHash,
            issuer.dPoPExpiryTime().toSeconds(),
            issuer.maxClockSkew().toSeconds(),
            new DPoPIssuer(clientId),
            dPoPSingleUseChecker,
            getSystemClock());
    }

    private void validateKeyProof(SignedJWT dPoPProof, String expectedKeyThumbprint) {
        try {
            String keyThumbprint = dPoPProof.getHeader().getJWK().computeThumbprint().toString();
            if (!expectedKeyThumbprint.equals(keyThumbprint)) {
                throw new ServiceException(INVALID_DPOP_PROOF, "Invalid DPoP key binding");
            }
        } catch (JOSEException e) {
            throw new ServiceException(e);
        }
    }
}
