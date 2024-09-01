package ee.ria.eudi.qeaa.issuer.validation;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.oauth2.sdk.dpop.verifiers.DPoPIssuer;
import com.nimbusds.oauth2.sdk.id.JWTID;
import com.nimbusds.oauth2.sdk.util.singleuse.SingleUseChecker;
import ee.ria.eudi.qeaa.issuer.configuration.properties.IssuerProperties;
import ee.ria.eudi.qeaa.issuer.error.ServiceException;
import ee.ria.eudi.qeaa.issuer.service.AuthorizationServerMetadataService;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Component;

import java.text.ParseException;
import java.time.Clock;
import java.util.Map;
import java.util.Set;

import static ee.ria.eudi.qeaa.issuer.controller.CredentialController.CREDENTIAL_REQUEST_MAPPING;
import static ee.ria.eudi.qeaa.issuer.error.ErrorCode.INVALID_DPOP_PROOF;

@Component
@RequiredArgsConstructor
public class DPoPValidator {
    public static final JOSEObjectType JOSE_TYPE_DPOP_JWT = new JOSEObjectType("dpop+jwt");
    private final IssuerProperties issuerProperties;
    private final SingleUseChecker<Map.Entry<DPoPIssuer, JWTID>> dPoPSingleUseChecker;
    private final AuthorizationServerMetadataService asMetadataService;
    @Getter
    private final Clock systemClock = Clock.systemUTC();

    public void validate(SignedJWT dPoPProof, String expectedAccessTokenHash, JWTClaimsSet accessTokenClaims) {
        try {
            String clientId = accessTokenClaims.getStringClaim("client_id");
            String expectedKeyThumbprint = (String) accessTokenClaims.getJSONObjectClaim("cnf").get("jkt");
            JwsHeaderKeySelector jwsHeaderKeySelector = new JwsHeaderKeySelector(Set.copyOf(asMetadataService.getMetadata().getDPoPJWSAlgs()));
            ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
            jwtProcessor.setJWSKeySelector(jwsHeaderKeySelector);
            jwtProcessor.setJWSTypeVerifier(new DefaultJOSEObjectTypeVerifier<>(JOSE_TYPE_DPOP_JWT));
            jwtProcessor.setJWTClaimsSetVerifier(getClaimsVerifier(clientId, expectedAccessTokenHash));
            jwtProcessor.process(dPoPProof, null);
            validateKeyProof(dPoPProof, expectedKeyThumbprint);
        } catch (BadJOSEException | JOSEException | ParseException ex) {
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
