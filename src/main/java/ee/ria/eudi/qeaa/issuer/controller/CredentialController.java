package ee.ria.eudi.qeaa.issuer.controller;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.openid.connect.sdk.Nonce;
import ee.ria.eudi.qeaa.issuer.configuration.properties.IssuerProperties;
import ee.ria.eudi.qeaa.issuer.controller.resolver.DPoPAuthorizationHeader;
import ee.ria.eudi.qeaa.issuer.controller.resolver.DPoPHeader;
import ee.ria.eudi.qeaa.issuer.model.CredentialNonce;
import ee.ria.eudi.qeaa.issuer.model.CredentialRequest;
import ee.ria.eudi.qeaa.issuer.model.CredentialResponse;
import ee.ria.eudi.qeaa.issuer.repository.CredentialNonceRepository;
import ee.ria.eudi.qeaa.issuer.util.AccessTokenUtil;
import ee.ria.eudi.qeaa.issuer.validation.AccessTokenValidator;
import ee.ria.eudi.qeaa.issuer.validation.CredentialNonceValidator;
import ee.ria.eudi.qeaa.issuer.validation.CredentialRequestValidator;
import ee.ria.eudi.qeaa.issuer.validation.DPoPValidator;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.text.ParseException;
import java.time.Instant;

@RestController
@RequiredArgsConstructor
public class CredentialController {
    public static final String CREDENTIAL_REQUEST_MAPPING = "/credential";
    private final AccessTokenValidator accessTokenValidator;
    private final DPoPValidator dPoPValidator;
    private final CredentialRequestValidator credentialRequestValidator;
    private final CredentialNonceValidator credentialNonceValidator;
    private final CredentialNonceRepository credentialNonceRepository;
    private final IssuerProperties issuerProperties;

    @PostMapping(path = CREDENTIAL_REQUEST_MAPPING, consumes = MediaType.APPLICATION_JSON_VALUE)
    public CredentialResponse credentialRequest(
        @DPoPAuthorizationHeader SignedJWT accessToken,
        @DPoPHeader SignedJWT dPoP,
        @RequestBody(required = false) CredentialRequest credentialRequest) throws ParseException {

        String accessTokenHash = AccessTokenUtil.computeSHA256(accessToken.serialize());
        CredentialNonce cNonce = credentialNonceValidator.validate(accessTokenHash);
        JWTClaimsSet accessTokenClaims = accessTokenValidator.validate(accessToken);
        String clientId = accessTokenClaims.getStringClaim("client_id");
        SignedJWT keyProof = credentialRequestValidator.validate(credentialRequest, cNonce, clientId);
        String keyThumbprint = (String) accessTokenClaims.getJSONObjectClaim("cnf").get("jkt");
        dPoPValidator.validate(dPoP, clientId, keyThumbprint, accessTokenHash);

        JWK bindingKey = keyProof.getHeader().getJWK();
        String subject = accessTokenClaims.getSubject();

        return CredentialResponse.builder()
            .format("mso_mdoc")
            .cNonce(getCredentialNonce(accessTokenHash).getNonce())
            .cNonceExpiresIn(issuerProperties.issuer().cNonceExpiryTime().toSeconds())
            .build();
    }

    private CredentialNonce getCredentialNonce(String accessTokenHash) {
        return credentialNonceRepository.save(CredentialNonce.builder()
            .nonce(new Nonce().getValue())
            .issuedAt(Instant.now())
            .accessTokenHash(accessTokenHash)
            .build());
    }
}
