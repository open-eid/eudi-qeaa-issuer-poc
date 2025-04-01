package ee.ria.eudi.qeaa.issuer.controller;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import ee.ria.eudi.qeaa.issuer.controller.CredentialRequest.CredentialResponseEncryption;
import ee.ria.eudi.qeaa.issuer.controller.resolver.DPoPAuthorizationHeader;
import ee.ria.eudi.qeaa.issuer.controller.resolver.DPoPHeader;
import ee.ria.eudi.qeaa.issuer.model.CredentialNonce;
import ee.ria.eudi.qeaa.issuer.service.CredentialService;
import ee.ria.eudi.qeaa.issuer.util.AccessTokenUtil;
import ee.ria.eudi.qeaa.issuer.util.JwtUtil;
import ee.ria.eudi.qeaa.issuer.validation.AccessTokenValidator;
import ee.ria.eudi.qeaa.issuer.validation.CredentialNonceValidator;
import ee.ria.eudi.qeaa.issuer.validation.CredentialRequestValidator;
import ee.ria.eudi.qeaa.issuer.validation.DPoPValidator;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.security.PublicKey;
import java.util.List;
import java.util.Map;

import static ee.ria.eudi.qeaa.issuer.service.CredentialFormat.MSO_MDOC;

@RestController
@RequiredArgsConstructor
public class CredentialController {
    public static final String CREDENTIAL_REQUEST_MAPPING = "/credential";
    private final AccessTokenValidator accessTokenValidator;
    private final DPoPValidator dPoPValidator;
    private final CredentialService credentialService;
    private final CredentialRequestValidator credentialRequestValidator;
    private final CredentialNonceValidator credentialNonceValidator;
    private final ObjectMapper objectMapper;

    @PostMapping(path = CREDENTIAL_REQUEST_MAPPING, consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Object> credentialRequest(
        @DPoPAuthorizationHeader SignedJWT accessToken,
        @DPoPHeader SignedJWT dPoP,
        @RequestBody(required = false) CredentialRequest credentialRequest) {

        String accessTokenHash = AccessTokenUtil.computeSHA256(accessToken.serialize());
        CredentialNonce cNonce = credentialNonceValidator.validate(accessTokenHash);
        JWTClaimsSet accessTokenClaims = accessTokenValidator.validate(accessToken);
        dPoPValidator.validate(dPoP, accessTokenHash, accessTokenClaims);
        List<PublicKey> bindingKeys = credentialRequestValidator.validate(credentialRequest, accessTokenClaims, cNonce);
        CredentialResponse credentialResponse = credentialService.createMobileDrivingLicence(MSO_MDOC, accessTokenClaims.getSubject(), accessTokenHash, bindingKeys);

        return getResponseEntity(credentialRequest, credentialResponse);
    }

    private ResponseEntity<Object> getResponseEntity(CredentialRequest credentialRequest, CredentialResponse credentialResponse) {
        CredentialResponseEncryption responseEncryption = credentialRequest.credentialResponseEncryption();
        HttpHeaders httpHeaders = new HttpHeaders();
        if (responseEncryption != null) {
            String encryptedCredentialResponse = getEncryptedCredentialResponse(credentialResponse, responseEncryption);
            httpHeaders.setContentType(new MediaType("application", "jwt"));
            return new ResponseEntity<>(encryptedCredentialResponse, httpHeaders, HttpStatus.OK);
        } else {
            httpHeaders.setContentType(MediaType.APPLICATION_JSON);
            return new ResponseEntity<>(credentialResponse, httpHeaders, HttpStatus.OK);
        }
    }

    @SneakyThrows
    private String getEncryptedCredentialResponse(CredentialResponse credentialResponse, CredentialResponseEncryption responseEncryption) {
        Map<String, Object> claims = objectMapper.convertValue(credentialResponse, new TypeReference<>() {
        });
        return JwtUtil.getEncryptedJWT(objectMapper.writeValueAsString(responseEncryption.jwk()),
            responseEncryption.alg(), responseEncryption.enc(), claims);
    }
}
