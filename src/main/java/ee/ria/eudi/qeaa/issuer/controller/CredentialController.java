package ee.ria.eudi.qeaa.issuer.controller;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.openid.connect.sdk.Nonce;
import ee.ria.eudi.qeaa.issuer.configuration.properties.IssuerProperties;
import ee.ria.eudi.qeaa.issuer.controller.CredentialRequest.CredentialResponseEncryption;
import ee.ria.eudi.qeaa.issuer.controller.CredentialResponse.CredentialResponseBuilder;
import ee.ria.eudi.qeaa.issuer.controller.resolver.DPoPAuthorizationHeader;
import ee.ria.eudi.qeaa.issuer.controller.resolver.DPoPHeader;
import ee.ria.eudi.qeaa.issuer.error.ServiceException;
import ee.ria.eudi.qeaa.issuer.model.CredentialNonce;
import ee.ria.eudi.qeaa.issuer.model.Subject;
import ee.ria.eudi.qeaa.issuer.repository.CredentialNonceRepository;
import ee.ria.eudi.qeaa.issuer.repository.SubjectRepository;
import ee.ria.eudi.qeaa.issuer.service.CredentialService;
import ee.ria.eudi.qeaa.issuer.service.MobileDrivingLicence;
import ee.ria.eudi.qeaa.issuer.util.AccessTokenUtil;
import ee.ria.eudi.qeaa.issuer.util.JwtUtil;
import ee.ria.eudi.qeaa.issuer.validation.AccessTokenValidator;
import ee.ria.eudi.qeaa.issuer.validation.CredentialNonceValidator;
import ee.ria.eudi.qeaa.issuer.validation.CredentialRequestValidator;
import ee.ria.eudi.qeaa.issuer.validation.DPoPValidator;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import org.modelmapper.ModelMapper;
import org.modelmapper.TypeMap;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.security.PublicKey;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import static ee.ria.eudi.qeaa.issuer.service.CredentialFormat.MSO_MDOC;

@RestController
@RequiredArgsConstructor
public class CredentialController {
    public static final String CREDENTIAL_REQUEST_MAPPING = "/credential";
    private final AccessTokenValidator accessTokenValidator;
    private final DPoPValidator dPoPValidator;
    private final CredentialRequestValidator credentialRequestValidator;
    private final CredentialNonceValidator credentialNonceValidator;
    private final CredentialNonceRepository credentialNonceRepository;
    private final CredentialService credentialService;
    private final SubjectRepository subjectRepository;
    private final IssuerProperties.Issuer issuerProperties;
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
        CredentialResponse credentialResponse = getCredentialResponse(accessTokenHash, accessTokenClaims, bindingKeys);

        return getResponseEntity(credentialRequest, credentialResponse);
    }

    private CredentialResponse getCredentialResponse(String accessTokenHash, JWTClaimsSet accessTokenClaims, List<PublicKey> bindingKeys) {
        Subject subject = subjectRepository.findByAdministrativeNumber(accessTokenClaims.getSubject()).orElseThrow(() -> new ServiceException("Subject not found"));
        TypeMap<Subject, MobileDrivingLicence> subjectToMobileDrivingLicenseMapper = new ModelMapper().createTypeMap(Subject.class, MobileDrivingLicence.class);
        CredentialNonce cNonce = getCredentialNonce(accessTokenHash);
        List<String> credentials = bindingKeys.stream()
            .map(bindingKey -> credentialService.getMobileDrivingLicence(MSO_MDOC, subject, subjectToMobileDrivingLicenseMapper, bindingKey))
            .toList();
        CredentialResponseBuilder builder = CredentialResponse
            .builder()
            .cNonce(cNonce.getNonce())
            .cNonceExpiresIn(issuerProperties.cNonceExpiryTime().toSeconds());
        return credentials.size() == 1 ? builder.credential(credentials.getFirst()).build() : builder.credentials(credentials).build();
    }

    private CredentialNonce getCredentialNonce(String accessTokenHash) {
        return credentialNonceRepository.save(CredentialNonce.builder()
            .nonce(new Nonce().getValue())
            .issuedAt(Instant.now())
            .accessTokenHash(accessTokenHash)
            .build());
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
