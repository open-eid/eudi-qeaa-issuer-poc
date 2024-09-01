package ee.ria.eudi.qeaa.issuer.validation;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.jwt.proc.JWTClaimsSetVerifier;
import com.nimbusds.openid.connect.sdk.Nonce;
import ee.ria.eudi.qeaa.issuer.configuration.properties.IssuerProperties.Issuer;
import ee.ria.eudi.qeaa.issuer.configuration.properties.IssuerProperties.Issuer.CredentialEncryption;
import ee.ria.eudi.qeaa.issuer.controller.CredentialRequest;
import ee.ria.eudi.qeaa.issuer.controller.CredentialRequest.CredentialResponseEncryption;
import ee.ria.eudi.qeaa.issuer.controller.CredentialRequest.Proof;
import ee.ria.eudi.qeaa.issuer.error.CredentialNonceException;
import ee.ria.eudi.qeaa.issuer.error.ServiceException;
import ee.ria.eudi.qeaa.issuer.model.CredentialNonce;
import ee.ria.eudi.qeaa.issuer.repository.CredentialNonceRepository;
import ee.ria.eudi.qeaa.issuer.util.JwtUtil;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import org.springframework.stereotype.Component;

import java.security.PublicKey;
import java.text.ParseException;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static ee.ria.eudi.qeaa.issuer.error.ErrorCode.INVALID_CREDENTIAL_REQUEST;
import static ee.ria.eudi.qeaa.issuer.error.ErrorCode.INVALID_ENCRYPTION_PARAMETERS;
import static ee.ria.eudi.qeaa.issuer.error.ErrorCode.INVALID_PROOF;
import static ee.ria.eudi.qeaa.issuer.error.ErrorCode.UNSUPPORTED_CREDENTIAL_FORMAT;
import static ee.ria.eudi.qeaa.issuer.error.ErrorCode.UNSUPPORTED_CREDENTIAL_TYPE;
import static ee.ria.eudi.qeaa.issuer.service.CredentialFormat.MSO_MDOC;
import static ee.ria.eudi.qeaa.issuer.service.MetadataService.CREDENTIAL_IDENTIFIER_ORG_ISO_18013_5_1_MDL;
import static ee.ria.eudi.qeaa.issuer.service.MetadataService.DOCTYPE_ORG_ISO_18013_5_1_MDL;

@Component
@RequiredArgsConstructor
public class CredentialRequestValidator {
    public static final JOSEObjectType JOSE_TYPE_OPENID4VCI_PROOF_JWT = new JOSEObjectType("openid4vci-proof+jwt");
    public static final String PROOF_TYPE_JWT = "jwt";
    private final JwsHeaderKeySelector jwsHeaderKeySelector = new JwsHeaderKeySelector(Set.of(
        JWSAlgorithm.RS256,
        JWSAlgorithm.RS384,
        JWSAlgorithm.RS512,
        JWSAlgorithm.ES256,
        JWSAlgorithm.ES384,
        JWSAlgorithm.ES512,
        JWSAlgorithm.PS256,
        JWSAlgorithm.PS384,
        JWSAlgorithm.PS512
    ));
    private final Issuer issuerProperties;
    private final CredentialEncryption encryptionProperties;
    private final CredentialNonceRepository credentialNonceRepository;
    @Getter
    private final Clock systemClock = Clock.systemUTC();

    @SneakyThrows
    public List<PublicKey> validate(CredentialRequest request, JWTClaimsSet accessTokenClaims, CredentialNonce cNonce) {
        if (request == null) {
            throw new ServiceException(INVALID_CREDENTIAL_REQUEST, "Missing credential request");
        }
        List<Object> authorizationDetails = accessTokenClaims.getListClaim("authorization_details");
        String proofIssuerId = accessTokenClaims.getStringClaim("client_id");
        validateRequestedCredentialType(request, authorizationDetails);
        validateEncryptionRequirement(request);
        return validateJwtKeyProofs(request, cNonce, proofIssuerId);
    }

    private void validateRequestedCredentialType(CredentialRequest request, List<Object> authorizationDetails) {
        if (request.credentialIdentifier() != null && !request.credentialIdentifier().isBlank()) {
            if (request.format() != null || request.doctype() != null) {
                throw new ServiceException(UNSUPPORTED_CREDENTIAL_FORMAT,
                    "When credential_identifier is provided, format and doctype must be null");
            }
            if (!CREDENTIAL_IDENTIFIER_ORG_ISO_18013_5_1_MDL.equals(request.credentialIdentifier())) {
                throw new ServiceException(UNSUPPORTED_CREDENTIAL_FORMAT,
                    "Unsupported credential configuration: " + request.credentialIdentifier());
            }
            authorizationDetails
                .stream()
                .map(o -> (Map<?, ?>) o)
                .filter(ad -> CREDENTIAL_IDENTIFIER_ORG_ISO_18013_5_1_MDL.equals(ad.get("credential_configuration_id")))
                .findFirst()
                .orElseThrow(() -> new ServiceException(UNSUPPORTED_CREDENTIAL_FORMAT, "Credential configuration not authorized"));
            return;
        }
        String format = request.format();
        if (format == null || format.isBlank()) {
            throw new ServiceException(UNSUPPORTED_CREDENTIAL_FORMAT, "Missing credential format");
        }
        if (!MSO_MDOC.getValue().equals(format)) {
            throw new ServiceException(UNSUPPORTED_CREDENTIAL_FORMAT, "Unsupported credential format: " + request.format());
        }
        if (!DOCTYPE_ORG_ISO_18013_5_1_MDL.equals(request.doctype())) {
            throw new ServiceException(UNSUPPORTED_CREDENTIAL_TYPE, "Unsupported credential doctype: " + request.doctype());
        }
        authorizationDetails
            .stream()
            .map(o -> (Map<?, ?>) o)
            .filter(ad -> MSO_MDOC.getValue().equals(ad.get("format")))
            .findFirst().orElseThrow(() -> new ServiceException(UNSUPPORTED_CREDENTIAL_FORMAT, "Credential format not authorized"));
    }

    private void validateEncryptionRequirement(CredentialRequest request) {
        CredentialResponseEncryption responseEncryption = request.credentialResponseEncryption();
        if (encryptionProperties.required()) {
            if (responseEncryption == null) {
                throw new ServiceException(INVALID_ENCRYPTION_PARAMETERS, "Missing credential response encryption request parameter");
            }
            if (responseEncryption.jwk() == null || responseEncryption.jwk().isBlank()) {
                throw new ServiceException(INVALID_ENCRYPTION_PARAMETERS, "Invalid credential response encryption key");
            }
            if (!encryptionProperties.supportedAlgorithms().contains(responseEncryption.alg())) {
                throw new ServiceException(INVALID_ENCRYPTION_PARAMETERS, "Unsupported response encryption algorithm: " + responseEncryption.alg());
            }
            if (!encryptionProperties.supportedEncodings().contains(responseEncryption.enc())) {
                throw new ServiceException(INVALID_ENCRYPTION_PARAMETERS, "Unsupported response encryption encoding: " + responseEncryption.enc());
            }
        }
    }

    private List<PublicKey> validateJwtKeyProofs(CredentialRequest request, CredentialNonce cNonce, String proofIssuerId) {
        if (request.proof() != null) {
            return List.of(validateJwtKeyProof(request.proof(), cNonce, proofIssuerId));
        } else if (request.proofs() != null && !request.proofs().isEmpty()) {
            return request.proofs().stream()
                .map(proof -> validateJwtKeyProof(proof, cNonce, proofIssuerId))
                .toList();
        } else {
            throw new ServiceException(INVALID_CREDENTIAL_REQUEST, "Missing key proof");
        }
    }

    public PublicKey validateJwtKeyProof(Proof proof, CredentialNonce cNonce, String proofIssuer) {
        try {
            if (!PROOF_TYPE_JWT.equals(proof.proofType())) {
                throw new ServiceException(INVALID_CREDENTIAL_REQUEST, "Unsupported key proof type: " + proof.proofType());
            }
            SignedJWT jwtKeyProof = SignedJWT.parse(proof.jwt());
            ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
            jwtProcessor.setJWSKeySelector(jwsHeaderKeySelector);
            jwtProcessor.setJWSTypeVerifier(new DefaultJOSEObjectTypeVerifier<>(JOSE_TYPE_OPENID4VCI_PROOF_JWT));
            jwtProcessor.setJWTClaimsSetVerifier(getJwtKeyProofClaimsVerifier(cNonce, proofIssuer));
            jwtProcessor.process(jwtKeyProof, null);
            return JwtUtil.toPublicKey(jwtKeyProof.getHeader().getJWK());
        } catch (CredentialNonceException ex) {
            throw new CredentialNonceException(generateCredentialNonce(cNonce.getAccessTokenHash()).getNonce(),
                issuerProperties.cNonceExpiryTime().toSeconds());
        } catch (ParseException | BadJOSEException | JOSEException ex) {
            throw new ServiceException(INVALID_PROOF, "Invalid key proof", ex);
        }
    }

    private CredentialNonce generateCredentialNonce(String accessTokenHash) {
        Nonce nonce = new Nonce();
        return credentialNonceRepository.save(CredentialNonce.builder()
            .nonce(nonce.getValue())
            .issuedAt(Instant.now())
            .accessTokenHash(accessTokenHash)
            .build());
    }

    private JWTClaimsSetVerifier<SecurityContext> getJwtKeyProofClaimsVerifier(CredentialNonce cNonce, String proofIssuer) {
        return new JwtKeyProofClaimsVerifier(proofIssuer, issuerProperties.baseUrl(), cNonce,
            issuerProperties.keyProofExpiryTime().toSeconds(), issuerProperties.maxClockSkew().toSeconds(), getSystemClock());
    }
}
