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
import com.nimbusds.jwt.proc.JWTClaimsSetVerifier;
import com.nimbusds.openid.connect.sdk.Nonce;
import ee.ria.eudi.qeaa.issuer.configuration.properties.IssuerProperties;
import ee.ria.eudi.qeaa.issuer.error.CredentialNonceException;
import ee.ria.eudi.qeaa.issuer.error.ServiceException;
import ee.ria.eudi.qeaa.issuer.model.CredentialNonce;
import ee.ria.eudi.qeaa.issuer.model.CredentialRequest;
import ee.ria.eudi.qeaa.issuer.repository.CredentialNonceRepository;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.text.ParseException;
import java.time.Clock;
import java.time.Instant;
import java.util.Set;

import static ee.ria.eudi.qeaa.issuer.error.ErrorCode.INVALID_CREDENTIAL_REQUEST;
import static ee.ria.eudi.qeaa.issuer.error.ErrorCode.INVALID_PROOF;
import static ee.ria.eudi.qeaa.issuer.error.ErrorCode.UNSUPPORTED_CREDENTIAL_FORMAT;
import static ee.ria.eudi.qeaa.issuer.error.ErrorCode.UNSUPPORTED_CREDENTIAL_TYPE;

@Component
@RequiredArgsConstructor
public class CredentialRequestValidator {
    public static final String FORMAT_MSO_MDOC = "mso_mdoc";
    public static final String DOC_TYPE_ISO_18013_MDL = "org.iso.18013.5.1.mDL";
    public static final String JOSE_TYPE_OPENID4VCI_PROOF_JWT = "openid4vci-proof+jwt";
    public static final String PROOF_TYPE_JWT = "jwt";
    private final JwsHeaderKeySelector jwsHeaderKeySelector = new JwsHeaderKeySelector(Set.of(JWSAlgorithm.RS256,
        JWSAlgorithm.RS384, JWSAlgorithm.RS512, JWSAlgorithm.ES256, JWSAlgorithm.ES384, JWSAlgorithm.ES512));
    private final IssuerProperties issuerProperties;
    private final CredentialNonceRepository credentialNonceRepository;
    @Getter
    private final Clock systemClock = Clock.systemUTC();

    public SignedJWT validate(CredentialRequest request, CredentialNonce cNonce, String proofIssuer) {
        if (request == null) {
            throw new ServiceException(INVALID_CREDENTIAL_REQUEST, "Missing credential request");
        }
        validateRequestedCredentialType(request);
        return validateJwtKeyProof(request, cNonce, proofIssuer);
    }

    private void validateRequestedCredentialType(CredentialRequest request) {
        if (!FORMAT_MSO_MDOC.equals(request.format())) {
            throw new ServiceException(UNSUPPORTED_CREDENTIAL_FORMAT, "Unsupported credential format: " + request.format());
        }
        if (!DOC_TYPE_ISO_18013_MDL.equals(request.doctype())) {
            throw new ServiceException(UNSUPPORTED_CREDENTIAL_TYPE, "Unsupported credential type: " + request.doctype());
        }
    }

    public SignedJWT validateJwtKeyProof(CredentialRequest request, CredentialNonce cNonce, String proofIssuer) {
        try {
            CredentialRequest.Proof proof = validateProof(request);
            SignedJWT jwtKeyProof = SignedJWT.parse(proof.jwt());
            ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
            jwtProcessor.setJWSKeySelector(jwsHeaderKeySelector);
            jwtProcessor.setJWSTypeVerifier(new DefaultJOSEObjectTypeVerifier<>(new JOSEObjectType(JOSE_TYPE_OPENID4VCI_PROOF_JWT)));
            jwtProcessor.setJWTClaimsSetVerifier(getJwtKeyProofClaimsVerifier(cNonce, proofIssuer));
            jwtProcessor.process(jwtKeyProof, null);
            return jwtKeyProof;
        } catch (CredentialNonceException ex) {
            throw new CredentialNonceException(generateCredentialNonce(cNonce.getAccessTokenHash()).getNonce(),
                issuerProperties.issuer().cNonceExpiryTime().toSeconds());
        } catch (ParseException | BadJOSEException | JOSEException ex) {
            throw new ServiceException(INVALID_PROOF, "Invalid Key Proof", ex);
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

    private CredentialRequest.Proof validateProof(CredentialRequest request) {
        CredentialRequest.Proof proof = request.proof();
        if (proof == null) {
            throw new ServiceException(INVALID_CREDENTIAL_REQUEST, "Missing Key Proof");
        }
        if (!PROOF_TYPE_JWT.equals(proof.proofType())) {
            throw new ServiceException(INVALID_CREDENTIAL_REQUEST, "Unsupported Key Proof type: " + proof.proofType());
        }
        return proof;
    }

    private JWTClaimsSetVerifier<SecurityContext> getJwtKeyProofClaimsVerifier(CredentialNonce cNonce, String proofIssuer) {
        IssuerProperties.Issuer issuer = issuerProperties.issuer();
        return new JwtKeyProofClaimsVerifier(proofIssuer, issuer.baseUrl(), cNonce,
            issuer.keyProofExpiryTime().toSeconds(), issuer.maxClockSkew().toSeconds(), getSystemClock());
    }
}
