package ee.ria.eudi.qeaa.issuer.validation;

import com.nimbusds.openid.connect.sdk.Nonce;
import ee.ria.eudi.qeaa.issuer.configuration.properties.IssuerProperties;
import ee.ria.eudi.qeaa.issuer.error.CredentialNonceException;
import ee.ria.eudi.qeaa.issuer.model.CredentialNonce;
import ee.ria.eudi.qeaa.issuer.repository.CredentialNonceRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.time.Instant;

@Component
@RequiredArgsConstructor
public class CredentialNonceValidator {
    private final CredentialNonceRepository credentialNonceRepository;
    private final IssuerProperties issuerProperties;

    public CredentialNonce validate(String accessTokenHash) {
        CredentialNonce cNonce = credentialNonceRepository.findByAccessTokenHash(accessTokenHash);
        long cNonceExpiryTime = issuerProperties.issuer().cNonceExpiryTime().toSeconds();
        Instant now = Instant.now();
        if (cNonce == null || cNonce.getIssuedAt().plusSeconds(cNonceExpiryTime).isBefore(now)) {
            Nonce nonce = new Nonce();
            CredentialNonce credentialNonce = CredentialNonce.builder()
                .nonce(nonce.getValue())
                .issuedAt(Instant.now())
                .accessTokenHash(accessTokenHash)
                .build();
            credentialNonceRepository.save(credentialNonce);
            throw new CredentialNonceException(credentialNonce.getNonce(), cNonceExpiryTime);
        }
        credentialNonceRepository.delete(cNonce);
        return cNonce;
    }
}
