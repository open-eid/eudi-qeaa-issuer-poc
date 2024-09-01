package ee.ria.eudi.qeaa.issuer.controller;

import com.nimbusds.openid.connect.sdk.Nonce;
import ee.ria.eudi.qeaa.issuer.configuration.properties.IssuerProperties;
import ee.ria.eudi.qeaa.issuer.model.CredentialNonce;
import ee.ria.eudi.qeaa.issuer.repository.CredentialNonceRepository;
import jakarta.validation.constraints.NotBlank;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;

@RestController
@RequiredArgsConstructor
public class CredentialNonceController {
    public static final String CREDENTIAL_NONCE_REQUEST_MAPPING = "/nonce";
    private final CredentialNonceRepository credentialNonceRepository;
    private final IssuerProperties issuerProperties;

    @PostMapping(path = CREDENTIAL_NONCE_REQUEST_MAPPING, consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public CredentialNonceResponse nonceRequest(@RequestParam(name = "ath") @NotBlank String ath) {
        Nonce nonce = new Nonce();
        CredentialNonce credentialNonce = CredentialNonce.builder()
            .nonce(nonce.getValue())
            .issuedAt(Instant.now())
            .accessTokenHash(ath)
            .build();
        credentialNonceRepository.save(credentialNonce);
        return new CredentialNonceResponse(credentialNonce.getNonce(), issuerProperties.issuer().cNonceExpiryTime().toSeconds());
    }
}
