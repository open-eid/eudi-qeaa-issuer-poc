package ee.ria.eudi.qeaa.issuer.model;

import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;

@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public record CredentialNonceResponse(
    String cNonce,
    long cNonceExpiresIn) {
}
