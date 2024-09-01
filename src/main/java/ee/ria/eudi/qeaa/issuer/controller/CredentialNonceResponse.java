package ee.ria.eudi.qeaa.issuer.controller;

import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;

@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public record CredentialNonceResponse(
    String cNonce,
    long cNonceExpiresIn) {
}
