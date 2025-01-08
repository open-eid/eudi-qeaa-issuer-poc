package ee.ria.eudi.qeaa.issuer.controller;

import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import lombok.Builder;

import java.util.List;

@Builder
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public record CredentialRequest(
    String credentialIdentifier,
    String format,
    String doctype,
    Proof proof,
    List<Proof> proofs,
    CredentialResponseEncryption credentialResponseEncryption) {

    @Builder
    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    public record Proof(
        String proofType,
        String jwt) {

    }

    @Builder
    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    public record CredentialResponseEncryption(
        Object jwk,
        String alg,
        String enc) {

    }
}
