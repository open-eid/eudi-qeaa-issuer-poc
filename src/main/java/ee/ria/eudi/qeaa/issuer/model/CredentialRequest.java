package ee.ria.eudi.qeaa.issuer.model;

import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import lombok.Builder;

@Builder
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public record CredentialRequest(
    String format,
    String doctype,
    Proof proof) {


    @Builder
    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    public record Proof(
        String proofType,
        String jwt) {

    }
}
