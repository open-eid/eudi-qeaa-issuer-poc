package ee.ria.eudi.qeaa.issuer.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import lombok.Builder;

import java.util.List;
import java.util.Map;

@Builder
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
@JsonInclude(JsonInclude.Include.NON_NULL)
public record CredentialIssuerMetadata(
    String credentialIssuer,
    String credentialEndpoint,
    String credentialNonceEndpoint,
    Map<String, CredentialType> credentialConfigurationsSupported,
    List<Display> display,
    List<String> authorizationServers) {

    @Builder
    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    public record Display(
        String name,
        String locale) {
    }

    @Builder
    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    public record CredentialType(
        String format,
        String doctype,
        List<String> cryptographicBindingMethodsSupported,
        List<String> credentialSigningAlgValuesSupported,
        Map<String, ProofType> proofTypesSupported,
        List<Display> display,
        Map<String, Map<String, Claim>> claims) {

        @Builder
        @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
        public record ProofType(
            List<String> proofSigningAlgValuesSupported) {
        }

        @Builder
        @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
        public record Display(
            String name,
            String locale,
            String logo,
            String description,
            String backgroundColor,
            String textColor) {
        }

        @Builder
        @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
        public record Claim(
            boolean mandatory,
            List<Display> display) {

            @Builder
            @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
            public record Display(
                String name,
                String locale) {
            }
        }
    }
}
