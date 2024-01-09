package ee.ria.eudi.qeaa.issuer.configuration.properties;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import org.hibernate.validator.constraints.time.DurationMax;
import org.hibernate.validator.constraints.time.DurationMin;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.time.Duration;
import java.util.List;
import java.util.Locale;

@Validated
@ConfigurationProperties(prefix = "eudi")
public record IssuerProperties(
    @NotNull
    Issuer issuer,
    @NotNull
    AuthorizationServer as) {

    @ConfigurationProperties(prefix = "eudi.issuer")
    public record Issuer(
        @NotBlank
        @Pattern(regexp = ".*(?<!/)$")
        String baseUrl,
        @NotNull
        Duration cNonceExpiryTime,
        @NotNull
        Duration dPoPExpiryTime,
        @NotNull
        Duration keyProofExpiryTime,
        @NotNull
        @DurationMin(seconds = 1)
        @DurationMax(seconds = 120)
        @NotNull
        Duration maxClockSkew,
        @NotNull
        Credential credential,
        @NotNull
        Metadata metadata) {

        public record Credential(
            Duration validity) {
        }

        public record Metadata(
            @NotNull
            List<Locale> supportedLocales) {
        }
    }

    public record AuthorizationServer(
        @NotBlank
        @Pattern(regexp = ".*(?<!/)$")
        String baseUrl) {
    }
}
