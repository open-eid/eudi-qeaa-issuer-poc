package ee.ria.eudi.qeaa.issuer.model;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.validation.annotation.Validated;

import java.time.Instant;

@Entity
@Table(name = "credential_nonces")
@Data
@Builder
@Validated
@NoArgsConstructor
@AllArgsConstructor
public class CredentialNonce {
    @Id
    private String accessTokenHash;
    private Instant issuedAt;
    private String nonce;
}
