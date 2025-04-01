package ee.ria.eudi.qeaa.issuer.model;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Entity
@Table(name = "credential_statuses", indexes = {
    @Index(name = "idx_status_index", columnList = "statusIndex"),
    @Index(name = "idx_status_list_uri", columnList = "statusListUri")
})
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class CredentialStatus {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne
    private Subject subject;
    @Builder.Default
    private LocalDateTime issuedAt = LocalDateTime.now();
    private int statusIndex;
    private String statusListUri;
}
