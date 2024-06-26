package ee.ria.eudi.qeaa.issuer.model;

import jakarta.persistence.Column;
import jakarta.persistence.Convert;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Lob;
import jakarta.persistence.Table;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDate;
import java.util.List;

@Entity
@Table(name = "subjects")
@Data
@NoArgsConstructor
public class Subject {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String subject;
    private String familyName;
    private String givenName;
    private LocalDate birthDate;
    private LocalDate issueDate;
    private LocalDate expiryDate;
    private String issuingCountry;
    private String issuingAuthority;
    private String documentNumber;
    @Lob
    private byte[] portrait;
    @Convert(converter = StringListConverter.class)
    @Column(name = "driving_privileges", nullable = false)
    private List<String> drivingPrivileges;
    private String unDistinguishingSign;
}

