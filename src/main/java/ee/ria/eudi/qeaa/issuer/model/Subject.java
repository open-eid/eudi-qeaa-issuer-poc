package ee.ria.eudi.qeaa.issuer.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
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
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public class Subject {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String administrativeNumber;
    private String familyName;
    private String givenName;
    private LocalDate birthDate;
    private LocalDate issueDate;
    private LocalDate expiryDate;
    private String issuingCountry;
    private String issuingAuthority;
    private String documentNumber;
    @Lob
    @JsonDeserialize(using = Base64DeserializerConverter.class)
    private byte[] portrait;
    @Lob
    @JsonDeserialize(using = Base64DeserializerConverter.class)
    private byte[] signatureUsualMark;
    @Convert(converter = StringListConverter.class)
    @Column(name = "driving_privileges", nullable = false)
    private List<String> drivingPrivileges;
    private String unDistinguishingSign;
    @Column(name = "age_over_18", nullable = false)
    @JsonProperty("age_over_18")
    private Boolean ageOver18;
}

