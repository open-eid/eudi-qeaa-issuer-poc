package ee.ria.eudi.qeaa.issuer.service;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDate;
import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
public final class MobileDrivingLicence {
    private String familyName;
    private String givenName;
    private LocalDate birthDate;
    private LocalDate issueDate;
    private LocalDate expiryDate;
    private String issuingCountry;
    private String issuingAuthority;
    private String documentNumber;
    private byte[] portrait;
    private List<String> drivingPrivileges;
    private String unDistinguishingSign;
}
